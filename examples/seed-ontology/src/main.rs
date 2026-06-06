#![allow(clippy::unwrap_used)]
//! Seed the schema.org ontology into an ordvec index for semantic intent routing.
//!
//! Downloads `all-MiniLM-L6-v2` weights (if absent), fetches the schema.org
//! types CSV, embeds each type as `label + comment + supertypes`, and writes:
//!
//!   - `schema-ontology.tvrq`  — ordvec RankQuant index (384-dim, 2-bit)
//!   - `schema-types.json`     — parallel array mapping position → type URI
//!
//! Both files are written to the Papillon model directory
//! (`~/Library/Application Support/papillon/models/` on macOS).
//!
//! Usage:
//!   cargo run --example seed-ontology
//!   cargo run --example seed-ontology -- --model-dir /path/to/custom/dir

use std::collections::HashMap;
use std::path::PathBuf;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use tokenizers::Tokenizer;

const SCHEMA_TYPES_URL: &str =
    "https://schema.org/version/latest/schemaorg-current-https-types.csv";
const MINILM_WEIGHTS_URL: &str =
    "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/model.safetensors";
const MINILM_TOKENIZER_URL: &str =
    "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json";
const WEIGHTS_FILENAME: &str = "all-minilm-l6-v2.safetensors";
const TOKENIZER_FILENAME: &str = "all-minilm-l6-v2-tokenizer.json";
const DIM: usize = 384;
const BITS: u8 = 2;
const MAX_SEQ_LEN: usize = 128;

fn main() {
    let model_dir = parse_model_dir();
    std::fs::create_dir_all(&model_dir).expect("create model dir");

    println!("Model directory: {}", model_dir.display());

    // Step 1: Ensure MiniLM weights are present.
    let weights_path = model_dir.join(WEIGHTS_FILENAME);
    let tokenizer_path = model_dir.join(TOKENIZER_FILENAME);

    if !tokenizer_path.exists() {
        println!("Downloading tokenizer (~500KB)…");
        download_sync(MINILM_TOKENIZER_URL, &tokenizer_path);
        println!("  → {}", tokenizer_path.display());
    } else {
        println!("Tokenizer already present.");
    }

    if !weights_path.exists() {
        println!("Downloading all-MiniLM-L6-v2 weights (~22MB)…");
        download_sync(MINILM_WEIGHTS_URL, &weights_path);
        println!("  → {}", weights_path.display());
    } else {
        println!("Weights already present.");
    }

    // Step 2: Load model.
    println!("Loading model…");
    let device = Device::Cpu;
    let tokenizer = Tokenizer::from_file(&tokenizer_path).expect("load tokenizer");
    let tensors = candle_core::safetensors::load(&weights_path, &device).expect("load weights");
    let vb = VarBuilder::from_tensors(tensors, DType::F32, &device);
    let config = BertConfig {
        hidden_size: 384,
        num_hidden_layers: 6,
        num_attention_heads: 12,
        intermediate_size: 1536,
        max_position_embeddings: 512,
        ..BertConfig::default()
    };
    let model = BertModel::load(vb, &config).expect("load BertModel");
    println!("  Model ready.");

    // Step 3: Fetch schema.org types CSV.
    println!("Fetching schema.org types…");
    let csv_bytes = reqwest::blocking::get(SCHEMA_TYPES_URL)
        .expect("fetch schema.org CSV")
        .bytes()
        .expect("read response bytes");

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_bytes.as_ref());

    // Parse CSV manually to avoid serde version aliasing issues.
    // Columns: id, label, comment, subTypeOf, ...
    let headers: Vec<String> = reader
        .headers()
        .expect("CSV headers")
        .iter()
        .map(str::to_owned)
        .collect();
    let id_col = headers.iter().position(|h| h == "id").unwrap_or(0);
    let label_col = headers.iter().position(|h| h == "label").unwrap_or(1);
    let comment_col = headers.iter().position(|h| h == "comment").unwrap_or(2);
    let subtype_col = headers.iter().position(|h| h == "subTypeOf").unwrap_or(3);

    let records: Vec<SchemaRow> = reader
        .records()
        .filter_map(|r| r.ok())
        .filter_map(|r| {
            let id = r.get(id_col)?.to_owned();
            let label = r.get(label_col)?.to_owned();
            if id.is_empty() || label.is_empty() {
                return None;
            }
            Some(SchemaRow {
                id,
                label,
                comment: r.get(comment_col).unwrap_or("").to_owned(),
                sub_type_of: r.get(subtype_col).unwrap_or("").to_owned(),
            })
        })
        .collect();

    let label_map: HashMap<&str, &str> = records
        .iter()
        .map(|r| (r.id.as_str(), r.label.as_str()))
        .collect();

    println!("  {} types loaded.", records.len());

    // Step 4: Embed each type.
    println!("Embedding {} types…", records.len());
    let mut flat: Vec<f32> = Vec::with_capacity(records.len() * DIM);
    let mut type_uris: Vec<String> = Vec::with_capacity(records.len());

    for (i, row) in records.iter().enumerate() {
        if i % 100 == 0 {
            print!("  {}/{}…\r", i, records.len());
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }

        let text = build_type_text(row, &label_map);
        let emb = embed(&model, &tokenizer, &device, &text)
            .unwrap_or_else(|| vec![0.0f32; DIM]);

        flat.extend_from_slice(&emb);
        // Normalise the URI to schema: prefix form used in the catalog.
        let short = row
            .id
            .strip_prefix("https://schema.org/")
            .unwrap_or(&row.id);
        type_uris.push(format!("schema:{short}"));
    }
    println!("  Embedded {} types.         ", records.len());

    // Step 5: Build ordvec index.
    println!("Building ordvec RankQuant index…");
    let mut index = ordvec::RankQuant::new(DIM, BITS);
    index.add(&flat);

    // Step 6: Write index + type list.
    let tvrq_path = model_dir.join("schema-ontology.tvrq");
    let types_path = model_dir.join("schema-types.json");

    index.write(&tvrq_path).expect("write .tvrq");
    let json = serde_json::to_string(&type_uris).expect("serialize type URIs");
    std::fs::write(&types_path, json).expect("write schema-types.json");

    println!("Written:");
    println!("  {}", tvrq_path.display());
    println!("  {}", types_path.display());
    println!("Done. {} schema.org types indexed.", type_uris.len());
}

// ── Types ────────────────────────────────────────────────────────────────────

struct SchemaRow {
    id: String,
    label: String,
    comment: String,
    sub_type_of: String,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build the text document for a schema.org type.
/// Includes label, plain-text comment, and parent type labels so the
/// embedding captures ontological position (e.g. ExchangeRateSpecification
/// is a StructuredValue, not just a float).
fn build_type_text(row: &SchemaRow, label_map: &HashMap<&str, &str>) -> String {
    let comment = strip_html(&row.comment);
    // Collect immediate supertype labels.
    let supertypes: Vec<&str> = row
        .sub_type_of
        .split(',')
        .filter_map(|s| {
            let uri = s.trim();
            label_map.get(uri).copied()
        })
        .collect();

    if supertypes.is_empty() {
        format!("{} {}", row.label, comment)
    } else {
        format!("{} {} is a type of {}", row.label, comment, supertypes.join(", "))
    }
}

/// Strip HTML tags from a schema.org comment field.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    // Collapse runs of whitespace.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Mean-pool + L2-normalise a text into a 384-dim embedding.
fn embed(model: &BertModel, tokenizer: &Tokenizer, device: &Device, text: &str) -> Option<Vec<f32>> {
    let enc = tokenizer.encode(text, true).ok()?;
    let ids: Vec<u32> = enc.get_ids().iter().cloned().take(MAX_SEQ_LEN).collect();
    let len = ids.len();

    let input_ids = Tensor::new(ids.as_slice(), device).ok()?.unsqueeze(0).ok()?;
    let token_type_ids = Tensor::zeros((1, len), DType::U32, device).ok()?;
    let attention_mask = Tensor::ones((1, len), DType::U32, device).ok()?;

    let hidden = model
        .forward(&input_ids, &token_type_ids, Some(&attention_mask))
        .ok()?;

    let pooled = hidden.mean(1).ok()?;
    let norm = pooled.sqr().ok()?.sum_keepdim(1).ok()?.sqrt().ok()?;
    let normalised = pooled.broadcast_div(&norm).ok()?;
    normalised.squeeze(0).ok()?.to_vec1::<f32>().ok()
}

/// Blocking HTTP download with a progress indicator.
fn download_sync(url: &str, dest: &PathBuf) {
    use std::io::Write;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }

    let mut resp = reqwest::blocking::get(url).expect("GET request");
    let total = resp.content_length().unwrap_or(0);
    let mut file = std::fs::File::create(dest).expect("create dest file");
    let mut downloaded = 0u64;
    let mut buf = vec![0u8; 65536];

    loop {
        let n = std::io::Read::read(&mut resp, &mut buf).expect("read chunk");
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).expect("write chunk");
        downloaded += n as u64;
        if total > 0 {
            print!("  {:.1}%\r", downloaded as f64 / total as f64 * 100.0);
            let _ = std::io::stdout().flush();
        }
    }
}

/// Parse `--model-dir` from args, or fall back to the Papillon default.
fn parse_model_dir() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--model-dir") {
        if let Some(dir) = args.get(pos + 1) {
            return PathBuf::from(dir);
        }
    }
    pap_agents::default_model_dir()
}
