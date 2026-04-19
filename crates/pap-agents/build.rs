//! Build script for pap-agents.
//!
//! Walks all `*.toml` files under `catalog/`, converts each to a JSON object
//! (via `toml::Value` → `serde_json::Value` so no struct duplication is
//! needed), and writes them as a JSON array to `$OUT_DIR/catalog.json`.
//!
//! The output is embedded at compile time by `src/catalog.rs`
//! (`default_catalog()`) using `include_str!`, making the catalog available
//! in WASM builds without any filesystem access at runtime.

use std::path::PathBuf;

fn main() {
    // Tell Cargo to re-run this script whenever the catalog changes.
    println!("cargo:rerun-if-changed=catalog/");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by Cargo");
    let catalog_dir = PathBuf::from(&manifest_dir).join("catalog");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo");
    let out_path = PathBuf::from(&out_dir).join("catalog.json");

    let mut entries: Vec<serde_json::Value> = Vec::new();
    collect_toml_entries(&catalog_dir, &catalog_dir, &mut entries);

    let json = serde_json::to_string(&entries)
        .expect("failed to serialize catalog entries to JSON");
    std::fs::write(&out_path, json)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));

    eprintln!(
        "[build] wrote {} catalog entries to {}",
        entries.len(),
        out_path.display()
    );
}

fn collect_toml_entries(
    catalog_root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<serde_json::Value>,
) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("[build] cannot read directory {}: {e}", dir.display());
            return;
        }
    };

    let mut paths: Vec<std::path::PathBuf> = read_dir
        .flatten()
        .map(|e| e.path())
        .collect();
    // Sort for deterministic output order.
    paths.sort();

    for path in paths {
        if path.is_dir() {
            collect_toml_entries(catalog_root, &path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            if let Some(val) = load_toml_as_json(catalog_root, &path) {
                out.push(val);
            }
        }
    }
}

fn load_toml_as_json(
    catalog_root: &std::path::Path,
    path: &std::path::Path,
) -> Option<serde_json::Value> {
    // Emit a per-file rerun directive so Cargo rebuilds when any individual
    // TOML file changes, not just when the directory mtime changes.
    println!("cargo:rerun-if-changed={}", path.display());

    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[build] cannot read {}: {e}", path.display());
            return None;
        }
    };

    let toml_val: toml::Value = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[build] parse error in {}: {e}", path.display());
            return None;
        }
    };

    // Convert TOML value tree → serde_json::Value.
    let mut json_val = toml_to_json(toml_val);

    // Inject fields that DynamicAgentDef requires but catalog TOMLs omit.
    if let Some(obj) = json_val.as_object_mut() {
        // `source` — always "Catalog" for embedded catalog entries; overwrite unconditionally
        // so a TOML that accidentally sets source="UserCreated" doesn't leak through.
        obj.insert("source".into(), serde_json::Value::String("Catalog".to_string()));

        // `catalog_path` — relative path from catalog root, forward-slash separators.
        let rel = path
            .strip_prefix(catalog_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        obj.entry("catalog_path")
            .or_insert_with(|| serde_json::Value::String(rel));

        // Fields with empty defaults that DynamicAgentDef expects.
        obj.entry("agent_did").or_insert(serde_json::Value::Null);
        obj.entry("operator_key_seed")
            .or_insert(serde_json::Value::Null);
        obj.entry("published_to")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        obj.entry("created_at")
            .or_insert_with(|| serde_json::Value::String(String::new()));
        obj.entry("updated_at")
            .or_insert_with(|| serde_json::Value::String(String::new()));
        obj.entry("llm_instructions")
            .or_insert_with(|| serde_json::Value::String(String::new()));
        obj.entry("subagents")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        obj.entry("object_types")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        obj.entry("requires_disclosure")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        obj.entry("returns")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        obj.entry("configurable_properties")
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        obj.entry("version")
            .or_insert_with(|| serde_json::Value::String("0.1.0".to_string()));
    }

    Some(json_val)
}

/// Recursively convert a [`toml::Value`] to a [`serde_json::Value`].
fn toml_to_json(val: toml::Value) -> serde_json::Value {
    match val {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::Number(i.into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        toml::Value::Boolean(b) => serde_json::Value::Bool(b),
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(toml_to_json).collect())
        }
        toml::Value::Table(tbl) => {
            let map = tbl
                .into_iter()
                .map(|(k, v)| (k, toml_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}
