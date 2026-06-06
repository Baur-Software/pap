//! Semantic agent index — ordvec-backed nearest-neighbour retrieval.
//!
//! Two operating modes, selected by which files are present in the model dir:
//!
//! **Ontology mode** (preferred): `schema-ontology.tvrq` + `schema-types.json`
//!   Built by `examples/seed-ontology`. Routes query → nearest schema.org type
//!   URIs → catalog agents whose `returns`/`object_types` match. More accurate
//!   because the ontology embedding is denser and covers all PAP vocabulary.
//!
//! **Descriptor mode** (fallback): embeds agent descriptors at startup.
//!   No prebuilt index needed; requires `all-minilm-l6-v2.safetensors`.
//!
//! Both modes sit between BM25 (Level 2) and federation NLU (Level 3):
//!
//! ```text
//! 1. URL keyword rules   ~0µs    papillon-shared detect_intent()
//! 2. BM25 token index   ~50µs   IntentIndex
//! 2.5 Semantic index    ~5ms    SemanticIndex   ← this module
//! 3. Federation NLU    ~100ms   classify_intent() level-3 path
//! ```
//!
//! Only available when the `semantic` feature is enabled (implies `candle`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use candle_core::{DType, Device, Tensor};
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use tokenizers::Tokenizer;

use crate::llm::default_model_dir;
use crate::DynamicAgentDef;

/// Output dimension of all-MiniLM-L6-v2.
const DIM: usize = 384;
/// ordvec quantisation bits (2 → 96 bytes/doc at 384-dim).
const BITS: u8 = 2;
/// Maximum tokens per text fed to the encoder.
const MAX_SEQ_LEN: usize = 128;

// ── Public result type ────────────────────────────────────────────────────────

/// A single semantic match returned by [`SemanticIndex::search`].
pub struct SemanticMatch {
    /// Schema.org action type (e.g. `"schema:TradeAction"`).
    pub action: String,
    /// Agent name from the catalog (e.g. `"Frankfurter Exchange Rates"`).
    pub agent_name: String,
    /// Cosine-similarity score in the rank-quantised space (higher = better).
    pub score: f32,
}

// ── Internal types ────────────────────────────────────────────────────────────

struct EmbedState {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

/// An entry in the descriptor-mode index parallel array.
struct DescriptorEntry {
    agent_name: String,
    action: String,
}

/// An entry in the ontology-mode index: maps position → schema type URI
/// and the agents that return or accept that type.
struct OntologyEntry {
    #[allow(dead_code)]
    type_uri: String,
    /// Agents whose `returns` or `object_types` include this URI.
    agents: Vec<AgentRef>,
}

struct AgentRef {
    agent_name: String,
    action: String,
}

enum IndexKind {
    /// ordvec store + parallel agent entries (descriptor mode).
    Descriptor {
        store: ordvec::RankQuant,
        entries: Vec<DescriptorEntry>,
    },
    /// Prebuilt ordvec store + ontology entries (ontology mode).
    Ontology {
        store: ordvec::RankQuant,
        entries: Vec<OntologyEntry>,
    },
}

// ── SemanticIndex ─────────────────────────────────────────────────────────────

/// Ordvec-backed semantic index for PAP intent routing.
///
/// Prefer [`SemanticIndex::from_ontology`] when the prebuilt schema.org
/// index exists (run `cargo run --example seed-ontology` once to generate it).
/// Fall back to [`SemanticIndex::build`] (descriptor mode) otherwise.
pub struct SemanticIndex {
    index: IndexKind,
    state: Mutex<Option<EmbedState>>,
}

impl SemanticIndex {
    // ── Ontology mode ─────────────────────────────────────────────────────────

    /// Load a prebuilt schema.org ontology index.
    ///
    /// Requires:
    ///   - `{model_dir}/schema-ontology.tvrq`
    ///   - `{model_dir}/schema-types.json`
    ///   - `{model_dir}/all-minilm-l6-v2.safetensors`
    ///   - `{model_dir}/all-minilm-l6-v2-tokenizer.json`
    ///
    /// Returns `None` if any file is missing; callers fall through gracefully.
    pub fn from_ontology(
        agents: &[DynamicAgentDef],
        model_dir: Option<PathBuf>,
    ) -> Option<Self> {
        let dir = model_dir.unwrap_or_else(default_model_dir);
        let tvrq_path = dir.join("schema-ontology.tvrq");
        let types_path = dir.join("schema-types.json");
        let weights_path = dir.join("all-minilm-l6-v2.safetensors");
        let tokenizer_path = dir.join("all-minilm-l6-v2-tokenizer.json");

        if !tvrq_path.exists()
            || !types_path.exists()
            || !weights_path.exists()
            || !tokenizer_path.exists()
        {
            return None;
        }

        let store = ordvec::RankQuant::load(&tvrq_path).ok()?;

        let type_uris: Vec<String> =
            serde_json::from_str(&std::fs::read_to_string(&types_path).ok()?).ok()?;

        // Build a reverse map: type_uri → Vec<AgentRef>
        let mut type_to_agents: HashMap<String, Vec<AgentRef>> = HashMap::new();
        for agent in agents {
            for t in agent.returns.iter().chain(agent.object_types.iter()) {
                type_to_agents
                    .entry(t.clone())
                    .or_default()
                    .push(AgentRef {
                        agent_name: agent.name.clone(),
                        action: agent.action.clone(),
                    });
            }
        }

        let entries: Vec<OntologyEntry> = type_uris
            .into_iter()
            .map(|uri| {
                let agents = type_to_agents.remove(&uri).unwrap_or_default();
                OntologyEntry {
                    type_uri: uri,
                    agents,
                }
            })
            .collect();

        let state = load_embed_state(&weights_path, &tokenizer_path)?;

        Some(Self {
            index: IndexKind::Ontology { store, entries },
            state: Mutex::new(Some(state)),
        })
    }

    // ── Descriptor mode ───────────────────────────────────────────────────────

    /// Build a descriptor-mode index by embedding each agent's text at startup.
    ///
    /// Requires `all-minilm-l6-v2.safetensors` + `all-minilm-l6-v2-tokenizer.json`
    /// in `model_dir`. Returns `None` if absent.
    pub fn build(agents: &[DynamicAgentDef], model_dir: Option<PathBuf>) -> Option<Self> {
        let dir = model_dir.unwrap_or_else(default_model_dir);
        let weights_path = dir.join("all-minilm-l6-v2.safetensors");
        let tokenizer_path = dir.join("all-minilm-l6-v2-tokenizer.json");

        if !weights_path.exists() || !tokenizer_path.exists() {
            return None;
        }

        let state = load_embed_state(&weights_path, &tokenizer_path)?;
        let mut store = ordvec::RankQuant::new(DIM, BITS);
        let mut entries: Vec<DescriptorEntry> = Vec::with_capacity(agents.len());
        let mut flat: Vec<f32> = Vec::with_capacity(agents.len() * DIM);

        for agent in agents {
            let text = build_descriptor(agent);
            let emb = embed_text(&state, &text)?;
            flat.extend_from_slice(&emb);
            entries.push(DescriptorEntry {
                agent_name: agent.name.clone(),
                action: agent.action.clone(),
            });
        }

        if !flat.is_empty() {
            store.add(&flat);
        }

        Some(Self {
            index: IndexKind::Descriptor { store, entries },
            state: Mutex::new(Some(state)),
        })
    }

    // ── Search ────────────────────────────────────────────────────────────────

    /// Return the top-`k` agent matches most semantically similar to `query`.
    ///
    /// In ontology mode, routes through schema.org types first: the closest
    /// type URIs are resolved to catalog agents via their `returns`/`object_types`.
    /// In descriptor mode, ranks agents directly by embedding similarity.
    pub fn search(&self, query: &str, k: usize) -> Vec<SemanticMatch> {
        if k == 0 {
            return vec![];
        }

        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return vec![],
        };
        let emb = match embed_text(state, query) {
            Some(e) => e,
            None => return vec![],
        };

        match &self.index {
            IndexKind::Descriptor { store, entries } => {
                if entries.is_empty() {
                    return vec![];
                }
                let k_clamped = k.min(entries.len());
                let results = store.search_asymmetric(&emb, k_clamped);
                let ids = results.indices_for_query(0);
                let scores = results.scores_for_query(0);
                ids.iter()
                    .zip(scores.iter())
                    .filter_map(|(&id, &score)| {
                        let e = entries.get(id as usize)?;
                        Some(SemanticMatch {
                            action: e.action.clone(),
                            agent_name: e.agent_name.clone(),
                            score,
                        })
                    })
                    .collect()
            }
            IndexKind::Ontology { store, entries } => {
                if entries.is_empty() {
                    return vec![];
                }
                // Search a wider window to find entries that have agent coverage.
                let window = (k * 8).min(entries.len());
                let results = store.search_asymmetric(&emb, window);
                let ids = results.indices_for_query(0);
                let scores = results.scores_for_query(0);

                let mut matches: Vec<SemanticMatch> = Vec::new();
                for (&id, &score) in ids.iter().zip(scores.iter()) {
                    let entry = match entries.get(id as usize) {
                        Some(e) => e,
                        None => continue,
                    };
                    for agent_ref in &entry.agents {
                        matches.push(SemanticMatch {
                            action: agent_ref.action.clone(),
                            agent_name: agent_ref.agent_name.clone(),
                            score,
                        });
                        if matches.len() >= k {
                            return matches;
                        }
                    }
                }
                matches
            }
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn load_embed_state(weights_path: &std::path::Path, tokenizer_path: &std::path::Path) -> Option<EmbedState> {
    let device = Device::Cpu;
    let tokenizer = Tokenizer::from_file(tokenizer_path).ok()?;
    let tensors = candle_core::safetensors::load(weights_path, &device).ok()?;
    let vb = candle_nn::VarBuilder::from_tensors(tensors, DType::F32, &device);
    let config = BertConfig {
        hidden_size: 384,
        num_hidden_layers: 6,
        num_attention_heads: 12,
        intermediate_size: 1536,
        max_position_embeddings: 512,
        ..BertConfig::default()
    };
    let model = BertModel::load(vb, &config).ok()?;
    Some(EmbedState { model, tokenizer, device })
}

fn build_descriptor(agent: &DynamicAgentDef) -> String {
    let cap = agent
        .llm_instructions
        .char_indices()
        .nth(200)
        .map(|(i, _)| i)
        .unwrap_or(agent.llm_instructions.len());
    let instructions = &agent.llm_instructions[..cap];
    let object_types = agent
        .object_types
        .iter()
        .map(|t| t.strip_prefix("schema:").unwrap_or(t))
        .collect::<Vec<_>>()
        .join(" ");
    let returns = agent
        .returns
        .iter()
        .map(|t| t.strip_prefix("schema:").unwrap_or(t))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {} {} {}",
        agent.name, agent.provider, agent.description, instructions, object_types, returns
    )
}

fn embed_text(state: &EmbedState, text: &str) -> Option<Vec<f32>> {
    let enc = state.tokenizer.encode(text, true).ok()?;
    let ids: Vec<u32> = enc.get_ids().iter().cloned().collect();
    let len = ids.len().min(MAX_SEQ_LEN);
    let ids = &ids[..len];

    let input_ids = Tensor::new(ids, &state.device).ok()?.unsqueeze(0).ok()?;
    let token_type_ids = Tensor::zeros((1, len), DType::U32, &state.device).ok()?;
    let attention_mask = Tensor::ones((1, len), DType::U32, &state.device).ok()?;

    let hidden = state
        .model
        .forward(&input_ids, &token_type_ids, Some(&attention_mask))
        .ok()?;

    let pooled = hidden.mean(1).ok()?;
    let norm = pooled.sqr().ok()?.sum_keepdim(1).ok()?.sqrt().ok()?;
    let normalised = pooled.broadcast_div(&norm).ok()?;
    normalised.squeeze(0).ok()?.to_vec1::<f32>().ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_returns_none_when_model_absent() {
        let result = SemanticIndex::build(&[], Some(PathBuf::from("/nonexistent/path")));
        assert!(result.is_none());
    }

    #[test]
    fn from_ontology_returns_none_when_files_absent() {
        let result = SemanticIndex::from_ontology(&[], Some(PathBuf::from("/nonexistent/path")));
        assert!(result.is_none());
    }
}
