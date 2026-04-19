//! Shared types for dataset discovery across the IPC boundary.
//!
//! `Serialize + Deserialize`, no async, no HTTP, no Leptos.
//! Compiles under both `native` and `wasm` features.

use serde::{Deserialize, Serialize};

/// A single dataset result produced by one PAP agent via the full 6-phase handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DatasetResult {
    /// Always "Dataset".
    pub schema_type: String,
    pub name: String,
    pub description: Option<String>,
    pub url: Option<String>,
    /// MIME types e.g. "application/parquet", "text/csv"
    pub encoding_format: Vec<String>,
    pub license: Option<String>,
    pub creator: Option<String>,
    pub date_modified: Option<String>,
    /// Direct download URLs from schema:DataDownload
    pub distribution: Vec<String>,
    pub source_agent: String,
    pub source_agent_did: String,
    /// Preference-blended rank (0.0–2.0+)
    pub relevance_score: f64,
    /// Full Croissant JSON-LD blob if available
    pub croissant_metadata: Option<serde_json::Value>,
    /// True when restored from long-horizon memex cache
    pub from_memex: bool,
}

impl Default for DatasetResult {
    fn default() -> Self {
        Self {
            schema_type: "Dataset".to_string(),
            name: String::new(),
            description: None,
            url: None,
            encoding_format: Vec::new(),
            license: None,
            creator: None,
            date_modified: None,
            distribution: Vec::new(),
            source_agent: String::new(),
            source_agent_did: String::new(),
            relevance_score: 0.5,
            croissant_metadata: None,
            from_memex: false,
        }
    }
}

/// FSM for multi-agent fan-out dataset discovery.
///
/// Carried in `block_updated` events during the handshake fan-out.
/// The authoritative final state lives in the `block_resolved` block content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatasetDiscoveryState {
    /// Memex had a recent cache hit — shown immediately while fresh handshakes run.
    RestoredFromMemex {
        results: Vec<DatasetResult>,
        cached_at: String,
        agents_queried: u8,
    },
    FanningOut {
        agents_queried: u8,
    },
    Accumulating {
        agents_pending: u8,
        partial_results: Vec<DatasetResult>,
    },
    Complete {
        results: Vec<DatasetResult>,
    },
    NoResults {
        agents_tried: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_result_roundtrip_serializes() {
        let r = DatasetResult {
            schema_type: "Dataset".to_string(),
            name: "IMDB Reviews".to_string(),
            description: Some("Sentiment dataset".to_string()),
            url: Some("https://huggingface.co/datasets/imdb".to_string()),
            encoding_format: vec!["application/parquet".to_string()],
            license: Some("MIT".to_string()),
            creator: Some("Andrew Maas".to_string()),
            date_modified: Some("2024-01-01T00:00:00Z".to_string()),
            distribution: vec!["https://example.com/data.parquet".to_string()],
            source_agent: "HuggingFace Dataset Search".to_string(),
            source_agent_did: "did:key:z6MkHF1234".to_string(),
            relevance_score: 0.87,
            croissant_metadata: None,
            from_memex: false,
        };
        let json = serde_json::to_string(&r).expect("serialize failed");
        let back: DatasetResult = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(r, back);
    }

    #[test]
    fn restored_from_memex_variant_roundtrip() {
        let state = DatasetDiscoveryState::RestoredFromMemex {
            results: vec![DatasetResult::default()],
            cached_at: "2026-04-15T12:00:00Z".to_string(),
            agents_queried: 2,
        };
        let json = serde_json::to_string(&state).expect("serialize failed");
        let back: DatasetDiscoveryState = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(state, back);
    }

    #[test]
    fn no_results_variant_roundtrip() {
        let state = DatasetDiscoveryState::NoResults { agents_tried: 2 };
        let json = serde_json::to_string(&state).expect("serialize failed");
        let back: DatasetDiscoveryState = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(state, back);
    }
}
