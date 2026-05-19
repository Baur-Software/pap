pub mod canvas_ops;
pub use canvas_ops::{
    filter_messages_by_canvas, merge_canvases_from_records, merge_messages_dedup,
    parse_inline_citations, segment_with_citations, InlineCitation, TextSegment,
};
pub mod credential_gate;
pub mod dataset_types;
pub use dataset_types::{DatasetDiscoveryState, DatasetResult};
pub mod schema_signature;
pub use schema_signature::SchemaSignature;
pub mod block_container;
pub use block_container::{BlockConnection, BlockContainer, BlockPosition, WiringError};
pub mod events;
pub mod intent;
pub mod json_ld_query;
pub mod pap_uri;
pub use pap_uri::{resolve_pap_uri, LinkOrigin, PapUriError, ResolvedUri};
pub mod schema_phrase;
pub mod template_gen;
pub use schema_phrase::schema_phrase;
pub mod types;

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod db;

/// Agent profile aggregation from the episode store (native only).
pub mod agent_profile;

#[cfg(feature = "native")]
pub mod episode_db;

/// Local preference-learning engine — all data stays on the principal's device.
#[cfg(feature = "native")]
pub mod preference_engine;
#[cfg(feature = "native")]
pub use preference_engine::PreferenceEngine;

/// Personal context aggregation for the orchestrator system prompt.
/// Synthesizes episode history, agent profiles, and user traits into a
/// compact JSON-LD preamble injected into every orchestrator LLM call.
#[cfg(feature = "native")]
pub mod personal_context;
#[cfg(feature = "native")]
pub use personal_context::PersonalContext;

/// WASM-safe local agent registry backed by IndexedDB.
///
/// Compiled when the `wasm` feature is enabled (both in browser WASM builds and
/// in native test runs with `--features wasm`).  Provides
/// [`wasm_registry::WasmAgentRegistry`] which mirrors what the desktop
/// `AppState::with_db()` does for catalog seeding and agent discovery.
#[cfg(feature = "wasm")]
pub mod wasm_registry;
#[cfg(feature = "wasm")]
pub use wasm_registry::{WasmAgentRegistry, WasmDynamicAgentDef};

pub use events::*;
pub use json_ld_query::JsonLdQuery;
pub use template_gen::generate_template_from_json_ld;
pub use types::*;
