pub mod events;
pub mod intent;
pub mod json_ld_query;
pub mod pap_uri;
pub use pap_uri::{resolve_pap_uri, LinkOrigin, PapUriError, ResolvedUri};
pub mod template_gen;
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

pub use events::*;
pub use json_ld_query::JsonLdQuery;
pub use template_gen::generate_template_from_json_ld;
pub use types::*;
