use serde::{Deserialize, Serialize};

/// A synthesized summary of a single completed agent interaction episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeSummary {
    /// Ephemeral session DID (first 16 chars of receipt_session_id for display).
    pub session_did: String,
    /// Agent DID hash (privacy-safe — never raw DID).
    pub agent_did: String,
    /// Human-readable agent name.
    pub agent_name: String,
    /// Schema.org action type exercised, e.g. "schema:SearchAction".
    pub action: String,
    /// Episode outcome: "success", "failure", or "rejected".
    pub outcome: String,
    /// ISO-8601 timestamp of when the episode was recorded.
    pub timestamp: String,
    /// SHA-256 hash of the receipt session ID — used as a stable identity.
    pub receipt_hash: String,
    /// Optional human-readable summary of the agent's intent.
    pub intent_summary: Option<String>,
}

/// Synthesized canvas state returned to the frontend for outcome rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasSummaryState {
    /// Principal DID — the root of trust for this session.
    pub principal_did: String,
    /// All completed episode summaries, most recent first.
    pub episodes: Vec<EpisodeSummary>,
    /// Count of episodes in "success" outcome.
    pub success_count: u32,
    /// Count of episodes in "failure" or "rejected" outcome.
    pub failure_count: u32,
    /// Count of distinct session IDs currently active (episodes with no result yet).
    /// In the in-memory model this is always 0; future SQLite integration will populate it.
    pub active_sessions: u32,
}

/// Summary of a single resolved block, passed in from the frontend to build
/// the Guide block payload. Contains only the minimum fields needed for
/// summary generation — no raw content is transmitted.
#[derive(Debug, Deserialize)]
pub struct GuideBlockSummary {
    pub schema_type: String,
    pub agent_name: String,
    /// First 80 chars of the result text, for context.
    pub snippet: String,
}

/// The payload returned to the frontend for upserting the Guide block.
#[derive(Debug, Serialize)]
pub struct GuideBlockPayload {
    /// Always "guide-{canvas_id}"
    pub block_id: String,
    pub summary: String,
    pub suggestions: Vec<papillon_shared::GuideSuggestion>,
}
