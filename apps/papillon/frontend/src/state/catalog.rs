use leptos::prelude::*;
use papillon_shared::AgentInfo;
use std::collections::HashMap;

/// Reactive name-to-DID index built from the connected registry's agent list.
/// Used by the pap:// resolver's step 2 (catalog name lookup).
#[derive(Clone, Copy)]
pub struct CatalogState {
    /// Lowercase agent name → did:key:... string.
    /// None entries are omitted — only agents with a known DID are indexed.
    pub entries: RwSignal<HashMap<String, String>>,
}

impl Default for CatalogState {
    fn default() -> Self {
        Self {
            entries: RwSignal::new(HashMap::new()),
        }
    }
}

impl CatalogState {
    /// Rebuild the index from a fresh agent list.
    /// Called when the registry browser loads agents or the user connects to a new registry.
    pub fn refresh(&self, agents: &[AgentInfo]) {
        self.entries.set(build_catalog(agents));
    }

    /// Snapshot the current entries for synchronous resolution (no reactive tracking).
    pub fn snapshot(&self) -> HashMap<String, String> {
        self.entries.get_untracked()
    }
}

/// Build a `name → DID` map from an agent list.
/// Agents without a `agent_did` are skipped (remote registry agents without a known DID
/// cannot be directly resolved via catalog shorthand).
pub fn build_catalog(agents: &[AgentInfo]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for agent in agents {
        if let Some(did) = agent.agent_did.as_ref() {
            // Keep first entry on name collision — last-writer-wins would silently
            // redirect the principal's intent to the wrong agent.
            map.entry(agent.name.to_lowercase()).or_insert_with(|| did.clone());
        }
    }
    map
}
