//! DatasetState — Leptos context for multi-agent dataset discovery.
//!
//! Follows the same `#[derive(Clone, Copy)]` + `RwSignal` pattern as
//! `OrchestratorState` and `RegistryState`.

use std::collections::HashMap;
use leptos::prelude::*;
use papillon_shared::{DatasetDiscoveryState, DatasetResult};

/// Phase of discovery for a given block — for progress display.
#[derive(Debug, Clone, PartialEq)]
pub enum DiscoveryPhase {
    Idle,
    RestoringFromMemex,
    FanningOut { total: u8 },
    Accumulating { done: u8, total: u8 },
    Complete,
    Failed(String),
}

impl Default for DiscoveryPhase {
    fn default() -> Self {
        Self::Idle
    }
}

/// Root context for dataset discovery state.
///
/// Keyed by `block_id` so multiple simultaneous dataset queries don't interfere.
#[derive(Clone, Copy)]
pub struct DatasetState {
    /// Merged dataset results per block_id, sorted by relevance_score.
    pub results_by_block: RwSignal<HashMap<String, Vec<DatasetResult>>>,
    /// Current discovery phase per block_id.
    pub phase_by_block: RwSignal<HashMap<String, DiscoveryPhase>>,
    /// Memex-restored results — shown as "from memory" hints.
    pub memex_results_by_block: RwSignal<HashMap<String, (Vec<DatasetResult>, String)>>,
    /// Names of registered dataset agents (for provider badge display).
    pub provider_names: RwSignal<Vec<String>>,
    /// Last error, if any.
    pub error: RwSignal<Option<String>>,
}

impl Default for DatasetState {
    fn default() -> Self {
        Self {
            results_by_block: RwSignal::new(HashMap::new()),
            phase_by_block: RwSignal::new(HashMap::new()),
            memex_results_by_block: RwSignal::new(HashMap::new()),
            provider_names: RwSignal::new(Vec::new()),
            error: RwSignal::new(None),
        }
    }
}

impl DatasetState {
    /// Apply a DatasetDiscoveryState update from a block_updated or block_resolved event.
    pub fn apply_discovery_state(&self, block_id: &str, dds: DatasetDiscoveryState) {
        match dds {
            DatasetDiscoveryState::RestoredFromMemex {
                results,
                cached_at,
                agents_queried,
            } => {
                self.memex_results_by_block.update(|m| {
                    m.insert(block_id.to_string(), (results, cached_at));
                });
                self.phase_by_block.update(|m| {
                    m.insert(
                        block_id.to_string(),
                        DiscoveryPhase::FanningOut {
                            total: agents_queried,
                        },
                    );
                });
            }
            DatasetDiscoveryState::FanningOut { agents_queried } => {
                self.phase_by_block.update(|m| {
                    m.insert(
                        block_id.to_string(),
                        DiscoveryPhase::FanningOut {
                            total: agents_queried,
                        },
                    );
                });
            }
            DatasetDiscoveryState::Accumulating {
                agents_pending,
                partial_results,
            } => {
                self.results_by_block.update(|m| {
                    m.insert(block_id.to_string(), partial_results);
                });
                self.phase_by_block.update(|m| {
                    m.insert(
                        block_id.to_string(),
                        DiscoveryPhase::Accumulating {
                            done: 0,
                            total: agents_pending,
                        },
                    );
                });
            }
            DatasetDiscoveryState::Complete { results } => {
                self.results_by_block.update(|m| {
                    m.insert(block_id.to_string(), results);
                });
                self.phase_by_block.update(|m| {
                    m.insert(block_id.to_string(), DiscoveryPhase::Complete);
                });
            }
            DatasetDiscoveryState::NoResults { .. } => {
                self.results_by_block.update(|m| {
                    m.insert(block_id.to_string(), vec![]);
                });
                self.phase_by_block.update(|m| {
                    m.insert(
                        block_id.to_string(),
                        DiscoveryPhase::Failed("No datasets found".to_string()),
                    );
                });
            }
        }
    }

    /// Apply the final resolved results for a block.
    pub fn apply_resolved(&self, block_id: &str, results: Vec<DatasetResult>) {
        self.results_by_block.update(|m| {
            m.insert(block_id.to_string(), results);
        });
        self.phase_by_block.update(|m| {
            m.insert(block_id.to_string(), DiscoveryPhase::Complete);
        });
    }

    /// Get results for a given block, or empty vec.
    pub fn results_for(&self, block_id: &str) -> Vec<DatasetResult> {
        self.results_by_block
            .get()
            .get(block_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get memex hint for a given block.
    pub fn memex_hint_for(&self, block_id: &str) -> Option<(Vec<DatasetResult>, String)> {
        self.memex_results_by_block.get().get(block_id).cloned()
    }

    /// Get current discovery phase for a block.
    pub fn phase_for(&self, block_id: &str) -> DiscoveryPhase {
        self.phase_by_block
            .get()
            .get(block_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Clear all state for a given block_id (e.g., on DID change).
    pub fn clear_block(&self, block_id: &str) {
        self.results_by_block.update(|m| {
            m.remove(block_id);
        });
        self.phase_by_block.update(|m| {
            m.remove(block_id);
        });
        self.memex_results_by_block.update(|m| {
            m.remove(block_id);
        });
    }

    /// Clear all dataset state (e.g., on DID change / profile switch).
    pub fn clear_all(&self) {
        self.results_by_block.set(HashMap::new());
        self.phase_by_block.set(HashMap::new());
        self.memex_results_by_block.set(HashMap::new());
        self.error.set(None);
    }
}
