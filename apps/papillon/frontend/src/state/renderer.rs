use leptos::prelude::*;
use std::sync::Arc;

use crate::components::block_renderer::{create_default_registry, RendererRegistry};

/// App-level renderer registry state.
///
/// Pre-populated with all shipped hardcoded templates at startup;
/// extended reactively when user-defined or agent-registered templates load
/// (via the sync `Effect` in `app.rs`).
///
/// `registered_keys` drives the schema type autocomplete in `TemplatesTab`
/// from the live registry — no static lists required.
#[derive(Clone, Copy)]
pub struct RendererState {
    /// The live shared registry instance for the session.
    ///
    /// `StoredValue` provides owned, non-reactive storage for `Arc<RendererRegistry>`
    /// (non-`Copy`) within the Leptos reactive graph while keeping `RendererState`
    /// itself `Clone + Copy`.
    pub registry: StoredValue<Arc<RendererRegistry>>,
    /// Reactive enumeration of type-global schema keys.
    ///
    /// Updated by an `Effect` in `app.rs` whenever `TemplatesState` changes,
    /// so newly agent-registered or user-created types appear in the autocomplete
    /// without a page reload.
    pub registered_keys: RwSignal<Vec<String>>,
}

impl Default for RendererState {
    fn default() -> Self {
        let registry = create_default_registry();
        let initial_keys = registry.registered_type_keys();
        Self {
            registry: StoredValue::new(registry),
            registered_keys: RwSignal::new(initial_keys),
        }
    }
}
