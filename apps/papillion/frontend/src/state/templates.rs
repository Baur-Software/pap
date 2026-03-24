use leptos::prelude::*;
use papillion_shared::types::Template;

/// Frontend state for user-defined templates.
///
/// Stores global templates (available to all profiles) and profile-specific templates
/// for the current identity. Templates are loaded lazily via Tauri commands and updated
/// when the user's DID changes.
#[derive(Clone, Copy, Debug)]
pub struct TemplatesState {
    /// Global templates available to all profiles
    pub global_templates: RwSignal<Vec<Template>>,
    /// Templates scoped to the current profile/identity
    pub profile_templates: RwSignal<Vec<Template>>,
}

impl TemplatesState {
    /// Get all templates (global + profile-specific combined).
    pub fn all_templates(&self) -> Vec<Template> {
        let mut all = self.global_templates.get();
        all.extend(self.profile_templates.get());
        all
    }
}

impl Default for TemplatesState {
    fn default() -> Self {
        Self {
            global_templates: RwSignal::new(vec![]),
            profile_templates: RwSignal::new(vec![]),
        }
    }
}
