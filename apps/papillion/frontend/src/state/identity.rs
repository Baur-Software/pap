use leptos::prelude::*;
use papillion_shared::{IdentityInfo, ProfileMetadata, SuccessorDesignation};

#[derive(Clone, Copy)]
pub struct IdentityState {
    pub info: RwSignal<Option<IdentityInfo>>,
    pub loading: RwSignal<bool>,
    pub backed_up: RwSignal<bool>,
    pub successors: RwSignal<Vec<SuccessorDesignation>>,
    /// All available profiles
    pub profiles: RwSignal<Vec<ProfileMetadata>>,
    /// Current active profile ID
    pub current_profile_id: RwSignal<Option<String>>,
    /// Loading profiles from backend
    pub profiles_loading: RwSignal<bool>,
}

impl IdentityState {
    /// Get the current profile metadata
    pub fn current_profile(&self) -> Option<ProfileMetadata> {
        let id = self.current_profile_id.get()?;
        self.profiles
            .get()
            .into_iter()
            .find(|p| p.id == id)
    }
}

impl Default for IdentityState {
    fn default() -> Self {
        Self {
            info: RwSignal::new(None),
            loading: RwSignal::new(false),
            backed_up: RwSignal::new(false),
            successors: RwSignal::new(Vec::new()),
            profiles: RwSignal::new(Vec::new()),
            current_profile_id: RwSignal::new(None),
            profiles_loading: RwSignal::new(false),
        }
    }
}
