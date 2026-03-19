use leptos::prelude::*;
use papillion_shared::{IdentityInfo, SuccessorDesignation};

#[derive(Clone, Copy)]
pub struct IdentityState {
    pub info: RwSignal<Option<IdentityInfo>>,
    pub loading: RwSignal<bool>,
    pub backed_up: RwSignal<bool>,
    pub successors: RwSignal<Vec<SuccessorDesignation>>,
}

impl Default for IdentityState {
    fn default() -> Self {
        Self {
            info: RwSignal::new(None),
            loading: RwSignal::new(false),
            backed_up: RwSignal::new(false),
            successors: RwSignal::new(Vec::new()),
        }
    }
}
