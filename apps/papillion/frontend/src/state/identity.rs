use leptos::prelude::*;
use papillion_shared::IdentityInfo;

#[derive(Clone, Copy)]
pub struct IdentityState {
    pub info: RwSignal<Option<IdentityInfo>>,
    pub loading: RwSignal<bool>,
}

impl IdentityState {
    pub fn new() -> Self {
        Self {
            info: RwSignal::new(None),
            loading: RwSignal::new(false),
        }
    }
}
