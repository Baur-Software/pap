//! Leptos hooks for accessing the PapillonService from components.
//!
//! The service is provided as `Arc<dyn PapillonService>` in `App::new()`.
//! Tauri mode gets `TauriService`; browser mode gets `WebService`.

use std::sync::Arc;

use leptos::prelude::*;

use super::PapillonService;

/// Get the PapillonService from context.
///
/// Retrieves the `Arc<dyn PapillonService>` provided by the App component.
/// Panics if called outside the component tree (i.e. before App renders).
pub fn use_papillon_service() -> Arc<dyn PapillonService> {
    expect_context::<Arc<dyn PapillonService>>()
}
