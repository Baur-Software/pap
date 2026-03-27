//! Leptos hooks for accessing the PapillonService from components.
//!
//! Provides a convenient `use_papillon_service()` hook that can be called
//! from any component to get the current service implementation.

use std::sync::Arc;

use leptos::prelude::*;

use super::PapillonService;

/// Signal holding the application's PapillonService instance.
type ServiceSignal = RwSignal<Option<Arc<dyn PapillonService>>>;

/// Get the PapillonService from context.
///
/// This hook retrieves the service instance provided by the App component.
/// It panics if the service context has not been set up.
///
/// # Panics
///
/// Panics if called outside a component tree that provides the service context.
///
/// # Example
///
/// ```ignore
/// #[component]
/// fn MyComponent() -> impl IntoView {
///     let service = use_papillon_service();
///
///     let load_templates = move |_| {
///         let svc = service.clone();
///         spawn_local(async move {
///             match svc.get_global_templates().await {
///                 Ok(templates) => {
///                     // use templates
///                 },
///                 Err(e) => {
///                     // handle error
///                 }
///            }
///         });
///     };
///
///     view! {
///         <button on:click=load_templates>"Load Templates"</button>
///     }
/// }
/// ```
pub fn use_papillon_service() -> Arc<dyn PapillonService> {
    expect_context::<Arc<dyn PapillonService>>()
}

/// Setup the PapillonService context in the App.
///
/// This function should be called once in the App component to provide
/// the service to all child components.
///
/// # Example
///
/// ```ignore
/// #[component]
/// pub fn App() -> impl IntoView {
///     let service_signal = RwSignal::new(None);
///
///     // Initialize service asynchronously
///     spawn_local(async move {
///         let svc = get_papillon_service().await;
///         service_signal.set(Some(svc.clone()));
///         provide_context(svc);
///     });
///
///     // ...rest of app
/// }
/// ```
pub async fn init_papillon_service() -> Arc<dyn PapillonService> {
    super::get_papillon_service().await
}
