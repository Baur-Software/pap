//! Leptos hooks for accessing the PapillionService from components.
//!
//! Provides a convenient `use_papillion_service()` hook that can be called
//! from any component to get the current service implementation.

use std::sync::Arc;

use leptos::prelude::*;

use super::PapillionService;

/// Signal holding the application's PapillionService instance.
type ServiceSignal = RwSignal<Option<Arc<dyn PapillionService>>>;

/// Get the PapillionService from context.
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
///     let service = use_papillion_service();
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
pub fn use_papillion_service() -> Arc<dyn PapillionService> {
    expect_context::<Arc<dyn PapillionService>>()
}

/// Setup the PapillionService context in the App.
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
///         let svc = get_papillion_service().await;
///         service_signal.set(Some(svc.clone()));
///         provide_context(svc);
///     });
///
///     // ...rest of app
/// }
/// ```
pub async fn init_papillion_service() -> Arc<dyn PapillionService> {
    super::get_papillion_service().await
}
