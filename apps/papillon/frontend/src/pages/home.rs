use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

/// /home redirects to the canvas (/).
/// The canvas empty state IS the home screen — just the prompt.
#[component]
pub fn HomePage() -> impl IntoView {
    let navigate = use_navigate();
    Effect::new(move |_| {
        navigate("/", Default::default());
    });
    view! { <div></div> }
}
