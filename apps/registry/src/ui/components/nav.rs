use leptos::prelude::*;
use leptos_router::hooks::use_location;

#[component]
pub fn Sidebar() -> impl IntoView {
    let location = use_location();
    let path = move || location.pathname.get();

    let nav_item = move |href: &'static str, icon: &'static str, label: &'static str| {
        let is_active = move || path().starts_with(href) && (href != "/" || path() == "/");
        view! {
            <a
                href=href
                class=move || if is_active() { "nav-link active" } else { "nav-link" }
            >
                <span class="nav-link-icon">{icon}</span>
                <span class="nav-link-label">{label}</span>
            </a>
        }
    };

    view! {
        <aside class="sidebar">
            <div class="sidebar-logo">
                <div class="sidebar-logo-mark">"🦋"</div>
                <div>
                    <div class="sidebar-logo-text">"Chrysalis"</div>
                    <div class="sidebar-logo-sub">"Agent Registry"</div>
                </div>
            </div>
            <nav class="nav-section">
                <div class="nav-section-label">"Overview"</div>
                {nav_item("/", "◈", "Dashboard")}
            </nav>
            <nav class="nav-section" style="margin-top: var(--sp-md)">
                <div class="nav-section-label">"Registry"</div>
                {nav_item("/agents", "⬡", "Agents")}
                {nav_item("/peers", "◎", "Peers")}
            </nav>
            <nav class="nav-section" style="margin-top: var(--sp-md)">
                <div class="nav-section-label">"Admin"</div>
                {nav_item("/settings", "⚙", "Settings")}
            </nav>
        </aside>
    }
}
