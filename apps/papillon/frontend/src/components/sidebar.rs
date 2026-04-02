use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_location;

#[component]
pub fn Sidebar() -> impl IntoView {
    let location = use_location();

    view! {
        <nav class="sidebar app-sidebar">
            <A
                href="/"
                attr:class=move || {
                    if location.pathname.get() == "/" {
                        "sidebar-icon active"
                    } else {
                        "sidebar-icon"
                    }
                }
            >
                <IconHome />
            </A>
            <A
                href="/browse"
                attr:class=move || {
                    if location.pathname.get().starts_with("/browse") {
                        "sidebar-icon active"
                    } else {
                        "sidebar-icon"
                    }
                }
            >
                <IconLayers />
            </A>
            <A
                href="/activity"
                attr:class=move || {
                    if location.pathname.get().starts_with("/activity") {
                        "sidebar-icon active"
                    } else {
                        "sidebar-icon"
                    }
                }
            >
                <IconDatabase />
            </A>
            <div style="flex:1" />
            <A
                href="/settings"
                attr:class=move || {
                    if location.pathname.get().starts_with("/settings") {
                        "sidebar-icon active"
                    } else {
                        "sidebar-icon"
                    }
                }
            >
                <IconGear />
            </A>
        </nav>
    }
}

#[component]
fn IconHome() -> impl IntoView {
    view! {
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
            <polyline points="9 22 9 12 15 12 15 22"/>
        </svg>
    }
}

#[component]
fn IconLayers() -> impl IntoView {
    view! {
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="12 2 2 7 12 12 22 7 12 2"/>
            <polyline points="2 17 12 22 22 17"/>
            <polyline points="2 12 12 17 22 12"/>
        </svg>
    }
}

#[component]
fn IconDatabase() -> impl IntoView {
    view! {
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <ellipse cx="12" cy="5" rx="9" ry="3"/>
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
        </svg>
    }
}

#[component]
fn IconGear() -> impl IntoView {
    view! {
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
    }
}
