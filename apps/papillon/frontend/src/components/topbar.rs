use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::profile_avatar::ProfileAvatar;
use crate::state::canvas::CanvasState;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::{IdentityInfo, OrchestratorStatus};

#[component]
pub fn TopBar() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let orchestrator = expect_context::<OrchestratorState>();
    let canvas_state = expect_context::<CanvasState>();
    let menu_open = RwSignal::new(false);
    let profile_menu_open = RwSignal::new(false);

    let did_display = move || {
        identity
            .info
            .get()
            .map(|i| {
                let did = &i.did;
                if did.len() > 20 {
                    format!("{}...{}", &did[..8], &did[did.len() - 6..])
                } else {
                    did.clone()
                }
            })
            .unwrap_or_else(|| "No identity".to_string())
    };

    let _current_profile_name = move || {
        identity
            .current_profile()
            .map(|p| p.name)
            .unwrap_or_else(|| "Profile".to_string())
    };

    let switch_profile = move |profile_id: String| {
        profile_menu_open.set(false);
        spawn_local(async move {
            if let Ok(info) = bridge::invoke::<_, IdentityInfo>(
                "switch_profile",
                &serde_json::json!({"profile_id": profile_id}),
            )
            .await
            {
                identity.info.set(Some(info));
                // Reload profiles list to update active status
                use papillon_shared::ProfileMetadata;
                if let Ok(profiles) =
                    bridge::invoke_no_args::<Vec<ProfileMetadata>>("list_profiles").await
                {
                    if let Some(active) = profiles.iter().find(|p: &&ProfileMetadata| p.active) {
                        identity.current_profile_id.set(Some(active.id.clone()));
                    }
                    identity.profiles.set(profiles);
                }
            }
        });
    };

    let status_label = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "Ready",
        OrchestratorStatus::Downloading { .. } => "Setting up\u{2026}",
        OrchestratorStatus::Disconnected => "Agents only",
        OrchestratorStatus::Unconfigured => "Agents only",
    };

    let status_class = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "topbar-status ready",
        OrchestratorStatus::Downloading { .. } => "topbar-status working",
        _ => "topbar-status agents-only",
    };

    let toggle_menu = move |_: leptos::ev::MouseEvent| {
        menu_open.update(|v| *v = !*v);
    };

    let close_menu = move |_| {
        menu_open.set(false);
    };

    let canvases = move || canvas_state.canvases.get();
    let active_id = move || canvas_state.current_canvas_id.get();

    view! {
        <header class="topbar app-topbar">
            <button class="topbar-menu-btn" on:click=toggle_menu>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="3" y1="6" x2="21" y2="6"/>
                    <line x1="3" y1="12" x2="21" y2="12"/>
                    <line x1="3" y1="18" x2="21" y2="18"/>
                </svg>
            </button>
            <div class="topbar-brand">
                <img class="topbar-brand-icon" src="/logo.png" alt="Papillon" />
                <span class="topbar-brand-name">"PAPILLON_SYS"</span>
            </div>
            <div class="topbar-spacer" />
            <div class="topbar-meta">
                <div class="topbar-session-badge">
                    <div class="topbar-session-dot" />
                    <span class=status_class>{status_label}</span>
                </div>
                <span class="topbar-meta-sep">"|"</span>
                <span class="topbar-identity">{did_display}</span>
            </div>
            <A href="/settings" attr:class="topbar-settings-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
            </A>
        </header>
        <Show when=move || menu_open.get()>
            <div class="menu-backdrop" on:click=close_menu></div>
            <div class="menu-dropdown">
                <div class="menu-section-label">"Canvases"</div>
                <A href="/" attr:class="menu-item menu-item-new" on:click=move |_| {
                    canvas_state.new_canvas();
                    menu_open.set(false);
                }>
                    "+ New Canvas"
                </A>
                <For
                    each=canvases
                    key=|c| c.id.clone()
                    children=move |canvas| {
                        let cid = canvas.id.clone();
                        let cid_for_class = canvas.id.clone();
                        let cid_for_delete = canvas.id.clone();
                        view! {
                            <div class="menu-item-row">
                                <A
                                    href="/"
                                    attr:class=move || {
                                        if active_id().as_deref() == Some(&cid_for_class) {
                                            "menu-item active"
                                        } else {
                                            "menu-item"
                                        }
                                    }
                                    on:click=move |_| {
                                        canvas_state.current_canvas_id.set(Some(cid.clone()));
                                        menu_open.set(false);
                                    }
                                >
                                    {canvas.name.clone()}
                                </A>
                                <button
                                    class="menu-item-delete"
                                    title="Delete canvas"
                                    on:click=move |e| {
                                        e.stop_propagation();
                                        canvas_state.delete_canvas(&cid_for_delete);
                                    }
                                >
                                    "\u{00d7}"
                                </button>
                            </div>
                        }
                    }
                />
                <div class="menu-divider"></div>
                <A href="/browse" attr:class="menu-item" on:click=close_menu>
                    "Browse Registries"
                </A>
                <A href="/settings" attr:class="menu-item" on:click=close_menu>
                    "Settings"
                </A>
            </div>
        </Show>
        <Show when=move || profile_menu_open.get()>
            <div class="profile-menu-backdrop" on:click=move |_| profile_menu_open.set(false)></div>
            <div class="profile-menu-dropdown">
                <div class="profile-menu-section">
                    <div class="profile-menu-title">"Profiles"</div>
                    <For
                        each=move || identity.profiles.get()
                        key=|p| p.id.clone()
                        children=move |profile| {
                            let profile_id = profile.id.clone();
                            let is_active = profile.active;
                            let profile_name = profile.name.clone();
                            view! {
                                <button
                                    class=move || {
                                        if is_active {
                                            "profile-menu-item active"
                                        } else {
                                            "profile-menu-item"
                                        }
                                    }
                                    on:click=move |_| switch_profile(profile_id.clone())
                                >
                                    <ProfileAvatar name=profile_name.clone() />
                                    <span class="profile-menu-name">{profile_name}</span>
                                    <Show when=move || is_active>
                                        <span class="profile-menu-active-badge">"\u{2713}"</span>
                                    </Show>
                                </button>
                            }
                        }
                    />
                </div>
                <div class="profile-menu-divider"></div>
                <A href="/settings?tab=profiles" attr:class="profile-menu-link" on:click=move |_| profile_menu_open.set(false)>
                    "\u{2699} Profiles Settings"
                </A>
            </div>
        </Show>
    }
}
