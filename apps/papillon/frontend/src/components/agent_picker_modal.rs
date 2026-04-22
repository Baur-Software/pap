use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::AgentInfo;

/// Searchable agent picker modal.
/// `open` — reactive signal controlling visibility.
/// `on_select` — called with the chosen `AgentInfo`.
#[component]
pub fn AgentPickerModal(
    open: RwSignal<bool>,
    on_select: Callback<AgentInfo>,
) -> impl IntoView {
    let agents: RwSignal<Vec<AgentInfo>> = RwSignal::new(vec![]);
    let query: RwSignal<String> = RwSignal::new(String::new());
    let loading: RwSignal<bool> = RwSignal::new(false);

    // Load agents when modal opens.
    Effect::new(move || {
        if !open.get() {
            return;
        }
        loading.set(true);
        spawn_local(async move {
            match bridge::invoke_no_args::<Vec<AgentInfo>>("list_local_agents").await {
                Ok(list) => agents.set(list),
                Err(_) => agents.set(vec![]),
            }
            loading.set(false);
        });
    });

    let filtered = move || {
        let q = query.get().to_lowercase();
        agents
            .get()
            .into_iter()
            .filter(|a| {
                q.is_empty()
                    || a.name.to_lowercase().contains(&q)
                    || a.capabilities.iter().any(|c| c.to_lowercase().contains(&q))
                    || a.category.to_lowercase().contains(&q)
            })
            .collect::<Vec<_>>()
    };

    view! {
        <Show when=move || open.get()>
            <div
                class="agent-picker-overlay"
                on:click=move |ev| {
                    use wasm_bindgen::JsCast;
                    let target = ev.target()
                        .and_then(|t| t.dyn_into::<web_sys::Element>().ok());
                    if target
                        .as_ref()
                        .map(|el| el.class_name() == "agent-picker-overlay")
                        .unwrap_or(false)
                    {
                        open.set(false);
                        query.set(String::new());
                    }
                }
            >
                <div class="agent-picker-modal">
                    <div class="agent-picker-header">
                        <span class="agent-picker-title">"INSTALLED AGENTS"</span>
                        <button
                            class="agent-picker-close"
                            on:click=move |_| {
                                open.set(false);
                                query.set(String::new());
                            }
                            aria-label="Close agent picker"
                        >"×"</button>
                    </div>

                    <input
                        type="text"
                        class="agent-picker-search"
                        placeholder="Search by name, action type, or category…"
                        prop:value=move || query.get()
                        on:input=move |ev| query.set(event_target_value(&ev))
                        autofocus=true
                    />

                    <div class="agent-picker-count">
                        {move || {
                            let total = agents.get().len();
                            let shown = filtered().len();
                            if query.get().is_empty() {
                                format!("{total} agents installed")
                            } else {
                                format!("{shown} of {total}")
                            }
                        }}
                    </div>

                    <div class="agent-picker-grid">
                        <Show
                            when=move || loading.get()
                            fallback=move || {
                                let items = filtered();
                                if items.is_empty() {
                                    view! {
                                        <div class="agent-picker-empty">
                                            {move || format!("No agents match \"{}\"", query.get())}
                                        </div>
                                    }
                                    .into_any()
                                } else {
                                    items
                                        .into_iter()
                                        .map(|agent| {
                                            let cap = agent
                                                .capabilities
                                                .first()
                                                .cloned()
                                                .unwrap_or_default()
                                                .trim_start_matches("schema:")
                                                .to_string();
                                            let src = agent.source.clone();
                                            let a2 = agent.clone();
                                            view! {
                                                <div
                                                    class="agent-picker-card"
                                                    on:click=move |_| {
                                                        on_select.run(a2.clone());
                                                        open.set(false);
                                                        query.set(String::new());
                                                    }
                                                >
                                                    <div class="agent-picker-card-name">
                                                        {agent.name}
                                                    </div>
                                                    <div class="agent-picker-card-cap">{cap}</div>
                                                    <div class="agent-picker-card-source">{src}</div>
                                                </div>
                                            }
                                        })
                                        .collect::<Vec<_>>()
                                        .into_any()
                                }
                            }
                        >
                            <div class="agent-picker-empty">"Loading agents…"</div>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
    }
}
