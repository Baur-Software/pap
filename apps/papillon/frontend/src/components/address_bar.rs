use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::registry::RegistryState;
use papillon_shared::{AgentInfo, RegistryInfo};

#[component]
pub fn AddressBar() -> impl IntoView {
    let registry = expect_context::<RegistryState>();
    let (url, set_url) = signal(String::new());

    let on_keydown = move |ev: web_sys::KeyboardEvent| {
        if ev.key() == "Enter" {
            let value = url.get();
            if value.is_empty() {
                return;
            }
            registry.current_url.set(value.clone());
            registry.loading.set(true);
            registry.error.set(None);

            spawn_local(async move {
                #[derive(serde::Serialize)]
                struct Args {
                    url: String,
                }
                match bridge::invoke::<Args, RegistryInfo>(
                    "navigate_registry",
                    &Args { url: value.clone() },
                )
                .await
                {
                    Ok(info) => {
                        registry.info.set(Some(info));
                        // Auto-load agents after successful navigation
                        #[derive(serde::Serialize)]
                        struct ListArgs {
                            registry_url: String,
                        }
                        if let Ok(agents) = bridge::invoke::<ListArgs, Vec<AgentInfo>>(
                            "list_agents",
                            &ListArgs {
                                registry_url: value,
                            },
                        )
                        .await
                        {
                            registry.agents.set(agents);
                        }
                    }
                    Err(e) => {
                        registry.error.set(Some(e));
                    }
                }
                registry.loading.set(false);
            });
        }
    };

    view! {
        <div class="address-bar">
            <input
                type="text"
                placeholder="pap://registry.example.com"
                prop:value=url
                on:input=move |ev| {
                    use wasm_bindgen::JsCast;
                    let target: web_sys::EventTarget = ev.target().unwrap();
                    let input: web_sys::HtmlInputElement = target.unchecked_into();
                    set_url.set(input.value());
                }
                on:keydown=on_keydown
            />
        </div>
    }
}
