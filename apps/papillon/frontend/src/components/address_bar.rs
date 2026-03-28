use leptos::prelude::*;

use crate::state::registry::RegistryState;

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
            registry.connect_to(&value);
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
