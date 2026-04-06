use leptos::prelude::*;

/// Schema type autocomplete input backed by types already registered in the
/// current session. No static vocabulary lists — suggestions come exclusively
/// from the caller-supplied `registered_types` signal.
///
/// An unknown type (not yet registered) is always accepted as valid: the user
/// may be defining a new type for the first time.
#[component]
pub fn SchemaTypeInput(
    value: RwSignal<String>,
    /// Deduped, sorted list of schema types already registered in the session.
    /// Derived from the existing templates signal in the parent component.
    registered_types: Signal<Vec<String>>,
    #[prop(default = "e.g. FlightReservation")] placeholder: &'static str,
) -> impl IntoView {
    let show_dropdown = RwSignal::new(false);

    // Filtered suggestions: case-insensitive contains, max 8, excluding exact match
    let suggestions = move || -> Vec<String> {
        let input = value.get();
        let all = registered_types.get();
        if all.is_empty() {
            return vec![];
        }
        let lower = input.to_lowercase();
        all.into_iter()
            .filter(|t| {
                let tl = t.to_lowercase();
                tl.contains(&lower) && *t != value.get()
            })
            .take(8)
            .collect()
    };

    view! {
        <div style="position: relative;">
            <input
                type="text"
                placeholder=placeholder
                prop:value=move || value.get()
                on:input=move |ev| {
                    value.set(event_target_value(&ev));
                    show_dropdown.set(true);
                }
                on:focus=move |_| show_dropdown.set(true)
                on:blur=move |_| show_dropdown.set(false)
                style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 10px; color: var(--text-1); font-size: 13px; box-sizing: border-box;"
            />
            <Show when=move || show_dropdown.get() && !suggestions().is_empty()>
                <div style="position: absolute; top: calc(100% + 2px); left: 0; right: 0; background: var(--bg-1); border: 1px solid var(--border); border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 9999; overflow: hidden; max-height: 240px; overflow-y: auto;">
                    <For
                        each=suggestions
                        key=|t| t.clone()
                        children=move |type_name| {
                            let name = type_name.clone();
                            let hovered = RwSignal::new(false);
                            view! {
                                <div
                                    on:mousedown=move |ev| {
                                        ev.prevent_default();
                                        value.set(name.clone());
                                        show_dropdown.set(false);
                                    }
                                    on:mouseenter=move |_| hovered.set(true)
                                    on:mouseleave=move |_| hovered.set(false)
                                    style=move || format!(
                                        "padding: 9px 12px; font-size: 13px; color: var(--text-1); cursor: pointer; font-family: var(--font-mono); background: {};",
                                        if hovered.get() { "var(--bg-tertiary)" } else { "transparent" }
                                    )
                                >
                                    {type_name.clone()}
                                </div>
                            }
                        }
                    />
                </div>
            </Show>
        </div>
    }
}
