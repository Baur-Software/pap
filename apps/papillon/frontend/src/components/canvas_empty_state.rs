use leptos::prelude::*;

use crate::state::canvas::CanvasState;

/// Onboarding step data
#[derive(Clone)]
struct OnboardStep {
    question: &'static str,
    hint: &'static str,
    options: &'static [(&'static str, &'static str)], // (label, prompt_prefix)
}

const STEPS: &[OnboardStep] = &[
    OnboardStep {
        question: "What do you want to do with Papillon today?",
        hint: "Choose one to get started — you can always change direction.",
        options: &[
            ("Research something", "tell me about "),
            ("Track news & trends", "what's happening with "),
            ("Look something up", "define "),
            ("Explore a topic in depth", "research "),
            ("Just try it out", "weather in "),
        ],
    },
    OnboardStep {
        question: "What topics interest you most?",
        hint: "This helps Papillon surface useful agents for you.",
        options: &[
            ("Technology & software", "github "),
            ("Science & research", "paper on "),
            ("Finance & markets", "convert 100 USD to EUR"),
            ("Travel & geography", "where is "),
            ("Culture & books", "book about "),
        ],
    },
    OnboardStep {
        question: "How do you prefer to start?",
        hint: "You can mix and match — these are just shortcuts.",
        options: &[
            ("Type a question naturally", "explain "),
            ("Browse by web address", "https://"),
            ("Search the web", "search for "),
            ("Check the news", "hacker news "),
            ("Ask about weather", "weather in "),
        ],
    },
];

/// Onboarding empty state — shown when the canvas has no blocks.
/// Guides new users through a short personalisation flow instead of
/// dumping a raw agent grid on them.
#[component]
pub fn CanvasEmptyState() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    // Which step (0..STEPS.len()) we're on. None = flow complete (freeform mode)
    let step: RwSignal<Option<usize>> = RwSignal::new(Some(0));
    // Breadcrumb selections made so far
    let choices: RwSignal<Vec<String>> = RwSignal::new(vec![]);

    let current_step = move || step.get().and_then(|i| STEPS.get(i).cloned());
    let total = STEPS.len();

    view! {
        <div class="canvas-empty-state">
            <Show
                when=move || step.get().is_some()
                fallback=move || {
                    // Free-form mode after onboarding
                    view! {
                        <div class="onboard-done">
                            <div class="onboard-done-msg">
                                "You're set up. Type anything in the address bar above to get started."
                            </div>
                            <div class="onboard-done-choices">
                                {move || choices.get().iter().enumerate().map(|(i, c)| view! {
                                    <span class="onboard-breadcrumb-tag">
                                        <span class="onboard-breadcrumb-num">{i + 1}</span>
                                        {c.clone()}
                                    </span>
                                }).collect::<Vec<_>>()}
                            </div>
                        </div>
                    }
                }
            >
                {move || current_step().map(|s| {
                    let step_idx = step.get().unwrap_or(0);
                    view! {
                        <div class="onboard-card">
                            // Progress dots
                            <div class="onboard-progress">
                                {(0..total).map(|i| view! {
                                    <div class=move || if i == step_idx {
                                        "onboard-dot active"
                                    } else if i < step_idx {
                                        "onboard-dot done"
                                    } else {
                                        "onboard-dot"
                                    } />
                                }).collect::<Vec<_>>()}
                            </div>

                            <div class="onboard-question">{s.question}</div>
                            <div class="onboard-hint">{s.hint}</div>

                            <div class="onboard-options">
                                {s.options.iter().map(|&(label, prompt_prefix)| {
                                    let canvas_state = canvas_state;
                                    let label_str = label.to_string();
                                    view! {
                                        <button
                                            class="onboard-option"
                                            on:click=move |_| {
                                                // Record choice as breadcrumb
                                                choices.update(|v| v.push(label_str.clone()));

                                                let next = step_idx + 1;
                                                if next >= total {
                                                    // Last step — submit the prompt and end onboarding
                                                    step.set(None);
                                                    canvas_state.prefill_prompt.set(Some(prompt_prefix.to_string()));
                                                    canvas_state.focus_prompt.update(|n| *n += 1);
                                                } else {
                                                    // Advance to next step
                                                    step.set(Some(next));
                                                }
                                            }
                                        >
                                            {label}
                                        </button>
                                    }
                                }).collect::<Vec<_>>()}
                            </div>

                            // Skip link
                            <button
                                class="onboard-skip"
                                on:click=move |_| step.set(None)
                            >
                                "Skip setup"
                            </button>
                        </div>
                    }
                })}
            </Show>
        </div>
    }
}
