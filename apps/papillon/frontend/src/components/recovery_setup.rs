use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::recovery::RecoveryState;
use papillon_shared::RecoverySetupResult;

/// M-of-N Shamir recovery setup modal.
///
/// Shown post-onboarding to encourage principals to distribute shard backups.
/// The modal is skippable and dismissible at any time.
///
/// Flow:
///   Step 1 — Introduction: explain what SSS recovery is and why it matters
///   Step 2 — Configure M and N (threshold and total shards)
///   Step 3 — Generate shards, display each for download/copy
///   Step 4 — Confirmation
#[component]
pub fn RecoverySetup() -> impl IntoView {
    let recovery = expect_context::<RecoveryState>();
    let step = RwSignal::new(1u8);

    // -- Step 2 local copies so the user can edit before generating
    let m_input = RwSignal::new(2u8);
    let n_input = RwSignal::new(3u8);

    // -- Step 3: current shard index (0-based cursor through the shard list)
    let shard_cursor = RwSignal::new(0usize);

    let generate = move |_| {
        let m = m_input.get();
        let n = n_input.get();
        if m == 0 || m > n {
            recovery.error.set(Some(format!(
                "Threshold {m} must be ≥ 1 and ≤ total {n}"
            )));
            return;
        }
        recovery.error.set(None);
        recovery.generating.set(true);

        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, RecoverySetupResult>(
                "create_recovery_shards",
                &serde_json::json!({ "threshold": m, "total": n }),
            )
            .await
            {
                Ok(result) => {
                    recovery.threshold.set(m);
                    recovery.total.set(n);
                    recovery.shards.set(result.shards);
                    recovery.manifest_json.set(result.manifest_json);
                    recovery.generating.set(false);
                    shard_cursor.set(0);
                    step.set(3);
                }
                Err(e) => {
                    recovery.error.set(Some(format!("Generation failed: {e}")));
                    recovery.generating.set(false);
                }
            }
        });
    };

    let mark_done = move |_| {
        // Persist to backend first; update UI state only after success so the
        // post-onboarding prompt does not re-appear on restart.
        spawn_local(async move {
            let _ = bridge::invoke_no_args::<()>("mark_recovery_complete").await;
            // Whether or not the backend call succeeded, dismiss the modal so
            // the user is not stuck.  On failure the DB flag is not set and the
            // prompt will appear again on next launch, which is acceptable.
            recovery.setup_complete.set(true);
            recovery.show_setup.set(false);
            step.set(1);
            recovery.shards.set(Vec::new());
            recovery.manifest_json.set(String::new());
        });
    };

    let skip = move |_| {
        // Clear any generated shard data from WASM heap before dismissing.
        recovery.shards.set(Vec::new());
        recovery.manifest_json.set(String::new());
        recovery.show_setup.set(false);
        step.set(1);
    };

    view! {
        <Show when=move || recovery.show_setup.get()>
            <div class="setup-overlay">
                <div class="setup-wizard">
                    // Header
                    <div class="setup-boot-header">
                        <div class="setup-boot-line">"RECOVERY_SETUP — INSTITUTIONAL KEY SPLITTING"</div>
                        <div class="setup-boot-line">"> Shamir M-of-N secret sharing over GF(2^8)"</div>
                        <div class="setup-boot-line">"> Spec §13.5 — no central authority"</div>
                    </div>

                    // Step indicator
                    <div class="setup-step-strip">
                        <div class=move || if step.get() == 1 { "setup-step active" } else { "setup-step" }>
                            "[01] INTRODUCTION"
                        </div>
                        <div class=move || if step.get() == 2 { "setup-step active" } else { "setup-step" }>
                            "[02] CONFIGURE"
                        </div>
                        <div class=move || if step.get() == 3 { "setup-step active" } else { "setup-step" }>
                            "[03] DISTRIBUTE"
                        </div>
                        <div class=move || if step.get() == 4 { "setup-step active" } else { "setup-step" }>
                            "[04] CONFIRM"
                        </div>
                    </div>

                    // ── Step 1: Introduction ──────────────────────────────
                    <Show when=move || step.get() == 1>
                        <div class="setup-inputs">
                            <p style="margin: 0 0 1rem;">
                                "If your device is lost, no one can recover your identity without your key. "
                                "This setup splits your key into N shards and distributes them to N trustees. "
                                "Any M trustees can cooperate to reconstruct your identity."
                            </p>
                            <p style="margin: 0 0 1rem;">
                                "Trustees never see your full key — they only hold one shard. "
                                "Fewer than M shards reveal nothing (mathematically provable)."
                            </p>
                            <p style="margin: 0;">
                                "Suitable trustees: a bank's safety deposit contact, a notary, a trusted family member, "
                                "a lawyer, or a hardware security key in a separate location."
                            </p>
                        </div>
                        <div class="setup-actions">
                            <button class="btn-ghost" on:click=skip>"[ SKIP_FOR_NOW ]"</button>
                            <button class="btn-sys" on:click=move |_| step.set(2)>"[ CONTINUE ]"</button>
                        </div>
                    </Show>

                    // ── Step 2: Configure M and N ─────────────────────────
                    <Show when=move || step.get() == 2>
                        <div class="setup-inputs">
                            <label>"THRESHOLD (M) — minimum shards needed to recover"</label>
                            <input
                                type="number"
                                min="1"
                                max="255"
                                prop:value=move || m_input.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<u8>() {
                                        m_input.set(v);
                                    }
                                }
                            />
                            <label>"TOTAL SHARDS (N) — number of trustees"</label>
                            <input
                                type="number"
                                min="1"
                                max="255"
                                prop:value=move || n_input.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<u8>() {
                                        n_input.set(v);
                                    }
                                }
                            />
                            <p style="color: var(--gold); margin-top: 0.5rem;">
                                {move || format!(
                                    "Any {} of {} trustees can reconstruct your identity",
                                    m_input.get(),
                                    n_input.get()
                                )}
                            </p>
                        </div>
                        <Show when=move || recovery.error.get().is_some()>
                            <p class="setup-error">{move || recovery.error.get().unwrap_or_default()}</p>
                        </Show>
                        <div class="setup-actions">
                            <button class="btn-ghost" on:click=move |_| step.set(1)>"[ BACK ]"</button>
                            <button
                                class="btn-sys"
                                disabled=move || recovery.generating.get()
                                on:click=generate
                            >
                                {move || if recovery.generating.get() { "[ GENERATING... ]" } else { "[ GENERATE_SHARDS ]" }}
                            </button>
                        </div>
                    </Show>

                    // ── Step 3: Distribute shards (one at a time) ────────
                    // Show exactly one shard at a time so that all shard JSONs are never
                    // simultaneously present in the DOM — prevents browser extensions or
                    // devtools from reading all shards in a single sweep.
                    <Show when=move || step.get() == 3>
                        <div class="setup-inputs">
                            {move || {
                                let shards = recovery.shards.get();
                                let cursor = shard_cursor.get();
                                let total = shards.len();
                                if total == 0 {
                                    return view! { <p>"No shards generated."</p> }.into_any();
                                }
                                let shard = &shards[cursor];
                                let idx = shard.index;
                                let shard_json = shard.shard_json.clone();
                                let copy_json = shard.shard_json.clone();
                                let is_last = cursor + 1 >= total;
                                view! {
                                    <div>
                                        <p style="margin: 0 0 0.5rem;">
                                            {format!("SHARD {idx} of {total} — deliver to trustee {idx}")}
                                        </p>
                                        <p style="margin: 0 0 1rem; color: var(--gold); font-size: 0.85rem;">
                                            "Save this shard securely before advancing. Previous shards are not shown again."
                                        </p>
                                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                                            <span style="color: var(--teal);">{format!("SHARD_{idx}")}</span>
                                            <button
                                                class="btn-ghost"
                                                style="padding: 0.1rem 0.5rem; font-size: 0.75rem;"
                                                on:click=move |_| {
                                                    let json = copy_json.clone();
                                                    spawn_local(async move {
                                                        if let Some(window) = web_sys::window() {
                                                            let _ = window.navigator().clipboard().write_text(&json);
                                                        }
                                                    });
                                                }
                                            >
                                                "[ COPY ]"
                                            </button>
                                        </div>
                                        <textarea
                                            readonly=true
                                            rows="4"
                                            style="width: 100%; font-family: var(--mono); font-size: 0.7rem; resize: none; background: var(--surface); color: var(--text); border: 1px solid var(--border);"
                                        >
                                            {shard_json}
                                        </textarea>
                                        <div class="setup-actions" style="margin-top: 1rem;">
                                            <button class="btn-ghost" on:click=move |_| {
                                                recovery.shards.set(Vec::new());
                                                recovery.manifest_json.set(String::new());
                                                step.set(2);
                                            }>"[ REGENERATE ]"</button>
                                            {if is_last {
                                                view! {
                                                    <button class="btn-sys" on:click=move |_| step.set(4)>
                                                        "[ ALL_DISTRIBUTED ]"
                                                    </button>
                                                }.into_any()
                                            } else {
                                                view! {
                                                    <button class="btn-sys" on:click=move |_| shard_cursor.set(cursor + 1)>
                                                        {format!("[ NEXT_SHARD ({}/{}) ]", cursor + 1, total)}
                                                    </button>
                                                }.into_any()
                                            }}
                                        </div>
                                    </div>
                                }.into_any()
                            }}
                        </div>
                    </Show>

                    // ── Step 4: Confirmation ──────────────────────────────
                    <Show when=move || step.get() == 4>
                        <div class="setup-inputs">
                            <p style="margin: 0 0 1rem;">
                                {move || format!(
                                    "Recovery configured: {} of {} shards required.",
                                    recovery.threshold.get(),
                                    recovery.total.get()
                                )}
                            </p>
                            <p style="color: var(--teal); margin: 0;">
                                "> RECOVERY_SCHEME_ACTIVE — your principal identity is now recoverable"
                            </p>
                        </div>
                        <div class="setup-actions">
                            <button class="btn-sys" on:click=mark_done>"[ DONE ]"</button>
                        </div>
                    </Show>
                </div>
            </div>
        </Show>
    }
}
