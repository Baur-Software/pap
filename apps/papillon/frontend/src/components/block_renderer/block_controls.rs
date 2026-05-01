use leptos::prelude::*;

use crate::state::canvas::CanvasState;
use super::BlockContext;

/// Toolbar that appears at the top-right of each block on hover.
///
/// Controls: Pin, Copy Ref, Duplicate, Archive, Delete.
/// Delete uses a "click again to confirm" pattern -- first click changes the
/// button text to "Sure?", second click calls `delete_block()`. Resets after
/// 2 seconds if not confirmed.
#[component]
pub fn BlockControls() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let block_ctx = expect_context::<BlockContext>();
    let block_id = block_ctx.id.get_value();

    // -- Pin toggle --
    let is_pinned = move || {
        canvas_state
            .pinned_blocks
            .get()
            .contains(&block_ctx.id.get_value())
    };

    let on_pin = move |e: leptos::ev::MouseEvent| {
        e.stop_propagation();
        canvas_state.toggle_pin(&block_ctx.id.get_value());
    };

    // -- Copy reference --
    let on_copy_ref = move |e: leptos::ev::MouseEvent| {
        e.stop_propagation();
        canvas_state.copy_block_ref(&block_ctx.id.get_value());
    };

    // -- Duplicate --
    let on_duplicate = move |e: leptos::ev::MouseEvent| {
        e.stop_propagation();
        canvas_state.duplicate_block(&block_ctx.id.get_value());
    };

    // -- Archive toggle --
    let is_archived = move || {
        canvas_state
            .archived_blocks
            .get()
            .contains(&block_ctx.id.get_value())
    };

    let on_archive = move |e: leptos::ev::MouseEvent| {
        e.stop_propagation();
        canvas_state.toggle_archive(&block_ctx.id.get_value());
    };

    // -- Delete with confirmation --
    let confirming_delete = RwSignal::new(false);

    let on_delete = move |e: leptos::ev::MouseEvent| {
        e.stop_propagation();
        if confirming_delete.get_untracked() {
            // Second click: actually delete
            canvas_state.delete_block(&block_ctx.id.get_value());
            confirming_delete.set(false);
        } else {
            // First click: enter confirmation state
            confirming_delete.set(true);
            // Reset after 2 seconds if not confirmed.
            // Create a JS Promise-based delay without needing gloo-timers.
            let confirming = confirming_delete;
            wasm_bindgen_futures::spawn_local(async move {
                let promise = js_sys::Promise::new(&mut |resolve, _| {
                    let _ = web_sys::window()
                        .unwrap()
                        .set_timeout_with_callback_and_timeout_and_arguments_0(
                            &resolve, 2000,
                        );
                });
                let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                confirming.set(false);
            });
        }
    };

    let _ = block_id; // used via block_ctx closures above

    view! {
        <div
            class="block-controls"
            on:click=|e: leptos::ev::MouseEvent| e.stop_propagation()
        >
            // Pin toggle
            <button
                class=move || if is_pinned() { "block-control-btn active" } else { "block-control-btn" }
                title=move || if is_pinned() { "Unpin" } else { "Pin" }
                on:click=on_pin
            >
                {move || if is_pinned() { "Pinned" } else { "Pin" }}
            </button>

            // Copy reference
            <button
                class="block-control-btn"
                title="Copy block reference"
                on:click=on_copy_ref
            >
                "Ref"
            </button>

            // Duplicate
            <button
                class="block-control-btn"
                title="Duplicate this block"
                on:click=on_duplicate
            >
                "Dup"
            </button>

            // Archive toggle
            <button
                class=move || if is_archived() { "block-control-btn active" } else { "block-control-btn" }
                title=move || if is_archived() { "Unarchive" } else { "Archive" }
                on:click=on_archive
            >
                {move || if is_archived() { "Restore" } else { "Archive" }}
            </button>

            // Delete with confirmation
            <button
                class=move || if confirming_delete.get() { "block-control-btn confirm" } else { "block-control-btn" }
                title="Delete this block"
                on:click=on_delete
            >
                {move || if confirming_delete.get() { "Sure?" } else { "Del" }}
            </button>
        </div>
    }
}
