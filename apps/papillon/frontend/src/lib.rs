mod app;
mod bridge;
pub mod components;
pub mod handshake;
pub mod orchestrator_runtime;
pub mod pages;
pub mod service;
pub mod state;
pub mod workflow_labels;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
