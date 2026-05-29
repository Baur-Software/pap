#![recursion_limit = "256"]
#![allow(clippy::unwrap_used)]

pub mod ui;

#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod config;
#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub(crate) mod net_guard;
#[cfg(feature = "ssr")]
pub mod routes;
#[cfg(feature = "ssr")]
pub mod state;
#[cfg(feature = "ssr")]
pub(crate) mod tls;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn hydrate() {
    use crate::ui::app::App;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
