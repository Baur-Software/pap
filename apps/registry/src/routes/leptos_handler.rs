use axum::Router;
use leptos::config::LeptosOptions;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use leptos_meta::MetaTags;

use crate::state::AppState;
use crate::ui::app::App;

pub fn leptos_router(options: LeptosOptions, state: AppState) -> Router<LeptosOptions> {
    let routes = generate_route_list(App);
    Router::new()
        .leptos_routes_with_context(
            &options,
            routes,
            {
                let state = state.clone();
                move || {
                    provide_context(state.clone());
                }
            },
            {
                let options = options.clone();
                move || shell(options.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler(shell))
}

fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options=options.clone() />
                <MetaTags/>
                <link rel="stylesheet" id="leptos" href="/pkg/pap-registry-ui.css"/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}
