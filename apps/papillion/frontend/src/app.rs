use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::components::address_bar::AddressBar;
use crate::components::sidebar::Sidebar;
use crate::pages::browse::BrowsePage;
use crate::pages::dashboard::DashboardPage;
use crate::pages::pipelines::PipelinesPage;
use crate::pages::receipts::ReceiptsPage;
use crate::pages::sessions::SessionsPage;
use crate::pages::settings::SettingsPage;
use crate::state::identity::IdentityState;
use crate::state::registry::RegistryState;

#[component]
pub fn App() -> impl IntoView {
    let identity_state = IdentityState::new();
    let registry_state = RegistryState::new();
    provide_context(identity_state);
    provide_context(registry_state);

    view! {
        <Router>
            <div class="app-shell">
                <header class="header">
                    <h1>"Papillion"</h1>
                    <AddressBar />
                </header>
                <Sidebar />
                <main class="main-content">
                    <Routes fallback=|| "Page not found.">
                        <Route path=path!("/") view=DashboardPage />
                        <Route path=path!("/browse") view=BrowsePage />
                        <Route path=path!("/sessions") view=SessionsPage />
                        <Route path=path!("/pipelines") view=PipelinesPage />
                        <Route path=path!("/receipts") view=ReceiptsPage />
                        <Route path=path!("/settings") view=SettingsPage />
                    </Routes>
                </main>
                <footer class="status-bar">
                    <span>"Ready"</span>
                </footer>
            </div>
        </Router>
    }
}
