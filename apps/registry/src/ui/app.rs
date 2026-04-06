use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::ui::components::nav::Sidebar;
use crate::ui::pages::agent_designer::AgentDesignerPage;
use crate::ui::pages::agents::AgentsPage;
use crate::ui::pages::dashboard::DashboardPage;
use crate::ui::pages::federation_admin::FederationAdminPage;
use crate::ui::pages::peers::PeersPage;
use crate::ui::pages::settings::SettingsPage;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <div class="app-shell">
                <Sidebar />
                <main class="main-content">
                    <Routes fallback=|| view! { <NotFound /> }>
                        <Route path=path!("/") view=DashboardPage />
                        <Route path=path!("/agents") view=AgentsPage />
                        <Route path=path!("/agents/design") view=AgentDesignerPage />
                        <Route path=path!("/peers") view=PeersPage />
                        <Route path=path!("/admin/federation") view=FederationAdminPage />
                        <Route path=path!("/settings") view=SettingsPage />
                    </Routes>
                </main>
            </div>
        </Router>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <div class="page">
            <div class="empty-state">
                <div class="empty-state-icon">"◌"</div>
                <div class="empty-state-title">"Page not found"</div>
                <a href="/" class="btn btn-secondary" style="margin-top: var(--sp-md)">"← Back to Dashboard"</a>
            </div>
        </div>
    }
}
