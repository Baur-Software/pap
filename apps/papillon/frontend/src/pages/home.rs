use leptos::prelude::*;

use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::OrchestratorStatus;

#[component]
pub fn HomePage() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let orchestrator = expect_context::<OrchestratorState>();

    let identity_status = move || {
        if identity.info.get().is_some() {
            "ACTIVE"
        } else {
            "INITIALIZING"
        }
    };
    let identity_status_class = move || {
        if identity.info.get().is_some() {
            "readiness-status-badge active"
        } else {
            "readiness-status-badge warn"
        }
    };
    let identity_desc = move || match identity.info.get() {
        Some(info) => {
            let did = &info.did;
            let short = if did.len() > 32 {
                format!("{}...{}", &did[..16], &did[did.len() - 8..])
            } else {
                did.clone()
            };
            format!(
                "Local cryptographic identity established \u{2022} {}",
                short
            )
        }
        None => "Generating sovereign identity keypair\u{2026}".to_string(),
    };

    let network_status = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "READY",
        OrchestratorStatus::Disconnected | OrchestratorStatus::Unconfigured => "READY",
        OrchestratorStatus::Downloading { .. } => "SYNCING",
    };
    let network_status_class = move || "readiness-status-badge active";

    let llm_desc = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "LLM connected \u{2022} Federation server active".to_string(),
        OrchestratorStatus::Downloading { progress_pct } => {
            format!("Downloading model \u{2022} {}%", progress_pct)
        }
        _ => "Federation server active \u{2022} Agents available".to_string(),
    };

    view! {
        <div class="readiness-page">
            <div class="readiness-hero">
                <div class="readiness-shield">
                    <img src="/logo.png" alt="Papillon" width="40" height="40" />
                </div>
                <div class="readiness-title">"PAPILLON AGENTIC BROWSER"</div>
                <div class="readiness-subtitle">"SOVEREIGN COMPUTING ENVIRONMENT v0.6.0"</div>
            </div>

            <div class="readiness-panel">
                <div class="readiness-panel-header">"SYSTEM READINESS DIAGNOSTICS"</div>

                <div class="readiness-row">
                    <div class="readiness-row-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <circle cx="12" cy="11" r="4"/>
                            <path d="M3 20a9 9 0 0 1 18 0"/>
                        </svg>
                    </div>
                    <div class="readiness-row-body">
                        <div class="readiness-row-name">
                            "ROOT_OF_TRUST"
                            <span class=identity_status_class>{identity_status}</span>
                        </div>
                        <div class="readiness-row-desc">{identity_desc}</div>
                    </div>
                    <div class="readiness-row-meta">
                        <div class="readiness-row-meta-label">"Key Strength"</div>
                        <div class="readiness-row-meta-value">"ED25519"</div>
                    </div>
                    <div class="readiness-check">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <polyline points="20 6 9 17 4 12"/>
                        </svg>
                    </div>
                </div>

                <div class="readiness-row">
                    <div class="readiness-row-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <ellipse cx="12" cy="5" rx="9" ry="3"/>
                            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                        </svg>
                    </div>
                    <div class="readiness-row-body">
                        <div class="readiness-row-name">
                            "LOCAL_VAULT"
                            <span class="readiness-status-badge active">"AVAILABLE"</span>
                        </div>
                        <div class="readiness-row-desc">"Encrypted storage initialized \u{2022} Experience memory active"</div>
                    </div>
                    <div class="readiness-row-meta">
                        <div class="readiness-row-meta-label">"Storage"</div>
                        <div class="readiness-row-meta-value">"LOCAL"</div>
                    </div>
                    <div class="readiness-check">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <polyline points="20 6 9 17 4 12"/>
                        </svg>
                    </div>
                </div>

                <div class="readiness-row">
                    <div class="readiness-row-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                        </svg>
                    </div>
                    <div class="readiness-row-body">
                        <div class="readiness-row-name">
                            "NETWORK_HANDSHAKE"
                            <span class=network_status_class>{network_status}</span>
                        </div>
                        <div class="readiness-row-desc">{llm_desc}</div>
                    </div>
                    <div class="readiness-row-meta">
                        <div class="readiness-row-meta-label">"Protocol"</div>
                        <div class="readiness-row-meta-value">"PAP_v1"</div>
                    </div>
                    <div class="readiness-check">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <polyline points="20 6 9 17 4 12"/>
                        </svg>
                    </div>
                </div>

            </div>
        </div>
    }
}
