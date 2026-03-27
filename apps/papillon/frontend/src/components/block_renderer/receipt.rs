use leptos::prelude::*;
use serde_json::Value;

/// Wrap rendered content with a receipt metadata footer.
/// The receipt shows session ID, co-signature count, and action type
/// as a subtle mono footer below the block content.
pub fn wrap_with_receipt(content_view: AnyView, receipt: Option<&Value>) -> AnyView {
    let receipt_view = receipt.map(|r| {
        let session = r.get("session_id").and_then(|v| v.as_str()).unwrap_or("-");
        let sigs = r.get("co_signatures").and_then(|v| v.as_u64()).unwrap_or(0);
        let action = r
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();

        // Truncate session ID for display
        let session_short = if session.len() > 12 {
            format!("{}...", &session[..12])
        } else {
            session.to_string()
        };

        view! {
            <div class="typed-receipt">
                <span class="typed-receipt-session">{session_short}</span>
                <span class="typed-receipt-sigs">{format!("{} co-sig", sigs)}</span>
                <span class="typed-receipt-action">{action}</span>
            </div>
        }
    });

    view! {
        <div class="typed-content-wrapper">
            {content_view}
            {receipt_view}
        </div>
    }
    .into_any()
}
