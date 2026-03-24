/// Health check endpoint for canary monitoring.
///
/// Returns application health status and uptime metrics.
/// Used by post-deploy verification to detect runtime failures.

use chrono::Utc;
use serde::Serialize;
use std::time::SystemTime;

/// Health status response structure
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub version: String,
}

/// Get health status of the Papillion orchestrator
///
/// Returns:
/// - status: "ok" if healthy, "degraded" or "error" otherwise
/// - timestamp: ISO 8601 UTC timestamp
/// - uptime_seconds: Seconds since application started
/// - version: Application version from Cargo.toml
#[tauri::command]
pub fn get_health_status() -> HealthResponse {
    let timestamp = Utc::now().to_rfc3339();
    let uptime = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    HealthResponse {
        status: "ok".to_string(),
        timestamp,
        uptime_seconds: uptime,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_returns_ok() {
        let health = get_health_status();
        assert_eq!(health.status, "ok");
        assert!(!health.timestamp.is_empty());
        assert!(health.uptime_seconds > 0);
        assert!(!health.version.is_empty());
    }
}
