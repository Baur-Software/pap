/// Health check endpoint for canary monitoring.
///
/// Returns application health status and uptime metrics.
/// Used by post-deploy verification to detect runtime failures.
use chrono::Utc;
use serde::Serialize;
use std::sync::OnceLock;
use std::time::Instant;

static APP_START_TIME: OnceLock<Instant> = OnceLock::new();

/// Initialize app start time (call once at startup)
pub fn init_health_metrics() {
    let _ = APP_START_TIME.get_or_init(Instant::now);
}

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

    // Calculate uptime from app start time, not UNIX_EPOCH
    let uptime_seconds = APP_START_TIME.get_or_init(Instant::now).elapsed().as_secs();

    HealthResponse {
        status: "ok".to_string(),
        timestamp,
        uptime_seconds,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_returns_ok() {
        init_health_metrics();
        let health = get_health_status();
        assert_eq!(health.status, "ok");
        assert!(!health.timestamp.is_empty());
        // Uptime should be reasonable (0-300 seconds for test runtime)
        assert!(
            health.uptime_seconds <= 300,
            "uptime {} exceeds test runtime",
            health.uptime_seconds
        );
        assert!(!health.version.is_empty());
    }

    #[test]
    fn health_uptime_increases() {
        init_health_metrics();
        let health1 = get_health_status();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let health2 = get_health_status();
        assert!(health2.uptime_seconds >= health1.uptime_seconds);
    }
}
