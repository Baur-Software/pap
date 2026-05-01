//! Runtime platform detection: OS capabilities vs Docker vs unsupported.
//!
//! Uses `os_capabilities::detect()` for real feature probing instead of
//! compile-time `#[cfg]` gating. A Linux binary running in a restricted
//! container where seccomp is blocked will correctly report `seccomp: false`
//! and fall through to Docker or error — not silently assume it works.

use std::path::Path;

use crate::os_capabilities;

/// The runtime environment detected at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEnvironment {
    /// Bare metal or VM with native OS capabilities available.
    Bare {
        seccomp: bool,
        pledge: bool,
        entitlements: bool,
        job_objects: bool,
    },
    /// Inside a container with Docker socket available for sibling container spawning.
    Docker { socket_path: String },
    /// No isolation mechanism available.
    Unsupported,
}

/// Detect the current runtime environment.
///
/// Probes actual OS capabilities at runtime via `os_capabilities::detect()`
/// rather than assuming availability based on compile target. This means a
/// Linux binary where seccomp is blocked (e.g. inside a restricted container)
/// correctly falls through to Docker spawning or returns Unsupported.
pub async fn detect_runtime() -> RuntimeEnvironment {
    if is_in_container() {
        if let Some(socket) = find_docker_socket().await {
            return RuntimeEnvironment::Docker {
                socket_path: socket,
            };
        }
    }

    let caps = os_capabilities::detect();

    let seccomp = caps.seccomp_available;
    let pledge = caps.pledge_available;
    let entitlements = caps.sandbox_framework_available;
    let job_objects = caps.job_objects_available;

    if seccomp || pledge || entitlements || job_objects {
        RuntimeEnvironment::Bare {
            seccomp,
            pledge,
            entitlements,
            job_objects,
        }
    } else {
        RuntimeEnvironment::Unsupported
    }
}

/// Check if we're running inside a container.
fn is_in_container() -> bool {
    // Check for /.dockerenv (Docker marker file).
    if Path::new("/.dockerenv").exists() {
        return true;
    }

    // Check cgroup for container markers (Linux only).
    #[cfg(target_os = "linux")]
    {
        if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
            if cgroup.contains("docker") || cgroup.contains("container") {
                return true;
            }
        }
    }

    false
}

/// Find Docker socket at standard locations.
async fn find_docker_socket() -> Option<String> {
    // Standard locations to check.
    let paths = vec![
        "/var/run/docker.sock",
        "/run/docker.sock",
        // Podman also uses docker.sock for compatibility.
        "/run/podman/podman.sock",
    ];

    for path in paths {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    // Check DOCKER_HOST environment variable.
    if let Ok(docker_host) = std::env::var("DOCKER_HOST") {
        // DOCKER_HOST can be unix:///path/to/socket or tcp://host:port
        if docker_host.starts_with("unix://") {
            let socket_path = docker_host.strip_prefix("unix://").unwrap_or("");
            if !socket_path.is_empty() && Path::new(socket_path).exists() {
                return Some(socket_path.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_bare_metal() {
        // On CI/testing, we typically get bare metal even in containers
        // because Docker socket isn't mounted.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let env = runtime.block_on(detect_runtime());

        match env {
            RuntimeEnvironment::Bare { .. } => {
                // Expected on CI or when OS capabilities are available.
            }
            RuntimeEnvironment::Docker { .. } => {
                // Also valid if Docker socket is mounted.
            }
            RuntimeEnvironment::Unsupported => {
                panic!("Unsupported platform");
            }
        }
    }

    #[test]
    fn test_is_in_container_detects_marker() {
        // This test only makes sense inside a container.
        // It documents the expected behavior.
        #[cfg(feature = "test_in_docker")]
        {
            assert!(is_in_container());
        }
    }

    #[test]
    fn test_find_docker_socket_checks_paths() {
        // Just verify the function doesn't panic.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _ = runtime.block_on(find_docker_socket());
    }
}
