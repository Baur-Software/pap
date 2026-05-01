#[cfg(test)]
mod tests {
    use crate::platform::detection::{detect_runtime, RuntimeEnvironment};

    #[tokio::test]
    async fn test_detect_runtime_returns_valid_environment() {
        let runtime = detect_runtime().await;

        // Must return one of the three variants — never panic.
        match runtime {
            RuntimeEnvironment::Bare { .. } => {}
            RuntimeEnvironment::Docker { ref socket_path } => {
                assert!(!socket_path.is_empty());
            }
            RuntimeEnvironment::Unsupported => {}
        }
    }

    #[tokio::test]
    async fn test_detect_runtime_is_deterministic() {
        let runtime1 = detect_runtime().await;
        let runtime2 = detect_runtime().await;

        assert_eq!(
            std::mem::discriminant(&runtime1),
            std::mem::discriminant(&runtime2),
            "detect_runtime must return the same variant on repeated calls"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_linux_reports_seccomp() {
        let runtime = detect_runtime().await;
        if let RuntimeEnvironment::Bare { seccomp, .. } = runtime {
            assert!(seccomp, "Linux bare metal must report seccomp capability");
        }
        // If Docker, that's also valid — we're in a container
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_windows_reports_job_objects() {
        let runtime = detect_runtime().await;
        if let RuntimeEnvironment::Bare { job_objects, .. } = runtime {
            assert!(
                job_objects,
                "Windows bare metal must report job_objects capability"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_macos_reports_entitlements() {
        let runtime = detect_runtime().await;
        if let RuntimeEnvironment::Bare { entitlements, .. } = runtime {
            assert!(
                entitlements,
                "macOS bare metal must report entitlements capability"
            );
        }
    }
}
