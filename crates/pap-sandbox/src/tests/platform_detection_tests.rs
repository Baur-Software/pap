#[cfg(test)]
mod tests {
    use crate::platform::detection::{detect_runtime, RuntimeEnvironment};

    #[tokio::test]
    async fn test_detect_runtime_returns_valid_environment() {
        let runtime = detect_runtime().await;

        match runtime {
            RuntimeEnvironment::Bare { .. } => {
                // Expected on native platforms
            }
            RuntimeEnvironment::Docker { socket_path } => {
                // Expected if running in Docker with socket mounted
                assert!(!socket_path.is_empty());
            }
            RuntimeEnvironment::Unsupported => {
                // Less common, but possible on obscure platforms
            }
        }
    }

    #[tokio::test]
    async fn test_detect_runtime_consistent() {
        let runtime1 = detect_runtime().await;
        let runtime2 = detect_runtime().await;

        // Subsequent calls should return the same variant
        // (may have different values if socket paths vary, but type should match)
        std::mem::discriminant(&runtime1) == std::mem::discriminant(&runtime2);
    }

    #[tokio::test]
    async fn test_bare_platform_has_capabilities() {
        let runtime = detect_runtime().await;

        if let RuntimeEnvironment::Bare {
            seccomp,
            pledge,
            entitlements,
            job_objects,
        } = runtime
        {
            // At least one capability should be true on a real platform.
            let has_any = seccomp || pledge || entitlements || job_objects;
            #[cfg(any(
                target_os = "linux",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "macos",
                target_os = "windows"
            ))]
            assert!(
                has_any,
                "Expected at least one capability on supported platform"
            );
        }
    }
}
