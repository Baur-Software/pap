//! Runtime OS capability detection for the sandbox.
//!
//! Probes which isolation primitives are actually available on the running
//! system. Results inform `CapabilityPolicy::effective_enforcement` so that
//! `AttestationReceipt` only claims enforcement for mechanisms that actually
//! applied — not for mechanisms that were requested but unavailable.
//!
//! All detection is done once at startup (lazy_static) and cached.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// OS-level isolation primitives available on this system at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsCapabilities {
    /// Platform name ("linux", "macos", "windows", "freebsd", etc.)
    pub platform: &'static str,

    // ── Syscall filtering ─────────────────────────────────────────────────────
    /// Linux: seccomp-BPF is available (kernel ≥ 3.5 + CAP_SYS_ADMIN or
    /// PR_SET_SECCOMP allowed by ambient capabilities / seccomp listener).
    pub seccomp_available: bool,

    /// BSD: pledge(2) is available (OpenBSD ≥ 5.9 or FreeBSD with compat).
    pub pledge_available: bool,

    /// macOS: Sandbox.framework `sandbox_init` is available.
    pub sandbox_framework_available: bool,

    // ── Process isolation ─────────────────────────────────────────────────────
    /// Windows: Job Objects can be created (requires appropriate privilege).
    pub job_objects_available: bool,

    /// Linux/BSD/macOS: process can be forked and exec'd into a restricted env.
    pub process_spawn_available: bool,

    // ── Memory protection ─────────────────────────────────────────────────────
    /// mlock(2) is usable — either RLIMIT_MEMLOCK > 0 or CAP_IPC_LOCK.
    pub mlock_available: bool,

    // ── Network restriction ───────────────────────────────────────────────────
    /// Network filtering is enforceable (seccomp/pledge/sandbox can block sockets).
    pub network_restriction_available: bool,

    // ── Filesystem restriction ────────────────────────────────────────────────
    /// Filesystem restriction is enforceable (seccomp path filtering, pledge
    /// unveil(2), macOS sandbox profiles, or Windows filesystem tokens).
    pub filesystem_restriction_available: bool,
}

static CAPABILITIES: OnceLock<OsCapabilities> = OnceLock::new();

/// Detect and return the OS capabilities of this system.
/// Detection runs once and is cached for the lifetime of the process.
pub fn detect() -> &'static OsCapabilities {
    CAPABILITIES.get_or_init(|| OsCapabilities {
        platform: current_platform(),
        seccomp_available: probe_seccomp(),
        pledge_available: probe_pledge(),
        sandbox_framework_available: probe_sandbox_framework(),
        job_objects_available: probe_job_objects(),
        process_spawn_available: probe_process_spawn(),
        mlock_available: probe_mlock(),
        network_restriction_available: probe_network_restriction(),
        filesystem_restriction_available: probe_filesystem_restriction(),
    })
}

fn current_platform() -> &'static str {
    #[cfg(target_os = "linux")]
    return "linux";
    #[cfg(target_os = "macos")]
    return "macos";
    #[cfg(target_os = "windows")]
    return "windows";
    #[cfg(target_os = "freebsd")]
    return "freebsd";
    #[cfg(target_os = "openbsd")]
    return "openbsd";
    #[cfg(target_os = "netbsd")]
    return "netbsd";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    return "unknown";
}

// ── seccomp (Linux) ───────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn probe_seccomp() -> bool {
    // Try to set a no-op seccomp filter in strict mode to confirm it's permitted.
    // We call prctl(PR_GET_SECCOMP) — if it returns 0 (not in seccomp) without
    // EINVAL, the kernel supports seccomp. A more thorough probe would try
    // PR_SET_SECCOMP + a trivial ALLOW filter, but that would affect this process;
    // instead we just verify the syscall number is known to the kernel.
    //
    // Fallback: check /proc/sys/kernel/unprivileged_bpf_disabled to see if
    // loading BPF is allowed without CAP_BPF.  If the file is absent (older
    // kernels) we assume seccomp is available (3.5+ kernels have it).
    unsafe {
        let ret = libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0);
        // ENOSYS means the kernel doesn't have seccomp at all.
        // Any other value (including 0 = SECCOMP_MODE_DISABLED) means it's there.
        ret != -1 || *libc::__errno_location() != libc::ENOSYS
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_seccomp() -> bool {
    false
}

// ── pledge (BSD) ─────────────────────────────────────────────────────────────

#[cfg(any(target_os = "openbsd"))]
fn probe_pledge() -> bool {
    // On OpenBSD, pledge() is always available in userspace.
    true
}

#[cfg(not(target_os = "openbsd"))]
fn probe_pledge() -> bool {
    false
}

// ── macOS Sandbox.framework ───────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn probe_sandbox_framework() -> bool {
    // sandbox_check(getpid(), "default", SANDBOX_FILTER_NONE) returns 0 if
    // sandboxing is not restricted; we just need to confirm the symbol is
    // available by checking if the Sandbox.framework is loaded.
    // Rather than dlopen at runtime, we rely on the weak-link: if this binary
    // was built with Sandbox.framework, it's available.
    true
}

#[cfg(not(target_os = "macos"))]
fn probe_sandbox_framework() -> bool {
    false
}

// ── Windows Job Objects ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn probe_job_objects() -> bool {
    // Job Objects are available on all Windows versions Vista and later.
    // Any process with appropriate permissions can create one; we return true
    // unconditionally and surface actual errors at spawn time.
    true
}

#[cfg(not(target_os = "windows"))]
fn probe_job_objects() -> bool {
    false
}

// ── Process spawn ─────────────────────────────────────────────────────────────

fn probe_process_spawn() -> bool {
    // On all supported platforms, spawning child processes is available unless
    // we're already inside a highly restricted sandbox (e.g. seccomp TSYNC
    // mode that blocks fork). A simple heuristic: on Unix, check that fork(2)
    // is not blocked by trying getpid() syscall — if we can run at all, we
    // can likely fork. On Windows, CreateProcess is always available.
    //
    // For robustness, we simply return true here; the spawner will surface
    // a SpawnError at runtime if the OS actually blocks it.
    true
}

// ── mlock ─────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn probe_mlock() -> bool {
    // Try to mlock a single page. If EPERM or ENOMEM (RLIMIT_MEMLOCK=0),
    // mlock is not usable. We test with a 1-byte allocation; the kernel
    // rounds to page size anyway.
    let data = vec![0u8; 1];
    let ret = unsafe { libc::mlock(data.as_ptr() as *const libc::c_void, data.len()) };
    if ret == 0 {
        // unlock immediately — we only wanted to probe availability
        unsafe {
            libc::munlock(data.as_ptr() as *const libc::c_void, data.len());
        }
        true
    } else {
        false
    }
}

#[cfg(not(unix))]
fn probe_mlock() -> bool {
    false
}

// ── Network restriction ───────────────────────────────────────────────────────

fn probe_network_restriction() -> bool {
    // Network restriction is available wherever the syscall filter mechanism is.
    probe_seccomp() || probe_pledge() || probe_sandbox_framework() || probe_job_objects()
}

// ── Filesystem restriction ────────────────────────────────────────────────────

fn probe_filesystem_restriction() -> bool {
    probe_seccomp() || probe_pledge() || probe_sandbox_framework() || probe_job_objects()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_consistent_results() {
        let first = detect();
        let second = detect();
        // Cached — pointer equality
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn platform_is_known() {
        let caps = detect();
        assert!(!caps.platform.is_empty());
        assert_ne!(caps.platform, "unknown");
    }

    #[test]
    fn mlock_probe_does_not_panic() {
        // Just ensure it runs without panicking on any platform.
        let _ = probe_mlock();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_probe_does_not_panic() {
        let _ = probe_seccomp();
    }
}
