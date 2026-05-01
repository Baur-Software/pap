pub mod detection;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub mod docker;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;
