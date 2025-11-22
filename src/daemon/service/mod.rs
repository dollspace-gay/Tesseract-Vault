/// Platform-specific service integration
///
/// Provides system service registration and management for:
/// - Windows Service Control Manager
/// - Linux systemd
/// - macOS launchd

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// Re-export platform-specific functions
#[cfg(windows)]
pub use self::windows::{install_service, uninstall_service, run_service};

#[cfg(target_os = "linux")]
pub use self::linux::{install_service, uninstall_service, enable_service, start_service, stop_service};

#[cfg(target_os = "macos")]
pub use self::macos::{install_service, uninstall_service, load_service, unload_service};
