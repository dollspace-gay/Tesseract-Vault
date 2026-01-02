// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Platform-specific service integration
//!
//! Provides system service registration and management for:
//! - Windows Service Control Manager
//! - Linux systemd

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

// Re-export platform-specific functions
#[cfg(windows)]
pub use self::windows::{install_service, run_service, uninstall_service};

#[cfg(target_os = "linux")]
pub use self::linux::{
    enable_service, install_service, start_service, stop_service, uninstall_service,
};
