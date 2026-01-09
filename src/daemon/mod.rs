// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Daemon module for managing long-running volume mount operations
//!
//! The daemon provides:
//! - Persistent tracking of mounted volumes across process boundaries
//! - IPC interface for mount/unmount/list operations
//! - Platform-specific service integration
//! - Automatic cleanup on shutdown
//! - Token-based authentication to prevent unauthorized access

pub mod auth;
#[cfg(kani)]
mod auth_kani;
pub mod client;
#[cfg(test)]
mod loom_tests;
pub mod protocol;
#[cfg(kani)]
mod protocol_kani;
pub mod server;

#[cfg(windows)]
pub mod service;

pub use auth::AuthManager;
pub use client::DaemonClient;
pub use protocol::{
    AuthenticatedRequest, DaemonCommand, DaemonResponse, DeadManStatusInfo, DeadManStatusType,
    MountInfo,
};
pub use server::DaemonServer;
