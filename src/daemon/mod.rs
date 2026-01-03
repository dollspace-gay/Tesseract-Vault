// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Daemon module for managing long-running volume mount operations
//!
//! The daemon provides:
//! - Persistent tracking of mounted volumes across process boundaries
//! - IPC interface for mount/unmount/list operations
//! - Platform-specific service integration
//! - Automatic cleanup on shutdown

pub mod client;
#[cfg(test)]
mod loom_tests;
pub mod protocol;
pub mod server;

#[cfg(windows)]
pub mod service;

pub use client::DaemonClient;
pub use protocol::{DaemonCommand, DaemonResponse, MountInfo};
pub use server::DaemonServer;
