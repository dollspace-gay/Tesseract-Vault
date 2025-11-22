/// Daemon module for managing long-running volume mount operations
///
/// The daemon provides:
/// - Persistent tracking of mounted volumes across process boundaries
/// - IPC interface for mount/unmount/list operations
/// - Platform-specific service integration
/// - Automatic cleanup on shutdown

pub mod protocol;
pub mod server;
pub mod client;

#[cfg(windows)]
pub mod service;

pub use protocol::{DaemonCommand, DaemonResponse, MountInfo};
pub use server::DaemonServer;
pub use client::DaemonClient;
