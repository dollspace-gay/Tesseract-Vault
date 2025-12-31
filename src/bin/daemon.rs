// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Secure Cryptor Daemon
//!
//! Long-running background service for managing encrypted volume mounts

use tesseract_lib::daemon::DaemonServer;

fn main() {
    println!("Starting Secure Cryptor Daemon...");

    let server = DaemonServer::new();

    if let Err(e) = server.run() {
        eprintln!("Daemon error: {}", e);
        std::process::exit(1);
    }
}
