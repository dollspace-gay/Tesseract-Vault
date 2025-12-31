// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! LUKS2 integration for Tesseract
//!
//! This module provides Tesseract's advanced security features for Linux
//! full disk encryption via LUKS2 integration.
//!
//! # Features
//!
//! - **TPM Sealing**: Bind LUKS keys to PCR values for measured boot
//! - **PQC Hybrid**: ML-KEM post-quantum protection for LUKS passphrases
//! - **Duress Password**: Destroy keys when coerced password entered
//! - **YubiKey 2FA**: Hardware-backed two-factor for LUKS unlock
//!
//! # Architecture
//!
//! Tesseract wraps the LUKS passphrase in a secure keyfile format that adds
//! these features without modifying LUKS itself. The keyfile is used with
//! `cryptsetup --key-file` for unlock operations.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Tesseract LUKS Keyfile                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Magic: "TESS-LUKS"                                         │
//! │  Version: 1                                                  │
//! │  Flags: TPM | PQC | Duress                                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Password Slot (Argon2id encrypted LUKS passphrase)         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TPM Slot (PCR-sealed LUKS passphrase) [optional]           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  PQC Metadata (ML-KEM encapsulated key) [optional]          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Duress Slot (triggers destruction) [optional]              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```no_run
//! use tesseract_lib::luks::{TesseractLuksKeyfile, LuksConfig};
//!
//! // Create a new keyfile for a LUKS passphrase
//! let config = LuksConfig::default();
//! let keyfile = TesseractLuksKeyfile::new("my-luks-passphrase", "tesseract-password", config)?;
//!
//! // Save to disk
//! keyfile.save("/etc/tesseract/root.keyfile")?;
//!
//! // Later: unlock the LUKS device
//! let luks_passphrase = keyfile.unlock("tesseract-password")?;
//! // Use with: cryptsetup open /dev/sda2 root --key-file -
//! ```

mod keyfile;

pub use keyfile::*;
