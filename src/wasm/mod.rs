// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! WebAssembly bindings for Secure Cryptor
//!
//! This module provides WebAssembly bindings for the core cryptographic functionality,
//! enabling secure encryption and decryption in web browsers.
//!
//! # Features
//!
//! - AES-GCM encryption/decryption
//! - Argon2 key derivation
//! - Post-quantum cryptography (ML-KEM-1024)
//! - File encryption/decryption
//! - Zero-copy operations where possible
//!
//! # Security Considerations
//!
//! - All sensitive data is zeroized after use
//! - Memory is not swappable in WASM environment
//! - Side-channel resistant implementations
//!
//! # Example (JavaScript)
//!
//! ```javascript
//! import init, { encrypt_text, decrypt_text } from './secure_cryptor_wasm.js';
//!
//! async function main() {
//!     await init();
//!
//!     const password = "my-secret-password";
//!     const plaintext = "Hello, World!";
//!
//!     // Encrypt
//!     const encrypted = encrypt_text(password, plaintext);
//!     console.log("Encrypted:", encrypted);
//!
//!     // Decrypt
//!     const decrypted = decrypt_text(password, encrypted);
//!     console.log("Decrypted:", decrypted);
//! }
//! ```

#[cfg(target_arch = "wasm32")]
pub mod bindings;

#[cfg(target_arch = "wasm32")]
pub mod security;

#[cfg(target_arch = "wasm32")]
pub use bindings::*;

#[cfg(target_arch = "wasm32")]
pub use security::*;

#[cfg(not(target_arch = "wasm32"))]
compile_error!("This module is only available when compiling to WebAssembly (wasm32)");
