// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for Argon2id key derivation.
//!
//! This module contains proof harnesses that verify critical properties of
//! the Argon2id KDF implementation using the Kani model checker.

#![cfg(kani)]

use super::kdf::Argon2Kdf;
use super::KeyDerivation;
use crate::config::CryptoConfig;

/// Verify that derive_key() always produces 32-byte keys.
///
/// Property: Output key length is always 32 bytes
#[kani::proof]
fn verify_key_length() {
    let kdf = Argon2Kdf::default_config();

    let password_len: usize = kani::any();
    kani::assume(password_len > 0 && password_len <= 128);

    let salt_len: usize = kani::any();
    kani::assume(salt_len >= 8 && salt_len <= 64);

    let password = vec![0u8; password_len];
    let salt = vec![0u8; salt_len];

    match kdf.derive_key(&password, &salt) {
        Ok(key) => {
            // Key must always be 32 bytes
            assert_eq!(key.len(), 32);
        }
        Err(_) => {
            // derive_key may fail on invalid parameters
            kani::cover!(true, "derive_key failed");
        }
    }
}

/// Verify that derive_key() is deterministic.
///
/// Property: Same inputs always produce same output
#[kani::proof]
#[kani::unwind(4)]
fn verify_determinism() {
    let kdf = Argon2Kdf::default_config();

    let password: [u8; 16] = kani::any();
    let salt: [u8; 16] = kani::any();

    // Derive key twice with same inputs
    match kdf.derive_key(&password, &salt) {
        Ok(key1) => {
            match kdf.derive_key(&password, &salt) {
                Ok(key2) => {
                    // Results must be identical
                    assert_eq!(&*key1, &*key2);
                }
                Err(_) => {
                    kani::cover!(false, "second derivation failed");
                }
            }
        }
        Err(_) => {
            kani::cover!(true, "first derivation failed");
        }
    }
}

/// Verify that derive_key() never panics with valid inputs.
///
/// Property: KDF handles all valid inputs gracefully
#[kani::proof]
fn verify_no_panic() {
    let kdf = Argon2Kdf::default_config();

    let password_len: usize = kani::any();
    kani::assume(password_len > 0 && password_len <= 256);

    let salt_len: usize = kani::any();
    kani::assume(salt_len >= 8 && salt_len <= 128);

    let password = vec![0u8; password_len];
    let salt = vec![0u8; salt_len];

    // Should never panic
    let _ = kdf.derive_key(&password, &salt);
}

/// Verify that different salts produce different keys.
///
/// Property: Salt uniqueness ensures key independence
#[kani::proof]
#[kani::unwind(4)]
fn verify_salt_uniqueness() {
    let kdf = Argon2Kdf::default_config();

    let password: [u8; 16] = kani::any();
    let salt1: [u8; 16] = kani::any();
    let salt2: [u8; 16] = kani::any();

    // Assume salts are different
    kani::assume(salt1 != salt2);

    match kdf.derive_key(&password, &salt1) {
        Ok(key1) => {
            match kdf.derive_key(&password, &salt2) {
                Ok(key2) => {
                    // Different salts should produce different keys
                    assert_ne!(&*key1, &*key2);
                }
                Err(_) => {
                    kani::cover!(false, "second derivation failed");
                }
            }
        }
        Err(_) => {
            kani::cover!(true, "first derivation failed");
        }
    }
}

/// Verify that different passwords produce different keys.
///
/// Property: Password uniqueness ensures key independence
#[kani::proof]
#[kani::unwind(4)]
fn verify_password_uniqueness() {
    let kdf = Argon2Kdf::default_config();

    let password1: [u8; 16] = kani::any();
    let password2: [u8; 16] = kani::any();
    let salt: [u8; 16] = kani::any();

    // Assume passwords are different
    kani::assume(password1 != password2);

    match kdf.derive_key(&password1, &salt) {
        Ok(key1) => {
            match kdf.derive_key(&password2, &salt) {
                Ok(key2) => {
                    // Different passwords should produce different keys
                    assert_ne!(&*key1, &*key2);
                }
                Err(_) => {
                    kani::cover!(false, "second derivation failed");
                }
            }
        }
        Err(_) => {
            kani::cover!(true, "first derivation failed");
        }
    }
}

/// Verify that generate_salt() produces correct length.
///
/// Property: Salt length meets minimum requirements
#[kani::proof]
fn verify_salt_generation() {
    let kdf = Argon2Kdf::default_config();

    let salt = kdf.generate_salt();

    // Salt should be at least 16 bytes (recommended)
    assert!(salt.len() >= 16);
}

/// Verify that KDF configuration parameters are valid.
///
/// Property: CryptoConfig enforces valid Argon2 parameters
#[kani::proof]
fn verify_config_validity() {
    let config = CryptoConfig::default();

    // Memory cost must be reasonable
    assert!(config.argon2_mem_cost_kib >= 8);
    assert!(config.argon2_mem_cost_kib <= 1048576); // Max 1GB

    // Time cost must be at least 1
    assert!(config.argon2_time_cost >= 1);
    assert!(config.argon2_time_cost <= 100);

    // Lanes must be valid
    assert!(config.argon2_lanes >= 1);
    assert!(config.argon2_lanes <= 16);
}

/// Verify no integer overflow in parameter calculations.
///
/// Property: All arithmetic is safe from overflow
#[kani::proof]
fn verify_no_overflow() {
    let mem_cost: u32 = kani::any();
    kani::assume(mem_cost >= 8 && mem_cost <= 1048576);

    let time_cost: u32 = kani::any();
    kani::assume(time_cost >= 1 && time_cost <= 100);

    let lanes: u32 = kani::any();
    kani::assume(lanes >= 1 && lanes <= 16);

    let config = CryptoConfig {
        argon2_mem_cost_kib: mem_cost,
        argon2_time_cost: time_cost,
        argon2_lanes: lanes,
        ..Default::default()
    };

    let kdf = Argon2Kdf::new(config);

    let password = b"test_password";
    let salt = b"test_salt_16byte";

    // Should not overflow or panic
    let _ = kdf.derive_key(password, salt);
}

/// Verify that empty password is handled correctly.
///
/// Property: KDF behavior with edge case inputs
#[kani::proof]
fn verify_empty_password() {
    let kdf = Argon2Kdf::default_config();

    let password: &[u8] = &[];
    let salt = b"test_salt_16byte";

    // Empty password should be handled (may succeed or fail)
    let result = kdf.derive_key(password, salt);

    // Just verify it doesn't panic
    match result {
        Ok(key) => {
            assert_eq!(key.len(), 32);
        }
        Err(_) => {
            kani::cover!(true, "empty password rejected");
        }
    }
}

/// Verify that short salt is handled correctly.
///
/// Property: Minimum salt length requirements
#[kani::proof]
fn verify_short_salt() {
    let kdf = Argon2Kdf::default_config();

    let password = b"test_password";
    let salt: &[u8] = b"short"; // Less than 8 bytes

    // Short salt should still work (Argon2 allows it)
    let result = kdf.derive_key(password, salt);

    // Verify no panic, may succeed or fail
    match result {
        Ok(key) => {
            assert_eq!(key.len(), 32);
        }
        Err(_) => {
            kani::cover!(true, "short salt rejected");
        }
    }
}

/// Verify that maximum size inputs are handled correctly.
///
/// Property: KDF handles large inputs without overflow
#[kani::proof]
fn verify_large_inputs() {
    let kdf = Argon2Kdf::default_config();

    // Test with large (but bounded) inputs
    let password_len: usize = kani::any();
    kani::assume(password_len > 0 && password_len <= 4096);

    let salt_len: usize = kani::any();
    kani::assume(salt_len >= 16 && salt_len <= 1024);

    let password = vec![0u8; password_len];
    let salt = vec![0u8; salt_len];

    // Should handle large inputs without overflow
    let result = kdf.derive_key(&password, &salt);

    match result {
        Ok(key) => {
            assert_eq!(key.len(), 32);
        }
        Err(_) => {
            kani::cover!(true, "large input derivation failed");
        }
    }
}
