// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for AES-GCM encryption.
//!
//! This module contains proof harnesses that verify critical properties of
//! the AES-GCM implementation using the Kani model checker.

#![cfg(kani)]

use super::aes_gcm::AesGcmEncryptor;
use super::Encryptor;
use crate::config::NONCE_LEN;

/// Verify that encrypt() produces ciphertext of correct length.
///
/// Property: |ciphertext| = |plaintext| + 16 (authentication tag)
#[kani::proof]
fn verify_encrypt_length() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    // Bound plaintext size to avoid state explosion
    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len <= 1024);

    let plaintext = vec![0u8; plaintext_len];

    match encryptor.encrypt(&key, &nonce, &plaintext) {
        Ok(ciphertext) => {
            // Ciphertext should be plaintext + 16-byte tag
            assert_eq!(ciphertext.len(), plaintext.len() + 16);
        }
        Err(_) => {
            // encrypt() should never fail with valid inputs
            kani::cover!(false, "encrypt failed with valid inputs");
        }
    }
}

/// Verify that encrypt() never panics with valid inputs.
///
/// Property: encrypt() handles all inputs gracefully without panicking.
#[kani::proof]
fn verify_encrypt_no_panic() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len <= 256);
    let plaintext = vec![0u8; plaintext_len];

    // Should never panic
    let _ = encryptor.encrypt(&key, &nonce, &plaintext);
}

/// Verify that encrypt() rejects invalid nonce lengths.
///
/// Property: encrypt() returns error for nonce.len() != NONCE_LEN
#[kani::proof]
fn verify_encrypt_rejects_invalid_nonce() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();

    // Create invalid nonce (wrong length)
    let nonce_len: usize = kani::any();
    kani::assume(nonce_len != NONCE_LEN);
    kani::assume(nonce_len <= 64);

    let nonce = vec![0u8; nonce_len];
    let plaintext = b"test";

    let result = encryptor.encrypt(&key, &nonce, plaintext);

    // Must fail with invalid nonce length
    assert!(result.is_err());
}

/// Verify encryption/decryption round-trip correctness.
///
/// Property: decrypt(encrypt(plaintext)) = plaintext
#[kani::proof]
#[kani::unwind(8)]  // Higher bound for vector operations
fn verify_roundtrip() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len <= 128);  // Small for feasibility

    let mut plaintext = vec![0u8; plaintext_len];
    for i in 0..plaintext_len {
        plaintext[i] = kani::any();
    }

    // Encrypt
    match encryptor.encrypt(&key, &nonce, &plaintext) {
        Ok(ciphertext) => {
            // Decrypt
            match encryptor.decrypt(&key, &nonce, &ciphertext) {
                Ok(decrypted) => {
                    // Round-trip must produce original plaintext
                    assert_eq!(decrypted, plaintext);
                }
                Err(_) => {
                    // Decryption should not fail for valid ciphertext
                    kani::cover!(false, "decrypt failed on valid ciphertext");
                }
            }
        }
        Err(_) => {
            // encrypt should not fail with valid inputs
            kani::cover!(false, "encrypt failed in roundtrip");
        }
    }
}

/// Verify that decrypt() rejects modified ciphertext (authentication).
///
/// Property: Tampering with ciphertext causes authentication failure
#[kani::proof]
#[kani::unwind(8)]
fn verify_authentication() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len > 0 && plaintext_len <= 64);

    let plaintext = vec![0u8; plaintext_len];

    match encryptor.encrypt(&key, &nonce, &plaintext) {
        Ok(mut ciphertext) => {
            // Tamper with ciphertext
            let tamper_index: usize = kani::any();
            kani::assume(tamper_index < ciphertext.len());

            let original_byte = ciphertext[tamper_index];
            let tamper_byte: u8 = kani::any();
            kani::assume(tamper_byte != original_byte);

            ciphertext[tamper_index] = tamper_byte;

            // Decryption should fail (authentication error)
            let result = encryptor.decrypt(&key, &nonce, &ciphertext);
            assert!(result.is_err(), "Tampered ciphertext should be rejected");
        }
        Err(_) => {
            kani::cover!(false, "encrypt failed");
        }
    }
}

/// Verify that decrypt() produces correct length output.
///
/// Property: |plaintext| = |ciphertext| - 16
#[kani::proof]
fn verify_decrypt_length() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    // Create valid ciphertext (via encryption)
    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len <= 256);

    let plaintext = vec![0u8; plaintext_len];

    match encryptor.encrypt(&key, &nonce, &plaintext) {
        Ok(ciphertext) => {
            match encryptor.decrypt(&key, &nonce, &ciphertext) {
                Ok(decrypted) => {
                    // Decrypted length should be ciphertext - tag
                    assert_eq!(decrypted.len(), ciphertext.len() - 16);
                }
                Err(_) => {
                    kani::cover!(false, "decrypt failed");
                }
            }
        }
        Err(_) => {}
    }
}

/// Verify that nonce_len() always returns NONCE_LEN.
///
/// Property: nonce_len() is constant and correct
#[kani::proof]
fn verify_nonce_len() {
    let encryptor = AesGcmEncryptor::new();
    assert_eq!(encryptor.nonce_len(), NONCE_LEN);
    assert_eq!(encryptor.nonce_len(), 12);
}

/// Verify no integer overflow in length calculations.
///
/// Property: All length arithmetic is safe from overflow
#[kani::proof]
fn verify_no_overflow() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    // Test with maximum reasonable plaintext size
    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len <= 65536);  // 64KB

    let plaintext = vec![0u8; plaintext_len];

    // Should not overflow or panic
    let _ = encryptor.encrypt(&key, &nonce, &plaintext);
}

/// Verify that decrypt() rejects ciphertext shorter than tag.
///
/// Property: Ciphertext must be at least 16 bytes (tag size)
#[kani::proof]
fn verify_decrypt_minimum_length() {
    let encryptor = AesGcmEncryptor::new();
    let key: [u8; 32] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();

    // Ciphertext too short (less than tag size)
    let short_len: usize = kani::any();
    kani::assume(short_len < 16);

    let ciphertext = vec![0u8; short_len];

    let result = encryptor.decrypt(&key, &nonce, &ciphertext);

    // Should fail (either due to length or authentication)
    assert!(result.is_err());
}
