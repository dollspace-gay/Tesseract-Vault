// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for AES-GCM decryption
//!
//! Tests the AES-GCM decryption path with arbitrary ciphertext to ensure
//! proper handling of malformed, truncated, or malicious input.
//! This is critical for security as decryption receives untrusted input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::AesGcmEncryptor;
use tesseract_lib::crypto::Encryptor;

fuzz_target!(|data: &[u8]| {
    // We need at least: key (32 bytes) + nonce (12 bytes) + some ciphertext
    if data.len() < 45 {
        return;
    }

    // Convert slice to fixed-size array for key
    let key: &[u8; 32] = data[0..32].try_into().unwrap();
    let nonce = &data[32..44];
    let ciphertext = &data[44..];

    let encryptor = AesGcmEncryptor::new();

    // Test decryption with arbitrary ciphertext
    // This should gracefully handle authentication failures
    let _ = encryptor.decrypt(key, nonce, ciphertext);

    // Also test with various nonce sizes
    if data.len() >= 57 {
        // Test with wrong nonce size (should fail gracefully)
        let wrong_nonce = &data[32..48]; // 16 bytes instead of 12
        let _ = encryptor.decrypt(key, wrong_nonce, &data[48..]);
    }

    // Test with empty ciphertext
    let _ = encryptor.decrypt(key, nonce, &[]);

    // Test with minimum valid ciphertext (just auth tag = 16 bytes)
    if ciphertext.len() >= 16 {
        let _ = encryptor.decrypt(key, nonce, &ciphertext[..16]);
    }
});
