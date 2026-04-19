// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Constant-Time Execution Verification using DudeCT
//!
//! This benchmark suite uses statistical analysis to detect timing leaks in
//! Tesseract's cryptographic operations. All tests exercise project code paths
//! (AesGcmEncryptor, Argon2Kdf) rather than upstream crates directly.
//!
//! ## Methodology
//!
//! DudeCT (Dude, is my code Constant Time?) uses Welch's t-test to statistically
//! compare execution times between two classes of inputs:
//! - Class A: "Fixed" inputs (e.g., all zeros, known patterns)
//! - Class B: "Random" inputs (varying data)
//!
//! If the code is constant-time, there should be no statistically significant
//! difference in execution time between the classes.
//!
//! ## Running
//!
//! ```bash
//! cargo bench --bench constant_time
//! ```
//!
//! A t-value below 4.5 indicates no timing leak detected (with high confidence).
//! Values above 4.5 suggest potential timing vulnerabilities.
//!
//! ## References
//!
//! - Original paper: https://eprint.iacr.org/2016/1123.pdf
//! - dudect-bencher: https://crates.io/crates/dudect-bencher

use dudect_bencher::rand::Rng;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

use tesseract_lib::crypto::aes_gcm::AesGcmEncryptor;
use tesseract_lib::crypto::kdf::Argon2Kdf;
use tesseract_lib::crypto::{Encryptor, KeyDerivation};
use tesseract_lib::hsm::tpm_utils::constant_time_compare;

/// Test that AES-GCM encryption is constant-time with respect to plaintext content.
///
/// Exercises Tesseract's AesGcmEncryptor::encrypt() which includes nonce validation
/// and the full project encryption path.
fn aes_gcm_encrypt_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let encryptor = AesGcmEncryptor::new();

    // Fixed plaintext (Class A) vs Random plaintext (Class B)
    let fixed_plaintext = [0u8; 64];
    let mut random_plaintext = [0u8; 64];
    rng.fill_bytes(&mut random_plaintext);

    runner.run_one(Class::Left, || {
        // Class A: Encrypt fixed (all-zero) plaintext through project encryptor
        let _ = encryptor.encrypt(&key, &nonce_bytes, &fixed_plaintext);
    });

    runner.run_one(Class::Right, || {
        // Class B: Encrypt random plaintext through project encryptor
        let _ = encryptor.encrypt(&key, &nonce_bytes, &random_plaintext);
    });
}

/// Test that AES-GCM decryption is constant-time with respect to ciphertext validity.
///
/// CRITICAL: Tests whether Tesseract's decryption path takes the same time for
/// valid vs invalid tags. Timing differences here could allow tag-guessing attacks.
fn aes_gcm_decrypt_ct(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let encryptor = AesGcmEncryptor::new();

    // Create a valid ciphertext through project encryptor
    let plaintext = [0x55u8; 64];
    let valid_ciphertext = encryptor.encrypt(&key, &nonce_bytes, &plaintext).unwrap();

    // Create an invalid ciphertext (corrupted tag)
    let mut invalid_ciphertext = valid_ciphertext.clone();
    if let Some(last) = invalid_ciphertext.last_mut() {
        *last ^= 0xFF; // Flip bits in the tag
    }

    runner.run_one(Class::Left, || {
        // Class A: Decrypt valid ciphertext (should succeed)
        let _ = encryptor.decrypt(&key, &nonce_bytes, &valid_ciphertext);
    });

    runner.run_one(Class::Right, || {
        // Class B: Decrypt invalid ciphertext (should fail, but in constant time!)
        let _ = encryptor.decrypt(&key, &nonce_bytes, &invalid_ciphertext);
    });
}

/// Test that AES-GCM decryption timing doesn't leak tag position.
///
/// Verifies that an attacker cannot determine WHERE in the tag the
/// corruption occurred based on timing through Tesseract's decrypt path.
fn aes_gcm_tag_position_ct(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let encryptor = AesGcmEncryptor::new();

    // Create a valid ciphertext through project encryptor
    let plaintext = [0x55u8; 64];
    let valid_ciphertext = encryptor.encrypt(&key, &nonce_bytes, &plaintext).unwrap();

    // Corrupt first byte of tag (at position ciphertext.len() - 16)
    let mut early_corrupt = valid_ciphertext.clone();
    let tag_start = early_corrupt.len().saturating_sub(16);
    if tag_start < early_corrupt.len() {
        early_corrupt[tag_start] ^= 0xFF;
    }

    // Corrupt last byte of tag
    let mut late_corrupt = valid_ciphertext.clone();
    if let Some(last) = late_corrupt.last_mut() {
        *last ^= 0xFF;
    }

    runner.run_one(Class::Left, || {
        // Class A: Early tag corruption
        let _ = encryptor.decrypt(&key, &nonce_bytes, &early_corrupt);
    });

    runner.run_one(Class::Right, || {
        // Class B: Late tag corruption
        let _ = encryptor.decrypt(&key, &nonce_bytes, &late_corrupt);
    });
}

/// Test that constant-time byte comparison works correctly.
///
/// Exercises Tesseract's `constant_time_compare()` wrapper from `hsm::tpm_utils`,
/// which is used throughout the project for secret comparisons. Verifies that
/// mismatch position (first byte vs last byte) does not affect timing.
fn subtle_compare_ct(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // Two identical arrays
    let fixed_a = [0x42u8; 32];

    // Array that differs at first byte
    let mut differ_first = fixed_a;
    differ_first[0] = 0x00;

    // Array that differs at last byte
    let mut differ_last = fixed_a;
    differ_last[31] = 0x00;

    runner.run_one(Class::Left, || {
        // Compare where mismatch is at the beginning — through project wrapper
        let _ = constant_time_compare(&fixed_a, &differ_first);
    });

    runner.run_one(Class::Right, || {
        // Compare where mismatch is at the end — through project wrapper
        let _ = constant_time_compare(&fixed_a, &differ_last);
    });
}

/// Test that Argon2 key derivation is constant-time with respect to password content.
///
/// Exercises Tesseract's Argon2Kdf::derive_key() — the actual project KDF path —
/// rather than the raw argon2 crate. Uses minimal parameters for benchmark speed.
fn argon2_derive_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    use tesseract_lib::config::CryptoConfig;

    // Use minimal parameters for faster testing (still exercises project code path)
    let config = CryptoConfig::new(1024, 1, 1);
    let kdf = Argon2Kdf::new(config);

    // Fixed salt for consistent testing
    let salt = b"testsalttestsalt";

    // Fixed password (all same character)
    let fixed_password = b"aaaaaaaaaaaaaaaa";

    // Random password
    let mut random_password = [0u8; 16];
    rng.fill_bytes(&mut random_password);
    // Ensure printable ASCII
    for byte in random_password.iter_mut() {
        *byte = (*byte % 95) + 32; // ASCII 32-126
    }

    runner.run_one(Class::Left, || {
        let _ = kdf.derive_key(fixed_password, salt);
    });

    runner.run_one(Class::Right, || {
        let _ = kdf.derive_key(&random_password, salt);
    });
}

/// Test encryption with Additional Authenticated Data (AAD).
///
/// Verifies that different AAD values don't affect encryption timing
/// through Tesseract's encrypt_with_aad() path.
fn aes_gcm_aad_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let encryptor = AesGcmEncryptor::new();

    let plaintext = [0x55u8; 64];

    // Fixed AAD
    let fixed_aad = [0u8; 32];

    // Random AAD
    let mut random_aad = [0u8; 32];
    rng.fill_bytes(&mut random_aad);

    runner.run_one(Class::Left, || {
        let _ = encryptor.encrypt_with_aad(&key, &nonce_bytes, &plaintext, &fixed_aad);
    });

    runner.run_one(Class::Right, || {
        let _ = encryptor.encrypt_with_aad(&key, &nonce_bytes, &plaintext, &random_aad);
    });
}

/// Test that key value doesn't leak through encryption timing.
///
/// Different keys should result in identical encryption times when
/// processed through Tesseract's AesGcmEncryptor.
fn aes_gcm_key_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let nonce_bytes = [0x24u8; 12];
    let plaintext = [0x55u8; 64];

    // Fixed key (all zeros - potentially weak, but timing should be same)
    let fixed_key = [0u8; 32];

    // Random key
    let mut random_key = [0u8; 32];
    rng.fill_bytes(&mut random_key);

    let encryptor = AesGcmEncryptor::new();

    runner.run_one(Class::Left, || {
        let _ = encryptor.encrypt(&fixed_key, &nonce_bytes, &plaintext);
    });

    runner.run_one(Class::Right, || {
        let _ = encryptor.encrypt(&random_key, &nonce_bytes, &plaintext);
    });
}

// Register all constant-time benchmarks
ctbench_main!(
    aes_gcm_encrypt_ct,
    aes_gcm_decrypt_ct,
    aes_gcm_tag_position_ct,
    subtle_compare_ct,
    argon2_derive_ct,
    aes_gcm_aad_ct,
    aes_gcm_key_ct
);
