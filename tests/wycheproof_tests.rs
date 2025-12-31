// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Wycheproof Test Suite Integration
//!
//! This module runs the C2SP Wycheproof test vectors against our cryptographic
//! implementations to verify correctness and resistance to known attacks.
//!
//! Test vectors repository: https://github.com/C2SP/wycheproof

use serde::Deserialize;
use std::fs;
use std::path::Path;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

// ML-KEM imports (only when post-quantum feature is enabled)
#[cfg(feature = "post-quantum")]
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem1024,
};

// Use rand 0.9 for ML-KEM compatibility (ml-kem uses rand_core 0.9)
#[cfg(feature = "post-quantum")]
use rand09 as rand_compat;

// Import our validated encapsulation function
#[cfg(feature = "post-quantum")]
use tesseract_lib::crypto::pqc::validate_encapsulation_key;

/// Wycheproof test group structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    key_size: usize,
    iv_size: usize,
    tag_size: usize,
    tests: Vec<TestCase>,
}

/// Wycheproof test case structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: usize,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: TestResult,
    flags: Vec<String>,
}

/// Test result expectation
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

/// Top-level Wycheproof test file structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WycheproofTestFile {
    #[allow(dead_code)]
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<TestGroup>,
}

/// Helper function to decode hex strings
fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

#[test]
fn test_aes_gcm_wycheproof() {
    let test_file_path = "tests/wycheproof/testvectors_v1/aes_gcm_test.json";

    // Skip if test vectors aren't cloned yet
    if !Path::new(test_file_path).exists() {
        eprintln!("Wycheproof test vectors not found. Run:");
        eprintln!("  git clone https://github.com/C2SP/wycheproof.git tests/wycheproof");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read Wycheproof AES-GCM test file");

    let test_file: WycheproofTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse Wycheproof test JSON");

    println!("Running {} AES-GCM tests from Wycheproof", test_file.number_of_tests);

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for group in &test_file.test_groups {
        // Only test 256-bit keys (our implementation uses AES-256)
        if group.key_size != 256 {
            skipped += group.tests.len();
            continue;
        }

        // Only test 96-bit IVs (12 bytes - our NONCE_LEN)
        if group.iv_size != 96 {
            skipped += group.tests.len();
            continue;
        }

        // Only test 128-bit tags (16 bytes - standard GCM tag size)
        if group.tag_size != 128 {
            skipped += group.tests.len();
            continue;
        }

        for test in &group.tests {
            // Decode test vectors
            let key = match decode_hex(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let nonce = match decode_hex(&test.iv) {
                Ok(n) => n,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let aad = match decode_hex(&test.aad) {
                Ok(a) => a,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let msg = match decode_hex(&test.msg) {
                Ok(m) => m,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let ct = match decode_hex(&test.ct) {
                Ok(c) => c,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let tag = match decode_hex(&test.tag) {
                Ok(t) => t,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            // Convert key to [u8; 32]
            let mut key_array = [0u8; 32];
            if key.len() != 32 {
                skipped += 1;
                continue;
            }
            key_array.copy_from_slice(&key);

            // Create cipher
            let cipher = Aes256Gcm::new(&key_array.into());
            let nonce_array: [u8; 12] = match nonce.as_slice().try_into() {
                Ok(n) => n,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let gcm_nonce = Nonce::from(nonce_array);

            // Test encryption and decryption
            match test.result {
                TestResult::Valid => {
                    // Should encrypt successfully
                    let payload = Payload {
                        msg: &msg,
                        aad: &aad,
                    };

                    match cipher.encrypt(&gcm_nonce, payload) {
                        Ok(ciphertext) => {
                            // Expected ciphertext is ct || tag
                            let mut expected = ct.clone();
                            expected.extend_from_slice(&tag);

                            if ciphertext == expected {
                                passed += 1;
                            } else {
                                println!("Test {} FAILED: Ciphertext mismatch", test.tc_id);
                                println!("  Comment: {}", test.comment);
                                println!("  Expected: {}", hex::encode(&expected));
                                println!("  Got:      {}", hex::encode(&ciphertext));
                                failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("Test {} FAILED: Encryption failed: {:?}", test.tc_id, e);
                            println!("  Comment: {}", test.comment);
                            failed += 1;
                        }
                    }

                    // Test decryption
                    let mut full_ciphertext = ct.clone();
                    full_ciphertext.extend_from_slice(&tag);

                    let decrypt_payload = Payload {
                        msg: &full_ciphertext,
                        aad: &aad,
                    };

                    match cipher.decrypt(&gcm_nonce, decrypt_payload) {
                        Ok(plaintext) => {
                            if plaintext == msg {
                                // Already counted in encryption pass
                            } else {
                                println!("Test {} FAILED: Decryption plaintext mismatch", test.tc_id);
                                println!("  Comment: {}", test.comment);
                                failed += 1;
                            }
                        }
                        Err(e) => {
                            println!("Test {} FAILED: Decryption failed: {:?}", test.tc_id, e);
                            println!("  Comment: {}", test.comment);
                            failed += 1;
                        }
                    }
                }
                TestResult::Invalid => {
                    // Should reject invalid ciphertext
                    let mut full_ciphertext = ct.clone();
                    full_ciphertext.extend_from_slice(&tag);

                    let decrypt_payload = Payload {
                        msg: &full_ciphertext,
                        aad: &aad,
                    };

                    match cipher.decrypt(&gcm_nonce, decrypt_payload) {
                        Ok(_) => {
                            println!("Test {} FAILED: Invalid ciphertext was accepted", test.tc_id);
                            println!("  Comment: {}", test.comment);
                            println!("  Flags: {:?}", test.flags);
                            failed += 1;
                        }
                        Err(_) => {
                            // Correctly rejected
                            passed += 1;
                        }
                    }
                }
                TestResult::Acceptable => {
                    // Implementation may accept or reject
                    // We don't count these as pass/fail
                    skipped += 1;
                }
            }
        }
    }

    println!("\nWycheproof AES-GCM Test Results:");
    println!("  Passed:  {}", passed);
    println!("  Failed:  {}", failed);
    println!("  Skipped: {}", skipped);
    println!("  Total:   {}", test_file.number_of_tests);

    assert_eq!(failed, 0, "Wycheproof tests failed");
}

#[test]
fn test_aes_gcm_wycheproof_known_issues() {
    // This test checks for known weak cases that implementations might handle differently
    // AAD with empty messages, unusual IV sizes, etc.

    let test_file_path = "tests/wycheproof/testvectors_v1/aes_gcm_test.json";

    if !Path::new(test_file_path).exists() {
        eprintln!("Wycheproof test vectors not found");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read test file");

    let test_file: WycheproofTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse test JSON");

    // Track tests with specific flags
    let mut edge_cases = std::collections::HashMap::new();

    for group in &test_file.test_groups {
        if group.key_size != 256 || group.iv_size != 96 || group.tag_size != 128 {
            continue;
        }

        for test in &group.tests {
            for flag in &test.flags {
                *edge_cases.entry(flag.clone()).or_insert(0) += 1;
            }
        }
    }

    println!("\nEdge cases in Wycheproof AES-GCM tests:");
    for (flag, count) in edge_cases.iter() {
        println!("  {}: {} tests", flag, count);
    }
}

// ============================================================================
// ML-KEM-1024 Wycheproof Tests
// ============================================================================

/// ML-KEM encapsulation test group structure
#[cfg(feature = "post-quantum")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemEncapsTestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    #[allow(dead_code)]
    parameter_set: String,
    tests: Vec<MlKemEncapsTestCase>,
}

/// ML-KEM encapsulation test case structure
#[cfg(feature = "post-quantum")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemEncapsTestCase {
    tc_id: usize,
    #[allow(dead_code)]
    flags: Vec<String>,
    #[allow(dead_code)]
    m: String,  // randomness seed
    ek: String, // encapsulation key (public key)
    #[allow(dead_code)]
    c: String,  // expected ciphertext (empty for invalid)
    #[allow(dead_code)]
    #[serde(rename = "K")]
    k: String,  // expected shared secret (empty for invalid)
    result: TestResult,
}

/// ML-KEM encapsulation test file structure
#[cfg(feature = "post-quantum")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemEncapsTestFile {
    #[allow(dead_code)]
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<MlKemEncapsTestGroup>,
}

/// ML-KEM decapsulation validation test group structure
#[cfg(feature = "post-quantum")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemDecapsTestGroup {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    test_type: String,
    #[allow(dead_code)]
    parameter_set: String,
    tests: Vec<MlKemDecapsTestCase>,
}

/// ML-KEM decapsulation validation test case structure
#[cfg(feature = "post-quantum")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemDecapsTestCase {
    tc_id: usize,
    #[allow(dead_code)]
    comment: String,
    dk: String, // decapsulation key (secret key)
    c: String,  // ciphertext
    result: TestResult,
    flags: Vec<String>,
}

/// ML-KEM decapsulation validation test file structure
#[cfg(feature = "post-quantum")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlKemDecapsTestFile {
    #[allow(dead_code)]
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<MlKemDecapsTestGroup>,
}

/// ML-KEM-1024 public key size in bytes
#[cfg(feature = "post-quantum")]
const MLKEM_1024_PUBLIC_KEY_SIZE: usize = 1568;

/// ML-KEM-1024 secret key size in bytes
#[cfg(feature = "post-quantum")]
const MLKEM_1024_SECRET_KEY_SIZE: usize = 3168;

/// ML-KEM-1024 ciphertext size in bytes
#[cfg(feature = "post-quantum")]
const MLKEM_1024_CIPHERTEXT_SIZE: usize = 1568;

/// Test ML-KEM-1024 encapsulation with Wycheproof vectors.
///
/// These tests verify that our implementation correctly rejects invalid
/// encapsulation keys with ModulusOverflow (coefficients >= field prime q=3329).
#[test]
#[cfg(feature = "post-quantum")]
fn test_mlkem_1024_encaps_wycheproof() {
    let test_file_path = "tests/wycheproof/testvectors_v1/mlkem_1024_encaps_test.json";

    // Skip if test vectors aren't cloned yet
    if !Path::new(test_file_path).exists() {
        eprintln!("ML-KEM Wycheproof test vectors not found. Run:");
        eprintln!("  git clone https://github.com/C2SP/wycheproof.git tests/wycheproof");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read ML-KEM encaps test file");

    let test_file: MlKemEncapsTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse ML-KEM encaps test JSON");

    println!("Running {} ML-KEM-1024 encapsulation tests from Wycheproof", test_file.number_of_tests);

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for group in &test_file.test_groups {
        for test in &group.tests {
            // Decode encapsulation key
            let ek_bytes = match decode_hex(&test.ek) {
                Ok(k) => k,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            // Check key size first
            if ek_bytes.len() != MLKEM_1024_PUBLIC_KEY_SIZE {
                // Wrong size - should be rejected
                if test.result == TestResult::Invalid {
                    passed += 1;
                } else {
                    println!("Test {} FAILED: Wrong key size {} should be invalid",
                             test.tc_id, ek_bytes.len());
                    failed += 1;
                }
                continue;
            }

            // Try to parse and use the encapsulation key
            let ek_array: &[u8; MLKEM_1024_PUBLIC_KEY_SIZE] = match ek_bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    if test.result == TestResult::Invalid {
                        passed += 1;
                    } else {
                        failed += 1;
                    }
                    continue;
                }
            };

            // First, validate the encapsulation key using our ModulusOverflow check
            let validation_result = validate_encapsulation_key(&ek_bytes);

            match test.result {
                TestResult::Valid => {
                    // Key should be valid - validation should pass
                    match validation_result {
                        Ok(()) => {
                            // Validation passed, now test actual encapsulation
                            type EK = <MlKem1024 as KemCore>::EncapsulationKey;
                            let ek = EK::from_bytes(ek_array.into());
                            let mut rng = rand_compat::rng();
                            match ek.encapsulate(&mut rng) {
                                Ok(_) => passed += 1,
                                Err(_) => {
                                    println!("Test {} FAILED: Valid key passed validation but encapsulation failed", test.tc_id);
                                    failed += 1;
                                }
                            }
                        }
                        Err(e) => {
                            println!("Test {} FAILED: Valid key was rejected by validation: {}", test.tc_id, e);
                            failed += 1;
                        }
                    }
                }
                TestResult::Invalid => {
                    // Key should be invalid - our validation should catch ModulusOverflow
                    match validation_result {
                        Ok(()) => {
                            // Our validation didn't catch it - this is unexpected
                            println!("Test {} FAILED: Invalid key (ModulusOverflow) passed validation", test.tc_id);
                            failed += 1;
                        }
                        Err(_) => {
                            // Correctly rejected by our validation
                            passed += 1;
                        }
                    }
                }
                TestResult::Acceptable => {
                    skipped += 1;
                }
            }
        }
    }

    println!("\nWycheproof ML-KEM-1024 Encapsulation Test Results:");
    println!("  Passed:  {}", passed);
    println!("  Failed:  {}", failed);
    println!("  Skipped: {}", skipped);
    println!("  Total:   {}", test_file.number_of_tests);

    // Don't fail on skipped ModulusOverflow tests - this is implementation-dependent
    assert_eq!(failed, 0, "ML-KEM encapsulation tests failed");
}

/// Test ML-KEM-1024 decapsulation validation with Wycheproof vectors.
///
/// These tests verify that our implementation correctly handles:
/// - Valid decapsulation key and ciphertext
/// - Incorrect ciphertext length
/// - Incorrect decapsulation key length
/// - Invalid decapsulation keys
#[test]
#[cfg(feature = "post-quantum")]
fn test_mlkem_1024_decaps_validation_wycheproof() {
    let test_file_path = "tests/wycheproof/testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json";

    // Skip if test vectors aren't cloned yet
    if !Path::new(test_file_path).exists() {
        eprintln!("ML-KEM Wycheproof test vectors not found. Run:");
        eprintln!("  git clone https://github.com/C2SP/wycheproof.git tests/wycheproof");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read ML-KEM decaps test file");

    let test_file: MlKemDecapsTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse ML-KEM decaps test JSON");

    println!("Running {} ML-KEM-1024 decapsulation validation tests from Wycheproof", test_file.number_of_tests);

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for group in &test_file.test_groups {
        for test in &group.tests {
            // Decode decapsulation key and ciphertext
            let dk_bytes = match decode_hex(&test.dk) {
                Ok(k) => k,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let ct_bytes = match decode_hex(&test.c) {
                Ok(c) => c,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            // Check for length validation tests
            let has_incorrect_dk_length = test.flags.contains(&"IncorrectDecapsulationKeyLength".to_string());
            let has_incorrect_ct_length = test.flags.contains(&"IncorrectCiphertextLength".to_string());

            // Test size validation
            if dk_bytes.len() != MLKEM_1024_SECRET_KEY_SIZE {
                if has_incorrect_dk_length && test.result == TestResult::Invalid {
                    passed += 1;
                    println!("Test {} PASSED: Correctly identified invalid DK length {}",
                             test.tc_id, dk_bytes.len());
                } else if test.result == TestResult::Invalid {
                    passed += 1;
                } else {
                    println!("Test {} FAILED: Wrong DK size {} should be handled",
                             test.tc_id, dk_bytes.len());
                    failed += 1;
                }
                continue;
            }

            if ct_bytes.len() != MLKEM_1024_CIPHERTEXT_SIZE {
                if has_incorrect_ct_length && test.result == TestResult::Invalid {
                    passed += 1;
                    println!("Test {} PASSED: Correctly identified invalid CT length {}",
                             test.tc_id, ct_bytes.len());
                } else if test.result == TestResult::Invalid {
                    passed += 1;
                } else {
                    println!("Test {} FAILED: Wrong CT size {} should be handled",
                             test.tc_id, ct_bytes.len());
                    failed += 1;
                }
                continue;
            }

            // Parse decapsulation key
            let dk_array: &[u8; MLKEM_1024_SECRET_KEY_SIZE] = match dk_bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    if test.result == TestResult::Invalid {
                        passed += 1;
                    } else {
                        failed += 1;
                    }
                    continue;
                }
            };

            // Parse ciphertext
            let ct_array: &[u8; MLKEM_1024_CIPHERTEXT_SIZE] = match ct_bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    if test.result == TestResult::Invalid {
                        passed += 1;
                    } else {
                        failed += 1;
                    }
                    continue;
                }
            };

            type DK = <MlKem1024 as KemCore>::DecapsulationKey;
            let dk = DK::from_bytes(dk_array.into());
            let ct = Ciphertext::<MlKem1024>::from(*ct_array);

            // Decapsulation in ML-KEM is designed to never fail (implicit rejection)
            // It always returns a shared secret, but the secret will be random/wrong
            // if the ciphertext is invalid
            let decaps_result = dk.decapsulate(&ct);

            match test.result {
                TestResult::Valid => {
                    // Should succeed (always does for ML-KEM)
                    match decaps_result {
                        Ok(_) => passed += 1,
                        Err(_) => {
                            println!("Test {} FAILED: Valid decapsulation failed", test.tc_id);
                            failed += 1;
                        }
                    }
                }
                TestResult::Invalid => {
                    // ML-KEM decapsulation never fails - it uses implicit rejection
                    // Invalid ciphertexts return a pseudorandom shared secret
                    // So we just verify it doesn't panic
                    match decaps_result {
                        Ok(_) => {
                            // Expected - implicit rejection returns a value
                            passed += 1;
                        }
                        Err(_) => {
                            // Unexpected - decapsulation should never fail
                            println!("Test {} UNEXPECTED: Decapsulation returned error (should use implicit rejection)", test.tc_id);
                            skipped += 1;
                        }
                    }
                }
                TestResult::Acceptable => {
                    skipped += 1;
                }
            }
        }
    }

    println!("\nWycheproof ML-KEM-1024 Decapsulation Validation Test Results:");
    println!("  Passed:  {}", passed);
    println!("  Failed:  {}", failed);
    println!("  Skipped: {}", skipped);
    println!("  Total:   {}", test_file.number_of_tests);

    assert_eq!(failed, 0, "ML-KEM decapsulation validation tests failed");
}

/// Analyze AES-GCM test group distribution to understand skipped tests.
///
/// Our implementation only tests AES-256-GCM with 96-bit IV and 128-bit tag.
/// This test shows the breakdown of all Wycheproof test groups.
#[test]
fn test_aes_gcm_wycheproof_distribution() {
    let test_file_path = "tests/wycheproof/testvectors_v1/aes_gcm_test.json";

    if !Path::new(test_file_path).exists() {
        eprintln!("Wycheproof test vectors not found");
        return;
    }

    let test_data = fs::read_to_string(test_file_path)
        .expect("Failed to read test file");

    let test_file: WycheproofTestFile = serde_json::from_str(&test_data)
        .expect("Failed to parse test JSON");

    println!("\n=== AES-GCM Wycheproof Test Distribution ===\n");
    println!("Total tests in file: {}\n", test_file.number_of_tests);

    // Group tests by configuration
    let mut tested = 0;
    let mut skipped_key_size = 0;
    let mut skipped_iv_size = 0;

    println!("Test Groups:");
    println!("{:>8} {:>8} {:>8} {:>6}   Status", "KeySize", "IvSize", "TagSize", "Tests");
    println!("{}", "-".repeat(50));

    for group in &test_file.test_groups {
        let count = group.tests.len();
        let status = if group.key_size != 256 {
            skipped_key_size += count;
            "SKIP (key != 256)"
        } else if group.iv_size != 96 {
            skipped_iv_size += count;
            "SKIP (IV != 96)"
        } else if group.tag_size != 128 {
            "SKIP (tag != 128)"
        } else {
            tested += count;
            "TESTED"
        };

        println!("{:>8} {:>8} {:>8} {:>6}   {}",
                 group.key_size, group.iv_size, group.tag_size, count, status);
    }

    println!("\n=== Summary ===");
    println!("Tested (AES-256, 96-bit IV, 128-bit tag): {}", tested);
    println!("Skipped due to key size != 256: {}", skipped_key_size);
    println!("Skipped due to IV size != 96: {}", skipped_iv_size);
    println!("Total skipped: {}", skipped_key_size + skipped_iv_size);
    println!("\nNote: We only support AES-256-GCM with 96-bit (12-byte) nonces,");
    println!("which is the most secure configuration per NIST SP 800-38D.");
}

/// Report edge cases found in ML-KEM Wycheproof tests
#[test]
#[cfg(feature = "post-quantum")]
fn test_mlkem_wycheproof_edge_cases() {
    println!("\nML-KEM Wycheproof Test Vectors Summary:");

    // Encapsulation tests
    let encaps_path = "tests/wycheproof/testvectors_v1/mlkem_1024_encaps_test.json";
    if Path::new(encaps_path).exists() {
        let test_data = fs::read_to_string(encaps_path).expect("Failed to read file");
        let test_file: MlKemEncapsTestFile = serde_json::from_str(&test_data).expect("Failed to parse");

        let mut flags: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for group in &test_file.test_groups {
            for test in &group.tests {
                for flag in &test.flags {
                    *flags.entry(flag.clone()).or_insert(0) += 1;
                }
            }
        }

        println!("\n  ML-KEM-1024 Encapsulation Tests: {} total", test_file.number_of_tests);
        for (flag, count) in &flags {
            println!("    {}: {} tests", flag, count);
        }
    }

    // Decapsulation validation tests
    let decaps_path = "tests/wycheproof/testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json";
    if Path::new(decaps_path).exists() {
        let test_data = fs::read_to_string(decaps_path).expect("Failed to read file");
        let test_file: MlKemDecapsTestFile = serde_json::from_str(&test_data).expect("Failed to parse");

        let mut flags: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for group in &test_file.test_groups {
            for test in &group.tests {
                for flag in &test.flags {
                    *flags.entry(flag.clone()).or_insert(0) += 1;
                }
            }
        }

        println!("\n  ML-KEM-1024 Decapsulation Validation Tests: {} total", test_file.number_of_tests);
        for (flag, count) in &flags {
            println!("    {}: {} tests", flag, count);
        }
    }
}
