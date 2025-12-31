//! NIST CAVP (Cryptographic Algorithm Validation Program) Test Suite
//!
//! This module runs the official NIST CAVP test vectors against our AES-256-GCM
//! implementation to verify correctness according to the government standard.
//!
//! Test vectors source: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program
//! Download: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use std::fs;
use std::path::Path;

/// NIST CAVP test section parameters
#[derive(Debug, Default, Clone)]
struct CavpSection {
    keylen: usize,   // in bits
    ivlen: usize,    // in bits
    ptlen: usize,    // in bits
    aadlen: usize,   // in bits
    taglen: usize,   // in bits
}

/// NIST CAVP encrypt test case
#[derive(Debug, Clone)]
struct CavpEncryptTest {
    count: usize,
    key: Vec<u8>,
    iv: Vec<u8>,
    pt: Vec<u8>,
    aad: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
}

/// NIST CAVP decrypt test case
#[derive(Debug, Clone)]
struct CavpDecryptTest {
    count: usize,
    key: Vec<u8>,
    iv: Vec<u8>,
    ct: Vec<u8>,
    aad: Vec<u8>,
    tag: Vec<u8>,
    pt: Option<Vec<u8>>,  // None means FAIL (invalid tag)
}

/// Parse a NIST CAVP .rsp file for encrypt tests
fn parse_cavp_encrypt_file(content: &str) -> Vec<(CavpSection, Vec<CavpEncryptTest>)> {
    let mut results = Vec::new();
    let mut current_section = CavpSection::default();
    let mut current_tests = Vec::new();
    let mut current_test: Option<CavpEncryptTest> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Parse section headers
        if line.starts_with('[') && line.ends_with(']') {
            // Add current test before saving (if any)
            if let Some(test) = current_test.take() {
                current_tests.push(test);
            }

            // If we have tests, save them before starting new section
            if !current_tests.is_empty() {
                results.push((current_section.clone(), current_tests));
                current_tests = Vec::new();
            }

            let inner = &line[1..line.len()-1];
            let parts: Vec<&str> = inner.split('=').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let value: usize = parts[1].parse().unwrap_or(0);
                match parts[0] {
                    "Keylen" => current_section.keylen = value,
                    "IVlen" => current_section.ivlen = value,
                    "PTlen" => current_section.ptlen = value,
                    "AADlen" => current_section.aadlen = value,
                    "Taglen" => current_section.taglen = value,
                    _ => {}
                }
            }
            continue;
        }

        // Parse test case fields
        let parts: Vec<&str> = line.splitn(2, '=').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0];
        let value = parts[1];

        match key {
            "Count" => {
                // Save previous test if exists
                if let Some(test) = current_test.take() {
                    current_tests.push(test);
                }
                current_test = Some(CavpEncryptTest {
                    count: value.parse().unwrap_or(0),
                    key: Vec::new(),
                    iv: Vec::new(),
                    pt: Vec::new(),
                    aad: Vec::new(),
                    ct: Vec::new(),
                    tag: Vec::new(),
                });
            }
            "Key" => {
                if let Some(ref mut test) = current_test {
                    test.key = hex::decode(value).unwrap_or_default();
                }
            }
            "IV" => {
                if let Some(ref mut test) = current_test {
                    test.iv = hex::decode(value).unwrap_or_default();
                }
            }
            "PT" => {
                if let Some(ref mut test) = current_test {
                    test.pt = hex::decode(value).unwrap_or_default();
                }
            }
            "AAD" => {
                if let Some(ref mut test) = current_test {
                    test.aad = hex::decode(value).unwrap_or_default();
                }
            }
            "CT" => {
                if let Some(ref mut test) = current_test {
                    test.ct = hex::decode(value).unwrap_or_default();
                }
            }
            "Tag" => {
                if let Some(ref mut test) = current_test {
                    test.tag = hex::decode(value).unwrap_or_default();
                }
            }
            _ => {}
        }
    }

    // Don't forget the last test
    if let Some(test) = current_test {
        current_tests.push(test);
    }
    if !current_tests.is_empty() {
        results.push((current_section, current_tests));
    }

    results
}

/// Parse a NIST CAVP .rsp file for decrypt tests
fn parse_cavp_decrypt_file(content: &str) -> Vec<(CavpSection, Vec<CavpDecryptTest>)> {
    let mut results = Vec::new();
    let mut current_section = CavpSection::default();
    let mut current_tests = Vec::new();
    let mut current_test: Option<CavpDecryptTest> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') {
            continue;
        }

        // Check for FAIL
        if line == "FAIL" {
            if let Some(ref mut test) = current_test {
                test.pt = None;
            }
            continue;
        }

        if line.is_empty() {
            continue;
        }

        // Parse section headers
        if line.starts_with('[') && line.ends_with(']') {
            // Add current test before saving (if any)
            if let Some(test) = current_test.take() {
                current_tests.push(test);
            }

            // If we have tests, save them before starting new section
            if !current_tests.is_empty() {
                results.push((current_section.clone(), current_tests));
                current_tests = Vec::new();
            }

            let inner = &line[1..line.len()-1];
            let parts: Vec<&str> = inner.split('=').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let value: usize = parts[1].parse().unwrap_or(0);
                match parts[0] {
                    "Keylen" => current_section.keylen = value,
                    "IVlen" => current_section.ivlen = value,
                    "PTlen" => current_section.ptlen = value,
                    "AADlen" => current_section.aadlen = value,
                    "Taglen" => current_section.taglen = value,
                    _ => {}
                }
            }
            continue;
        }

        // Parse test case fields
        let parts: Vec<&str> = line.splitn(2, '=').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0];
        let value = parts[1];

        match key {
            "Count" => {
                // Save previous test if exists
                if let Some(test) = current_test.take() {
                    current_tests.push(test);
                }
                current_test = Some(CavpDecryptTest {
                    count: value.parse().unwrap_or(0),
                    key: Vec::new(),
                    iv: Vec::new(),
                    ct: Vec::new(),
                    aad: Vec::new(),
                    tag: Vec::new(),
                    pt: None,
                });
            }
            "Key" => {
                if let Some(ref mut test) = current_test {
                    test.key = hex::decode(value).unwrap_or_default();
                }
            }
            "IV" => {
                if let Some(ref mut test) = current_test {
                    test.iv = hex::decode(value).unwrap_or_default();
                }
            }
            "CT" => {
                if let Some(ref mut test) = current_test {
                    test.ct = hex::decode(value).unwrap_or_default();
                }
            }
            "AAD" => {
                if let Some(ref mut test) = current_test {
                    test.aad = hex::decode(value).unwrap_or_default();
                }
            }
            "Tag" => {
                if let Some(ref mut test) = current_test {
                    test.tag = hex::decode(value).unwrap_or_default();
                }
            }
            "PT" => {
                if let Some(ref mut test) = current_test {
                    test.pt = Some(hex::decode(value).unwrap_or_default());
                }
            }
            _ => {}
        }
    }

    // Don't forget the last test
    if let Some(test) = current_test {
        current_tests.push(test);
    }
    if !current_tests.is_empty() {
        results.push((current_section, current_tests));
    }

    results
}

#[test]
fn test_nist_cavp_aes_gcm_encrypt_256() {
    let test_file_path = "tests/nist_cavp/gcmEncryptExtIV256.rsp";

    // Skip if test vectors aren't downloaded yet
    if !Path::new(test_file_path).exists() {
        eprintln!("NIST CAVP test vectors not found. Run:");
        eprintln!("  curl -o tests/nist_cavp/gcmtestvectors.zip https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip");
        eprintln!("  unzip tests/nist_cavp/gcmtestvectors.zip -d tests/nist_cavp/");
        return;
    }

    let content = fs::read_to_string(test_file_path)
        .expect("Failed to read NIST CAVP encrypt test file");

    let sections = parse_cavp_encrypt_file(&content);

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;

    for (section, tests) in &sections {
        // We only support:
        // - 256-bit keys
        // - 96-bit IVs
        // - 128-bit tags
        if section.keylen != 256 || section.ivlen != 96 || section.taglen != 128 {
            skipped_tests += tests.len();
            continue;
        }

        for test in tests {
            total_tests += 1;

            // Create cipher
            let cipher = Aes256Gcm::new_from_slice(&test.key)
                .expect("Failed to create cipher");

            // Create nonce
            let nonce = Nonce::from_slice(&test.iv);

            // Encrypt
            let result = if test.aad.is_empty() {
                cipher.encrypt(nonce, test.pt.as_slice())
            } else {
                cipher.encrypt(nonce, Payload {
                    msg: &test.pt,
                    aad: &test.aad,
                })
            };

            match result {
                Ok(ciphertext_with_tag) => {
                    // NIST CAVP separates CT and Tag
                    let expected_len = test.ct.len() + test.tag.len();
                    assert_eq!(
                        ciphertext_with_tag.len(), expected_len,
                        "Test {} (PTlen={}, AADlen={}): Output length mismatch",
                        test.count, section.ptlen, section.aadlen
                    );

                    let (ct, tag) = ciphertext_with_tag.split_at(test.ct.len());

                    assert_eq!(
                        ct, test.ct.as_slice(),
                        "Test {} (PTlen={}, AADlen={}): Ciphertext mismatch",
                        test.count, section.ptlen, section.aadlen
                    );

                    assert_eq!(
                        tag, test.tag.as_slice(),
                        "Test {} (PTlen={}, AADlen={}): Tag mismatch",
                        test.count, section.ptlen, section.aadlen
                    );

                    passed_tests += 1;
                }
                Err(e) => {
                    panic!(
                        "Test {} (PTlen={}, AADlen={}): Encryption failed: {:?}",
                        test.count, section.ptlen, section.aadlen, e
                    );
                }
            }
        }
    }

    println!("\nNIST CAVP AES-256-GCM Encrypt Results:");
    println!("  Passed: {}", passed_tests);
    println!("  Skipped (non-256/96/128): {}", skipped_tests);
    println!("  Total processed: {}", total_tests);

    assert!(passed_tests > 0, "No NIST CAVP encrypt tests passed!");
}

#[test]
fn test_nist_cavp_aes_gcm_decrypt_256() {
    let test_file_path = "tests/nist_cavp/gcmDecrypt256.rsp";

    // Skip if test vectors aren't downloaded yet
    if !Path::new(test_file_path).exists() {
        eprintln!("NIST CAVP test vectors not found.");
        return;
    }

    let content = fs::read_to_string(test_file_path)
        .expect("Failed to read NIST CAVP decrypt test file");

    let sections = parse_cavp_decrypt_file(&content);

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut skipped_tests = 0;
    let mut valid_tests = 0;
    let mut invalid_tests = 0;

    for (section, tests) in &sections {
        // We only support:
        // - 256-bit keys
        // - 96-bit IVs
        // - 128-bit tags
        if section.keylen != 256 || section.ivlen != 96 || section.taglen != 128 {
            skipped_tests += tests.len();
            continue;
        }

        for test in tests {
            total_tests += 1;

            // Create cipher
            let cipher = Aes256Gcm::new_from_slice(&test.key)
                .expect("Failed to create cipher");

            // Create nonce
            let nonce = Nonce::from_slice(&test.iv);

            // Combine CT and Tag for decryption
            let mut ciphertext_with_tag = test.ct.clone();
            ciphertext_with_tag.extend_from_slice(&test.tag);

            // Decrypt
            let result = if test.aad.is_empty() {
                cipher.decrypt(nonce, ciphertext_with_tag.as_slice())
            } else {
                cipher.decrypt(nonce, Payload {
                    msg: &ciphertext_with_tag,
                    aad: &test.aad,
                })
            };

            match (&test.pt, result) {
                // Expected valid, got valid
                (Some(expected_pt), Ok(plaintext)) => {
                    assert_eq!(
                        plaintext, *expected_pt,
                        "Test {} (PTlen={}, AADlen={}): Plaintext mismatch",
                        test.count, section.ptlen, section.aadlen
                    );
                    passed_tests += 1;
                    valid_tests += 1;
                }
                // Expected FAIL (invalid tag), got error
                (None, Err(_)) => {
                    passed_tests += 1;
                    invalid_tests += 1;
                }
                // Expected valid, got error
                (Some(_), Err(e)) => {
                    panic!(
                        "Test {} (PTlen={}, AADlen={}): Expected valid decryption but got error: {:?}",
                        test.count, section.ptlen, section.aadlen, e
                    );
                }
                // Expected FAIL, but decryption succeeded
                (None, Ok(plaintext)) => {
                    panic!(
                        "Test {} (PTlen={}, AADlen={}): Expected FAIL but decryption succeeded with {} bytes",
                        test.count, section.ptlen, section.aadlen, plaintext.len()
                    );
                }
            }
        }
    }

    println!("\nNIST CAVP AES-256-GCM Decrypt Results:");
    println!("  Passed: {} (valid: {}, rejected invalid: {})", passed_tests, valid_tests, invalid_tests);
    println!("  Skipped (non-256/96/128): {}", skipped_tests);
    println!("  Total processed: {}", total_tests);

    assert!(passed_tests > 0, "No NIST CAVP decrypt tests passed!");
    assert!(invalid_tests > 0, "No invalid tag rejection tests found!");
}

/// Test showing the distribution of NIST CAVP test vectors
#[test]
fn test_nist_cavp_distribution() {
    let encrypt_path = "tests/nist_cavp/gcmEncryptExtIV256.rsp";
    let decrypt_path = "tests/nist_cavp/gcmDecrypt256.rsp";

    if !Path::new(encrypt_path).exists() {
        eprintln!("NIST CAVP test vectors not found.");
        return;
    }

    let encrypt_content = fs::read_to_string(encrypt_path).expect("read encrypt file");
    let decrypt_content = fs::read_to_string(decrypt_path).expect("read decrypt file");

    let encrypt_sections = parse_cavp_encrypt_file(&encrypt_content);
    let decrypt_sections = parse_cavp_decrypt_file(&decrypt_content);

    println!("\nNIST CAVP AES-256-GCM Test Vector Distribution:");
    println!("================================================");

    println!("\nEncrypt tests by configuration:");
    let mut encrypt_total = 0;
    let mut encrypt_supported = 0;
    for (section, tests) in &encrypt_sections {
        let count = tests.len();
        encrypt_total += count;
        let supported = section.keylen == 256 && section.ivlen == 96 && section.taglen == 128;
        if supported {
            encrypt_supported += count;
        }
        println!(
            "  Keylen={}, IVlen={}, PTlen={}, AADlen={}, Taglen={}: {} tests {}",
            section.keylen, section.ivlen, section.ptlen, section.aadlen, section.taglen,
            count,
            if supported { "(SUPPORTED)" } else { "(skipped)" }
        );
    }

    println!("\nDecrypt tests by configuration:");
    let mut decrypt_total = 0;
    let mut decrypt_supported = 0;
    let mut decrypt_fail_count = 0;
    for (section, tests) in &decrypt_sections {
        let count = tests.len();
        let fail_count = tests.iter().filter(|t| t.pt.is_none()).count();
        decrypt_total += count;
        let supported = section.keylen == 256 && section.ivlen == 96 && section.taglen == 128;
        if supported {
            decrypt_supported += count;
            decrypt_fail_count += fail_count;
        }
        println!(
            "  Keylen={}, IVlen={}, PTlen={}, AADlen={}, Taglen={}: {} tests ({} FAIL) {}",
            section.keylen, section.ivlen, section.ptlen, section.aadlen, section.taglen,
            count, fail_count,
            if supported { "(SUPPORTED)" } else { "(skipped)" }
        );
    }

    println!("\nSummary:");
    println!("  Encrypt: {} supported out of {} total", encrypt_supported, encrypt_total);
    println!("  Decrypt: {} supported out of {} total ({} invalid tag tests)",
             decrypt_supported, decrypt_total, decrypt_fail_count);
}
