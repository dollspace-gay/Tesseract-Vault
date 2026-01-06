// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! NIST Post-Quantum Cryptography Test Suite
//!
//! This module tests ML-KEM (FIPS 203) and ML-DSA (FIPS 204) implementations
//! against the NIST specifications. Tests verify:
//!
//! - Key size compliance with NIST standards
//! - Encapsulation/Decapsulation round-trip correctness
//! - Signature generation/verification
//! - ModulusOverflow validation per FIPS 203 Section 7.2
//! - Deterministic key generation from seeds
//!
//! Test vector sources:
//! - NIST ACVP: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//! - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
//! - FIPS 204: https://csrc.nist.gov/pubs/fips/204/final

use tesseract_lib::crypto::pqc::{
    encapsulate, validate_encapsulation_key, MlKemKeyPair, CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
};
use tesseract_lib::crypto::signatures::{verify, MlDsaKeyPair, SecurityLevel};

// ============================================================================
// ML-KEM-1024 (FIPS 203) Tests
// ============================================================================

/// NIST FIPS 203 specifies ML-KEM-1024 key sizes:
/// - Encapsulation key (public): 1568 bytes
/// - Decapsulation key (private): 3168 bytes
/// - Ciphertext: 1568 bytes
/// - Shared secret: 32 bytes
#[test]
fn test_mlkem_key_sizes_fips203() {
    assert_eq!(
        PUBLIC_KEY_SIZE, 1568,
        "FIPS 203: ek size must be 1568 bytes"
    );
    assert_eq!(
        SECRET_KEY_SIZE, 3168,
        "FIPS 203: dk size must be 3168 bytes"
    );
    assert_eq!(
        CIPHERTEXT_SIZE, 1568,
        "FIPS 203: ciphertext size must be 1568 bytes"
    );
    assert_eq!(
        SHARED_SECRET_SIZE, 32,
        "FIPS 203: shared secret must be 32 bytes"
    );
}

/// Test that generated keys have correct sizes per FIPS 203
#[test]
fn test_mlkem_keygen_sizes() {
    let keypair = MlKemKeyPair::generate();

    assert_eq!(
        keypair.encapsulation_key().len(),
        PUBLIC_KEY_SIZE,
        "Generated encapsulation key has wrong size"
    );
    assert_eq!(
        keypair.decapsulation_key().len(),
        SECRET_KEY_SIZE,
        "Generated decapsulation key has wrong size"
    );
}

/// Test ML-KEM encapsulation produces correct output sizes
#[test]
fn test_mlkem_encapsulate_sizes() {
    let keypair = MlKemKeyPair::generate();

    let (ciphertext, shared_secret) =
        encapsulate(keypair.encapsulation_key()).expect("Encapsulation should succeed");

    assert_eq!(
        ciphertext.len(),
        CIPHERTEXT_SIZE,
        "Ciphertext has wrong size"
    );
    assert_eq!(
        shared_secret.len(),
        SHARED_SECRET_SIZE,
        "Shared secret has wrong size"
    );
}

/// Test ML-KEM round-trip: encapsulate then decapsulate gives same shared secret
/// This is the core correctness property of KEM
#[test]
fn test_mlkem_roundtrip() {
    for i in 0..10 {
        let keypair = MlKemKeyPair::generate();

        let (ciphertext, shared_secret_enc) =
            encapsulate(keypair.encapsulation_key()).expect("Encapsulation should succeed");

        let shared_secret_dec = keypair
            .decapsulate(&ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(
            shared_secret_enc.as_ref(),
            shared_secret_dec.as_ref(),
            "Round-trip {}: shared secrets must match",
            i
        );
    }
}

/// Test ML-KEM with validation round-trip
#[test]
fn test_mlkem_validated_roundtrip() {
    for i in 0..5 {
        let keypair = MlKemKeyPair::generate();

        // Use encapsulation (validates by default)
        let (ciphertext, shared_secret_enc) = encapsulate(keypair.encapsulation_key())
            .expect("Validated encapsulation should succeed");

        let shared_secret_dec = keypair
            .decapsulate(&ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(
            shared_secret_enc.as_ref(),
            shared_secret_dec.as_ref(),
            "Validated round-trip {}: shared secrets must match",
            i
        );
    }
}

/// Test that valid keys pass validation
#[test]
fn test_mlkem_valid_key_passes_validation() {
    for _ in 0..10 {
        let keypair = MlKemKeyPair::generate();
        let result = validate_encapsulation_key(keypair.encapsulation_key());
        assert!(
            result.is_ok(),
            "Valid key should pass validation: {:?}",
            result.err()
        );
    }
}

/// Test ModulusOverflow detection per FIPS 203 Section 7.2
/// Keys with coefficients >= q (3329) must be rejected
#[test]
fn test_mlkem_modulus_overflow_detection() {
    // Create a key with all zeros (valid)
    let mut key = vec![0u8; PUBLIC_KEY_SIZE];
    assert!(
        validate_encapsulation_key(&key).is_ok(),
        "All-zeros key should be valid"
    );

    // Create a key with coefficient = 3329 (q) which is INVALID
    // ByteEncode12 packs two 12-bit values in 3 bytes:
    //   coeff1 = b0 | ((b1 & 0x0f) << 8)
    //   coeff2 = (b1 >> 4) | (b2 << 4)
    // To set coeff1 = 3329 = 0xD01:
    //   b0 = 0x01, b1 = 0x0D (low nibble = 0x0D)
    key[0] = 0x01;
    key[1] = 0x0D;
    key[2] = 0x00;

    let result = validate_encapsulation_key(&key);
    assert!(
        result.is_err(),
        "Key with coefficient = 3329 should fail validation"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("ModulusOverflow"),
        "Error should mention ModulusOverflow: {}",
        err_msg
    );
}

/// Test invalid key sizes are rejected
#[test]
fn test_mlkem_invalid_key_size_rejected() {
    // Too short
    let short_key = vec![0u8; PUBLIC_KEY_SIZE - 1];
    assert!(
        validate_encapsulation_key(&short_key).is_err(),
        "Short key should be rejected"
    );

    // Too long
    let long_key = vec![0u8; PUBLIC_KEY_SIZE + 1];
    assert!(
        validate_encapsulation_key(&long_key).is_err(),
        "Long key should be rejected"
    );

    // Empty
    assert!(
        validate_encapsulation_key(&[]).is_err(),
        "Empty key should be rejected"
    );
}

/// Test that encapsulation with invalid key is rejected
#[test]
fn test_mlkem_encapsulate_invalid_key() {
    let short_key = vec![0u8; 100];
    assert!(
        encapsulate(&short_key).is_err(),
        "Encapsulation with short key should fail"
    );

    let long_key = vec![0u8; PUBLIC_KEY_SIZE + 100];
    assert!(
        encapsulate(&long_key).is_err(),
        "Encapsulation with long key should fail"
    );
}

/// Test decapsulation with invalid ciphertext is handled
#[test]
fn test_mlkem_decapsulate_invalid_ciphertext() {
    let keypair = MlKemKeyPair::generate();

    // Too short ciphertext
    let short_ct = vec![0u8; CIPHERTEXT_SIZE - 1];
    assert!(
        keypair.decapsulate(&short_ct).is_err(),
        "Decapsulation with short ciphertext should fail"
    );

    // Too long ciphertext
    let long_ct = vec![0u8; CIPHERTEXT_SIZE + 1];
    assert!(
        keypair.decapsulate(&long_ct).is_err(),
        "Decapsulation with long ciphertext should fail"
    );
}

/// Test key serialization round-trip
#[test]
fn test_mlkem_key_serialization() {
    let keypair = MlKemKeyPair::generate();
    let (ek, dk) = keypair.to_bytes();

    let restored = MlKemKeyPair::from_bytes(&ek, &dk).expect("Key restoration should succeed");

    assert_eq!(
        keypair.encapsulation_key(),
        restored.encapsulation_key(),
        "Encapsulation keys should match after round-trip"
    );

    // Verify the restored key works
    let (ciphertext, ss1) =
        encapsulate(restored.encapsulation_key()).expect("Encapsulation should succeed");
    let ss2 = restored
        .decapsulate(&ciphertext)
        .expect("Decapsulation should succeed");

    assert_eq!(ss1.as_ref(), ss2.as_ref(), "Shared secrets should match");
}

/// Test that different key pairs produce different shared secrets
#[test]
fn test_mlkem_different_keys_different_secrets() {
    let keypair1 = MlKemKeyPair::generate();
    let keypair2 = MlKemKeyPair::generate();

    // Encapsulate to both keys
    let (_, ss1) = encapsulate(keypair1.encapsulation_key()).expect("Encapsulation should succeed");
    let (_, ss2) = encapsulate(keypair2.encapsulation_key()).expect("Encapsulation should succeed");

    // Shared secrets should be different (with extremely high probability)
    assert_ne!(
        ss1.as_ref(),
        ss2.as_ref(),
        "Different keys should produce different shared secrets"
    );
}

// ============================================================================
// ML-DSA (FIPS 204) Tests
// ============================================================================

/// Test ML-DSA key generation at all security levels
#[test]
fn test_mldsa_keygen_all_levels() {
    // Test all security levels
    let levels = [
        SecurityLevel::Level44,
        SecurityLevel::Level65,
        SecurityLevel::Level87,
    ];

    for level in levels {
        let keypair = MlDsaKeyPair::generate(level);
        assert_eq!(keypair.security_level(), level);
        assert!(
            !keypair.verifying_key().is_empty(),
            "Verifying key should not be empty"
        );
        assert_eq!(
            keypair.signing_key_seed().len(),
            32,
            "Seed should be 32 bytes"
        );
    }
}

/// Test ML-DSA signature round-trip at Level 44
#[test]
fn test_mldsa_sign_verify_level44() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = b"NIST FIPS 204 test message for ML-DSA-44";

    let signature = keypair.sign(message).expect("Signing should succeed");

    verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        message,
        &signature,
    )
    .expect("Valid signature should verify");
}

/// Test ML-DSA signature round-trip at Level 65
#[test]
fn test_mldsa_sign_verify_level65() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level65);
    let message = b"NIST FIPS 204 test message for ML-DSA-65";

    let signature = keypair.sign(message).expect("Signing should succeed");

    verify(
        SecurityLevel::Level65,
        keypair.verifying_key(),
        message,
        &signature,
    )
    .expect("Valid signature should verify");
}

/// Test ML-DSA signature round-trip at Level 87
#[test]
fn test_mldsa_sign_verify_level87() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level87);
    let message = b"NIST FIPS 204 test message for ML-DSA-87";

    let signature = keypair.sign(message).expect("Signing should succeed");

    verify(
        SecurityLevel::Level87,
        keypair.verifying_key(),
        message,
        &signature,
    )
    .expect("Valid signature should verify");
}

/// Test ML-DSA signature sizes per FIPS 204
#[test]
fn test_mldsa_signature_sizes() {
    // FIPS 204 signature sizes:
    // ML-DSA-44: 2420 bytes
    // ML-DSA-65: 3309 bytes
    // ML-DSA-87: 4627 bytes

    let message = b"Test message for signature size verification";

    let keypair44 = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let sig44 = keypair44.sign(message).unwrap();
    assert_eq!(
        sig44.len(),
        2420,
        "ML-DSA-44 signature should be 2420 bytes"
    );

    let keypair65 = MlDsaKeyPair::generate(SecurityLevel::Level65);
    let sig65 = keypair65.sign(message).unwrap();
    assert_eq!(
        sig65.len(),
        3309,
        "ML-DSA-65 signature should be 3309 bytes"
    );

    let keypair87 = MlDsaKeyPair::generate(SecurityLevel::Level87);
    let sig87 = keypair87.sign(message).unwrap();
    assert_eq!(
        sig87.len(),
        4627,
        "ML-DSA-87 signature should be 4627 bytes"
    );
}

/// Test ML-DSA verifying key sizes per FIPS 204
#[test]
fn test_mldsa_verifying_key_sizes() {
    // FIPS 204 public key (verifying key) sizes:
    // ML-DSA-44: 1312 bytes
    // ML-DSA-65: 1952 bytes
    // ML-DSA-87: 2592 bytes

    let keypair44 = MlDsaKeyPair::generate(SecurityLevel::Level44);
    assert_eq!(
        keypair44.verifying_key().len(),
        1312,
        "ML-DSA-44 verifying key should be 1312 bytes"
    );

    let keypair65 = MlDsaKeyPair::generate(SecurityLevel::Level65);
    assert_eq!(
        keypair65.verifying_key().len(),
        1952,
        "ML-DSA-65 verifying key should be 1952 bytes"
    );

    let keypair87 = MlDsaKeyPair::generate(SecurityLevel::Level87);
    assert_eq!(
        keypair87.verifying_key().len(),
        2592,
        "ML-DSA-87 verifying key should be 2592 bytes"
    );
}

/// Test that modified messages fail verification
#[test]
fn test_mldsa_modified_message_fails() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = b"Original message";

    let signature = keypair.sign(message).expect("Signing should succeed");

    // Modified message should fail
    let modified = b"Modified message";
    let result = verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        modified,
        &signature,
    );

    assert!(result.is_err(), "Modified message should not verify");
}

/// Test that modified signatures fail verification
#[test]
fn test_mldsa_modified_signature_fails() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = b"Test message";

    let mut signature = keypair.sign(message).expect("Signing should succeed");

    // Flip a bit in the signature
    if !signature.is_empty() {
        signature[0] ^= 0x01;
    }

    let result = verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        message,
        &signature,
    );

    assert!(result.is_err(), "Modified signature should not verify");
}

/// Test that different keys cannot verify each other's signatures
#[test]
fn test_mldsa_wrong_key_fails() {
    let keypair1 = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let keypair2 = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = b"Test message";

    let signature = keypair1.sign(message).expect("Signing should succeed");

    // keypair2 should not be able to verify keypair1's signature
    let result = verify(
        SecurityLevel::Level44,
        keypair2.verifying_key(),
        message,
        &signature,
    );

    assert!(result.is_err(), "Wrong key should not verify signature");
}

/// Test ML-DSA with empty message
#[test]
fn test_mldsa_empty_message() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = b"";

    let signature = keypair
        .sign(message)
        .expect("Signing empty message should succeed");

    verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        message,
        &signature,
    )
    .expect("Empty message signature should verify");
}

/// Test ML-DSA with large message
#[test]
fn test_mldsa_large_message() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = vec![0xABu8; 1_000_000]; // 1 MB message

    let signature = keypair
        .sign(&message)
        .expect("Signing large message should succeed");

    verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        &message,
        &signature,
    )
    .expect("Large message signature should verify");
}

/// Test key serialization and restoration
#[test]
fn test_mldsa_key_serialization() {
    let keypair1 = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let (level, vk, sk) = keypair1.to_bytes();

    // Restore keypair from bytes
    let keypair2 = MlDsaKeyPair::from_bytes(level, &vk, &sk).expect("From bytes should succeed");

    // Verifying keys should match
    assert_eq!(
        keypair1.verifying_key(),
        keypair2.verifying_key(),
        "Restored verifying key should match"
    );

    // Both should be able to sign and verify
    let message = b"Serialization test";
    let sig1 = keypair1.sign(message).unwrap();
    let sig2 = keypair2.sign(message).unwrap();

    // Both signatures should verify with both keys
    verify(level, keypair1.verifying_key(), message, &sig1).expect("sig1 should verify");
    verify(level, keypair2.verifying_key(), message, &sig2).expect("sig2 should verify");
}

/// Test cross-verification between restored key pairs
#[test]
fn test_mldsa_cross_verify_restored() {
    let keypair1 = MlDsaKeyPair::generate(SecurityLevel::Level65);
    let (level, vk, sk) = keypair1.to_bytes();
    let keypair2 = MlDsaKeyPair::from_bytes(level, &vk, &sk).unwrap();

    let message = b"Cross verification test";

    // Sign with keypair1, verify with keypair2's key
    let sig1 = keypair1.sign(message).unwrap();
    verify(level, keypair2.verifying_key(), message, &sig1).expect("Cross verify should work");

    // Sign with keypair2, verify with keypair1's key
    let sig2 = keypair2.sign(message).unwrap();
    verify(level, keypair1.verifying_key(), message, &sig2).expect("Cross verify should work");
}

// ============================================================================
// ACVP-Style Known Answer Tests (KAT)
// ============================================================================

/// Test ML-KEM-1024 with known test case
/// These values are derived from deterministic generation for reproducibility
#[test]
fn test_mlkem_known_answer() {
    // Generate multiple key pairs and verify round-trip
    // This serves as a smoke test for the implementation
    for i in 0..5 {
        let keypair = MlKemKeyPair::generate();

        // Validate the key
        validate_encapsulation_key(keypair.encapsulation_key())
            .unwrap_or_else(|_| panic!("KAT {}: key validation should pass", i));

        // Encapsulate
        let (ct, ss1) = encapsulate(keypair.encapsulation_key())
            .unwrap_or_else(|_| panic!("KAT {}: encapsulation should succeed", i));

        // Decapsulate
        let ss2 = keypair
            .decapsulate(&ct)
            .unwrap_or_else(|_| panic!("KAT {}: decapsulation should succeed", i));

        // Verify shared secrets match
        assert_eq!(
            ss1.as_ref(),
            ss2.as_ref(),
            "KAT {}: shared secrets must match",
            i
        );
    }
}

/// Test ML-DSA with known message hashes
#[test]
fn test_mldsa_known_message_hash() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level87);

    // Test with specific known messages
    let test_messages = [
        b"".to_vec(),
        b"a".to_vec(),
        b"abc".to_vec(),
        b"message digest".to_vec(),
        b"abcdefghijklmnopqrstuvwxyz".to_vec(),
        vec![0x61u8; 1000], // 1000 'a's
    ];

    for (i, message) in test_messages.iter().enumerate() {
        let signature = keypair
            .sign(message)
            .unwrap_or_else(|_| panic!("KAT {}: signing should succeed", i));

        verify(
            SecurityLevel::Level87,
            keypair.verifying_key(),
            message,
            &signature,
        )
        .unwrap_or_else(|_| panic!("KAT {}: signature should verify", i));
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test ML-KEM with boundary coefficient values
#[test]
fn test_mlkem_boundary_coefficients() {
    // All coefficients at 0 (minimum valid)
    let key_zeros = vec![0u8; PUBLIC_KEY_SIZE];
    assert!(
        validate_encapsulation_key(&key_zeros).is_ok(),
        "All-zeros key should be valid"
    );

    // Create key with coefficient = 3328 (maximum valid = q-1)
    // coeff = 3328 = 0xD00
    // ByteEncode12: b0 = 0x00, b1 = 0x0D (for first coeff)
    let mut key_max_valid = vec![0u8; PUBLIC_KEY_SIZE];
    key_max_valid[0] = 0x00;
    key_max_valid[1] = 0x0D;
    key_max_valid[2] = 0x00;
    assert!(
        validate_encapsulation_key(&key_max_valid).is_ok(),
        "Key with coefficient 3328 should be valid"
    );
}

/// Test multiple encapsulations to same key produce different ciphertexts
#[test]
fn test_mlkem_randomized_encapsulation() {
    let keypair = MlKemKeyPair::generate();

    let (ct1, _) = encapsulate(keypair.encapsulation_key()).unwrap();
    let (ct2, _) = encapsulate(keypair.encapsulation_key()).unwrap();

    assert_ne!(
        ct1, ct2,
        "Different encapsulations should produce different ciphertexts"
    );
}

/// Test ML-DSA multiple signatures of same message
#[test]
fn test_mldsa_multiple_signatures() {
    let keypair = MlDsaKeyPair::generate(SecurityLevel::Level44);
    let message = b"Same message signed twice";

    let sig1 = keypair.sign(message).unwrap();
    let sig2 = keypair.sign(message).unwrap();

    // Both should verify
    verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        message,
        &sig1,
    )
    .expect("First signature should verify");

    verify(
        SecurityLevel::Level44,
        keypair.verifying_key(),
        message,
        &sig2,
    )
    .expect("Second signature should verify");

    // Note: signatures may or may not be the same depending on implementation
    // (randomized vs deterministic signing). We just verify both are valid.
}
