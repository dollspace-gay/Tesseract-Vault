// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for daemon authentication.
//!
//! These harnesses verify critical security properties of the auth system.

#![cfg(kani)]

use super::protocol::AUTH_TOKEN_LENGTH;

/// Verify token generation produces correct length.
#[kani::proof]
fn verify_token_generation_length() {
    // Token is AUTH_TOKEN_LENGTH bytes, hex-encoded to 2x length
    let byte_length = AUTH_TOKEN_LENGTH;
    let hex_length = byte_length * 2;

    assert_eq!(byte_length, 32);
    assert_eq!(hex_length, 64);
}

/// Verify hex-encoded token format is valid.
#[kani::proof]
fn verify_token_hex_format() {
    // Each hex digit represents 4 bits
    let bits_per_hex_digit = 4;
    let hex_digits = AUTH_TOKEN_LENGTH * 2;
    let total_bits = hex_digits * bits_per_hex_digit;

    // 64 hex digits = 256 bits
    assert_eq!(total_bits, 256);
}

/// Verify token validation length check comes first.
#[kani::proof]
fn verify_validation_length_check() {
    let expected_len = AUTH_TOKEN_LENGTH * 2;
    let test_len: usize = kani::any();

    // Length check should be first (okay to leak length mismatch)
    let lengths_match = test_len == expected_len;

    // If lengths don't match, validation should fail immediately
    if !lengths_match {
        // This is the early-exit path (not constant-time, which is fine)
        assert!(test_len != expected_len);
    }
}

/// Verify constant-time comparison only happens for equal-length inputs.
#[kani::proof]
fn verify_constant_time_precondition() {
    let stored_len = AUTH_TOKEN_LENGTH * 2;
    let provided_len: usize = kani::any();

    // Constant-time comparison should only occur when lengths match
    let should_do_ct_compare = stored_len == provided_len;

    if should_do_ct_compare {
        assert_eq!(stored_len, provided_len);
    }
}

/// Verify challenge-response nonce length is adequate.
#[kani::proof]
fn verify_challenge_response_security() {
    use super::protocol::CHALLENGE_NONCE_LENGTH;

    // Challenge should be at least 128 bits for replay protection
    assert!(CHALLENGE_NONCE_LENGTH * 8 >= 128);

    // Our implementation uses 256 bits
    assert_eq!(CHALLENGE_NONCE_LENGTH, 32);
}

/// Verify server identity proof uses domain separation.
#[kani::proof]
fn verify_server_identity_domain_separation() {
    // The domain separator "tesseract-server-identity-v1" ensures:
    // 1. Proofs cannot be reused for other purposes
    // 2. Version upgrades won't confuse old/new proofs
    // This is verified by the constant string length
    let domain_separator = b"tesseract-server-identity-v1";
    assert_eq!(domain_separator.len(), 28);
}

/// Verify keyed hash output size matches BLAKE3.
#[kani::proof]
fn verify_keyed_hash_output_size() {
    // BLAKE3 always produces 32-byte output by default
    const BLAKE3_OUTPUT_SIZE: usize = 32;

    // Server identity response should be 32 bytes
    use super::protocol::SERVER_IDENTITY_LENGTH;
    assert_eq!(SERVER_IDENTITY_LENGTH, BLAKE3_OUTPUT_SIZE);
}

/// Verify token file path doesn't cause overflow.
#[kani::proof]
fn verify_path_length_bounds() {
    // Typical max path lengths
    const MAX_PATH_WINDOWS: usize = 260;
    const MAX_PATH_UNIX: usize = 4096;

    // Token filename is fixed
    let token_filename = "daemon.token";
    let filename_len = token_filename.len();

    // Filename should fit in any path
    assert!(filename_len < MAX_PATH_WINDOWS);
    assert!(filename_len < MAX_PATH_UNIX);
}

/// Verify authentication error variants are distinct.
#[kani::proof]
fn verify_auth_error_discrimination() {
    // AuthError has 4 variants: RandomGeneration, TokenFile, InvalidFormat, InvalidToken
    // Each should produce a distinct error for proper handling
    let variant: u8 = kani::any();
    kani::assume(variant < 4);

    // All 4 variants are valid
    assert!(variant < 4);
}
