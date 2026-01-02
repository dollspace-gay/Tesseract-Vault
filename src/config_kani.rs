// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for configuration and constants.
//!
//! These harnesses verify pure logic properties without calling crypto
//! operations that would trigger inline assembly (cpuid).

#![cfg(kani)]

use crate::config::{
    CryptoConfig, ARGON2_LANES, ARGON2_MEM_COST_KIB, ARGON2_TIME_COST, MAGIC_BYTES, MAX_SALT_LEN,
    NONCE_LEN,
};

/// Verify AES-GCM nonce length is exactly 96 bits (12 bytes).
///
/// Property: NONCE_LEN == 12 (per NIST SP 800-38D recommendation)
#[kani::proof]
fn verify_nonce_len_constant() {
    assert_eq!(NONCE_LEN, 12, "AES-GCM nonce must be 96 bits (12 bytes)");
}

/// Verify magic bytes are correct format.
///
/// Property: Magic bytes identify file format version
#[kani::proof]
fn verify_magic_bytes() {
    assert_eq!(MAGIC_BYTES.len(), 8, "Magic bytes must be 8 bytes");
    assert_eq!(MAGIC_BYTES, b"SCRYPTv1");
}

/// Verify salt length bound is within u8 range.
///
/// Property: MAX_SALT_LEN fits in a u8 for compact storage
#[kani::proof]
fn verify_salt_len_bound() {
    assert!(MAX_SALT_LEN <= 255, "Salt length must fit in u8");
    assert!(MAX_SALT_LEN >= 16, "Salt should be at least 16 bytes");
}

/// Verify default Argon2 parameters meet OWASP recommendations.
///
/// Property: Default config provides adequate security margins
#[kani::proof]
fn verify_argon2_defaults() {
    // OWASP recommends minimum 19 MiB for Argon2id
    assert!(
        ARGON2_MEM_COST_KIB >= 19 * 1024,
        "Memory cost should be at least 19 MiB per OWASP"
    );

    // Time cost should be at least 2 iterations
    assert!(ARGON2_TIME_COST >= 2, "Time cost should be at least 2");

    // Parallelism should be reasonable
    assert!(ARGON2_LANES >= 1, "Need at least 1 lane");
    assert!(ARGON2_LANES <= 255, "Lanes must fit in u8");
}

/// Verify CryptoConfig::default() produces valid parameters.
///
/// Property: Default config values match constants
#[kani::proof]
fn verify_config_default_matches_constants() {
    let config = CryptoConfig::default();

    assert_eq!(config.argon2_mem_cost_kib, ARGON2_MEM_COST_KIB);
    assert_eq!(config.argon2_time_cost, ARGON2_TIME_COST);
    assert_eq!(config.argon2_lanes, ARGON2_LANES);
}

/// Verify CryptoConfig::new() stores parameters correctly.
///
/// Property: Constructor preserves all input values
#[kani::proof]
fn verify_config_new_preserves_values() {
    let mem: u32 = kani::any();
    let time: u32 = kani::any();
    let lanes: u32 = kani::any();

    // Bound to reasonable values to avoid state explosion
    kani::assume(mem >= 8 && mem <= 1048576);
    kani::assume(time >= 1 && time <= 100);
    kani::assume(lanes >= 1 && lanes <= 16);

    let config = CryptoConfig::new(mem, time, lanes);

    assert_eq!(config.argon2_mem_cost_kib, mem);
    assert_eq!(config.argon2_time_cost, time);
    assert_eq!(config.argon2_lanes, lanes);
}

/// Verify CryptoConfig::fast() has lower security than default.
///
/// Property: Fast config trades security for speed
#[kani::proof]
fn verify_config_fast_is_faster() {
    let fast = CryptoConfig::fast();
    let default = CryptoConfig::default();

    // Fast should have lower memory cost OR lower time cost
    assert!(
        fast.argon2_mem_cost_kib < default.argon2_mem_cost_kib
            || fast.argon2_time_cost < default.argon2_time_cost,
        "Fast config should be faster than default"
    );
}

/// Verify CryptoConfig::paranoid() has higher security than default.
///
/// Property: Paranoid config trades speed for security
#[kani::proof]
fn verify_config_paranoid_is_stronger() {
    let paranoid = CryptoConfig::paranoid();
    let default = CryptoConfig::default();

    // Paranoid should have higher memory cost OR higher time cost
    assert!(
        paranoid.argon2_mem_cost_kib > default.argon2_mem_cost_kib
            || paranoid.argon2_time_cost > default.argon2_time_cost,
        "Paranoid config should be stronger than default"
    );
}

/// Verify config parameter overflow safety.
///
/// Property: No overflow when computing total work factor
#[kani::proof]
fn verify_no_parameter_overflow() {
    let mem: u32 = kani::any();
    let time: u32 = kani::any();
    let lanes: u32 = kani::any();

    // Reasonable bounds
    kani::assume(mem >= 8 && mem <= 1048576);
    kani::assume(time >= 1 && time <= 100);
    kani::assume(lanes >= 1 && lanes <= 16);

    // Verify multiplication doesn't overflow
    // Work factor approximation: mem * time (simplified)
    let work_factor = mem.checked_mul(time);
    assert!(work_factor.is_some(), "Work factor should not overflow");
}
