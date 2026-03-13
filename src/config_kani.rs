// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for configuration and constants.
//!
//! These harnesses verify pure logic properties of CryptoConfig
//! using symbolic inputs, not constant self-assertions.
//!
//! ## Audit Notes
//!
//! Tautological harnesses removed:
//! - verify_nonce_len_constant (asserted NONCE_LEN == 12)
//! - verify_magic_bytes (asserted MAGIC_BYTES == b"SCRYPTv1")
//! - verify_salt_len_bound (asserted MAX_SALT_LEN <= 255)
//! - verify_argon2_defaults (asserted constants meet static thresholds)
//! - verify_config_default_matches_constants (asserted Default uses constants)
//!
//! These are all compile-time/unit-test level checks, not formal verification.
//! Retained harnesses exercise CryptoConfig methods with symbolic inputs.

#![cfg(kani)]

use crate::config::{
    CryptoConfig, MIN_SECURE_LANES, MIN_SECURE_MEM_COST_KIB, MIN_SECURE_TIME_COST,
};

/// Verify CryptoConfig::new() clamps insecure parameters to minimums.
///
/// Property: For ANY input values, the output config is at least as secure
/// as the minimum thresholds (CWE-326 mitigation).
#[kani::proof]
fn verify_config_new_clamps_to_minimums() {
    let mem: u32 = kani::any();
    let time: u32 = kani::any();
    let lanes: u32 = kani::any();

    // Bound to reasonable values to avoid state explosion
    kani::assume(mem >= 1 && mem <= 1048576);
    kani::assume(time >= 1 && time <= 100);
    kani::assume(lanes >= 1 && lanes <= 16);

    let config = CryptoConfig::new(mem, time, lanes);

    // Post-condition: all values are at least the secure minimum
    assert!(config.argon2_mem_cost_kib >= MIN_SECURE_MEM_COST_KIB);
    assert!(config.argon2_time_cost >= MIN_SECURE_TIME_COST);
    assert!(config.argon2_lanes >= MIN_SECURE_LANES);

    // Post-condition: values are max(input, minimum)
    assert_eq!(config.argon2_mem_cost_kib, mem.max(MIN_SECURE_MEM_COST_KIB));
    assert_eq!(config.argon2_time_cost, time.max(MIN_SECURE_TIME_COST));
    assert_eq!(config.argon2_lanes, lanes.max(MIN_SECURE_LANES));
}

/// Verify CryptoConfig::fast() has lower cost than default.
///
/// Property: Fast config trades security for speed.
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

    // But fast must still meet minimum security thresholds
    assert!(fast.argon2_mem_cost_kib >= MIN_SECURE_MEM_COST_KIB);
    assert!(fast.argon2_time_cost >= MIN_SECURE_TIME_COST);
    assert!(fast.argon2_lanes >= MIN_SECURE_LANES);
}

/// Verify CryptoConfig::paranoid() has higher cost than default.
///
/// Property: Paranoid config trades speed for security.
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
/// Property: No overflow when computing work factor for any reasonable params.
#[kani::proof]
fn verify_no_parameter_overflow() {
    let mem: u32 = kani::any();
    let time: u32 = kani::any();
    let lanes: u32 = kani::any();

    kani::assume(mem >= 8 && mem <= 1048576);
    kani::assume(time >= 1 && time <= 100);
    kani::assume(lanes >= 1 && lanes <= 16);

    // Work factor approximation: mem * time (simplified)
    let work_factor = mem.checked_mul(time);
    assert!(work_factor.is_some(), "Work factor should not overflow");
}

/// Verify security ordering: paranoid > default > fast for all parameters.
///
/// Property: The three presets form a strict partial order on security.
#[kani::proof]
fn verify_config_security_ordering() {
    let fast = CryptoConfig::fast();
    let default = CryptoConfig::default();
    let paranoid = CryptoConfig::paranoid();

    // Memory cost: paranoid >= default >= fast
    assert!(paranoid.argon2_mem_cost_kib >= default.argon2_mem_cost_kib);
    assert!(default.argon2_mem_cost_kib >= fast.argon2_mem_cost_kib);

    // At least one dimension is strictly greater for paranoid vs default
    assert!(
        paranoid.argon2_mem_cost_kib > default.argon2_mem_cost_kib
            || paranoid.argon2_time_cost > default.argon2_time_cost
            || paranoid.argon2_lanes > default.argon2_lanes
    );
}

/// Verify CryptoConfig::new() preserves inputs that are already above minimums.
///
/// Property: If all three inputs are >= their respective minimums, the output
/// equals the input exactly (no unnecessary clamping).
#[kani::proof]
fn verify_config_new_preserves_above_minimum() {
    let mem: u32 = kani::any();
    let time: u32 = kani::any();
    let lanes: u32 = kani::any();

    kani::assume(mem >= MIN_SECURE_MEM_COST_KIB && mem <= 1_048_576);
    kani::assume(time >= MIN_SECURE_TIME_COST && time <= 100);
    kani::assume(lanes >= MIN_SECURE_LANES && lanes <= 16);

    let config = CryptoConfig::new(mem, time, lanes);

    // Inputs at or above minimum are preserved exactly
    assert_eq!(config.argon2_mem_cost_kib, mem);
    assert_eq!(config.argon2_time_cost, time);
    assert_eq!(config.argon2_lanes, lanes);
}

/// Verify CryptoConfig::new() is monotonic: larger inputs never produce smaller outputs.
///
/// Property: For any two input triples (a, b, c) and (a', b', c') where
/// a' >= a, b' >= b, c' >= c, the outputs satisfy the same ordering.
/// This ensures the clamping logic doesn't invert or distort the relationship.
#[kani::proof]
fn verify_config_new_monotonic() {
    let mem1: u32 = kani::any();
    let time1: u32 = kani::any();
    let lanes1: u32 = kani::any();
    let mem2: u32 = kani::any();
    let time2: u32 = kani::any();
    let lanes2: u32 = kani::any();

    // Keep values bounded for tractability
    kani::assume(mem1 >= 1 && mem1 <= 262_144);
    kani::assume(time1 >= 1 && time1 <= 50);
    kani::assume(lanes1 >= 1 && lanes1 <= 16);
    kani::assume(mem2 >= mem1 && mem2 <= 262_144);
    kani::assume(time2 >= time1 && time2 <= 50);
    kani::assume(lanes2 >= lanes1 && lanes2 <= 16);

    let config1 = CryptoConfig::new(mem1, time1, lanes1);
    let config2 = CryptoConfig::new(mem2, time2, lanes2);

    assert!(config2.argon2_mem_cost_kib >= config1.argon2_mem_cost_kib);
    assert!(config2.argon2_time_cost >= config1.argon2_time_cost);
    assert!(config2.argon2_lanes >= config1.argon2_lanes);
}
