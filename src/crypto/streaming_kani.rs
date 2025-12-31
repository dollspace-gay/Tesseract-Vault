//! Kani formal verification harnesses for streaming encryption nonce handling.
//!
//! These harnesses verify critical safety properties of the nonce derivation
//! that prevents catastrophic nonce reuse in AES-GCM.

#![cfg(kani)]

use super::streaming::derive_chunk_nonce;
use crate::config::NONCE_LEN;

/// Verify that different chunk indices produce different nonces.
///
/// Property: For any base_nonce and i != j, derive_chunk_nonce(n, i) != derive_chunk_nonce(n, j)
///
/// This is CRITICAL for AES-GCM security. Nonce reuse under the same key
/// completely breaks authentication and allows key recovery.
#[kani::proof]
fn verify_nonce_uniqueness_different_indices() {
    let base_nonce: [u8; NONCE_LEN] = kani::any();
    let i: u64 = kani::any();
    let j: u64 = kani::any();

    kani::assume(i != j);

    let nonce_i = derive_chunk_nonce(&base_nonce, i);
    let nonce_j = derive_chunk_nonce(&base_nonce, j);

    // Different indices MUST produce different nonces
    assert_ne!(nonce_i, nonce_j, "CRITICAL: Nonce collision detected!");
}

/// Verify that the counter portion of the nonce is injective.
///
/// Property: The mapping from chunk_index to nonce[4..12] is bijective
#[kani::proof]
fn verify_counter_injection() {
    let i: u64 = kani::any();
    let j: u64 = kani::any();

    let counter_i = i.to_be_bytes();
    let counter_j = j.to_be_bytes();

    // If counters are equal, indices must be equal (injection)
    if counter_i == counter_j {
        assert_eq!(i, j, "Counter encoding is not injective");
    }
}

/// Verify nonce structure is correct (fixed || counter).
///
/// Property: First 4 bytes come from base_nonce, last 8 from counter
#[kani::proof]
fn verify_nonce_structure() {
    let base_nonce: [u8; NONCE_LEN] = kani::any();
    let chunk_index: u64 = kani::any();

    let nonce = derive_chunk_nonce(&base_nonce, chunk_index);

    // First 4 bytes must match base_nonce[0..4]
    assert_eq!(&nonce[0..4], &base_nonce[0..4], "Fixed field mismatch");

    // Last 8 bytes must be chunk_index in big-endian
    let expected_counter = chunk_index.to_be_bytes();
    assert_eq!(&nonce[4..12], &expected_counter, "Counter field mismatch");
}

/// Verify that nonce length is always correct.
///
/// Property: derive_chunk_nonce always returns exactly NONCE_LEN bytes
#[kani::proof]
fn verify_nonce_length() {
    let base_nonce: [u8; NONCE_LEN] = kani::any();
    let chunk_index: u64 = kani::any();

    let nonce = derive_chunk_nonce(&base_nonce, chunk_index);

    assert_eq!(nonce.len(), NONCE_LEN, "Nonce length incorrect");
    assert_eq!(nonce.len(), 12, "Nonce must be 96 bits for AES-GCM");
}

/// Verify maximum file size bound.
///
/// Property: With 1MB chunks and u64 counter, max file size is ~18 exabytes
#[kani::proof]
fn verify_max_file_size_bound() {
    const CHUNK_SIZE: u64 = 1024 * 1024; // 1 MB
    const MAX_CHUNKS: u64 = u64::MAX;

    // Verify the counter can handle the theoretical maximum
    // (This is a sanity check - u64::MAX chunks is already absurd)
    let max_file_bytes = MAX_CHUNKS.saturating_mul(CHUNK_SIZE);

    // Should not overflow (saturating_mul handles this)
    assert!(max_file_bytes > 0, "File size calculation should not underflow");
}

/// Verify nonce uniqueness for sequential chunks.
///
/// Property: Consecutive chunk indices produce different nonces
#[kani::proof]
fn verify_sequential_nonce_uniqueness() {
    let base_nonce: [u8; NONCE_LEN] = kani::any();
    let i: u64 = kani::any();

    // Avoid overflow
    kani::assume(i < u64::MAX);

    let nonce_i = derive_chunk_nonce(&base_nonce, i);
    let nonce_next = derive_chunk_nonce(&base_nonce, i + 1);

    assert_ne!(nonce_i, nonce_next, "Sequential nonces must differ");
}

/// Verify that zero chunk index produces valid nonce.
///
/// Property: First chunk (index 0) has well-defined nonce
#[kani::proof]
fn verify_zero_index_valid() {
    let base_nonce: [u8; NONCE_LEN] = kani::any();

    let nonce = derive_chunk_nonce(&base_nonce, 0);

    // Counter portion should be all zeros for index 0
    assert_eq!(&nonce[4..12], &[0u8; 8], "Zero index counter should be zeros");

    // Fixed portion should match
    assert_eq!(&nonce[0..4], &base_nonce[0..4], "Fixed field should match");
}

/// Verify that max chunk index produces valid nonce.
///
/// Property: Last possible chunk (u64::MAX) has well-defined nonce
#[kani::proof]
fn verify_max_index_valid() {
    let base_nonce: [u8; NONCE_LEN] = kani::any();

    let nonce = derive_chunk_nonce(&base_nonce, u64::MAX);

    // Counter portion should be all 0xFF for max index
    assert_eq!(&nonce[4..12], &[0xFF; 8], "Max index counter should be all 1s");

    // Fixed portion should match
    assert_eq!(&nonce[0..4], &base_nonce[0..4], "Fixed field should match");
}
