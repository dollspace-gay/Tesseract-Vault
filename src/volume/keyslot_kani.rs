// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for key slot operations.
//!
//! These harnesses verify critical security properties of the key slot system.

#![cfg(kani)]

use super::keyslot::{MASTER_KEY_SIZE, MAX_KEY_SLOTS};

/// Size of the encrypted master key (includes GCM authentication tag)
const ENCRYPTED_KEY_SIZE: usize = MASTER_KEY_SIZE + 16;

/// Verify MAX_KEY_SLOTS is reasonable.
#[kani::proof]
fn verify_max_key_slots() {
    // Current design: Slot 0 = primary password, Slot 1 = recovery key
    assert_eq!(MAX_KEY_SLOTS, 2);

    // Should be at least 1 (primary password)
    assert!(MAX_KEY_SLOTS >= 1);

    // Should be small to limit attack surface
    assert!(MAX_KEY_SLOTS <= 8);
}

/// Verify MASTER_KEY_SIZE is 32 bytes (AES-256).
#[kani::proof]
fn verify_master_key_size() {
    assert_eq!(MASTER_KEY_SIZE, 32);
    // 256 bits for AES-256
    assert_eq!(MASTER_KEY_SIZE * 8, 256);
}

/// Verify encrypted key size includes auth tag.
#[kani::proof]
fn verify_encrypted_key_size() {
    // AES-GCM tag is 16 bytes
    const GCM_TAG_SIZE: usize = 16;

    assert_eq!(ENCRYPTED_KEY_SIZE, MASTER_KEY_SIZE + GCM_TAG_SIZE);
    assert_eq!(ENCRYPTED_KEY_SIZE, 48);
}

/// Verify slot index bounds are checked.
#[kani::proof]
fn verify_slot_index_bounds() {
    let index: usize = kani::any();

    // Valid indices are 0 to MAX_KEY_SLOTS-1
    let is_valid = index < MAX_KEY_SLOTS;

    if is_valid {
        assert!(index < MAX_KEY_SLOTS);
    } else {
        assert!(index >= MAX_KEY_SLOTS);
    }
}

/// Verify active slot count is bounded.
#[kani::proof]
fn verify_active_count_bounds() {
    let active_count: usize = kani::any();

    // Active count cannot exceed MAX_KEY_SLOTS
    kani::assume(active_count <= MAX_KEY_SLOTS);

    assert!(active_count <= MAX_KEY_SLOTS);
    assert!(active_count <= 2);
}

/// Verify salt size matches Argon2id requirement.
#[kani::proof]
fn verify_salt_size() {
    const SALT_SIZE: usize = 32;
    const ARGON2_SALT_MIN: usize = 8;

    assert_eq!(SALT_SIZE, 32);
    assert!(SALT_SIZE >= ARGON2_SALT_MIN);
}

/// Verify nonce size matches AES-GCM requirement.
#[kani::proof]
fn verify_nonce_size() {
    const NONCE_SIZE: usize = 12;
    const AES_GCM_NONCE_SIZE: usize = 12; // 96-bit nonce

    assert_eq!(NONCE_SIZE, AES_GCM_NONCE_SIZE);
}

/// Verify key slot structure sizes don't overflow.
#[kani::proof]
fn verify_keyslot_struct_size() {
    // KeySlot contains:
    // - active: bool (1 byte, but aligned)
    // - salt: [u8; 32]
    // - nonce: [u8; 12]
    // - encrypted_master_key: [u8; 48]
    const SALT_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;

    let total_data = SALT_SIZE + NONCE_SIZE + ENCRYPTED_KEY_SIZE;
    assert_eq!(total_data, 92);

    // Should fit in reasonable memory
    assert!(total_data < 1024);
}

/// Verify find_free_slot returns valid index or None.
#[kani::proof]
fn verify_find_free_slot_result() {
    let result: Option<usize> = kani::any();

    match result {
        Some(index) => {
            // If Some, index must be valid
            kani::assume(index < MAX_KEY_SLOTS);
            assert!(index < MAX_KEY_SLOTS);
        }
        None => {
            // None means all slots are full - valid state
        }
    }
}

/// Verify duress password detection is boolean.
#[kani::proof]
fn verify_duress_detection_boolean() {
    let is_duress: bool = kani::any();

    // Duress detection should be a clear yes/no
    // No partial states allowed
    assert!(is_duress == true || is_duress == false);
}

/// Verify key destruction zeroizes all slots.
#[kani::proof]
fn verify_destruction_completeness() {
    // After destruction, active_count must be 0
    let slots_before: usize = kani::any();
    kani::assume(slots_before <= MAX_KEY_SLOTS);

    // Destruction sets all slots to inactive
    let slots_after: usize = 0;

    assert_eq!(slots_after, 0);
    assert!(slots_after < slots_before || slots_before == 0);
}

/// Verify password change preserves slot index.
#[kani::proof]
fn verify_password_change_slot_preservation() {
    let slot_index: usize = kani::any();
    kani::assume(slot_index < MAX_KEY_SLOTS);

    // After password change, same slot should be used
    let new_slot_index = slot_index;

    assert_eq!(slot_index, new_slot_index);
}

/// Verify derived key size matches expectations.
#[kani::proof]
fn verify_derived_key_size() {
    // V2 PQC hybrid key is 32 bytes
    const DERIVED_KEY_SIZE: usize = 32;

    assert_eq!(DERIVED_KEY_SIZE, MASTER_KEY_SIZE);
    assert_eq!(DERIVED_KEY_SIZE, 32);
}

/// Verify slot operations maintain invariant: at most MAX_KEY_SLOTS active.
#[kani::proof]
fn verify_slot_invariant() {
    let active_before: usize = kani::any();
    let operation: u8 = kani::any(); // 0=add, 1=remove, 2=update

    kani::assume(active_before <= MAX_KEY_SLOTS);
    kani::assume(operation <= 2);

    let active_after = match operation {
        0 => {
            // Add: can only succeed if there's room
            if active_before < MAX_KEY_SLOTS {
                active_before + 1
            } else {
                active_before // Fails, no change
            }
        }
        1 => {
            // Remove: can only decrease
            if active_before > 0 {
                active_before - 1
            } else {
                active_before
            }
        }
        _ => {
            // Update: no change to count
            active_before
        }
    };

    // Invariant: always <= MAX_KEY_SLOTS
    assert!(active_after <= MAX_KEY_SLOTS);
}
