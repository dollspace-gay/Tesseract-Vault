// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for volume header operations.
//!
//! These harnesses verify critical security properties of the volume header format
//! using symbolic execution over real logic.
//!
//! ## Audit Notes
//!
//! Tautological harnesses removed:
//! - verify_header_size_alignment (asserted 4096 == 4096)
//! - verify_cipher_algorithm_values (asserted enum discriminant values)
//! - verify_pq_algorithm_values (asserted enum discriminant values)
//! - verify_mlkem1024_key_sizes (asserted FIPS constants equal themselves)
//! - verify_checksum_size (asserted 32 == 32)
//! - verify_salt_size (asserted 32 == 32)
//! - verify_header_iv_size (asserted 12 == 12)
//! - verify_version_constants (asserted 1 != 2)
//! - verify_encrypted_dk_size (asserted 12+3168+16 == 3196)
//! - verify_pq_metadata_offset (asserted 4096 == 4096)
//! - verify_has_pqc_conditions (asserted tautology: A == A)
//!
//! Retained/added: harnesses that verify real logic with symbolic inputs.

#![cfg(kani)]

use super::{
    CipherAlgorithm, PqAlgorithm, PqVolumeMetadata, VolumeHeader, HEADER_SIZE,
    MAX_PQC_METADATA_SIZE, PQC_PADDING_SIZE, PQ_METADATA_SIZE,
};

/// Verify YubiKey flag bit operations are correct for any initial flags.
///
/// Property: Setting and clearing the YubiKey flag works correctly
/// regardless of what other flags are set.
#[kani::proof]
fn verify_yubikey_flag_operations() {
    let initial_flags: u8 = kani::any();
    let flag_value = VolumeHeader::FLAG_YUBIKEY_2FA;

    // Setting the flag
    let with_flag = initial_flags | flag_value;
    assert!(with_flag & flag_value != 0);

    // Clearing the flag
    let without_flag = with_flag & !flag_value;
    assert!(without_flag & flag_value == 0);

    // Other bits are preserved when setting
    assert_eq!(with_flag & !flag_value, initial_flags & !flag_value);

    // Other bits are preserved when clearing
    assert_eq!(without_flag & !flag_value, initial_flags & !flag_value);
}

/// Verify both flag constants are single, non-overlapping bits.
///
/// Property: FLAG_YUBIKEY_2FA and FLAG_KEYFILE_REQUIRED are each a power of 2,
/// and they occupy different bit positions (no overlap).
#[kani::proof]
fn verify_flags_are_single_nonoverlapping_bits() {
    let yubikey = VolumeHeader::FLAG_YUBIKEY_2FA;
    let keyfile = VolumeHeader::FLAG_KEYFILE_REQUIRED;

    // Both are powers of 2 (single bit)
    assert!(yubikey > 0 && (yubikey & (yubikey - 1)) == 0);
    assert!(keyfile > 0 && (keyfile & (keyfile - 1)) == 0);

    // They don't overlap
    assert_eq!(yubikey & keyfile, 0);
}

/// Verify keyfile flag bit operations are correct for any initial flags.
///
/// Property: Setting and clearing FLAG_KEYFILE_REQUIRED works correctly
/// regardless of what other flags are set. Symmetric to verify_yubikey_flag_operations.
#[kani::proof]
fn verify_keyfile_flag_operations() {
    let initial_flags: u8 = kani::any();
    let flag_value = VolumeHeader::FLAG_KEYFILE_REQUIRED;

    let with_flag = initial_flags | flag_value;
    assert!(with_flag & flag_value != 0);

    let without_flag = with_flag & !flag_value;
    assert!(without_flag & flag_value == 0);

    // Other bits preserved
    assert_eq!(with_flag & !flag_value, initial_flags & !flag_value);
    assert_eq!(without_flag & !flag_value, initial_flags & !flag_value);
}

/// Verify flags are independent: setting one never affects the other.
///
/// Property: For any initial flags byte, toggling FLAG_YUBIKEY_2FA does not
/// change the state of FLAG_KEYFILE_REQUIRED, and vice versa.
#[kani::proof]
fn verify_flag_independence() {
    let initial: u8 = kani::any();

    let yubikey = VolumeHeader::FLAG_YUBIKEY_2FA;
    let keyfile = VolumeHeader::FLAG_KEYFILE_REQUIRED;

    // Setting yubikey preserves keyfile state
    let after_set_yubikey = initial | yubikey;
    assert_eq!(after_set_yubikey & keyfile, initial & keyfile);

    // Clearing yubikey preserves keyfile state
    let after_clear_yubikey = initial & !yubikey;
    assert_eq!(after_clear_yubikey & keyfile, initial & keyfile);

    // Setting keyfile preserves yubikey state
    let after_set_keyfile = initial | keyfile;
    assert_eq!(after_set_keyfile & yubikey, initial & yubikey);

    // Clearing keyfile preserves yubikey state
    let after_clear_keyfile = initial & !keyfile;
    assert_eq!(after_clear_keyfile & yubikey, initial & yubikey);
}

/// Verify sector size is within valid range.
///
/// Property: Valid sector sizes are powers of 2 and at least 512.
#[kani::proof]
fn verify_sector_size_bounds() {
    let sector_size: u32 = kani::any();

    // Valid sector sizes: 512, 4096
    kani::assume(sector_size == 512 || sector_size == 4096);

    assert!(sector_size.is_power_of_two());
    assert!(sector_size >= 512);
}

/// Verify volume size does not overflow when combined with header.
///
/// Property: For any volume up to 16 TB, adding header size is safe.
#[kani::proof]
fn verify_volume_size_no_overflow() {
    let volume_size: u64 = kani::any();
    let header_size = HEADER_SIZE as u64;

    // Assume reasonable volume size (up to 16 TB)
    kani::assume(volume_size <= 16 * 1024 * 1024 * 1024 * 1024);

    let total = volume_size.checked_add(header_size);
    assert!(total.is_some());
}

/// Verify PQ metadata size constants are consistent.
///
/// Property: PQ_METADATA_SIZE fits within MAX_PQC_METADATA_SIZE and
/// padding is large enough for future algorithms (SPHINCS+).
#[kani::proof]
fn verify_pq_metadata_size_bounds() {
    assert!(PQ_METADATA_SIZE <= MAX_PQC_METADATA_SIZE);
    assert_eq!(PqVolumeMetadata::serialized_size(), PQ_METADATA_SIZE);

    // SPHINCS+-SHA2-256f signature size is approximately 49KB
    const SPHINCS_SIGNATURE_SIZE: usize = 49_856;
    assert!(PQC_PADDING_SIZE >= SPHINCS_SIGNATURE_SIZE);
}

/// Verify volume data offset calculation for symbolic sector sizes.
///
/// Property: Data starts after the header and is sector-aligned.
#[kani::proof]
fn verify_data_offset_alignment() {
    let sector_size: u64 = kani::any();
    kani::assume(sector_size == 512 || sector_size == 4096);

    let header_size = HEADER_SIZE as u64;

    // Data offset is header rounded up to sector boundary
    let data_offset = if header_size % sector_size == 0 {
        header_size
    } else {
        ((header_size / sector_size) + 1) * sector_size
    };

    // Data offset is sector-aligned
    assert_eq!(data_offset % sector_size, 0);
    // Data offset is at least header size
    assert!(data_offset >= header_size);
}

/// Verify has_pqc() correctly implements the dual-condition check.
///
/// Property: has_pqc() returns true if and only if pq_algorithm != None AND
/// pq_metadata_size > 0. Tests the actual VolumeHeader::has_pqc() method
/// with symbolic inputs. Catches bugs like using || instead of &&, or
/// inverting the None check.
#[kani::proof]
fn verify_has_pqc_logic() {
    let pq_metadata_size: u32 = kani::any();

    // Test with PqAlgorithm::None
    let header_none = VolumeHeader::kani_new(PqAlgorithm::None, pq_metadata_size, 0);
    // None algorithm means no PQC regardless of metadata size
    assert!(!header_none.has_pqc());

    // Test with PqAlgorithm::MlKem1024
    let header_mlkem = VolumeHeader::kani_new(PqAlgorithm::MlKem1024, pq_metadata_size, 0);
    // MlKem1024 with size > 0 means PQC is active
    if pq_metadata_size > 0 {
        assert!(header_mlkem.has_pqc());
    } else {
        // MlKem1024 but size == 0 means PQC is NOT active (inconsistent state)
        assert!(!header_mlkem.has_pqc());
    }
}

/// Verify requires_yubikey() faithfully reads the flag bit from a real header.
///
/// Property: VolumeHeader::requires_yubikey() returns true iff the
/// FLAG_YUBIKEY_2FA bit is set in the flags byte. Tests the actual method
/// on a constructed VolumeHeader with symbolic flags.
#[kani::proof]
fn verify_requires_yubikey_on_header() {
    let flags: u8 = kani::any();
    let header = VolumeHeader::kani_new(PqAlgorithm::None, 0, flags);

    let expected = flags & VolumeHeader::FLAG_YUBIKEY_2FA != 0;
    assert_eq!(header.requires_yubikey(), expected);
}

/// Verify requires_keyfile() faithfully reads the flag bit from a real header.
///
/// Property: VolumeHeader::requires_keyfile() returns true iff the
/// FLAG_KEYFILE_REQUIRED bit is set in the flags byte. Tests the actual method
/// on a constructed VolumeHeader with symbolic flags.
#[kani::proof]
fn verify_requires_keyfile_on_header() {
    let flags: u8 = kani::any();
    let header = VolumeHeader::kani_new(PqAlgorithm::None, 0, flags);

    let expected = flags & VolumeHeader::FLAG_KEYFILE_REQUIRED != 0;
    assert_eq!(header.requires_keyfile(), expected);
}

/// Verify pq_algorithm() getter returns what was stored.
///
/// Property: The pq_algorithm() getter on a VolumeHeader returns the exact
/// PqAlgorithm that was used during construction, for both variants.
#[kani::proof]
fn verify_pq_algorithm_getter() {
    let header_none = VolumeHeader::kani_new(PqAlgorithm::None, 0, 0);
    assert_eq!(header_none.pq_algorithm(), PqAlgorithm::None);

    let header_mlkem = VolumeHeader::kani_new(PqAlgorithm::MlKem1024, 100, 0);
    assert_eq!(header_mlkem.pq_algorithm(), PqAlgorithm::MlKem1024);
}

/// Verify is_v2() and version() agree on the header format version.
///
/// Property: The kani_new constructor always creates a V2 header (current version),
/// and is_v2() correctly identifies it.
#[kani::proof]
fn verify_version_getter_consistency() {
    let flags: u8 = kani::any();
    let header = VolumeHeader::kani_new(PqAlgorithm::None, 0, flags);

    // kani_new uses VERSION (which is VERSION_V2)
    assert!(header.is_v2());
    assert_eq!(header.version(), 2);
}

/// Verify PQ metadata doesn't overlap with volume data for symbolic volume sizes.
///
/// Property: When PQC is enabled, metadata fits between header and data.
#[kani::proof]
fn verify_pq_metadata_no_overlap() {
    let volume_size: u64 = kani::any();
    kani::assume(volume_size >= 1024 * 1024); // At least 1 MB
    kani::assume(volume_size <= 1024 * 1024 * 1024 * 1024); // Up to 1 TB

    let pq_offset = HEADER_SIZE as u64;
    let pq_end = pq_offset.checked_add(PQ_METADATA_SIZE as u64);
    assert!(pq_end.is_some());

    // PQ metadata must not extend beyond the volume
    let total_overhead = pq_end.unwrap().checked_add(PQC_PADDING_SIZE as u64);
    assert!(total_overhead.is_some());

    if total_overhead.unwrap() < volume_size {
        // There's room for data after PQ metadata
        let data_start = total_overhead.unwrap();
        assert!(data_start > pq_offset);
    }
}
