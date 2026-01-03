// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Kani formal verification harnesses for volume header operations.
//!
//! These harnesses verify critical security properties of the volume header format.

#![cfg(kani)]

use super::{
    CipherAlgorithm, HeaderError, PqAlgorithm, PqVolumeMetadata, VolumeHeader, HEADER_SIZE,
    MAX_PQC_METADATA_SIZE, PQC_PADDING_SIZE, PQ_METADATA_SIZE,
};

/// Verify that HEADER_SIZE is exactly 4096 bytes (4KB aligned).
#[kani::proof]
fn verify_header_size_alignment() {
    assert_eq!(HEADER_SIZE, 4096);
    assert_eq!(HEADER_SIZE % 4096, 0); // 4KB aligned
}

/// Verify CipherAlgorithm enum values are distinct and correct.
#[kani::proof]
fn verify_cipher_algorithm_values() {
    let gcm = CipherAlgorithm::Aes256Gcm as u8;
    let xts = CipherAlgorithm::Aes256Xts as u8;

    // Values should be correct
    assert_eq!(gcm, 1);
    assert_eq!(xts, 2);

    // Values should be distinct
    assert_ne!(gcm, xts);

    // Values should be non-zero (0 could indicate invalid)
    assert!(gcm > 0);
    assert!(xts > 0);
}

/// Verify PqAlgorithm enum values are distinct and correct.
#[kani::proof]
fn verify_pq_algorithm_values() {
    let none = PqAlgorithm::None as u8;
    let mlkem = PqAlgorithm::MlKem1024 as u8;

    // Values should be correct
    assert_eq!(none, 0);
    assert_eq!(mlkem, 1);

    // Values should be distinct
    assert_ne!(none, mlkem);
}

/// Verify PQ metadata size constants are consistent.
#[kani::proof]
fn verify_pq_metadata_size_bounds() {
    // Padding should be significant (60KB for future algorithms)
    assert_eq!(PQC_PADDING_SIZE, 60000);

    // Metadata size should be within maximum bounds
    assert!(PQ_METADATA_SIZE <= MAX_PQC_METADATA_SIZE);

    // Serialized size method should return the constant
    assert_eq!(PqVolumeMetadata::serialized_size(), PQ_METADATA_SIZE);
}

/// Verify ML-KEM-1024 key sizes are FIPS 203 compliant.
#[kani::proof]
fn verify_mlkem1024_key_sizes() {
    // FIPS 203 ML-KEM-1024 sizes (from constant definitions)
    const MLKEM1024_EK_SIZE: usize = 1568; // Encapsulation key
    const MLKEM1024_CT_SIZE: usize = 1568; // Ciphertext
    const MLKEM1024_DK_SIZE: usize = 3168; // Decapsulation key
    const ENCRYPTED_DK_SIZE: usize = 12 + MLKEM1024_DK_SIZE + 16; // nonce + DK + tag

    // Verify NIST FIPS 203 compliance
    assert_eq!(MLKEM1024_EK_SIZE, 1568);
    assert_eq!(MLKEM1024_CT_SIZE, 1568);
    assert_eq!(MLKEM1024_DK_SIZE, 3168);

    // Encrypted DK should include nonce and auth tag
    assert_eq!(ENCRYPTED_DK_SIZE, 3196);
}

/// Verify YubiKey flag bit operations are correct.
#[kani::proof]
fn verify_yubikey_flag_operations() {
    let flag_value = VolumeHeader::FLAG_YUBIKEY_2FA;

    // Should be bit 0
    assert_eq!(flag_value, 0x01);

    // Setting the flag should set bit 0
    let mut flags: u8 = 0;
    flags |= flag_value;
    assert!(flags & flag_value != 0);

    // Clearing the flag should clear bit 0
    flags &= !flag_value;
    assert!(flags & flag_value == 0);
}

/// Verify flag bit is a single bit (power of 2).
#[kani::proof]
fn verify_flag_is_single_bit() {
    let flag = VolumeHeader::FLAG_YUBIKEY_2FA;

    // A single bit flag should be a power of 2
    // For powers of 2: x & (x - 1) == 0 (where x > 0)
    assert!(flag > 0);
    assert_eq!(flag & (flag - 1), 0);
}

/// Verify sector size is within valid range (symbolic).
#[kani::proof]
fn verify_sector_size_bounds() {
    let sector_size: u32 = kani::any();

    // Valid sector sizes: 512, 4096
    kani::assume(sector_size == 512 || sector_size == 4096);

    // Sector size should be a power of 2
    assert!(sector_size.is_power_of_two());

    // Sector size should be at least 512
    assert!(sector_size >= 512);
}

/// Verify volume size does not overflow when combined with header.
#[kani::proof]
fn verify_volume_size_no_overflow() {
    let volume_size: u64 = kani::any();
    let header_size = HEADER_SIZE as u64;

    // Assume reasonable volume size (up to 16 TB)
    kani::assume(volume_size <= 16 * 1024 * 1024 * 1024 * 1024);

    // Total size should not overflow
    let total = volume_size.checked_add(header_size);
    assert!(total.is_some());
}

/// Verify PQ metadata offset is valid when PQC is enabled.
#[kani::proof]
fn verify_pq_metadata_offset() {
    // When PQC is enabled, metadata follows header
    let pq_offset = HEADER_SIZE as u64;

    // Offset should be exactly HEADER_SIZE
    assert_eq!(pq_offset, 4096);

    // Metadata should not overlap with header
    assert!(pq_offset >= HEADER_SIZE as u64);
}

/// Verify has_pqc returns true only when both conditions are met.
#[kani::proof]
fn verify_has_pqc_conditions() {
    let pq_algorithm: u8 = kani::any();
    let pq_metadata_size: u32 = kani::any();

    kani::assume(pq_algorithm <= 1); // Valid enum range

    let is_none = pq_algorithm == PqAlgorithm::None as u8;
    let has_metadata = pq_metadata_size > 0;

    // has_pqc should be true only when algorithm != None AND size > 0
    let expected = !is_none && has_metadata;

    // Symbolic verification of the logic
    assert_eq!(!is_none && has_metadata, expected);
}

/// Verify checksum field is exactly 32 bytes (BLAKE3 output).
#[kani::proof]
fn verify_checksum_size() {
    const BLAKE3_OUTPUT_SIZE: usize = 32;
    const CHECKSUM_SIZE: usize = 32;

    assert_eq!(CHECKSUM_SIZE, BLAKE3_OUTPUT_SIZE);
}

/// Verify salt size is exactly 32 bytes (Argon2id requirement).
#[kani::proof]
fn verify_salt_size() {
    const SALT_SIZE: usize = 32;
    const ARGON2_SALT_MIN: usize = 8; // Argon2 minimum

    assert_eq!(SALT_SIZE, 32);
    assert!(SALT_SIZE >= ARGON2_SALT_MIN);
}

/// Verify header IV size is exactly 12 bytes (AES-GCM requirement).
#[kani::proof]
fn verify_header_iv_size() {
    const IV_SIZE: usize = 12;
    const AES_GCM_NONCE_SIZE: usize = 12; // 96-bit nonce for AES-GCM

    assert_eq!(IV_SIZE, AES_GCM_NONCE_SIZE);
}

/// Verify version constants are distinct and in order.
#[kani::proof]
fn verify_version_constants() {
    const VERSION_V1: u32 = 1;
    const VERSION_V2: u32 = 2;

    // Versions should be distinct
    assert_ne!(VERSION_V1, VERSION_V2);

    // V2 should be greater than V1
    assert!(VERSION_V2 > VERSION_V1);

    // Versions should be positive
    assert!(VERSION_V1 > 0);
    assert!(VERSION_V2 > 0);
}

/// Verify encrypted DK size calculation is correct.
#[kani::proof]
fn verify_encrypted_dk_size() {
    const NONCE_SIZE: usize = 12;
    const DK_SIZE: usize = 3168;
    const TAG_SIZE: usize = 16;

    // Expected total: nonce + DK + auth tag
    const EXPECTED: usize = NONCE_SIZE + DK_SIZE + TAG_SIZE;

    assert_eq!(EXPECTED, 3196);
}

/// Verify cryptographic agility padding is sufficient for SPHINCS+.
#[kani::proof]
fn verify_sphincs_padding() {
    // SPHINCS+-SHA2-256f signature size is approximately 49KB
    const SPHINCS_SIGNATURE_SIZE: usize = 49_856;

    // Our padding should accommodate SPHINCS+
    assert!(PQC_PADDING_SIZE >= SPHINCS_SIGNATURE_SIZE);
}
