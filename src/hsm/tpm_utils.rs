// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Pure utility functions for TPM 2.0 operations, extracted for testability.
//!
//! This module contains platform-independent pure functions used by the TPM
//! implementation. By extracting these functions, we can achieve unit test
//! coverage even when TPM hardware is not available.

use super::tpm::{PcrIndex, TpmHashAlgorithm};

// ============================================================================
// TPM 2.0 Constants
// ============================================================================

/// TPM 2.0 command tags
pub mod tags {
    /// TPM_ST_NO_SESSIONS - command/response with no session handles
    pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    /// TPM_ST_SESSIONS - command/response with session handles
    pub const TPM_ST_SESSIONS: u16 = 0x8002;
}

/// TPM 2.0 command codes
pub mod commands {
    /// TPM2_PCR_Read command code
    pub const TPM2_PCR_READ: u32 = 0x0000017E;
    /// TPM2_GetRandom command code
    pub const TPM2_GET_RANDOM: u32 = 0x0000017B;
    /// TPM2_Create command code
    pub const TPM2_CREATE: u32 = 0x00000153;
    /// TPM2_Load command code
    pub const TPM2_LOAD: u32 = 0x00000157;
    /// TPM2_Unseal command code
    pub const TPM2_UNSEAL: u32 = 0x0000015E;
}

/// TPM 2.0 algorithm identifiers
pub mod algorithms {
    /// TPM_ALG_SHA1
    pub const TPM_ALG_SHA1: u16 = 0x0004;
    /// TPM_ALG_SHA256
    pub const TPM_ALG_SHA256: u16 = 0x000B;
    /// TPM_ALG_SHA384
    pub const TPM_ALG_SHA384: u16 = 0x000C;
    /// TPM_ALG_SHA512
    pub const TPM_ALG_SHA512: u16 = 0x000D;
}

// ============================================================================
// Algorithm Conversion Functions
// ============================================================================

/// Convert `TpmHashAlgorithm` to TPM2 algorithm identifier.
///
/// # Arguments
///
/// * `algorithm` - The hash algorithm enum value
///
/// # Returns
///
/// The TPM2 algorithm identifier (u16).
pub fn hash_algorithm_to_tpm_alg(algorithm: TpmHashAlgorithm) -> u16 {
    match algorithm {
        TpmHashAlgorithm::Sha1 => algorithms::TPM_ALG_SHA1,
        TpmHashAlgorithm::Sha256 => algorithms::TPM_ALG_SHA256,
        TpmHashAlgorithm::Sha384 => algorithms::TPM_ALG_SHA384,
        TpmHashAlgorithm::Sha512 => algorithms::TPM_ALG_SHA512,
    }
}

/// Convert TPM2 algorithm identifier to `TpmHashAlgorithm`.
///
/// # Arguments
///
/// * `alg_id` - The TPM2 algorithm identifier
///
/// # Returns
///
/// The hash algorithm enum value, or `None` if the ID is not recognized.
pub fn tpm_alg_to_hash_algorithm(alg_id: u16) -> Option<TpmHashAlgorithm> {
    match alg_id {
        algorithms::TPM_ALG_SHA1 => Some(TpmHashAlgorithm::Sha1),
        algorithms::TPM_ALG_SHA256 => Some(TpmHashAlgorithm::Sha256),
        algorithms::TPM_ALG_SHA384 => Some(TpmHashAlgorithm::Sha384),
        algorithms::TPM_ALG_SHA512 => Some(TpmHashAlgorithm::Sha512),
        _ => None,
    }
}

// ============================================================================
// PCR Bitmap Functions
// ============================================================================

/// Calculate the byte index and bit mask for a PCR index.
///
/// TPM PCR selection uses a bitmap where each bit represents a PCR.
/// PCRs 0-7 are in byte 0, PCRs 8-15 are in byte 1, etc.
///
/// # Arguments
///
/// * `pcr_index` - The PCR index (0-23)
///
/// # Returns
///
/// A tuple of (byte_index, bit_mask).
pub fn pcr_index_to_bitmap(pcr_index: u8) -> (u8, u8) {
    let byte_index = pcr_index / 8;
    let bit_mask = 1u8 << (pcr_index % 8);
    (byte_index, bit_mask)
}

/// Create a 3-byte PCR selection bitmap for a single PCR.
///
/// # Arguments
///
/// * `pcr_index` - The PCR index (0-23)
///
/// # Returns
///
/// A 3-byte array representing the PCR selection bitmap.
pub fn create_pcr_select_bitmap(pcr_index: PcrIndex) -> [u8; 3] {
    let idx = pcr_index as u8;
    let (byte_idx, bit_mask) = pcr_index_to_bitmap(idx);
    let mut bitmap = [0u8; 3];
    if byte_idx < 3 {
        bitmap[byte_idx as usize] = bit_mask;
    }
    bitmap
}

/// Create a 3-byte PCR selection bitmap for multiple PCRs.
///
/// # Arguments
///
/// * `pcr_indices` - Slice of PCR indices
///
/// # Returns
///
/// A 3-byte array representing the PCR selection bitmap.
pub fn create_pcr_select_bitmap_multi(pcr_indices: &[PcrIndex]) -> [u8; 3] {
    let mut bitmap = [0u8; 3];
    for &idx in pcr_indices {
        let pcr_idx = idx as u8;
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(pcr_idx);
        if byte_idx < 3 {
            bitmap[byte_idx as usize] |= bit_mask;
        }
    }
    bitmap
}

// ============================================================================
// TPM Command Building Functions
// ============================================================================

/// Build a TPM2_PCR_Read command buffer.
///
/// # Arguments
///
/// * `pcr_index` - The PCR index to read
/// * `algorithm` - The hash algorithm for the PCR bank
///
/// # Returns
///
/// A vector containing the complete TPM command buffer.
pub fn build_pcr_read_command(pcr_index: PcrIndex, algorithm: TpmHashAlgorithm) -> Vec<u8> {
    let hash_alg = hash_algorithm_to_tpm_alg(algorithm);
    let pcr_select = create_pcr_select_bitmap(pcr_index);

    let mut cmd = Vec::with_capacity(64);

    // Tag: TPM_ST_NO_SESSIONS (0x8001)
    cmd.extend_from_slice(&tags::TPM_ST_NO_SESSIONS.to_be_bytes());
    // Size placeholder (will be filled later)
    cmd.extend_from_slice(&0u32.to_be_bytes());
    // Command code: TPM2_PCR_Read
    cmd.extend_from_slice(&commands::TPM2_PCR_READ.to_be_bytes());
    // pcrSelectionIn.count = 1
    cmd.extend_from_slice(&1u32.to_be_bytes());
    // pcrSelectionIn[0].hash
    cmd.extend_from_slice(&hash_alg.to_be_bytes());
    // pcrSelectionIn[0].sizeOfSelect = 3 (24 PCRs = 3 bytes)
    cmd.push(3);
    // pcrSelectionIn[0].pcrSelect
    cmd.extend_from_slice(&pcr_select);

    // Update size field
    let cmd_size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&cmd_size.to_be_bytes());

    cmd
}

/// Build a TPM2_GetRandom command buffer.
///
/// # Arguments
///
/// * `bytes_requested` - Number of random bytes to request (max 32 per call)
///
/// # Returns
///
/// A vector containing the complete TPM command buffer.
pub fn build_get_random_command(bytes_requested: u16) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(12);

    // Tag: TPM_ST_NO_SESSIONS (0x8001)
    cmd.extend_from_slice(&tags::TPM_ST_NO_SESSIONS.to_be_bytes());
    // Size: 12 bytes
    cmd.extend_from_slice(&12u32.to_be_bytes());
    // Command code: TPM2_GetRandom
    cmd.extend_from_slice(&commands::TPM2_GET_RANDOM.to_be_bytes());
    // bytesRequested
    cmd.extend_from_slice(&bytes_requested.to_be_bytes());

    cmd
}

// ============================================================================
// TPM Response Parsing Functions
// ============================================================================

/// Parse a TPM response header.
///
/// # Arguments
///
/// * `response` - The raw TPM response buffer
///
/// # Returns
///
/// A tuple of (tag, size, response_code) or an error message.
pub fn parse_response_header(response: &[u8]) -> Result<(u16, u32, u32), &'static str> {
    if response.len() < 10 {
        return Err("Response too short for header");
    }

    let tag = u16::from_be_bytes([response[0], response[1]]);
    let size = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);
    let response_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    Ok((tag, size, response_code))
}

/// Check if a TPM response code indicates success.
///
/// # Arguments
///
/// * `response_code` - The TPM response code
///
/// # Returns
///
/// `true` if the response code indicates success (0).
pub fn is_success_response(response_code: u32) -> bool {
    response_code == 0
}

/// Parse the random bytes from a TPM2_GetRandom response.
///
/// # Arguments
///
/// * `response` - The raw TPM response buffer
///
/// # Returns
///
/// The random bytes or an error message.
pub fn parse_get_random_response(response: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (_tag, _size, response_code) = parse_response_header(response)?;

    if !is_success_response(response_code) {
        return Err("TPM returned error response");
    }

    if response.len() < 12 {
        return Err("Response too short for random data");
    }

    // Parse TPM2B_DIGEST: size(2) + buffer
    let random_size = u16::from_be_bytes([response[10], response[11]]) as usize;

    if random_size == 0 {
        return Err("No random bytes returned");
    }

    if 12 + random_size > response.len() {
        return Err("Random data extends beyond response");
    }

    Ok(response[12..12 + random_size].to_vec())
}

// ============================================================================
// Policy Digest Computation
// ============================================================================

/// Compute a policy digest from PCR values.
///
/// This creates a deterministic digest that binds sealed data to specific PCR values.
///
/// # Arguments
///
/// * `pcr_values` - Slice of (PCR index, PCR value) pairs
/// * `auth_value` - Optional authorization value to include
///
/// # Returns
///
/// A 32-byte policy digest.
pub fn compute_policy_digest(
    pcr_values: &[(PcrIndex, Vec<u8>)],
    auth_value: Option<&[u8]>,
) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();

    for (idx, value) in pcr_values {
        hasher.update(&[*idx as u8]);
        hasher.update(value);
    }

    if let Some(auth) = auth_value {
        hasher.update(auth);
    }

    *hasher.finalize().as_bytes()
}

/// Derive a sealing key from TPM random data and policy digest.
///
/// # Arguments
///
/// * `tpm_random` - Random bytes from TPM
/// * `policy_digest` - The policy digest
///
/// # Returns
///
/// A 32-byte sealing key.
pub fn derive_sealing_key(tpm_random: &[u8], policy_digest: &[u8]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(tpm_random);
    hasher.update(policy_digest);

    *hasher.finalize().as_bytes()
}

/// XOR encrypt/decrypt data with a key (symmetric operation).
///
/// # Arguments
///
/// * `data` - Data to encrypt/decrypt
/// * `key` - 32-byte key
///
/// # Returns
///
/// Encrypted/decrypted data.
pub fn xor_encrypt_decrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % 32])
        .collect()
}

// ============================================================================
// Constant-Time Comparison
// ============================================================================

/// Compare two byte slices in constant time.
///
/// This prevents timing attacks when comparing secret values.
///
/// # Arguments
///
/// * `a` - First slice
/// * `b` - Second slice
///
/// # Returns
///
/// `true` if the slices are equal.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Algorithm Conversion Tests
    // ========================================

    #[test]
    fn test_hash_algorithm_to_tpm_alg_sha1() {
        assert_eq!(
            hash_algorithm_to_tpm_alg(TpmHashAlgorithm::Sha1),
            algorithms::TPM_ALG_SHA1
        );
    }

    #[test]
    fn test_hash_algorithm_to_tpm_alg_sha256() {
        assert_eq!(
            hash_algorithm_to_tpm_alg(TpmHashAlgorithm::Sha256),
            algorithms::TPM_ALG_SHA256
        );
    }

    #[test]
    fn test_hash_algorithm_to_tpm_alg_sha384() {
        assert_eq!(
            hash_algorithm_to_tpm_alg(TpmHashAlgorithm::Sha384),
            algorithms::TPM_ALG_SHA384
        );
    }

    #[test]
    fn test_hash_algorithm_to_tpm_alg_sha512() {
        assert_eq!(
            hash_algorithm_to_tpm_alg(TpmHashAlgorithm::Sha512),
            algorithms::TPM_ALG_SHA512
        );
    }

    #[test]
    fn test_tpm_alg_to_hash_algorithm_roundtrip() {
        for alg in [
            TpmHashAlgorithm::Sha1,
            TpmHashAlgorithm::Sha256,
            TpmHashAlgorithm::Sha384,
            TpmHashAlgorithm::Sha512,
        ] {
            let tpm_alg = hash_algorithm_to_tpm_alg(alg);
            let back = tpm_alg_to_hash_algorithm(tpm_alg);
            assert_eq!(back, Some(alg));
        }
    }

    #[test]
    fn test_tpm_alg_to_hash_algorithm_unknown() {
        assert_eq!(tpm_alg_to_hash_algorithm(0xFFFF), None);
        assert_eq!(tpm_alg_to_hash_algorithm(0x0000), None);
    }

    // ========================================
    // PCR Bitmap Tests
    // ========================================

    #[test]
    fn test_pcr_index_to_bitmap_pcr0() {
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(0);
        assert_eq!(byte_idx, 0);
        assert_eq!(bit_mask, 0b00000001);
    }

    #[test]
    fn test_pcr_index_to_bitmap_pcr7() {
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(7);
        assert_eq!(byte_idx, 0);
        assert_eq!(bit_mask, 0b10000000);
    }

    #[test]
    fn test_pcr_index_to_bitmap_pcr8() {
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(8);
        assert_eq!(byte_idx, 1);
        assert_eq!(bit_mask, 0b00000001);
    }

    #[test]
    fn test_pcr_index_to_bitmap_pcr15() {
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(15);
        assert_eq!(byte_idx, 1);
        assert_eq!(bit_mask, 0b10000000);
    }

    #[test]
    fn test_pcr_index_to_bitmap_pcr16() {
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(16);
        assert_eq!(byte_idx, 2);
        assert_eq!(bit_mask, 0b00000001);
    }

    #[test]
    fn test_pcr_index_to_bitmap_pcr23() {
        let (byte_idx, bit_mask) = pcr_index_to_bitmap(23);
        assert_eq!(byte_idx, 2);
        assert_eq!(bit_mask, 0b10000000);
    }

    #[test]
    fn test_create_pcr_select_bitmap_single() {
        let bitmap = create_pcr_select_bitmap(PcrIndex::Pcr0);
        assert_eq!(bitmap, [0b00000001, 0, 0]);

        let bitmap = create_pcr_select_bitmap(PcrIndex::Pcr7);
        assert_eq!(bitmap, [0b10000000, 0, 0]);

        let bitmap = create_pcr_select_bitmap(PcrIndex::Pcr8);
        assert_eq!(bitmap, [0, 0b00000001, 0]);
    }

    #[test]
    fn test_create_pcr_select_bitmap_multi() {
        let bitmap = create_pcr_select_bitmap_multi(&[PcrIndex::Pcr0, PcrIndex::Pcr7]);
        assert_eq!(bitmap, [0b10000001, 0, 0]);

        let bitmap =
            create_pcr_select_bitmap_multi(&[PcrIndex::Pcr0, PcrIndex::Pcr8, PcrIndex::Pcr16]);
        assert_eq!(bitmap, [0b00000001, 0b00000001, 0b00000001]);
    }

    #[test]
    fn test_create_pcr_select_bitmap_empty() {
        let bitmap = create_pcr_select_bitmap_multi(&[]);
        assert_eq!(bitmap, [0, 0, 0]);
    }

    // ========================================
    // Command Building Tests
    // ========================================

    #[test]
    fn test_build_pcr_read_command_structure() {
        let cmd = build_pcr_read_command(PcrIndex::Pcr0, TpmHashAlgorithm::Sha256);

        // Check tag
        assert_eq!(&cmd[0..2], &tags::TPM_ST_NO_SESSIONS.to_be_bytes());

        // Command structure:
        // - Tag (2) + Size (4) + Command (4) + Count (4) + Hash (2) + SizeOfSelect (1) + PcrSelect (3)
        // = 20 bytes
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        assert_eq!(size, 20);
        assert_eq!(cmd.len(), 20);

        // Check command code
        assert_eq!(&cmd[6..10], &commands::TPM2_PCR_READ.to_be_bytes());

        // Check selection count = 1
        assert_eq!(&cmd[10..14], &1u32.to_be_bytes());

        // Check hash algorithm (SHA256 = 0x000B)
        assert_eq!(&cmd[14..16], &algorithms::TPM_ALG_SHA256.to_be_bytes());

        // Check sizeOfSelect = 3
        assert_eq!(cmd[16], 3);

        // Check PCR bitmap (PCR0 = bit 0 of byte 0)
        assert_eq!(cmd[17], 0b00000001);
        assert_eq!(cmd[18], 0);
        assert_eq!(cmd[19], 0);
    }

    #[test]
    fn test_build_pcr_read_command_different_pcrs() {
        let cmd0 = build_pcr_read_command(PcrIndex::Pcr0, TpmHashAlgorithm::Sha256);
        let cmd7 = build_pcr_read_command(PcrIndex::Pcr7, TpmHashAlgorithm::Sha256);

        // Commands should be same length
        assert_eq!(cmd0.len(), cmd7.len());

        // But PCR bitmap should be different
        assert_ne!(cmd0[17..20], cmd7[17..20]);
    }

    #[test]
    fn test_build_get_random_command_structure() {
        let cmd = build_get_random_command(32);

        // Check tag
        assert_eq!(&cmd[0..2], &tags::TPM_ST_NO_SESSIONS.to_be_bytes());

        // Check size (should be 12 bytes)
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        assert_eq!(size, 12);
        assert_eq!(cmd.len(), 12);

        // Check command code
        assert_eq!(&cmd[6..10], &commands::TPM2_GET_RANDOM.to_be_bytes());

        // Check bytes requested
        assert_eq!(&cmd[10..12], &32u16.to_be_bytes());
    }

    #[test]
    fn test_build_get_random_command_different_sizes() {
        let cmd16 = build_get_random_command(16);
        let cmd32 = build_get_random_command(32);

        // Both should be 12 bytes
        assert_eq!(cmd16.len(), 12);
        assert_eq!(cmd32.len(), 12);

        // But bytes requested field differs
        assert_eq!(&cmd16[10..12], &16u16.to_be_bytes());
        assert_eq!(&cmd32[10..12], &32u16.to_be_bytes());
    }

    // ========================================
    // Response Parsing Tests
    // ========================================

    #[test]
    fn test_parse_response_header_valid() {
        let response = [
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x0A, // size = 10
            0x00, 0x00, 0x00, 0x00, // response code = success
        ];

        let (tag, size, rc) = parse_response_header(&response).unwrap();
        assert_eq!(tag, 0x8001);
        assert_eq!(size, 10);
        assert_eq!(rc, 0);
    }

    #[test]
    fn test_parse_response_header_error() {
        let response = [
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x0A, // size = 10
            0x00, 0x00, 0x01, 0x01, // response code = error
        ];

        let (tag, size, rc) = parse_response_header(&response).unwrap();
        assert_eq!(tag, 0x8001);
        assert_eq!(size, 10);
        assert_eq!(rc, 0x101);
        assert!(!is_success_response(rc));
    }

    #[test]
    fn test_parse_response_header_too_short() {
        let response = [0x80, 0x01, 0x00];
        assert!(parse_response_header(&response).is_err());
    }

    #[test]
    fn test_parse_get_random_response_valid() {
        let response = vec![
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x10, // size = 16
            0x00, 0x00, 0x00, 0x00, // response code = success
            0x00, 0x04, // random size = 4
            0xDE, 0xAD, 0xBE, 0xEF, // random data
        ];

        let random = parse_get_random_response(&response).unwrap();
        assert_eq!(random, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_get_random_response_error() {
        let response = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x01, // error code
        ];

        assert!(parse_get_random_response(&response).is_err());
    }

    #[test]
    fn test_is_success_response() {
        assert!(is_success_response(0));
        assert!(!is_success_response(0x101));
        assert!(!is_success_response(0x8028400F));
    }

    // ========================================
    // Policy Digest Tests
    // ========================================

    #[test]
    fn test_compute_policy_digest_empty() {
        let digest = compute_policy_digest(&[], None);
        // Should produce a valid 32-byte digest
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_compute_policy_digest_deterministic() {
        let pcr_values = vec![
            (PcrIndex::Pcr0, vec![0u8; 32]),
            (PcrIndex::Pcr7, vec![1u8; 32]),
        ];

        let digest1 = compute_policy_digest(&pcr_values, None);
        let digest2 = compute_policy_digest(&pcr_values, None);

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_compute_policy_digest_different_pcrs() {
        let pcr_values1 = vec![(PcrIndex::Pcr0, vec![0u8; 32])];
        let pcr_values2 = vec![(PcrIndex::Pcr7, vec![0u8; 32])];

        let digest1 = compute_policy_digest(&pcr_values1, None);
        let digest2 = compute_policy_digest(&pcr_values2, None);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_compute_policy_digest_with_auth() {
        let pcr_values = vec![(PcrIndex::Pcr0, vec![0u8; 32])];

        let digest1 = compute_policy_digest(&pcr_values, None);
        let digest2 = compute_policy_digest(&pcr_values, Some(b"password"));

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_derive_sealing_key_deterministic() {
        let tpm_random = vec![0xABu8; 32];
        let policy_digest = vec![0xCDu8; 32];

        let key1 = derive_sealing_key(&tpm_random, &policy_digest);
        let key2 = derive_sealing_key(&tpm_random, &policy_digest);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_sealing_key_different_inputs() {
        let tpm_random1 = vec![0xAAu8; 32];
        let tpm_random2 = vec![0xBBu8; 32];
        let policy_digest = vec![0xCCu8; 32];

        let key1 = derive_sealing_key(&tpm_random1, &policy_digest);
        let key2 = derive_sealing_key(&tpm_random2, &policy_digest);

        assert_ne!(key1, key2);
    }

    // ========================================
    // XOR Encryption Tests
    // ========================================

    #[test]
    fn test_xor_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, TPM!";

        let ciphertext = xor_encrypt_decrypt(plaintext, &key);
        let decrypted = xor_encrypt_decrypt(&ciphertext, &key);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xor_encrypt_decrypt_different_keys() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"Secret data";

        let ciphertext = xor_encrypt_decrypt(plaintext, &key1);
        let wrong_decrypt = xor_encrypt_decrypt(&ciphertext, &key2);

        assert_ne!(wrong_decrypt, plaintext.to_vec());
    }

    #[test]
    fn test_xor_encrypt_empty() {
        let key = [0x42u8; 32];
        let result = xor_encrypt_decrypt(&[], &key);
        assert!(result.is_empty());
    }

    // ========================================
    // Constant-Time Comparison Tests
    // ========================================

    #[test]
    fn test_constant_time_compare_equal() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 6];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        let a = [1, 2, 3];
        let b = [1, 2, 3, 4];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_empty() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert!(constant_time_compare(&a, &b));
    }

    // ========================================
    // Constants Tests
    // ========================================

    #[test]
    fn test_tpm_constants() {
        assert_eq!(tags::TPM_ST_NO_SESSIONS, 0x8001);
        assert_eq!(tags::TPM_ST_SESSIONS, 0x8002);
        assert_eq!(commands::TPM2_PCR_READ, 0x0000017E);
        assert_eq!(commands::TPM2_GET_RANDOM, 0x0000017B);
    }

    #[test]
    fn test_algorithm_constants() {
        assert_eq!(algorithms::TPM_ALG_SHA1, 0x0004);
        assert_eq!(algorithms::TPM_ALG_SHA256, 0x000B);
        assert_eq!(algorithms::TPM_ALG_SHA384, 0x000C);
        assert_eq!(algorithms::TPM_ALG_SHA512, 0x000D);
    }
}
