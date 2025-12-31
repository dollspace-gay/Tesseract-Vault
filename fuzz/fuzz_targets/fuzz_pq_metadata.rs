// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for Post-Quantum metadata deserialization
//!
//! Tests the parsing of PQ volume metadata (ML-KEM-1024 encapsulation keys,
//! ciphertexts, and encrypted decapsulation keys) from arbitrary byte sequences.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::{PqVolumeMetadata, PQ_METADATA_SIZE};

fuzz_target!(|data: &[u8]| {
    // Test deserialization from arbitrary data
    let _ = PqVolumeMetadata::from_bytes(data);

    // Test with exact expected size
    if data.len() >= PQ_METADATA_SIZE {
        let _ = PqVolumeMetadata::from_bytes(&data[..PQ_METADATA_SIZE]);
    }
});
