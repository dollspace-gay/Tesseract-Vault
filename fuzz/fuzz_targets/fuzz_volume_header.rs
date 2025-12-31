// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for VolumeHeader deserialization
//!
//! Tests the parsing of volume headers from arbitrary byte sequences to ensure
//! no panics, memory corruption, or undefined behavior occurs when parsing
//! malformed or malicious input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::{VolumeHeader, HEADER_SIZE};

fuzz_target!(|data: &[u8]| {
    // Only test if we have enough data for a complete header
    if data.len() >= HEADER_SIZE {
        // Test deserialization from exact-size slice
        let header_data = &data[..HEADER_SIZE];
        let _ = VolumeHeader::from_bytes(header_data);
    }

    // Also test with various sizes to check size validation
    if !data.is_empty() {
        let _ = VolumeHeader::from_bytes(data);
    }
});
