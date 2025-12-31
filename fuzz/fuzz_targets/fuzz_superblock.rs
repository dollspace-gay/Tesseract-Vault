// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for filesystem Superblock deserialization
//!
//! Tests the parsing of filesystem superblocks from arbitrary byte sequences.
//! The superblock contains critical filesystem metadata like block counts,
//! inode counts, and journal pointers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::Superblock;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize superblock from arbitrary data
    if let Ok(superblock) = bincode::deserialize::<Superblock>(data) {
        // If deserialization succeeds, test validation
        let _ = superblock.validate();

        // Test checksum verification (should handle any input safely)
        let _ = superblock.verify_checksum();
    }
});
