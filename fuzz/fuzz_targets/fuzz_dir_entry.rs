// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for DirEntry deserialization
//!
//! Tests the parsing of directory entries from arbitrary byte sequences.
//! Directory entries contain inode references and filenames.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::FsDirEntry;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize directory entry from arbitrary data
    if let Ok(entry) = postcard::from_bytes::<FsDirEntry>(data) {
        // If deserialization succeeds, test accessor methods
        let _ = entry.is_deleted();
        let _ = entry.size();

        // Test name_str (may return Utf8Error for invalid UTF-8)
        let _ = entry.name_str();
    }
});
