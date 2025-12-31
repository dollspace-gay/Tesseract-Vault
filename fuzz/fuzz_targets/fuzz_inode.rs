// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for Inode deserialization
//!
//! Tests the parsing of filesystem inodes from arbitrary byte sequences.
//! Inodes store file metadata including type, permissions, timestamps,
//! and block pointers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::{Inode, INODE_SIZE};

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize inode from arbitrary data
    if let Ok(inode) = bincode::deserialize::<Inode>(data) {
        // If deserialization succeeds, test accessor methods
        let _ = inode.file_type();
        let _ = inode.permissions();
        let _ = inode.is_dir();
        let _ = inode.is_file();
        let _ = inode.is_symlink();

        // Test block calculations
        if inode.size > 0 {
            let _ = inode.block_index_for_offset(0);
            let _ = inode.block_index_for_offset(inode.size.saturating_sub(1));
        }
    }

    // Test with exact inode size if we have enough data
    if data.len() >= INODE_SIZE as usize {
        let _ = bincode::deserialize::<Inode>(&data[..INODE_SIZE as usize]);
    }
});
