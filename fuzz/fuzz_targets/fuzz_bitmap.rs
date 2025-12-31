// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Fuzzing target for filesystem Bitmap operations
//!
//! Tests bitmap operations (block/inode allocation tracking) with
//! arbitrary data to ensure safe handling of edge cases.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::Bitmap;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Create bitmap from arbitrary data
    let mut bitmap = Bitmap::from_data(data.to_vec());

    // Test various operations that should not panic
    let total_bits = data.len() * 8;

    // Test is_set across the bitmap
    for i in 0..total_bits.min(1000) {
        let _ = bitmap.is_set(i);
    }

    // Test set/clear operations
    if total_bits > 0 {
        let test_index = data[0] as usize % total_bits;
        bitmap.set(test_index);
        let _ = bitmap.is_set(test_index);
        bitmap.clear(test_index);
    }

    // Test find_first_clear
    let _ = bitmap.find_first_clear(0);
    if total_bits > 1 {
        let start = data[0] as usize % total_bits;
        let _ = bitmap.find_first_clear(start);
    }

    // Test count operations
    let _ = bitmap.count_set();
    let _ = bitmap.count_clear(total_bits);

    // Test out-of-bounds access (should be safe)
    let _ = bitmap.is_set(usize::MAX);
    bitmap.set(usize::MAX);
    bitmap.clear(usize::MAX);
});
