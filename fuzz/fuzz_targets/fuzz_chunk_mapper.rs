//! Fuzzing target for ChunkMapper operations
//!
//! Tests chunk offset calculations and range mapping with arbitrary inputs
//! to ensure no panics or integer overflows occur.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::{ChunkMapper, DEFAULT_CHUNK_SIZE};

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    // Extract parameters from fuzz data
    let volume_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let chunk_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let offset = u64::from_le_bytes(data[16..24].try_into().unwrap());

    // Skip invalid configurations (chunk_size == 0 would cause division by zero)
    // The library should handle this, but we can also test with valid sizes
    if chunk_size == 0 || volume_size == 0 {
        return;
    }

    // Test with various chunk sizes
    let chunk_sizes = [
        chunk_size.min(1 << 30), // Limit to 1GB chunks
        DEFAULT_CHUNK_SIZE as u64,
        512,
        4096,
        65536,
    ];

    for cs in chunk_sizes {
        if cs == 0 {
            continue;
        }

        if let Ok(mapper) = ChunkMapper::new(volume_size, cs) {
            // Test chunk calculations
            let _ = mapper.total_chunks();
            let _ = mapper.chunk_index(offset);
            let _ = mapper.offset_in_chunk(offset);

            // Test chunk location
            let _ = mapper.chunk_location(offset);

            // Test range calculations if we have enough data
            if data.len() >= 32 {
                let length = u64::from_le_bytes(data[24..32].try_into().unwrap());
                if length > 0 && length < 1 << 30 {
                    let _ = mapper.chunk_range(offset, length);
                }
            }
        }
    }
});
