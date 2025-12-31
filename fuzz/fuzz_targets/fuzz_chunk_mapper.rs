//! Fuzzing target for ChunkMapper operations
//!
//! Tests chunk offset calculations and range mapping with arbitrary inputs
//! to ensure no panics or integer overflows occur.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::{ChunkMapper, DEFAULT_CHUNK_SIZE};

/// Common sector sizes for testing
const SECTOR_SIZES: [u64; 2] = [512, 4096];

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    // Extract parameters from fuzz data
    let volume_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let chunk_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let offset = u64::from_le_bytes(data[16..24].try_into().unwrap());

    // Skip invalid configurations
    if chunk_size == 0 || volume_size == 0 {
        return;
    }

    // Test with various chunk sizes (must be within valid range: 64KB - 64MB)
    let chunk_sizes = [
        chunk_size.clamp(64 * 1024, 64 * 1024 * 1024),
        DEFAULT_CHUNK_SIZE,
        64 * 1024,      // MIN_CHUNK_SIZE
        4 * 1024 * 1024, // 4MB
    ];

    for cs in chunk_sizes {
        for sector_size in SECTOR_SIZES {
            // ChunkMapper::new takes 3 args: volume_size, chunk_size, sector_size
            if let Ok(mapper) = ChunkMapper::new(volume_size, cs, sector_size) {
                // Test chunk calculations
                let _ = mapper.total_chunks();
                let _ = mapper.chunk_size();
                let _ = mapper.volume_size();
                let _ = mapper.sector_size();
                let _ = mapper.sectors_per_chunk();
                let _ = mapper.total_sectors();

                // Test offset mapping (may return error for out-of-bounds)
                let _ = mapper.map_offset(offset);
                let _ = mapper.global_sector_index(offset);

                // Test chunk actual size
                let _ = mapper.chunk_actual_size(offset / cs);

                // Test logical offset conversion
                let chunk_id = offset / cs;
                let chunk_offset = offset % cs;
                let _ = mapper.to_logical_offset(chunk_id, chunk_offset);

                // Test range calculations if we have enough data
                if data.len() >= 32 {
                    let length = u64::from_le_bytes(data[24..32].try_into().unwrap());
                    if length > 0 && length < 1 << 30 {
                        let _ = mapper.map_range(offset, length);
                    }
                }
            }
        }
    }
});
