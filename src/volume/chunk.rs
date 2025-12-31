//! Volume-level chunk mapping for logical offset translation
//!
//! This module provides functionality to map logical byte offsets within an
//! encrypted volume to chunk IDs and chunk-relative offsets. This is essential
//! for efficient random access within large encrypted volumes.
//!
//! ## Chunking Strategy
//!
//! The volume data area is divided into fixed-size chunks (default 4MB).
//! Each chunk is independently addressable and can be:
//! - Encrypted/decrypted independently (using sector-based XTS encryption)
//! - Cached independently for performance
//! - Mapped to underlying storage sectors
//!
//! ## Mapping Example
//!
//! For a volume with 4MB (4,194,304 bytes) chunks:
//! - Logical offset 0 → Chunk 0, offset 0
//! - Logical offset 5,000,000 → Chunk 1, offset 805,696
//! - Logical offset 12,000,000 → Chunk 2, offset 3,611,392
//!
//! ## Integration with Sector Encryption
//!
//! Chunks contain multiple sectors. The chunk-relative offset is further
//! divided into sector index and sector-relative offset for encryption.

use thiserror::Error;

/// Default chunk size: 4 MB (4,194,304 bytes)
/// This is a good balance between:
/// - Memory efficiency (not too large for caching)
/// - I/O efficiency (large enough for sequential reads)
/// - Encryption overhead (chunk boundaries align with sector boundaries)
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Minimum chunk size: 64 KB
/// Smaller chunks reduce memory usage but increase metadata overhead
pub const MIN_CHUNK_SIZE: u64 = 64 * 1024;

/// Maximum chunk size: 64 MB
/// Larger chunks improve sequential performance but use more memory
pub const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;

/// Errors that can occur during chunk mapping
#[derive(Debug, Error)]
pub enum ChunkError {
    /// Offset is beyond the volume size
    #[error("Offset {offset} is beyond volume size {volume_size}")]
    OffsetOutOfBounds { offset: u64, volume_size: u64 },

    /// Invalid chunk size configuration
    #[error("Invalid chunk size: {0} (must be between {} and {} bytes)", MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)]
    InvalidChunkSize(u64),

    /// Chunk size must be aligned to sector size
    #[error("Chunk size {chunk_size} must be a multiple of sector size {sector_size}")]
    ChunkSectorMisalignment { chunk_size: u64, sector_size: u64 },
}

pub type Result<T> = std::result::Result<T, ChunkError>;

/// Result of mapping a logical offset to chunk coordinates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLocation {
    /// The chunk ID (0-indexed)
    pub chunk_id: u64,
    /// Byte offset within the chunk
    pub chunk_offset: u64,
    /// The original logical offset that was mapped
    pub logical_offset: u64,
}

impl ChunkLocation {
    /// Returns the sector index within this chunk
    ///
    /// # Arguments
    ///
    /// * `sector_size` - Size of each sector in bytes
    pub fn sector_index(&self, sector_size: u64) -> u64 {
        self.chunk_offset / sector_size
    }

    /// Returns the byte offset within the sector
    ///
    /// # Arguments
    ///
    /// * `sector_size` - Size of each sector in bytes
    pub fn sector_offset(&self, sector_size: u64) -> u64 {
        self.chunk_offset % sector_size
    }

    /// Returns the global sector index (across all chunks)
    ///
    /// # Arguments
    ///
    /// * `sector_size` - Size of each sector in bytes
    /// * `chunk_size` - Size of each chunk in bytes
    pub fn global_sector_index(&self, sector_size: u64, chunk_size: u64) -> u64 {
        let sectors_per_chunk = chunk_size / sector_size;
        (self.chunk_id * sectors_per_chunk) + self.sector_index(sector_size)
    }
}

/// Result of mapping a byte range to chunk coordinates
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRange {
    /// The starting chunk location
    pub start: ChunkLocation,
    /// The ending chunk location (exclusive)
    pub end: ChunkLocation,
    /// Total number of chunks touched by this range
    pub chunk_count: u64,
    /// Total bytes in the range
    pub total_bytes: u64,
}

impl ChunkRange {
    /// Returns an iterator over chunk IDs in this range
    pub fn chunk_ids(&self) -> impl Iterator<Item = u64> {
        self.start.chunk_id..=self.end.chunk_id
    }

    /// Returns whether this range spans multiple chunks
    pub fn spans_multiple_chunks(&self) -> bool {
        self.chunk_count > 1
    }
}

/// Chunk mapper for translating logical offsets to chunk coordinates
///
/// This struct provides efficient mapping between logical byte offsets
/// in a volume and their corresponding chunk locations.
#[derive(Debug, Clone)]
pub struct ChunkMapper {
    /// Size of each chunk in bytes
    chunk_size: u64,
    /// Total size of the data area in bytes
    volume_size: u64,
    /// Sector size for sub-chunk addressing
    sector_size: u64,
    /// Total number of chunks in the volume
    total_chunks: u64,
    /// Number of sectors per chunk
    sectors_per_chunk: u64,
}

impl ChunkMapper {
    /// Creates a new chunk mapper
    ///
    /// # Arguments
    ///
    /// * `volume_size` - Total size of the volume data area in bytes
    /// * `chunk_size` - Size of each chunk in bytes
    /// * `sector_size` - Size of each sector in bytes
    ///
    /// # Returns
    ///
    /// A new ChunkMapper instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Chunk size is not within valid range
    /// - Chunk size is not a multiple of sector size
    pub fn new(volume_size: u64, chunk_size: u64, sector_size: u64) -> Result<Self> {
        // Validate chunk size
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(ChunkError::InvalidChunkSize(chunk_size));
        }

        // Chunk size must be aligned to sector size
        if !chunk_size.is_multiple_of(sector_size) {
            return Err(ChunkError::ChunkSectorMisalignment { chunk_size, sector_size });
        }

        let total_chunks = volume_size.div_ceil(chunk_size);
        let sectors_per_chunk = chunk_size / sector_size;

        Ok(Self {
            chunk_size,
            volume_size,
            sector_size,
            total_chunks,
            sectors_per_chunk,
        })
    }

    /// Creates a chunk mapper with default chunk size (4MB)
    ///
    /// # Arguments
    ///
    /// * `volume_size` - Total size of the volume data area in bytes
    /// * `sector_size` - Size of each sector in bytes
    pub fn with_defaults(volume_size: u64, sector_size: u64) -> Result<Self> {
        Self::new(volume_size, DEFAULT_CHUNK_SIZE, sector_size)
    }

    /// Maps a logical byte offset to chunk coordinates
    ///
    /// # Arguments
    ///
    /// * `offset` - Logical byte offset within the volume
    ///
    /// # Returns
    ///
    /// Chunk location containing chunk ID and chunk-relative offset
    ///
    /// # Errors
    ///
    /// Returns an error if offset is beyond volume size
    pub fn map_offset(&self, offset: u64) -> Result<ChunkLocation> {
        if offset >= self.volume_size {
            return Err(ChunkError::OffsetOutOfBounds {
                offset,
                volume_size: self.volume_size,
            });
        }

        let chunk_id = offset / self.chunk_size;
        let chunk_offset = offset % self.chunk_size;

        Ok(ChunkLocation {
            chunk_id,
            chunk_offset,
            logical_offset: offset,
        })
    }

    /// Maps a byte range to chunk coordinates
    ///
    /// # Arguments
    ///
    /// * `start_offset` - Starting logical byte offset
    /// * `length` - Number of bytes in the range
    ///
    /// # Returns
    ///
    /// Chunk range describing all chunks touched by this range
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Start offset is beyond volume size
    /// - Range extends beyond volume size
    pub fn map_range(&self, start_offset: u64, length: u64) -> Result<ChunkRange> {
        if start_offset >= self.volume_size {
            return Err(ChunkError::OffsetOutOfBounds {
                offset: start_offset,
                volume_size: self.volume_size,
            });
        }

        // Clamp end to volume size (use saturating_add to prevent overflow)
        let end_offset = start_offset.saturating_add(length).min(self.volume_size);
        let actual_length = end_offset - start_offset;

        let start = self.map_offset(start_offset)?;

        // End is exclusive, so we need the last byte's location
        let end = if end_offset == 0 {
            start
        } else {
            self.map_offset(end_offset.saturating_sub(1))?
        };

        let chunk_count = end.chunk_id - start.chunk_id + 1;

        Ok(ChunkRange {
            start,
            end,
            chunk_count,
            total_bytes: actual_length,
        })
    }

    /// Converts a chunk ID and chunk offset back to a logical offset
    ///
    /// # Arguments
    ///
    /// * `chunk_id` - The chunk ID
    /// * `chunk_offset` - Offset within the chunk
    ///
    /// # Returns
    ///
    /// The logical byte offset, or None if out of bounds
    pub fn to_logical_offset(&self, chunk_id: u64, chunk_offset: u64) -> Option<u64> {
        let offset = chunk_id * self.chunk_size + chunk_offset;
        if offset < self.volume_size {
            Some(offset)
        } else {
            None
        }
    }

    /// Returns the global sector index for a logical offset
    ///
    /// This is the sector index used by the SectorCipher for encryption.
    ///
    /// # Arguments
    ///
    /// * `offset` - Logical byte offset within the volume
    pub fn global_sector_index(&self, offset: u64) -> Result<u64> {
        let location = self.map_offset(offset)?;
        Ok(location.global_sector_index(self.sector_size, self.chunk_size))
    }

    /// Returns the chunk size
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Returns the volume size
    pub fn volume_size(&self) -> u64 {
        self.volume_size
    }

    /// Returns the sector size
    pub fn sector_size(&self) -> u64 {
        self.sector_size
    }

    /// Returns the total number of chunks
    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    /// Returns the number of sectors per chunk
    pub fn sectors_per_chunk(&self) -> u64 {
        self.sectors_per_chunk
    }

    /// Returns the total number of sectors in the volume
    pub fn total_sectors(&self) -> u64 {
        self.volume_size.div_ceil(self.sector_size)
    }

    /// Returns the size of a specific chunk (last chunk may be smaller)
    ///
    /// # Arguments
    ///
    /// * `chunk_id` - The chunk ID to get the size of
    pub fn chunk_actual_size(&self, chunk_id: u64) -> Option<u64> {
        if chunk_id >= self.total_chunks {
            return None;
        }

        if chunk_id == self.total_chunks - 1 {
            // Last chunk may be partial
            let remaining = self.volume_size % self.chunk_size;
            if remaining == 0 {
                Some(self.chunk_size)
            } else {
                Some(remaining)
            }
        } else {
            Some(self.chunk_size)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECTOR_SIZE: u64 = 4096; // 4KB sectors
    const TEST_CHUNK_SIZE: u64 = 4 * 1024 * 1024; // 4MB chunks

    #[test]
    fn test_chunk_mapper_creation() {
        let volume_size = 100 * 1024 * 1024; // 100 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        assert_eq!(mapper.chunk_size(), TEST_CHUNK_SIZE);
        assert_eq!(mapper.volume_size(), volume_size);
        assert_eq!(mapper.sector_size(), TEST_SECTOR_SIZE);
        assert_eq!(mapper.total_chunks(), 25); // 100MB / 4MB = 25
        assert_eq!(mapper.sectors_per_chunk(), 1024); // 4MB / 4KB = 1024
    }

    #[test]
    fn test_chunk_mapper_with_defaults() {
        let volume_size = 50 * 1024 * 1024; // 50 MB
        let mapper = ChunkMapper::with_defaults(volume_size, TEST_SECTOR_SIZE).unwrap();

        assert_eq!(mapper.chunk_size(), DEFAULT_CHUNK_SIZE);
        assert_eq!(mapper.total_chunks(), 13); // ceil(50 / 4) = 13
    }

    #[test]
    fn test_invalid_chunk_size() {
        let volume_size = 100 * 1024 * 1024;

        // Too small
        assert!(ChunkMapper::new(volume_size, MIN_CHUNK_SIZE - 1, TEST_SECTOR_SIZE).is_err());

        // Too large
        assert!(ChunkMapper::new(volume_size, MAX_CHUNK_SIZE + 1, TEST_SECTOR_SIZE).is_err());

        // Not aligned to sector size
        assert!(ChunkMapper::new(volume_size, 1024 * 1024 + 1, TEST_SECTOR_SIZE).is_err());
    }

    #[test]
    fn test_map_offset_basic() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Offset 0 -> Chunk 0, offset 0
        let loc = mapper.map_offset(0).unwrap();
        assert_eq!(loc.chunk_id, 0);
        assert_eq!(loc.chunk_offset, 0);
        assert_eq!(loc.logical_offset, 0);

        // Offset 1000 -> Chunk 0, offset 1000
        let loc = mapper.map_offset(1000).unwrap();
        assert_eq!(loc.chunk_id, 0);
        assert_eq!(loc.chunk_offset, 1000);

        // Offset 5,000,000 -> Chunk 1, offset 805,696 (5M - 4M = 1M - 194304)
        let loc = mapper.map_offset(5_000_000).unwrap();
        assert_eq!(loc.chunk_id, 1);
        assert_eq!(loc.chunk_offset, 5_000_000 - TEST_CHUNK_SIZE);

        // Offset at chunk boundary -> Chunk 1, offset 0
        let loc = mapper.map_offset(TEST_CHUNK_SIZE).unwrap();
        assert_eq!(loc.chunk_id, 1);
        assert_eq!(loc.chunk_offset, 0);
    }

    #[test]
    fn test_map_offset_out_of_bounds() {
        let volume_size = 10 * 1024 * 1024; // 10 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Exactly at volume size - should fail
        assert!(mapper.map_offset(volume_size).is_err());

        // Beyond volume size - should fail
        assert!(mapper.map_offset(volume_size + 1).is_err());
    }

    #[test]
    fn test_sector_addressing() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Offset in first sector of first chunk
        let loc = mapper.map_offset(100).unwrap();
        assert_eq!(loc.sector_index(TEST_SECTOR_SIZE), 0);
        assert_eq!(loc.sector_offset(TEST_SECTOR_SIZE), 100);

        // Offset in second sector of first chunk
        let loc = mapper.map_offset(5000).unwrap();
        assert_eq!(loc.sector_index(TEST_SECTOR_SIZE), 1); // 5000 / 4096 = 1
        assert_eq!(loc.sector_offset(TEST_SECTOR_SIZE), 904); // 5000 % 4096 = 904

        // Global sector index for offset in second chunk
        let loc = mapper.map_offset(TEST_CHUNK_SIZE + 8192).unwrap();
        // Chunk 1, sector 2 within chunk
        assert_eq!(loc.chunk_id, 1);
        assert_eq!(loc.sector_index(TEST_SECTOR_SIZE), 2);
        // Global sector = 1024 sectors in chunk 0 + 2 = 1026
        assert_eq!(loc.global_sector_index(TEST_SECTOR_SIZE, TEST_CHUNK_SIZE), 1026);
    }

    #[test]
    fn test_map_range_single_chunk() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Range within single chunk
        let range = mapper.map_range(1000, 5000).unwrap();
        assert_eq!(range.start.chunk_id, 0);
        assert_eq!(range.end.chunk_id, 0);
        assert_eq!(range.chunk_count, 1);
        assert_eq!(range.total_bytes, 5000);
        assert!(!range.spans_multiple_chunks());
    }

    #[test]
    fn test_map_range_multiple_chunks() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Range spanning chunk boundary
        let start = TEST_CHUNK_SIZE - 1000; // 1000 bytes before end of chunk 0
        let range = mapper.map_range(start, 5000).unwrap();
        assert_eq!(range.start.chunk_id, 0);
        assert_eq!(range.end.chunk_id, 1);
        assert_eq!(range.chunk_count, 2);
        assert!(range.spans_multiple_chunks());

        // Verify chunk IDs iterator
        let chunk_ids: Vec<u64> = range.chunk_ids().collect();
        assert_eq!(chunk_ids, vec![0, 1]);
    }

    #[test]
    fn test_map_range_multiple_full_chunks() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Range spanning 3 full chunks
        let range = mapper.map_range(0, TEST_CHUNK_SIZE * 3).unwrap();
        assert_eq!(range.start.chunk_id, 0);
        assert_eq!(range.end.chunk_id, 2);
        assert_eq!(range.chunk_count, 3);
    }

    #[test]
    fn test_map_range_clamped_to_volume() {
        let volume_size = 10 * 1024 * 1024; // 10 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Range extends beyond volume - should be clamped
        let range = mapper.map_range(9 * 1024 * 1024, 10 * 1024 * 1024).unwrap();
        assert_eq!(range.total_bytes, 1024 * 1024); // Only 1 MB actual
    }

    #[test]
    fn test_to_logical_offset() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Chunk 0, offset 0 -> logical 0
        assert_eq!(mapper.to_logical_offset(0, 0), Some(0));

        // Chunk 0, offset 1000 -> logical 1000
        assert_eq!(mapper.to_logical_offset(0, 1000), Some(1000));

        // Chunk 1, offset 0 -> logical 4MB
        assert_eq!(mapper.to_logical_offset(1, 0), Some(TEST_CHUNK_SIZE));

        // Chunk 1, offset 1000 -> logical 4MB + 1000
        assert_eq!(mapper.to_logical_offset(1, 1000), Some(TEST_CHUNK_SIZE + 1000));

        // Beyond volume - should return None
        assert_eq!(mapper.to_logical_offset(100, 0), None);
    }

    #[test]
    fn test_global_sector_index() {
        let volume_size = 20 * 1024 * 1024; // 20 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // First sector
        assert_eq!(mapper.global_sector_index(0).unwrap(), 0);

        // Second sector in first chunk
        assert_eq!(mapper.global_sector_index(TEST_SECTOR_SIZE).unwrap(), 1);

        // First sector in second chunk
        assert_eq!(mapper.global_sector_index(TEST_CHUNK_SIZE).unwrap(), 1024);

        // Second sector in second chunk
        assert_eq!(mapper.global_sector_index(TEST_CHUNK_SIZE + TEST_SECTOR_SIZE).unwrap(), 1025);
    }

    #[test]
    fn test_chunk_actual_size() {
        // Volume size not aligned to chunk size
        let volume_size = 10 * 1024 * 1024 + 1000; // 10MB + 1000 bytes
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Total chunks = ceil((10MB + 1000) / 4MB) = 3
        assert_eq!(mapper.total_chunks(), 3);

        // First two chunks are full size
        assert_eq!(mapper.chunk_actual_size(0), Some(TEST_CHUNK_SIZE));
        assert_eq!(mapper.chunk_actual_size(1), Some(TEST_CHUNK_SIZE));

        // Last chunk is partial: 10MB + 1000 - 8MB = 2MB + 1000
        let expected_last = volume_size - 2 * TEST_CHUNK_SIZE;
        assert_eq!(mapper.chunk_actual_size(2), Some(expected_last));

        // Non-existent chunk
        assert_eq!(mapper.chunk_actual_size(3), None);
    }

    #[test]
    fn test_total_sectors() {
        let volume_size = 10 * 1024 * 1024; // 10 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // 10 MB / 4 KB = 2560 sectors
        assert_eq!(mapper.total_sectors(), 2560);
    }

    #[test]
    fn test_roundtrip_mapping() {
        let volume_size = 50 * 1024 * 1024; // 50 MB
        let mapper = ChunkMapper::new(volume_size, TEST_CHUNK_SIZE, TEST_SECTOR_SIZE).unwrap();

        // Test various offsets for roundtrip
        for offset in [0, 1000, TEST_CHUNK_SIZE - 1, TEST_CHUNK_SIZE,
                       TEST_CHUNK_SIZE + 1000, volume_size - 1] {
            let loc = mapper.map_offset(offset).unwrap();
            let recovered = mapper.to_logical_offset(loc.chunk_id, loc.chunk_offset);
            assert_eq!(recovered, Some(offset), "Roundtrip failed for offset {}", offset);
        }
    }
}
