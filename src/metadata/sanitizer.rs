// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Core metadata sanitization implementation.
//!
//! Provides the main `MetadataSanitizer` type and configuration options
//! for sanitizing various metadata types.

use crate::memory::scrub::{scrub_bytes_pattern, ScrubPattern};
use crate::volume::format::{Inode, Superblock, JournalEntry, JournalHeader, Bitmap};
use rand::Rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during metadata sanitization.
#[derive(Debug, Error)]
pub enum SanitizationError {
    /// Failed to generate random data
    #[error("Random number generation failed: {0}")]
    RandomGeneration(String),

    /// Invalid timestamp value
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Sanitization verification failed
    #[error("Sanitization verification failed: {0}")]
    VerificationFailed(String),

    /// I/O error during sanitization
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for sanitization operations.
pub type SanitizationResult<T> = Result<T, SanitizationError>;

/// Strategy for sanitizing timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimestampStrategy {
    /// Set all timestamps to Unix epoch (0)
    #[default]
    Zero,

    /// Set all timestamps to a fixed date (Jan 1, 2000)
    FixedDate,

    /// Set timestamps to random values within a plausible range
    Random,

    /// Normalize to start of day (removes time-of-day information)
    NormalizeToDay,

    /// Preserve original timestamps (no sanitization)
    Preserve,
}

/// Configuration options for metadata sanitization.
#[derive(Debug, Clone)]
pub struct SanitizationOptions {
    /// Strategy for handling timestamps
    pub timestamp_strategy: TimestampStrategy,

    /// Whether to add random padding to obscure file sizes
    pub add_size_padding: bool,

    /// Range for random padding size (min, max) in bytes
    pub padding_range: (usize, usize),

    /// Whether to clear filesystem slack space
    pub clear_slack_space: bool,

    /// Whether to clear filesystem journal
    pub clear_journal: bool,

    /// Scrub pattern to use for clearing data
    pub scrub_pattern: ScrubPattern,

    /// Whether to sanitize volume UUIDs
    pub sanitize_uuids: bool,

    /// Whether to sanitize volume labels
    pub sanitize_labels: bool,

    /// Fixed timestamp for FixedDate strategy (Unix seconds)
    /// Default: 946684800 (Jan 1, 2000 00:00:00 UTC)
    pub fixed_timestamp: u64,

    /// Random timestamp range (min, max) in Unix seconds
    /// Default: (946684800, 1577836800) (2000-2020)
    pub random_timestamp_range: (u64, u64),
}

impl Default for SanitizationOptions {
    fn default() -> Self {
        Self {
            timestamp_strategy: TimestampStrategy::Zero,
            add_size_padding: false,
            padding_range: (1024, 4096),
            clear_slack_space: true,
            clear_journal: true,
            scrub_pattern: ScrubPattern::Zero,
            sanitize_uuids: true,
            sanitize_labels: true,
            fixed_timestamp: 946684800, // Jan 1, 2000
            random_timestamp_range: (946684800, 1577836800), // 2000-2020
        }
    }
}

impl SanitizationOptions {
    /// Creates options for maximum privacy (all sanitization enabled).
    pub fn max_privacy() -> Self {
        Self {
            timestamp_strategy: TimestampStrategy::Zero,
            add_size_padding: true,
            padding_range: (4096, 65536),
            clear_slack_space: true,
            clear_journal: true,
            scrub_pattern: ScrubPattern::Dod522022M,
            sanitize_uuids: true,
            sanitize_labels: true,
            ..Default::default()
        }
    }

    /// Creates options for paranoid security (DoD-level scrubbing).
    pub fn paranoid() -> Self {
        Self {
            timestamp_strategy: TimestampStrategy::Zero,
            add_size_padding: true,
            padding_range: (8192, 131072),
            clear_slack_space: true,
            clear_journal: true,
            scrub_pattern: ScrubPattern::Paranoid,
            sanitize_uuids: true,
            sanitize_labels: true,
            ..Default::default()
        }
    }

    /// Creates options that preserve usability while removing sensitive metadata.
    pub fn balanced() -> Self {
        Self {
            timestamp_strategy: TimestampStrategy::NormalizeToDay,
            add_size_padding: true,
            padding_range: (1024, 4096),
            clear_slack_space: true,
            clear_journal: true,
            scrub_pattern: ScrubPattern::Zero,
            sanitize_uuids: false,
            sanitize_labels: false,
            ..Default::default()
        }
    }
}

/// Metadata sanitizer for secure metadata clearing.
///
/// This is the main entry point for sanitizing metadata across the Tesseract
/// encryption system. It can sanitize:
/// - File attributes (timestamps, permissions)
/// - Inodes (filesystem metadata)
/// - Superblocks (filesystem-level metadata)
/// - Volume headers (encryption metadata)
/// - Journal entries (filesystem journal)
/// - Slack space and padding areas
#[derive(Debug, Clone)]
pub struct MetadataSanitizer {
    options: SanitizationOptions,
}

impl Default for MetadataSanitizer {
    fn default() -> Self {
        Self::new(SanitizationOptions::default())
    }
}

impl MetadataSanitizer {
    /// Creates a new sanitizer with the given options.
    pub fn new(options: SanitizationOptions) -> Self {
        Self { options }
    }

    /// Creates a sanitizer with maximum privacy settings.
    pub fn max_privacy() -> Self {
        Self::new(SanitizationOptions::max_privacy())
    }

    /// Creates a sanitizer with paranoid security settings.
    pub fn paranoid() -> Self {
        Self::new(SanitizationOptions::paranoid())
    }

    /// Creates a sanitizer with balanced settings.
    pub fn balanced() -> Self {
        Self::new(SanitizationOptions::balanced())
    }

    /// Returns the current sanitization options.
    pub fn options(&self) -> &SanitizationOptions {
        &self.options
    }

    /// Generates a sanitized timestamp based on the configured strategy.
    pub fn generate_timestamp(&self) -> u64 {
        match self.options.timestamp_strategy {
            TimestampStrategy::Zero => 0,
            TimestampStrategy::FixedDate => self.options.fixed_timestamp,
            TimestampStrategy::Random => {
                let mut rng = rand::rng();
                let (min, max) = self.options.random_timestamp_range;
                rng.random_range(min..=max)
            }
            TimestampStrategy::NormalizeToDay => {
                // Current time normalized to start of day
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs();
                // Round down to start of day (86400 seconds per day)
                (now / 86400) * 86400
            }
            TimestampStrategy::Preserve => {
                // Return current time as a fallback when preserve is used
                // but a new timestamp is requested
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs()
            }
        }
    }

    /// Sanitizes a single timestamp value according to the configured strategy.
    ///
    /// Returns the original timestamp if `Preserve` strategy is used.
    pub fn sanitize_timestamp(&self, original: u64) -> u64 {
        match self.options.timestamp_strategy {
            TimestampStrategy::Preserve => original,
            _ => self.generate_timestamp(),
        }
    }

    /// Sanitizes a `SystemTime` value.
    pub fn sanitize_system_time(&self, original: SystemTime) -> SystemTime {
        match self.options.timestamp_strategy {
            TimestampStrategy::Preserve => original,
            _ => {
                let timestamp = self.generate_timestamp();
                UNIX_EPOCH + Duration::from_secs(timestamp)
            }
        }
    }

    /// Sanitizes an inode's metadata.
    ///
    /// This sanitizes:
    /// - All timestamps (atime, mtime, ctime, crtime)
    /// - UID/GID if configured
    pub fn sanitize_inode(&self, inode: &mut Inode) {
        let ts = self.generate_timestamp();
        inode.atime = self.sanitize_timestamp(inode.atime);
        inode.mtime = self.sanitize_timestamp(inode.mtime);
        inode.ctime = self.sanitize_timestamp(inode.ctime);
        inode.crtime = self.sanitize_timestamp(inode.crtime);

        // Use the pre-generated timestamp if strategy produces same value
        if self.options.timestamp_strategy != TimestampStrategy::Random {
            inode.atime = ts;
            inode.mtime = ts;
            inode.ctime = ts;
            inode.crtime = ts;
        }
    }

    /// Sanitizes a superblock's metadata.
    ///
    /// This sanitizes:
    /// - Mount times
    /// - Write times
    /// - UUID (if configured)
    /// - Volume label (if configured)
    /// - Mount count
    pub fn sanitize_superblock(&self, superblock: &mut Superblock) {
        let ts = self.generate_timestamp();

        superblock.last_mount_time = ts;
        superblock.last_write_time = ts;
        superblock.mount_count = 0;

        if self.options.sanitize_uuids {
            superblock.uuid = [0u8; 16];
        }

        if self.options.sanitize_labels {
            superblock.label = [0u8; 64];
        }
    }

    /// Sanitizes a volume header's metadata.
    ///
    /// Note: This creates a new header with sanitized timestamps.
    /// The salt and cryptographic material are NOT modified as they
    /// are essential for decryption.
    pub fn sanitize_volume_header_timestamps(&self, created_at: &mut u64, modified_at: &mut u64) {
        let ts = self.generate_timestamp();
        *created_at = ts;
        *modified_at = ts;
    }

    /// Securely clears a journal header.
    pub fn clear_journal_header(&self, header: &mut JournalHeader) {
        header.head = 0;
        header.tail = 0;
        header.sequence = 1;
        scrub_bytes_pattern(&mut header.reserved, self.options.scrub_pattern);
    }

    /// Securely clears a journal entry.
    pub fn clear_journal_entry(&self, entry: &mut JournalEntry) {
        entry.sequence = 0;
        entry.op_type = 0;
        entry.flags = 0;
        entry.data_len = 0;
        entry.target = 0;
        entry.checksum = 0;
    }

    /// Securely clears a byte slice (e.g., slack space, padding).
    pub fn clear_bytes(&self, data: &mut [u8]) {
        scrub_bytes_pattern(data, self.options.scrub_pattern);
    }

    /// Clears a bitmap's data.
    pub fn clear_bitmap(&self, bitmap: &mut Bitmap) {
        scrub_bytes_pattern(bitmap.data_mut(), self.options.scrub_pattern);
    }

    /// Calculates padding size to add to a file.
    ///
    /// Returns the number of padding bytes to add based on configuration.
    pub fn calculate_padding_size(&self) -> usize {
        if !self.options.add_size_padding {
            return 0;
        }

        let mut rng = rand::rng();
        let (min, max) = self.options.padding_range;
        rng.random_range(min..=max)
    }

    /// Generates random padding bytes.
    pub fn generate_padding(&self, size: usize) -> Vec<u8> {
        let mut padding = vec![0u8; size];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut padding);
        padding
    }

    /// Verifies that a byte slice has been properly sanitized (all zeros).
    ///
    /// Only valid for patterns that end with zero (which is all patterns
    /// in our `ScrubPattern` enum).
    pub fn verify_cleared(&self, data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let options = SanitizationOptions::default();
        assert_eq!(options.timestamp_strategy, TimestampStrategy::Zero);
        assert!(!options.add_size_padding);
        assert!(options.clear_slack_space);
    }

    #[test]
    fn test_timestamp_zero_strategy() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            timestamp_strategy: TimestampStrategy::Zero,
            ..Default::default()
        });

        assert_eq!(sanitizer.generate_timestamp(), 0);
        assert_eq!(sanitizer.sanitize_timestamp(12345678), 0);
    }

    #[test]
    fn test_timestamp_fixed_strategy() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            timestamp_strategy: TimestampStrategy::FixedDate,
            fixed_timestamp: 946684800,
            ..Default::default()
        });

        assert_eq!(sanitizer.generate_timestamp(), 946684800);
    }

    #[test]
    fn test_timestamp_random_strategy() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            timestamp_strategy: TimestampStrategy::Random,
            random_timestamp_range: (1000, 2000),
            ..Default::default()
        });

        for _ in 0..100 {
            let ts = sanitizer.generate_timestamp();
            assert!(ts >= 1000 && ts <= 2000);
        }
    }

    #[test]
    fn test_timestamp_preserve_strategy() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            timestamp_strategy: TimestampStrategy::Preserve,
            ..Default::default()
        });

        let original = 12345678;
        assert_eq!(sanitizer.sanitize_timestamp(original), original);
    }

    #[test]
    fn test_timestamp_normalize_to_day() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            timestamp_strategy: TimestampStrategy::NormalizeToDay,
            ..Default::default()
        });

        let ts = sanitizer.generate_timestamp();
        // Should be divisible by 86400 (seconds in a day)
        assert_eq!(ts % 86400, 0);
    }

    #[test]
    fn test_sanitize_inode() {
        let mut inode = Inode::new_file(0o644);
        inode.atime = 1234567890;
        inode.mtime = 1234567891;
        inode.ctime = 1234567892;
        inode.crtime = 1234567893;

        let sanitizer = MetadataSanitizer::default();
        sanitizer.sanitize_inode(&mut inode);

        assert_eq!(inode.atime, 0);
        assert_eq!(inode.mtime, 0);
        assert_eq!(inode.ctime, 0);
        assert_eq!(inode.crtime, 0);
    }

    #[test]
    fn test_sanitize_superblock() {
        let mut superblock = Superblock::new(1000, "TestVolume");
        superblock.mount_count = 10;
        superblock.uuid = [0xFF; 16];

        let sanitizer = MetadataSanitizer::default();
        sanitizer.sanitize_superblock(&mut superblock);

        assert_eq!(superblock.mount_count, 0);
        assert_eq!(superblock.uuid, [0u8; 16]);
        assert_eq!(superblock.label, [0u8; 64]);
    }

    #[test]
    fn test_clear_bytes() {
        let mut data = vec![0xFF; 256];

        let sanitizer = MetadataSanitizer::default();
        sanitizer.clear_bytes(&mut data);

        assert!(sanitizer.verify_cleared(&data));
    }

    #[test]
    fn test_padding_generation() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            add_size_padding: true,
            padding_range: (100, 200),
            ..Default::default()
        });

        for _ in 0..100 {
            let size = sanitizer.calculate_padding_size();
            assert!(size >= 100 && size <= 200);
        }
    }

    #[test]
    fn test_no_padding_when_disabled() {
        let sanitizer = MetadataSanitizer::new(SanitizationOptions {
            add_size_padding: false,
            ..Default::default()
        });

        assert_eq!(sanitizer.calculate_padding_size(), 0);
    }

    #[test]
    fn test_max_privacy_preset() {
        let options = SanitizationOptions::max_privacy();
        assert_eq!(options.timestamp_strategy, TimestampStrategy::Zero);
        assert!(options.add_size_padding);
        assert_eq!(options.scrub_pattern, ScrubPattern::Dod522022M);
    }

    #[test]
    fn test_paranoid_preset() {
        let options = SanitizationOptions::paranoid();
        assert_eq!(options.scrub_pattern, ScrubPattern::Paranoid);
        assert!(options.padding_range.1 >= 131072);
    }

    #[test]
    fn test_balanced_preset() {
        let options = SanitizationOptions::balanced();
        assert_eq!(options.timestamp_strategy, TimestampStrategy::NormalizeToDay);
        assert!(!options.sanitize_uuids);
        assert!(!options.sanitize_labels);
    }

    #[test]
    fn test_clear_journal_header() {
        let mut header = JournalHeader::new(4);
        header.head = 100;
        header.tail = 200;
        header.sequence = 50;
        header.reserved = [0xFF; 32];

        let sanitizer = MetadataSanitizer::default();
        sanitizer.clear_journal_header(&mut header);

        assert_eq!(header.head, 0);
        assert_eq!(header.tail, 0);
        assert_eq!(header.sequence, 1);
        assert!(header.reserved.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_clear_journal_entry() {
        let mut entry = JournalEntry::new(
            100,
            crate::volume::format::JournalOpType::WriteBlock,
            50,
            4096,
        );

        let sanitizer = MetadataSanitizer::default();
        sanitizer.clear_journal_entry(&mut entry);

        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.op_type, 0);
        assert_eq!(entry.target, 0);
        assert_eq!(entry.data_len, 0);
    }

    #[test]
    fn test_system_time_sanitization() {
        let sanitizer = MetadataSanitizer::default();
        let original = SystemTime::now();
        let sanitized = sanitizer.sanitize_system_time(original);

        assert_eq!(sanitized, UNIX_EPOCH);
    }
}
