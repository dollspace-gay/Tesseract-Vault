//! File size padding for anti-forensics protection.
//!
//! This module provides utilities for adding random padding to files
//! to obscure their original sizes and prevent size-based identification.
//!
//! # Motivation
//!
//! File sizes can leak significant information:
//! - Specific file sizes may identify known documents
//! - Size patterns can reveal file types (e.g., typical JPEG vs PNG sizes)
//! - Size clustering can identify related files
//!
//! By adding random padding, we break these correlations.
//!
//! # Padding Strategies
//!
//! - **Random**: Add a random amount of padding within a range
//! - **BlockAligned**: Pad to block size boundaries (e.g., 4KB)
//! - **PowerOfTwo**: Pad to next power of two
//! - **Fixed**: Add a fixed amount of padding

use rand::Rng;
use thiserror::Error;

/// Errors that can occur during padding operations.
#[derive(Debug, Error)]
pub enum PaddingError {
    /// Requested padding size is too large
    #[error("Padding size too large: {requested} bytes (max: {max})")]
    TooLarge { requested: usize, max: usize },

    /// Invalid padding range
    #[error("Invalid padding range: min ({min}) > max ({max})")]
    InvalidRange { min: usize, max: usize },

    /// Random generation failed
    #[error("Random generation failed: {0}")]
    RandomFailed(String),
}

/// Strategy for calculating padding size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaddingStrategy {
    /// No padding
    None,

    /// Random padding within a specified range
    #[default]
    Random,

    /// Pad to align to block size boundaries
    BlockAligned {
        /// Block size for alignment (typically 4096)
        block_size: usize,
    },

    /// Pad to next power of two
    PowerOfTwo,

    /// Add a fixed amount of padding
    Fixed {
        /// Number of bytes to add
        size: usize,
    },

    /// Minimum size padding - ensure file is at least this size
    MinimumSize {
        /// Minimum size in bytes
        min_size: usize,
    },
}

/// Configuration for padding generation.
#[derive(Debug, Clone)]
pub struct PaddingGenerator {
    /// Padding strategy to use
    pub strategy: PaddingStrategy,

    /// Minimum random padding (for Random strategy)
    pub min_random: usize,

    /// Maximum random padding (for Random strategy)
    pub max_random: usize,

    /// Maximum total padding allowed (safety limit)
    pub max_total: usize,
}

impl Default for PaddingGenerator {
    fn default() -> Self {
        Self {
            strategy: PaddingStrategy::Random,
            min_random: 1024,      // 1KB minimum
            max_random: 16384,     // 16KB maximum
            max_total: 1048576,    // 1MB safety limit
        }
    }
}

impl PaddingGenerator {
    /// Creates a new padding generator with the given strategy.
    pub fn new(strategy: PaddingStrategy) -> Self {
        Self {
            strategy,
            ..Default::default()
        }
    }

    /// Creates a generator for random padding within the given range.
    pub fn random(min: usize, max: usize) -> Self {
        Self {
            strategy: PaddingStrategy::Random,
            min_random: min,
            max_random: max,
            ..Default::default()
        }
    }

    /// Creates a generator for block-aligned padding.
    pub fn block_aligned(block_size: usize) -> Self {
        Self {
            strategy: PaddingStrategy::BlockAligned { block_size },
            ..Default::default()
        }
    }

    /// Creates a generator for power-of-two padding.
    pub fn power_of_two() -> Self {
        Self {
            strategy: PaddingStrategy::PowerOfTwo,
            ..Default::default()
        }
    }

    /// Creates a generator for fixed-size padding.
    pub fn fixed(size: usize) -> Self {
        Self {
            strategy: PaddingStrategy::Fixed { size },
            ..Default::default()
        }
    }

    /// Sets the maximum total padding allowed.
    pub fn with_max_total(mut self, max: usize) -> Self {
        self.max_total = max;
        self
    }

    /// Calculates the padding size for a file of the given size.
    ///
    /// # Arguments
    ///
    /// * `original_size` - The original file size in bytes
    ///
    /// # Returns
    ///
    /// The number of padding bytes to add.
    pub fn calculate_padding(&self, original_size: usize) -> Result<usize, PaddingError> {
        let padding = match self.strategy {
            PaddingStrategy::None => 0,

            PaddingStrategy::Random => {
                if self.min_random > self.max_random {
                    return Err(PaddingError::InvalidRange {
                        min: self.min_random,
                        max: self.max_random,
                    });
                }
                let mut rng = rand::rng();
                rng.random_range(self.min_random..=self.max_random)
            }

            PaddingStrategy::BlockAligned { block_size } => {
                if block_size == 0 {
                    0
                } else {
                    let remainder = original_size % block_size;
                    if remainder == 0 {
                        // Already aligned, add one full block for obfuscation
                        block_size
                    } else {
                        block_size - remainder
                    }
                }
            }

            PaddingStrategy::PowerOfTwo => {
                if original_size == 0 {
                    0
                } else {
                    let next_power = original_size.next_power_of_two();
                    next_power - original_size
                }
            }

            PaddingStrategy::Fixed { size } => size,

            PaddingStrategy::MinimumSize { min_size } => {
                if original_size >= min_size {
                    0
                } else {
                    min_size - original_size
                }
            }
        };

        // Apply safety limit
        if padding > self.max_total {
            return Err(PaddingError::TooLarge {
                requested: padding,
                max: self.max_total,
            });
        }

        Ok(padding)
    }

    /// Generates random padding bytes.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of padding bytes to generate
    ///
    /// # Returns
    ///
    /// A vector of random bytes.
    pub fn generate_bytes(&self, size: usize) -> Vec<u8> {
        generate_padding(size)
    }
}

/// Generates random padding bytes.
///
/// Uses cryptographically secure random number generation.
///
/// # Arguments
///
/// * `size` - Number of bytes to generate
///
/// # Returns
///
/// A vector of random bytes.
pub fn generate_padding(size: usize) -> Vec<u8> {
    let mut padding = vec![0u8; size];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut padding);
    padding
}

/// Calculates the total padded size for a file.
///
/// # Arguments
///
/// * `original_size` - The original file size
/// * `padding_size` - The amount of padding to add
///
/// # Returns
///
/// The total size after padding.
pub fn calculate_padded_size(original_size: usize, padding_size: usize) -> usize {
    original_size.saturating_add(padding_size)
}

/// Rounds a size up to the nearest block boundary.
///
/// # Arguments
///
/// * `size` - The size to round
/// * `block_size` - The block size for alignment
///
/// # Returns
///
/// The size rounded up to the nearest block boundary.
#[allow(dead_code)]
pub fn round_to_block(size: usize, block_size: usize) -> usize {
    if block_size == 0 {
        return size;
    }
    let remainder = size % block_size;
    if remainder == 0 {
        size
    } else {
        size + (block_size - remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_padding() {
        let gen = PaddingGenerator::new(PaddingStrategy::None);
        assert_eq!(gen.calculate_padding(1000).unwrap(), 0);
        assert_eq!(gen.calculate_padding(0).unwrap(), 0);
    }

    #[test]
    fn test_random_padding() {
        let gen = PaddingGenerator::random(100, 200);

        for _ in 0..100 {
            let padding = gen.calculate_padding(1000).unwrap();
            assert!(padding >= 100 && padding <= 200);
        }
    }

    #[test]
    fn test_block_aligned_padding() {
        let gen = PaddingGenerator::block_aligned(4096);

        // Not aligned: should pad to alignment
        let padding = gen.calculate_padding(1000).unwrap();
        assert_eq!(padding, 4096 - 1000);

        // Already aligned: should add one full block
        let padding = gen.calculate_padding(4096).unwrap();
        assert_eq!(padding, 4096);

        // Verify result is aligned
        let total = 1000 + gen.calculate_padding(1000).unwrap();
        assert_eq!(total % 4096, 0);
    }

    #[test]
    fn test_power_of_two_padding() {
        let gen = PaddingGenerator::power_of_two();

        // 1000 -> 1024 (next power of two)
        let padding = gen.calculate_padding(1000).unwrap();
        assert_eq!(padding, 24);
        assert_eq!(1000 + padding, 1024);

        // 1024 -> 1024 (already power of two, no padding needed)
        let padding = gen.calculate_padding(1024).unwrap();
        assert_eq!(padding, 0);

        // 5000 -> 8192
        let padding = gen.calculate_padding(5000).unwrap();
        assert_eq!(padding, 8192 - 5000);
    }

    #[test]
    fn test_fixed_padding() {
        let gen = PaddingGenerator::fixed(1024);

        assert_eq!(gen.calculate_padding(0).unwrap(), 1024);
        assert_eq!(gen.calculate_padding(1000).unwrap(), 1024);
        assert_eq!(gen.calculate_padding(10000).unwrap(), 1024);
    }

    #[test]
    fn test_minimum_size_padding() {
        let gen = PaddingGenerator::new(PaddingStrategy::MinimumSize { min_size: 4096 });

        // Below minimum: should pad up
        assert_eq!(gen.calculate_padding(1000).unwrap(), 3096);

        // At minimum: no padding
        assert_eq!(gen.calculate_padding(4096).unwrap(), 0);

        // Above minimum: no padding
        assert_eq!(gen.calculate_padding(5000).unwrap(), 0);
    }

    #[test]
    fn test_max_total_limit() {
        let gen = PaddingGenerator {
            strategy: PaddingStrategy::Fixed { size: 2_000_000 },
            max_total: 1_000_000,
            ..Default::default()
        };

        let result = gen.calculate_padding(0);
        assert!(matches!(result, Err(PaddingError::TooLarge { .. })));
    }

    #[test]
    fn test_invalid_range() {
        let gen = PaddingGenerator {
            strategy: PaddingStrategy::Random,
            min_random: 200,
            max_random: 100, // Invalid: min > max
            ..Default::default()
        };

        let result = gen.calculate_padding(0);
        assert!(matches!(result, Err(PaddingError::InvalidRange { .. })));
    }

    #[test]
    fn test_generate_padding() {
        let padding = generate_padding(1024);
        assert_eq!(padding.len(), 1024);

        // Should be random (very unlikely to be all zeros)
        assert!(!padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_calculate_padded_size() {
        assert_eq!(calculate_padded_size(1000, 500), 1500);
        assert_eq!(calculate_padded_size(usize::MAX, 1), usize::MAX); // Saturating
    }

    #[test]
    fn test_round_to_block() {
        assert_eq!(round_to_block(1000, 4096), 4096);
        assert_eq!(round_to_block(4096, 4096), 4096);
        assert_eq!(round_to_block(4097, 4096), 8192);
        assert_eq!(round_to_block(100, 0), 100); // Zero block size returns original
    }

    #[test]
    fn test_builder_pattern() {
        let gen = PaddingGenerator::random(500, 1000)
            .with_max_total(5000);

        assert_eq!(gen.min_random, 500);
        assert_eq!(gen.max_random, 1000);
        assert_eq!(gen.max_total, 5000);
    }
}
