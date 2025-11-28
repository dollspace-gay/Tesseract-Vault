//! Metadata sanitization for anti-forensics protection.
//!
//! This module provides secure sanitization of metadata to prevent forensic analysis
//! from revealing sensitive information about encrypted files and volumes.
//!
//! # Features
//!
//! - **Timestamp sanitization**: Zero or randomize timestamps to prevent timeline analysis
//! - **Size padding**: Add random padding to obscure original file sizes
//! - **Filesystem metadata clearing**: Wipe journal entries, slack space, and other metadata
//! - **Volume header sanitization**: Clean volume headers during secure deletion
//!
//! # Security Model
//!
//! Metadata can leak sensitive information even when file contents are encrypted:
//! - File modification times reveal when documents were accessed
//! - File sizes can identify file types or specific documents
//! - Filesystem journals may contain unencrypted metadata
//! - Directory structures reveal organizational patterns
//!
//! This module provides defense-in-depth by sanitizing this metadata.
//!
//! # Example
//!
//! ```no_run
//! use tesseract_lib::metadata::{MetadataSanitizer, SanitizationOptions, TimestampStrategy};
//!
//! let sanitizer = MetadataSanitizer::new(SanitizationOptions {
//!     timestamp_strategy: TimestampStrategy::Zero,
//!     add_size_padding: true,
//!     padding_range: (1024, 4096),
//!     clear_slack_space: true,
//!     ..Default::default()
//! });
//!
//! // Sanitize file attributes before writing
//! let mut attr = tesseract_lib::volume::filesystem::FileAttr::default();
//! sanitizer.sanitize_file_attr(&mut attr);
//! ```

mod sanitizer;
mod padding;

pub use sanitizer::{
    MetadataSanitizer,
    SanitizationOptions,
    TimestampStrategy,
    SanitizationResult,
    SanitizationError,
};
pub use padding::{
    PaddingGenerator,
    PaddingStrategy,
    generate_padding,
    calculate_padded_size,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _options = SanitizationOptions::default();
        let _sanitizer = MetadataSanitizer::default();
        let _strategy = TimestampStrategy::Zero;
    }
}
