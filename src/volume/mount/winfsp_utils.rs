// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Pure utility functions for WinFSP, extracted for testability.
//!
//! This module contains platform-independent utility functions used by the WinFSP
//! filesystem implementation. By extracting these pure functions, we can achieve
//! unit test coverage even when the WinFSP driver is not installed.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::super::format::InodeType;

/// Windows FILETIME epoch: January 1, 1601
/// This is the difference between Windows FILETIME epoch and Unix epoch in 100ns intervals.
pub const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

/// Number of 100-nanosecond intervals per second.
pub const TICKS_PER_SECOND: u64 = 10_000_000;

/// Windows file attribute constants
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;

/// Convert Windows FILETIME (100-nanosecond intervals since 1601) to Unix timestamp.
///
/// FILETIME represents the number of 100-nanosecond intervals since January 1, 1601.
/// Unix timestamps count seconds since January 1, 1970.
///
/// # Arguments
///
/// * `filetime` - Windows FILETIME value (100ns intervals since 1601)
///
/// # Returns
///
/// Unix timestamp (seconds since 1970), or 0 if the FILETIME is before Unix epoch.
///
/// # Examples
///
/// ```
/// use tesseract_lib::volume::mount::winfsp_utils::filetime_to_unix;
///
/// // Unix epoch in FILETIME
/// let epoch = 116_444_736_000_000_000u64;
/// assert_eq!(filetime_to_unix(epoch), 0);
///
/// // One second after Unix epoch
/// assert_eq!(filetime_to_unix(epoch + 10_000_000), 1);
/// ```
pub fn filetime_to_unix(filetime: u64) -> u64 {
    if filetime < FILETIME_UNIX_DIFF {
        0
    } else {
        (filetime - FILETIME_UNIX_DIFF) / TICKS_PER_SECOND
    }
}

/// Convert Unix timestamp to Windows FILETIME.
///
/// # Arguments
///
/// * `unix_time` - Unix timestamp (seconds since 1970)
///
/// # Returns
///
/// Windows FILETIME value (100ns intervals since 1601).
///
/// # Examples
///
/// ```
/// use tesseract_lib::volume::mount::winfsp_utils::unix_to_filetime;
///
/// // Unix epoch should map to Windows epoch + diff
/// assert_eq!(unix_to_filetime(0), 116_444_736_000_000_000);
///
/// // One second after Unix epoch
/// assert_eq!(unix_to_filetime(1), 116_444_736_010_000_000);
/// ```
pub fn unix_to_filetime(unix_time: u64) -> u64 {
    FILETIME_UNIX_DIFF + (unix_time * TICKS_PER_SECOND)
}

/// Convert `SystemTime` to Windows FILETIME.
///
/// # Arguments
///
/// * `time` - A `SystemTime` value
///
/// # Returns
///
/// Windows FILETIME value. Returns FILETIME for Unix epoch (0) if the time
/// is before Unix epoch (due to `SystemTime` limitations).
///
/// # Examples
///
/// ```
/// use std::time::{SystemTime, Duration, UNIX_EPOCH};
/// use tesseract_lib::volume::mount::winfsp_utils::systemtime_to_filetime;
///
/// // Unix epoch
/// let filetime = systemtime_to_filetime(UNIX_EPOCH);
/// assert_eq!(filetime, 116_444_736_000_000_000);
/// ```
pub fn systemtime_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => unix_to_filetime(duration.as_secs()),
        Err(_) => unix_to_filetime(0),
    }
}

/// Normalize a Windows path for internal filesystem use.
///
/// This function:
/// - Strips leading backslashes
/// - Converts all backslashes to forward slashes
/// - Ensures the path starts with a forward slash (root)
///
/// # Arguments
///
/// * `path` - The Windows path to normalize
///
/// # Returns
///
/// A normalized `PathBuf` suitable for internal filesystem operations.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use tesseract_lib::volume::mount::winfsp_utils::normalize_path;
///
/// assert_eq!(normalize_path(Path::new("\\foo\\bar")), Path::new("/foo/bar"));
/// assert_eq!(normalize_path(Path::new("\\")), Path::new("/"));
/// assert_eq!(normalize_path(Path::new("")), Path::new("/"));
/// ```
pub fn normalize_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let normalized = path_str.trim_start_matches('\\').replace('\\', "/");

    if normalized.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(format!("/{}", normalized))
    }
}

/// Convert InodeType to Windows file attributes.
///
/// Maps our internal file type representation to Windows file attribute flags.
///
/// # Arguments
///
/// * `itype` - The inode type to convert
///
/// # Returns
///
/// Windows file attribute flags.
///
/// # Examples
///
/// ```
/// use tesseract_lib::volume::format::InodeType;
/// use tesseract_lib::volume::mount::winfsp_utils::{
///     inode_type_to_attributes,
///     FILE_ATTRIBUTE_DIRECTORY,
///     FILE_ATTRIBUTE_NORMAL,
///     FILE_ATTRIBUTE_REPARSE_POINT,
/// };
///
/// assert_eq!(inode_type_to_attributes(InodeType::Directory), FILE_ATTRIBUTE_DIRECTORY);
/// assert_eq!(inode_type_to_attributes(InodeType::File), FILE_ATTRIBUTE_NORMAL);
/// assert_eq!(inode_type_to_attributes(InodeType::Symlink), FILE_ATTRIBUTE_REPARSE_POINT);
/// ```
pub fn inode_type_to_attributes(itype: InodeType) -> u32 {
    match itype {
        InodeType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        InodeType::File => FILE_ATTRIBUTE_NORMAL,
        InodeType::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
    }
}

/// Convert Windows file attributes to Unix file mode.
///
/// Maps Windows read-only attribute to Unix mode permissions.
///
/// # Arguments
///
/// * `attributes` - Windows file attributes
///
/// # Returns
///
/// Unix file mode (permissions).
pub fn attributes_to_mode(attributes: u32) -> u16 {
    if attributes & FILE_ATTRIBUTE_READONLY != 0 {
        0o444 // Read-only
    } else {
        0o644 // Read-write
    }
}

/// Check if file attributes indicate read-only.
///
/// # Arguments
///
/// * `attributes` - Windows file attributes
///
/// # Returns
///
/// `true` if the file is read-only.
pub fn is_readonly(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_READONLY != 0
}

/// Check if file attributes indicate a directory.
///
/// # Arguments
///
/// * `attributes` - Windows file attributes
///
/// # Returns
///
/// `true` if the path is a directory.
pub fn is_directory(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// Calculate allocation size from file size.
///
/// Allocation size is always a multiple of the block size.
///
/// # Arguments
///
/// * `file_size` - The actual file size in bytes
/// * `block_size` - The filesystem block size
///
/// # Returns
///
/// The allocation size (rounded up to block boundary).
pub fn calculate_allocation_size(file_size: u64, block_size: u64) -> u64 {
    file_size.div_ceil(block_size) * block_size
}

/// Extract the filename component from a path.
///
/// # Arguments
///
/// * `path` - The path to extract filename from
///
/// # Returns
///
/// The filename as a String, or empty string if no filename component.
pub fn extract_filename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Get the parent path, defaulting to root if none.
///
/// # Arguments
///
/// * `path` - The path to get parent of
///
/// # Returns
///
/// The parent path, or root ("/") if no parent.
pub fn get_parent_or_root(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ========================================
    // Timestamp Conversion Tests
    // ========================================

    #[test]
    fn test_filetime_to_unix_epoch() {
        // Unix epoch in FILETIME format
        assert_eq!(filetime_to_unix(FILETIME_UNIX_DIFF), 0);
    }

    #[test]
    fn test_filetime_to_unix_one_second() {
        // One second after Unix epoch
        let one_sec_after = FILETIME_UNIX_DIFF + TICKS_PER_SECOND;
        assert_eq!(filetime_to_unix(one_sec_after), 1);
    }

    #[test]
    fn test_filetime_to_unix_before_epoch() {
        // Before Unix epoch should return 0
        assert_eq!(filetime_to_unix(0), 0);
        assert_eq!(filetime_to_unix(FILETIME_UNIX_DIFF - 1), 0);
    }

    #[test]
    fn test_filetime_to_unix_year_2000() {
        // January 1, 2000 00:00:00 UTC
        // Unix timestamp: 946684800
        let unix_2000 = 946684800u64;
        let filetime_2000 = FILETIME_UNIX_DIFF + (unix_2000 * TICKS_PER_SECOND);
        assert_eq!(filetime_to_unix(filetime_2000), unix_2000);
    }

    #[test]
    fn test_filetime_to_unix_year_2038() {
        // Test Y2K38 boundary (max 32-bit signed timestamp)
        let y2k38 = 2147483647u64;
        let filetime_2038 = FILETIME_UNIX_DIFF + (y2k38 * TICKS_PER_SECOND);
        assert_eq!(filetime_to_unix(filetime_2038), y2k38);
    }

    #[test]
    fn test_filetime_to_unix_far_future() {
        // Year 3000 (well beyond Y2K38)
        let far_future = 32503680000u64; // ~Jan 1, 3000
        let filetime_future = FILETIME_UNIX_DIFF + (far_future * TICKS_PER_SECOND);
        assert_eq!(filetime_to_unix(filetime_future), far_future);
    }

    #[test]
    fn test_unix_to_filetime_epoch() {
        assert_eq!(unix_to_filetime(0), FILETIME_UNIX_DIFF);
    }

    #[test]
    fn test_unix_to_filetime_one_second() {
        assert_eq!(unix_to_filetime(1), FILETIME_UNIX_DIFF + TICKS_PER_SECOND);
    }

    #[test]
    fn test_unix_to_filetime_year_2000() {
        let unix_2000 = 946684800u64;
        let expected = FILETIME_UNIX_DIFF + (unix_2000 * TICKS_PER_SECOND);
        assert_eq!(unix_to_filetime(unix_2000), expected);
    }

    #[test]
    fn test_filetime_unix_roundtrip() {
        // Test roundtrip conversion preserves timestamp
        let test_times = [0u64, 1, 1000, 946684800, 1704067200, 2147483647];

        for &unix_time in &test_times {
            let filetime = unix_to_filetime(unix_time);
            let back = filetime_to_unix(filetime);
            assert_eq!(back, unix_time, "Roundtrip failed for {}", unix_time);
        }
    }

    #[test]
    fn test_systemtime_to_filetime_epoch() {
        let filetime = systemtime_to_filetime(SystemTime::UNIX_EPOCH);
        assert_eq!(filetime, FILETIME_UNIX_DIFF);
    }

    #[test]
    fn test_systemtime_to_filetime_future() {
        let future = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000);
        let filetime = systemtime_to_filetime(future);
        let expected = FILETIME_UNIX_DIFF + (1000000 * TICKS_PER_SECOND);
        assert_eq!(filetime, expected);
    }

    #[test]
    fn test_systemtime_to_filetime_current() {
        let now = SystemTime::now();
        let filetime = systemtime_to_filetime(now);

        // Should be after Unix epoch
        assert!(filetime >= FILETIME_UNIX_DIFF);

        // Convert back and verify it's reasonable (within last 100 years)
        let unix = filetime_to_unix(filetime);
        assert!(unix > 0);
        assert!(unix < 10000000000); // Before year 2286
    }

    // ========================================
    // Path Normalization Tests
    // ========================================

    #[test]
    fn test_normalize_path_backslashes() {
        assert_eq!(
            normalize_path(Path::new("\\foo\\bar")),
            PathBuf::from("/foo/bar")
        );
    }

    #[test]
    fn test_normalize_path_root() {
        assert_eq!(normalize_path(Path::new("\\")), PathBuf::from("/"));
    }

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(normalize_path(Path::new("")), PathBuf::from("/"));
    }

    #[test]
    fn test_normalize_path_single_component() {
        assert_eq!(normalize_path(Path::new("\\foo")), PathBuf::from("/foo"));
    }

    #[test]
    fn test_normalize_path_deep_nesting() {
        assert_eq!(
            normalize_path(Path::new("\\a\\b\\c\\d\\e")),
            PathBuf::from("/a/b/c/d/e")
        );
    }

    #[test]
    fn test_normalize_path_mixed_slashes() {
        // Forward slashes should be preserved
        assert_eq!(
            normalize_path(Path::new("\\foo/bar\\baz")),
            PathBuf::from("/foo/bar/baz")
        );
    }

    #[test]
    fn test_normalize_path_no_leading_backslash() {
        // Paths without leading backslash still get normalized
        assert_eq!(
            normalize_path(Path::new("foo\\bar")),
            PathBuf::from("/foo/bar")
        );
    }

    #[test]
    fn test_normalize_path_multiple_leading_backslashes() {
        assert_eq!(
            normalize_path(Path::new("\\\\foo\\bar")),
            PathBuf::from("/foo/bar")
        );
    }

    #[test]
    fn test_normalize_path_spaces() {
        assert_eq!(
            normalize_path(Path::new("\\foo bar\\baz qux")),
            PathBuf::from("/foo bar/baz qux")
        );
    }

    #[test]
    fn test_normalize_path_special_chars() {
        assert_eq!(
            normalize_path(Path::new("\\foo-bar_baz.txt")),
            PathBuf::from("/foo-bar_baz.txt")
        );
    }

    // ========================================
    // Inode Type to Attributes Tests
    // ========================================

    #[test]
    fn test_inode_type_to_attributes_directory() {
        assert_eq!(
            inode_type_to_attributes(InodeType::Directory),
            FILE_ATTRIBUTE_DIRECTORY
        );
    }

    #[test]
    fn test_inode_type_to_attributes_file() {
        assert_eq!(
            inode_type_to_attributes(InodeType::File),
            FILE_ATTRIBUTE_NORMAL
        );
    }

    #[test]
    fn test_inode_type_to_attributes_symlink() {
        assert_eq!(
            inode_type_to_attributes(InodeType::Symlink),
            FILE_ATTRIBUTE_REPARSE_POINT
        );
    }

    // ========================================
    // Attributes to Mode Tests
    // ========================================

    #[test]
    fn test_attributes_to_mode_readonly() {
        assert_eq!(attributes_to_mode(FILE_ATTRIBUTE_READONLY), 0o444);
    }

    #[test]
    fn test_attributes_to_mode_readwrite() {
        assert_eq!(attributes_to_mode(FILE_ATTRIBUTE_NORMAL), 0o644);
    }

    #[test]
    fn test_attributes_to_mode_directory_readonly() {
        let attrs = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY;
        assert_eq!(attributes_to_mode(attrs), 0o444);
    }

    #[test]
    fn test_attributes_to_mode_zero() {
        assert_eq!(attributes_to_mode(0), 0o644);
    }

    // ========================================
    // Attribute Check Tests
    // ========================================

    #[test]
    fn test_is_readonly_true() {
        assert!(is_readonly(FILE_ATTRIBUTE_READONLY));
    }

    #[test]
    fn test_is_readonly_false() {
        assert!(!is_readonly(FILE_ATTRIBUTE_NORMAL));
    }

    #[test]
    fn test_is_readonly_combined() {
        let attrs = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY;
        assert!(is_readonly(attrs));
    }

    #[test]
    fn test_is_directory_true() {
        assert!(is_directory(FILE_ATTRIBUTE_DIRECTORY));
    }

    #[test]
    fn test_is_directory_false() {
        assert!(!is_directory(FILE_ATTRIBUTE_NORMAL));
    }

    #[test]
    fn test_is_directory_combined() {
        let attrs = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY;
        assert!(is_directory(attrs));
    }

    // ========================================
    // Allocation Size Tests
    // ========================================

    #[test]
    fn test_allocation_size_zero() {
        assert_eq!(calculate_allocation_size(0, 4096), 0);
    }

    #[test]
    fn test_allocation_size_exact_block() {
        assert_eq!(calculate_allocation_size(4096, 4096), 4096);
    }

    #[test]
    fn test_allocation_size_one_byte() {
        assert_eq!(calculate_allocation_size(1, 4096), 4096);
    }

    #[test]
    fn test_allocation_size_partial_block() {
        assert_eq!(calculate_allocation_size(5000, 4096), 8192);
    }

    #[test]
    fn test_allocation_size_multiple_blocks() {
        assert_eq!(calculate_allocation_size(10000, 4096), 12288);
    }

    #[test]
    fn test_allocation_size_large_file() {
        // 1 GB file
        let one_gb = 1024 * 1024 * 1024u64;
        assert_eq!(calculate_allocation_size(one_gb, 4096), one_gb);
    }

    // ========================================
    // Filename Extraction Tests
    // ========================================

    #[test]
    fn test_extract_filename_simple() {
        assert_eq!(extract_filename(Path::new("/foo/bar.txt")), "bar.txt");
    }

    #[test]
    fn test_extract_filename_no_extension() {
        assert_eq!(extract_filename(Path::new("/foo/bar")), "bar");
    }

    #[test]
    fn test_extract_filename_root() {
        assert_eq!(extract_filename(Path::new("/")), "");
    }

    #[test]
    fn test_extract_filename_empty() {
        assert_eq!(extract_filename(Path::new("")), "");
    }

    #[test]
    fn test_extract_filename_deep_path() {
        assert_eq!(extract_filename(Path::new("/a/b/c/d/file.ext")), "file.ext");
    }

    // ========================================
    // Parent Path Tests
    // ========================================

    #[test]
    fn test_get_parent_or_root_simple() {
        let parent = get_parent_or_root(Path::new("/foo/bar"));
        assert_eq!(parent, Path::new("/foo"));
    }

    #[test]
    fn test_get_parent_or_root_root() {
        let parent = get_parent_or_root(Path::new("/"));
        assert_eq!(parent, Path::new("/"));
    }

    #[test]
    fn test_get_parent_or_root_single_component() {
        let parent = get_parent_or_root(Path::new("/foo"));
        assert_eq!(parent, Path::new("/"));
    }

    // ========================================
    // Constants Tests
    // ========================================

    #[test]
    fn test_constants() {
        assert_eq!(FILE_ATTRIBUTE_DIRECTORY, 0x10);
        assert_eq!(FILE_ATTRIBUTE_NORMAL, 0x80);
        assert_eq!(FILE_ATTRIBUTE_READONLY, 0x01);
        assert_eq!(FILE_ATTRIBUTE_REPARSE_POINT, 0x400);
        assert_eq!(INVALID_FILE_ATTRIBUTES, 0xFFFFFFFF);
    }

    #[test]
    fn test_filetime_constants() {
        // Verify our constants are correct
        assert_eq!(FILETIME_UNIX_DIFF, 116_444_736_000_000_000);
        assert_eq!(TICKS_PER_SECOND, 10_000_000);
    }

    #[test]
    fn test_attribute_flags_non_overlapping() {
        // Verify attribute flags don't overlap unexpectedly
        assert_eq!(FILE_ATTRIBUTE_DIRECTORY & FILE_ATTRIBUTE_NORMAL, 0);
        assert_eq!(FILE_ATTRIBUTE_DIRECTORY & FILE_ATTRIBUTE_READONLY, 0);
        assert_eq!(FILE_ATTRIBUTE_NORMAL & FILE_ATTRIBUTE_READONLY, 0);
    }
}
