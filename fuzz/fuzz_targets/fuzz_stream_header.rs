//! Fuzzing target for StreamHeader deserialization
//!
//! Tests the parsing of streaming encryption headers (V3 format) from
//! arbitrary byte sequences. These headers contain salt, nonces, chunk
//! sizes, and optional PQC metadata.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use tesseract_lib::StreamHeader;

fuzz_target!(|data: &[u8]| {
    // Create a cursor to simulate reading from a file
    let mut cursor = Cursor::new(data);

    // Attempt to read/parse the stream header
    // This tests magic byte validation, version checks, and field parsing
    let _ = StreamHeader::read_from(&mut cursor);
});
