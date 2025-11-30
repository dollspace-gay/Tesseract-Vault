//! Fuzzing target for KeySlots deserialization
//!
//! Tests the parsing of key slot data from arbitrary byte sequences.
//! Key slots contain encrypted master keys and are security-critical.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tesseract_lib::volume::KeySlots;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize key slots from arbitrary data
    if let Ok(keyslots) = bincode::deserialize::<KeySlots>(data) {
        // If deserialization succeeds, test accessor methods
        let _ = keyslots.active_count();
        let _ = keyslots.has_duress_password();
        let _ = keyslots.find_free_slot();

        // Test slot checks for all possible indices
        for i in 0..8 {
            let _ = keyslots.is_slot_active(i);
        }
    }
});
