// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Property-based testing for encryption operations
//!
//! Uses proptest to verify cryptographic invariants with arbitrary inputs.
//! These tests ensure encryption/decryption round-trips work correctly
//! for all possible inputs.

use proptest::prelude::*;
use tesseract_lib::crypto::aes_gcm::AesGcmEncryptor;
use tesseract_lib::crypto::kdf::Argon2Kdf;
use tesseract_lib::crypto::Encryptor;
use tesseract_lib::crypto::KeyDerivation;
use tesseract_lib::{decrypt_bytes, encrypt_bytes};

// Strategy for generating arbitrary plaintext (0 bytes to 64KB)
fn plaintext_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..65536)
}

// Strategy for generating passwords (8-128 bytes, meeting password requirements)
fn password_strategy() -> impl Strategy<Value = String> {
    // Generate passwords that meet validation requirements:
    // - At least 8 characters
    // - Contains uppercase, lowercase, digit, and special char
    prop::string::string_regex("[A-Z][a-z]{4,10}[0-9]{2,4}[!@#$%^&*]")
        .unwrap()
        .prop_filter("Password must be at least 8 chars", |p| p.len() >= 8)
}

// Strategy for generating raw byte passwords (for low-level tests)
fn raw_password_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..128)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: Encryption followed by decryption returns original plaintext
    #[test]
    fn roundtrip_encryption(
        plaintext in plaintext_strategy(),
        password in password_strategy()
    ) {
        // Encrypt
        let (salt, nonce, ciphertext) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted = decrypt_bytes(&salt, &nonce, &ciphertext, &password)
            .expect("Decryption should succeed");

        // Verify round-trip
        prop_assert_eq!(&plaintext, &decrypted);
    }

    /// Property: Ciphertext is never equal to plaintext (for non-empty input)
    #[test]
    fn ciphertext_differs_from_plaintext(
        plaintext in prop::collection::vec(any::<u8>(), 16..10000),
        password in password_strategy()
    ) {
        let (_salt, _nonce, ciphertext) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");

        // Ciphertext should always differ from plaintext
        let min_len = plaintext.len().min(ciphertext.len());
        prop_assert_ne!(&plaintext[..min_len], &ciphertext[..min_len]);
    }

    /// Property: Same plaintext with different passwords produces different ciphertext
    #[test]
    fn different_passwords_produce_different_ciphertext(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        password1 in password_strategy(),
        password2 in password_strategy()
    ) {
        prop_assume!(password1 != password2);

        let (_, _, ciphertext1) = encrypt_bytes(&plaintext, &password1)
            .expect("Encryption should succeed");
        let (_, _, ciphertext2) = encrypt_bytes(&plaintext, &password2)
            .expect("Encryption should succeed");

        // Different passwords should produce different ciphertext
        prop_assert_ne!(ciphertext1, ciphertext2);
    }

    /// Property: Encryption uses random nonces (same plaintext/password differs each time)
    #[test]
    fn encryption_uses_random_nonce(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        password in password_strategy()
    ) {
        let (_, nonce1, ciphertext1) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");
        let (_, nonce2, ciphertext2) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");

        // Nonces should differ (random generation)
        prop_assert_ne!(nonce1, nonce2);

        // Therefore ciphertext should also differ
        prop_assert_ne!(ciphertext1, ciphertext2);
    }

    /// Property: Ciphertext includes authentication tag overhead
    #[test]
    fn ciphertext_has_overhead(
        plaintext in plaintext_strategy(),
        password in password_strategy()
    ) {
        let (_, _, ciphertext) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");

        // AES-GCM adds 16 bytes for authentication tag
        prop_assert!(ciphertext.len() >= plaintext.len() + 16);
    }

    /// Property: Wrong password fails decryption (authentication)
    #[test]
    fn wrong_password_fails(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        password1 in password_strategy(),
        password2 in password_strategy()
    ) {
        prop_assume!(password1 != password2);

        let (salt, nonce, ciphertext) = encrypt_bytes(&plaintext, &password1)
            .expect("Encryption should succeed");

        // Decryption with wrong password should fail
        let result = decrypt_bytes(&salt, &nonce, &ciphertext, &password2);
        prop_assert!(result.is_err());
    }

    /// Property: Tampered ciphertext fails authentication
    #[test]
    fn tampered_ciphertext_fails(
        plaintext in prop::collection::vec(any::<u8>(), 16..1000),
        password in password_strategy(),
        tamper_index in 0usize..1000,
        tamper_value in any::<u8>()
    ) {
        let (salt, nonce, mut ciphertext) = encrypt_bytes(&plaintext, &password)
            .expect("Encryption should succeed");

        // Tamper with ciphertext
        let idx = tamper_index % ciphertext.len();
        let original = ciphertext[idx];
        prop_assume!(tamper_value != original); // Ensure we actually change something
        ciphertext[idx] = tamper_value;

        // Decryption should fail due to authentication
        let result = decrypt_bytes(&salt, &nonce, &ciphertext, &password);
        prop_assert!(result.is_err());
    }
}

// Low-level AES-GCM tests
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: AES-GCM encrypt/decrypt round-trip
    #[test]
    fn aes_gcm_roundtrip(
        plaintext in plaintext_strategy(),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12)
    ) {
        let key_array: [u8; 32] = key.try_into().unwrap();
        let encryptor = AesGcmEncryptor::new();

        let ciphertext = encryptor.encrypt(&key_array, &nonce, &plaintext)
            .expect("Encryption should succeed");

        let decrypted = encryptor.decrypt(&key_array, &nonce, &ciphertext)
            .expect("Decryption should succeed");

        prop_assert_eq!(&plaintext, &decrypted);
    }

    /// Property: AES-GCM ciphertext length = plaintext + 16 (tag)
    #[test]
    fn aes_gcm_ciphertext_length(
        plaintext in plaintext_strategy(),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12)
    ) {
        let key_array: [u8; 32] = key.try_into().unwrap();
        let encryptor = AesGcmEncryptor::new();

        let ciphertext = encryptor.encrypt(&key_array, &nonce, &plaintext)
            .expect("Encryption should succeed");

        // AES-GCM appends 16-byte authentication tag
        prop_assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }
}

// Key derivation tests
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Property: Key derivation is deterministic with same salt
    #[test]
    fn key_derivation_deterministic(
        password in raw_password_strategy(),
        salt in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        let kdf = Argon2Kdf::default();

        let key1 = kdf.derive_key(&password, &salt)
            .expect("Key derivation should succeed");
        let key2 = kdf.derive_key(&password, &salt)
            .expect("Key derivation should succeed");

        prop_assert_eq!(key1.as_slice(), key2.as_slice());
    }

    /// Property: Different salts produce different keys
    #[test]
    fn different_salts_different_keys(
        password in raw_password_strategy(),
        salt1 in prop::collection::vec(any::<u8>(), 16..=16),
        salt2 in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        prop_assume!(salt1 != salt2);

        let kdf = Argon2Kdf::default();

        let key1 = kdf.derive_key(&password, &salt1)
            .expect("Key derivation should succeed");
        let key2 = kdf.derive_key(&password, &salt2)
            .expect("Key derivation should succeed");

        prop_assert_ne!(key1.as_slice(), key2.as_slice());
    }

    /// Property: Different passwords produce different keys
    #[test]
    fn different_passwords_different_keys(
        password1 in raw_password_strategy(),
        password2 in raw_password_strategy(),
        salt in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        prop_assume!(password1 != password2);

        let kdf = Argon2Kdf::default();

        let key1 = kdf.derive_key(&password1, &salt)
            .expect("Key derivation should succeed");
        let key2 = kdf.derive_key(&password2, &salt)
            .expect("Key derivation should succeed");

        prop_assert_ne!(key1.as_slice(), key2.as_slice());
    }

    /// Property: Derived keys are always 32 bytes
    #[test]
    fn key_length_is_constant(
        password in raw_password_strategy(),
        salt in prop::collection::vec(any::<u8>(), 16..=16)
    ) {
        let kdf = Argon2Kdf::default();

        let key = kdf.derive_key(&password, &salt)
            .expect("Key derivation should succeed");

        prop_assert_eq!(key.len(), 32);
    }
}

// BLAKE3 hash tests
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Property: Hash function is deterministic
    #[test]
    fn hash_is_deterministic(data in plaintext_strategy()) {
        let hash1 = blake3::hash(&data);
        let hash2 = blake3::hash(&data);

        prop_assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    }

    /// Property: Different inputs produce different hashes
    #[test]
    fn hash_differs_for_different_inputs(
        data1 in prop::collection::vec(any::<u8>(), 1..1000),
        data2 in prop::collection::vec(any::<u8>(), 1..1000)
    ) {
        prop_assume!(data1 != data2);

        let hash1 = blake3::hash(&data1);
        let hash2 = blake3::hash(&data2);

        prop_assert_ne!(hash1.as_bytes(), hash2.as_bytes());
    }

    /// Property: Hash length is always 32 bytes
    #[test]
    fn hash_length_is_constant(data in plaintext_strategy()) {
        let hash = blake3::hash(&data);
        prop_assert_eq!(hash.as_bytes().len(), 32);
    }
}

// ChunkMapper property tests
#[cfg(test)]
mod volume_proptests {
    use super::*;
    use tesseract_lib::volume::{ChunkMapper, DEFAULT_CHUNK_SIZE};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Property: ChunkMapper offset mapping is consistent
        #[test]
        fn chunk_mapper_offset_consistency(
            volume_size in DEFAULT_CHUNK_SIZE..1024 * 1024 * 1024,
            sector_size in prop::sample::select(vec![512u64, 4096u64])
        ) {
            let chunk_size = DEFAULT_CHUNK_SIZE;

            if let Ok(mapper) = ChunkMapper::new(volume_size, chunk_size, sector_size) {
                // Total chunks should be consistent with volume size
                let total = mapper.total_chunks();
                prop_assert!(total > 0);

                // Chunk size should match what we set
                prop_assert_eq!(mapper.chunk_size(), chunk_size);

                // Volume size should match
                prop_assert_eq!(mapper.volume_size(), volume_size);
            }
        }

        /// Property: map_offset returns valid chunk locations for valid offsets
        #[test]
        fn chunk_mapper_valid_offsets(
            volume_size in DEFAULT_CHUNK_SIZE..100 * 1024 * 1024,
            offset_ratio in 0.0f64..0.99
        ) {
            let chunk_size = DEFAULT_CHUNK_SIZE;

            if let Ok(mapper) = ChunkMapper::new(volume_size, chunk_size, 512) {
                let offset = (offset_ratio * (volume_size as f64)) as u64;

                if offset < volume_size {
                    if let Ok(location) = mapper.map_offset(offset) {
                        // Chunk ID should be within range
                        prop_assert!(location.chunk_id < mapper.total_chunks());

                        // Offset within chunk should be less than chunk size
                        prop_assert!(location.chunk_offset < chunk_size);
                    }
                }
            }
        }

        /// Property: to_logical_offset is inverse of map_offset
        #[test]
        fn chunk_mapper_roundtrip(
            volume_size in DEFAULT_CHUNK_SIZE..100 * 1024 * 1024,
            offset_ratio in 0.0f64..0.99
        ) {
            if let Ok(mapper) = ChunkMapper::new(volume_size, DEFAULT_CHUNK_SIZE, 512) {
                let original_offset = (offset_ratio * (volume_size as f64)) as u64;

                if original_offset < volume_size {
                    if let Ok(location) = mapper.map_offset(original_offset) {
                        let reconstructed = mapper.to_logical_offset(
                            location.chunk_id,
                            location.chunk_offset
                        );

                        if let Some(reconstructed_offset) = reconstructed {
                            prop_assert_eq!(original_offset, reconstructed_offset);
                        }
                    }
                }
            }
        }

        /// Property: map_range never panics with arbitrary inputs
        #[test]
        fn chunk_mapper_range_no_panic(
            volume_size in DEFAULT_CHUNK_SIZE..u64::MAX / 2,
            offset in 0u64..u64::MAX / 2,
            length in 0u64..u64::MAX / 2
        ) {
            if let Ok(mapper) = ChunkMapper::new(volume_size, DEFAULT_CHUNK_SIZE, 512) {
                // Should not panic regardless of input
                let _ = mapper.map_range(offset, length);
            }
        }
    }
}
