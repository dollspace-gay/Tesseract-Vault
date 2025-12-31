// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! WASM bindings implementation

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use base64::Engine;

use crate::crypto::{Encryptor, KeyDerivation};
use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::crypto::kdf::Argon2Kdf;
use crate::config::CryptoConfig;

/// Initialize the WASM module
///
/// This should be called once when the WASM module is loaded.
/// It sets up panic hooks for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    // Set up panic hook for better error messages
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Configuration for encryption operations
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptConfig {
    /// Use Argon2 for key derivation (recommended)
    use_argon2: bool,
    /// Argon2 memory cost in KB (default: 65536 = 64MB)
    memory_cost: u32,
    /// Argon2 time cost (iterations, default: 3)
    time_cost: u32,
}

#[wasm_bindgen]
impl EncryptConfig {
    /// Create a new encryption configuration with default settings
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fast configuration (lower security, faster)
    #[wasm_bindgen]
    pub fn fast() -> Self {
        Self {
            use_argon2: true,
            memory_cost: 8192,  // 8MB
            time_cost: 1,
        }
    }

    /// Create a balanced configuration (recommended)
    #[wasm_bindgen]
    pub fn balanced() -> Self {
        Self::default()
    }

    /// Create a secure configuration (higher security, slower)
    #[wasm_bindgen]
    pub fn secure() -> Self {
        Self {
            use_argon2: true,
            memory_cost: 131072,  // 128MB
            time_cost: 5,
        }
    }
}

impl Default for EncryptConfig {
    fn default() -> Self {
        Self {
            use_argon2: true,
            memory_cost: 65536,  // 64MB
            time_cost: 3,
        }
    }
}

/// Encrypt a text string with a password
///
/// # Arguments
///
/// * `password` - The password to use for encryption
/// * `plaintext` - The text to encrypt
///
/// # Returns
///
/// Base64-encoded encrypted data
///
/// # Example
///
/// ```javascript
/// const encrypted = encrypt_text("my-password", "Hello, World!");
/// console.log(encrypted); // Base64 string
/// ```
#[wasm_bindgen]
pub fn encrypt_text(password: &str, plaintext: &str) -> Result<String, JsValue> {
    encrypt_text_with_config(password, plaintext, &EncryptConfig::default())
}

/// Encrypt a text string with custom configuration
///
/// # Arguments
///
/// * `password` - The password to use for encryption
/// * `plaintext` - The text to encrypt
/// * `config` - Encryption configuration
///
/// # Returns
///
/// Base64-encoded encrypted data
#[wasm_bindgen]
pub fn encrypt_text_with_config(
    password: &str,
    plaintext: &str,
    config: &EncryptConfig,
) -> Result<String, JsValue> {
    // Create Argon2 KDF with custom parameters
    let crypto_config = CryptoConfig {
        argon2_mem_cost_kib: config.memory_cost,
        argon2_time_cost: config.time_cost,
        argon2_lanes: 1,
    };
    let kdf = Argon2Kdf::new(crypto_config);

    // Generate salt
    let salt = kdf.generate_salt();

    // Derive key from password
    let key = kdf
        .derive_key(password.as_bytes(), &salt)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    // Generate random nonce
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce)
        .map_err(|e| JsValue::from_str(&format!("Random generation failed: {}", e)))?;

    // Encrypt
    let encryptor = AesGcmEncryptor;
    let ciphertext = encryptor
        .encrypt(&*key, &nonce, plaintext.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    // Encode as base64
    Ok(base64::engine::general_purpose::STANDARD.encode(&result))
}

/// Decrypt a text string with a password
///
/// # Arguments
///
/// * `password` - The password used for encryption
/// * `encrypted_base64` - Base64-encoded encrypted data
///
/// # Returns
///
/// Decrypted plaintext string
///
/// # Example
///
/// ```javascript
/// const decrypted = decrypt_text("my-password", encrypted_data);
/// console.log(decrypted); // "Hello, World!"
/// ```
#[wasm_bindgen]
pub fn decrypt_text(password: &str, encrypted_base64: &str) -> Result<String, JsValue> {
    decrypt_text_with_config(password, encrypted_base64, &EncryptConfig::default())
}

/// Decrypt a text string with custom configuration
///
/// # Arguments
///
/// * `password` - The password used for encryption
/// * `encrypted_base64` - Base64-encoded encrypted data
/// * `config` - Encryption configuration (must match encryption config)
///
/// # Returns
///
/// Decrypted plaintext string
#[wasm_bindgen]
pub fn decrypt_text_with_config(
    password: &str,
    encrypted_base64: &str,
    config: &EncryptConfig,
) -> Result<String, JsValue> {
    // Decode base64
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| JsValue::from_str(&format!("Base64 decode failed: {}", e)))?;

    // Extract: salt || nonce || ciphertext
    // Salt size is determined by the KDF (typically 32 bytes for Argon2)
    let salt_size = 32;
    if data.len() < salt_size + 12 {
        return Err(JsValue::from_str("Invalid encrypted data"));
    }

    let (salt, rest) = data.split_at(salt_size);
    let (nonce, ciphertext) = rest.split_at(12);

    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid nonce"))?;

    // Create Argon2 KDF with custom parameters
    let crypto_config = CryptoConfig {
        argon2_mem_cost_kib: config.memory_cost,
        argon2_time_cost: config.time_cost,
        argon2_lanes: 1,
    };
    let kdf = Argon2Kdf::new(crypto_config);

    // Derive key from password
    let key = kdf
        .derive_key(password.as_bytes(), salt)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    // Decrypt
    let encryptor = AesGcmEncryptor;
    let plaintext = encryptor
        .decrypt(&*key, &nonce, ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;

    // Convert to string
    String::from_utf8(plaintext)
        .map_err(|e| JsValue::from_str(&format!("UTF-8 decode failed: {}", e)))
}

/// Encrypt binary data with a password
///
/// # Arguments
///
/// * `password` - The password to use for encryption
/// * `data` - Binary data to encrypt
///
/// # Returns
///
/// Encrypted data (salt || nonce || ciphertext)
#[wasm_bindgen]
pub fn encrypt_bytes(password: &str, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    encrypt_bytes_with_config(password, data, &EncryptConfig::default())
}

/// Encrypt binary data with custom configuration
#[wasm_bindgen]
pub fn encrypt_bytes_with_config(
    password: &str,
    data: &[u8],
    config: &EncryptConfig,
) -> Result<Vec<u8>, JsValue> {
    // Create Argon2 KDF with custom parameters
    let crypto_config = CryptoConfig {
        argon2_mem_cost_kib: config.memory_cost,
        argon2_time_cost: config.time_cost,
        argon2_lanes: 1,
    };
    let kdf = Argon2Kdf::new(crypto_config);

    // Generate salt
    let salt = kdf.generate_salt();

    // Derive key from password
    let key = kdf
        .derive_key(password.as_bytes(), &salt)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    // Generate random nonce
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce)
        .map_err(|e| JsValue::from_str(&format!("Random generation failed: {}", e)))?;

    // Encrypt
    let encryptor = AesGcmEncryptor;
    let ciphertext = encryptor
        .encrypt(&*key, &nonce, data)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt binary data with a password
///
/// # Arguments
///
/// * `password` - The password used for encryption
/// * `encrypted_data` - Encrypted data (salt || nonce || ciphertext)
///
/// # Returns
///
/// Decrypted binary data
#[wasm_bindgen]
pub fn decrypt_bytes(password: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, JsValue> {
    decrypt_bytes_with_config(password, encrypted_data, &EncryptConfig::default())
}

/// Decrypt binary data with custom configuration
#[wasm_bindgen]
pub fn decrypt_bytes_with_config(
    password: &str,
    encrypted_data: &[u8],
    config: &EncryptConfig,
) -> Result<Vec<u8>, JsValue> {
    // Extract: salt || nonce || ciphertext
    let salt_size = 32;
    if encrypted_data.len() < salt_size + 12 {
        return Err(JsValue::from_str("Invalid encrypted data"));
    }

    let (salt, rest) = encrypted_data.split_at(salt_size);
    let (nonce, ciphertext) = rest.split_at(12);

    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid nonce"))?;

    // Create Argon2 KDF with custom parameters
    let crypto_config = CryptoConfig {
        argon2_mem_cost_kib: config.memory_cost,
        argon2_time_cost: config.time_cost,
        argon2_lanes: 1,
    };
    let kdf = Argon2Kdf::new(crypto_config);

    // Derive key from password
    let key = kdf
        .derive_key(password.as_bytes(), salt)
        .map_err(|e| JsValue::from_str(&format!("Key derivation failed: {}", e)))?;

    // Decrypt
    let encryptor = AesGcmEncryptor;
    encryptor
        .decrypt(&*key, &nonce, ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))
}

/// Get version information
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Security audit information
#[wasm_bindgen]
pub fn security_audit_info() -> String {
    format!(
        "Tesseract Vault v{} - Security Features:\n\
         - AES-256-GCM authenticated encryption\n\
         - Argon2id memory-hard key derivation\n\
         - Post-quantum hybrid encryption (ML-KEM-1024)\n\
         - Constant-time operations\n\
         - Automatic memory zeroization",
        env!("CARGO_PKG_VERSION")
    )
}

// Remote Wipe WASM Bindings
// -------------------------
// These functions allow the web interface to create authenticated wipe commands
// that can be sent via cloud sync to remotely destroy encryption keys.

use crate::volume::remote_wipe::{WipeCommand, WipeCommandType, WipeToken};

/// Create a wipe command from a hex token
///
/// This is the primary function for the web remote wipe interface.
/// The user enters their wipe token (from QR code or manual copy) and
/// this function creates a signed command to send via cloud sync.
///
/// # Arguments
///
/// * `token_hex` - The wipe token as a hex string (64 characters)
/// * `volume_id` - The volume ID to target
/// * `command_type` - The type of command: "destroy", "lock", "checkin", or "revoke"
/// * `message` - Optional message (e.g., reason for wipe)
///
/// # Returns
///
/// JSON-serialized WipeCommand ready for transmission
#[wasm_bindgen]
pub fn create_wipe_command(
    token_hex: &str,
    volume_id: &str,
    command_type: &str,
    message: Option<String>,
) -> Result<String, JsValue> {
    // Parse the token
    let token = WipeToken::from_hex(token_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid token: {}", e)))?;

    // Parse command type
    let cmd_type = match command_type.to_lowercase().as_str() {
        "destroy" | "destroykeys" => WipeCommandType::DestroyKeys,
        "lock" => WipeCommandType::Lock,
        "checkin" | "check-in" => WipeCommandType::CheckIn,
        "revoke" | "revoketoken" => WipeCommandType::RevokeToken,
        _ => return Err(JsValue::from_str(&format!(
            "Invalid command type: {}. Use 'destroy', 'lock', 'checkin', or 'revoke'",
            command_type
        ))),
    };

    // Create the command
    let command = match message {
        Some(msg) => WipeCommand::with_message(&token, volume_id, cmd_type, &msg),
        None => WipeCommand::new(&token, volume_id, cmd_type),
    };

    // Serialize to JSON
    serde_json::to_string(&command)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

/// Verify a wipe command signature
///
/// Use this to verify that a command was signed with the correct token.
///
/// # Arguments
///
/// * `command_json` - JSON-serialized WipeCommand
/// * `token_hex` - The wipe token as a hex string
///
/// # Returns
///
/// true if signature is valid, false otherwise
#[wasm_bindgen]
pub fn verify_wipe_command(command_json: &str, token_hex: &str) -> Result<bool, JsValue> {
    // Parse the token
    let token = WipeToken::from_hex(token_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid token: {}", e)))?;

    // Parse the command
    let command: WipeCommand = serde_json::from_str(command_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid command JSON: {}", e)))?;

    Ok(command.verify(&token))
}

/// Check if a wipe command is still fresh (within time window)
///
/// Commands expire after 5 minutes to prevent replay attacks.
///
/// # Arguments
///
/// * `command_json` - JSON-serialized WipeCommand
///
/// # Returns
///
/// true if command is fresh, false if expired
#[wasm_bindgen]
pub fn is_wipe_command_fresh(command_json: &str) -> Result<bool, JsValue> {
    let command: WipeCommand = serde_json::from_str(command_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid command JSON: {}", e)))?;

    Ok(command.is_fresh())
}

/// Get command details from a serialized command
///
/// # Arguments
///
/// * `command_json` - JSON-serialized WipeCommand
///
/// # Returns
///
/// Human-readable command details
#[wasm_bindgen]
pub fn get_wipe_command_info(command_json: &str) -> Result<String, JsValue> {
    let command: WipeCommand = serde_json::from_str(command_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid command JSON: {}", e)))?;

    let cmd_type_str = match command.data.command_type {
        WipeCommandType::DestroyKeys => "Destroy Keys (IRREVERSIBLE)",
        WipeCommandType::Lock => "Lock Volume",
        WipeCommandType::CheckIn => "Check-In",
        WipeCommandType::RevokeToken => "Revoke Token",
    };

    let message = command.data.message.as_deref().unwrap_or("None");

    Ok(format!(
        "Command Type: {}\nVolume ID: {}\nTimestamp: {}\nMessage: {}\nFresh: {}",
        cmd_type_str,
        command.data.volume_id,
        command.data.timestamp,
        message,
        command.is_fresh()
    ))
}

/// Generate a random volume ID for testing
///
/// Creates a random 16-character hex ID.
#[wasm_bindgen]
pub fn generate_test_volume_id() -> String {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("RNG failed");
    hex::encode(bytes)
}

/// Generate a test wipe token (FOR TESTING ONLY)
///
/// WARNING: In production, tokens should only be generated on the device
/// that will receive wipe commands. This function is for demonstration
/// and testing purposes only.
#[wasm_bindgen]
pub fn generate_test_wipe_token() -> String {
    let token = WipeToken::generate();
    token.to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_text() {
        let password = "test-password";
        let plaintext = "Hello, World!";

        let encrypted = encrypt_text(password, plaintext).unwrap();
        let decrypted = decrypt_text(password, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_bytes() {
        let password = "test-password";
        let data = b"Binary data test";

        let encrypted = encrypt_bytes(password, data).unwrap();
        let decrypted = decrypt_bytes(password, &encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[wasm_bindgen_test]
    fn test_config_presets() {
        let fast = EncryptConfig::fast();
        assert_eq!(fast.memory_cost, 8192);

        let balanced = EncryptConfig::balanced();
        assert_eq!(balanced.memory_cost, 65536);

        let secure = EncryptConfig::secure();
        assert_eq!(secure.memory_cost, 131072);
    }
}
