// Tauri commands for secure-cryptor GUI

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::State;

// Progress tracking state
#[derive(Default)]
struct ProgressState {
    current: Arc<Mutex<Option<ProgressInfo>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgressInfo {
    progress: f64,
    bytes_processed: u64,
    total_bytes: u64,
    speed_mbps: f64,
    eta_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptRequest {
    input_path: String,
    output_path: String,
    password: String,
    use_compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DecryptRequest {
    input_path: String,
    output_path: String,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperationResult {
    success: bool,
    message: String,
    error: Option<String>,
}

/// Encrypts a file with the provided password
#[tauri::command]
async fn encrypt_file(
    request: EncryptRequest,
    state: State<'_, ProgressState>,
) -> Result<OperationResult, String> {
    use secure_cryptor::{ChunkedEncryptor, ChunkedReader, StreamConfig};
    use secure_cryptor::crypto::aes_gcm::AesGcmEncryptor;
    use secure_cryptor::crypto::kdf::Argon2Kdf;
    use secure_cryptor::crypto::KeyDerivation;
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let input_path = PathBuf::from(&request.input_path);
    let output_path = PathBuf::from(&request.output_path);

    // Create stream configuration
    let mut config = StreamConfig::default();
    if request.use_compression {
        config = config.with_compression(true);
    }

    // Open input file
    let reader = ChunkedReader::open(&input_path, config)
        .map_err(|e| format!("Failed to open input file: {}", e))?;

    // Derive key from password
    let kdf = Argon2Kdf::default();
    let salt = kdf.generate_salt();
    let key = kdf.derive_key(request.password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    // Generate base nonce
    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut base_nonce);

    // Create encryptor
    let encryptor = ChunkedEncryptor::new(
        reader,
        Box::new(AesGcmEncryptor::new()),
        key,
        base_nonce,
        String::from_utf8(salt).unwrap(),
    );

    // Open output file
    let mut output = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    // Encrypt
    encryptor.encrypt_to(&mut output)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(OperationResult {
        success: true,
        message: format!("File encrypted successfully: {}", output_path.display()),
        error: None,
    })
}

/// Decrypts a file with the provided password
#[tauri::command]
async fn decrypt_file(
    request: DecryptRequest,
    state: State<'_, ProgressState>,
) -> Result<OperationResult, String> {
    use secure_cryptor::{ChunkedDecryptor};
    use secure_cryptor::crypto::aes_gcm::AesGcmEncryptor;
    use secure_cryptor::crypto::kdf::Argon2Kdf;
    use secure_cryptor::crypto::KeyDerivation;
    use zeroize::Zeroizing;

    let input_path = PathBuf::from(&request.input_path);
    let output_path = PathBuf::from(&request.output_path);

    // Open encrypted file
    let input = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to open input file: {}", e))?;

    // Create decryptor (reads header to get salt)
    let mut decryptor = ChunkedDecryptor::new(
        input,
        Box::new(AesGcmEncryptor::new()),
        Zeroizing::new([0u8; 32]), // Placeholder, will derive actual key
    ).map_err(|e| format!("Failed to read encrypted file: {}", e))?;

    // Get salt from header
    let salt = decryptor.header().salt.as_bytes();

    // Derive key from password and salt
    let kdf = Argon2Kdf::default();
    let key = kdf.derive_key(request.password.as_bytes(), salt)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    // Re-create decryptor with correct key
    let input = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to reopen input file: {}", e))?;

    let mut decryptor = ChunkedDecryptor::new(
        input,
        Box::new(AesGcmEncryptor::new()),
        key,
    ).map_err(|e| format!("Failed to initialize decryption: {}", e))?;

    // Open output file
    let mut output = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    // Decrypt
    decryptor.decrypt_to(&mut output)
        .map_err(|e| format!("Decryption failed (wrong password?): {}", e))?;

    Ok(OperationResult {
        success: true,
        message: format!("File decrypted successfully: {}", output_path.display()),
        error: None,
    })
}

/// Validates a password for strength
#[tauri::command]
fn validate_password(password: String) -> Result<bool, String> {
    use secure_cryptor::validation::validate_password;

    match validate_password(&password) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Gets file information
#[tauri::command]
fn get_file_info(path: String) -> Result<FileInfo, String> {
    let metadata = std::fs::metadata(&path)
        .map_err(|e| format!("Failed to get file info: {}", e))?;

    Ok(FileInfo {
        size: metadata.len(),
        size_formatted: secure_cryptor::progress::format_bytes(metadata.len()),
        is_encrypted: path.ends_with(".enc") || path.ends_with(".encrypted"),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileInfo {
    size: u64,
    size_formatted: String,
    is_encrypted: bool,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ProgressState::default())
        .invoke_handler(tauri::generate_handler![
            encrypt_file,
            decrypt_file,
            validate_password,
            get_file_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
