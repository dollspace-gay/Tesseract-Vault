// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Volume migration utilities
//!
//! This module provides functionality to migrate existing V1 volumes
//! (classical encryption only) to V2 volumes with post-quantum cryptography support.
//!
//! # Migration Process
//!
//! 1. Read and verify V1 volume header
//! 2. Unlock volume with password to get master key
//! 3. Generate new ML-KEM-1024 keypair for PQC
//! 4. Encrypt PQC decapsulation key with master key
//! 5. Create V2 header with PQC metadata
//! 6. Backup original header for rollback
//! 7. Write new V2 header and PQC metadata
//! 8. Verify migration succeeded
//!
//! # Rollback
//!
//! If migration fails, the original V1 header can be restored from backup.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

use super::container::{KEYSLOTS_OFFSET, KEYSLOTS_SIZE, PRIMARY_HEADER_OFFSET};
use super::header::{
    HeaderError, PqAlgorithm, PqVolumeMetadata, VolumeHeader, HEADER_SIZE, PQC_PADDING_SIZE,
};
use super::keyslot::{KeySlotError, KeySlots, MasterKey};
use crate::crypto::aes_gcm::AesGcmEncryptor;
use crate::crypto::pqc::{encapsulate_unchecked, MlKemKeyPair};
use crate::crypto::Encryptor;

/// Errors that can occur during volume migration
#[derive(Debug, Error)]
pub enum MigrationError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Header error
    #[error("Header error: {0}")]
    Header(#[from] HeaderError),

    /// Key slot error
    #[error("Key slot error: {0}")]
    KeySlot(#[from] KeySlotError),

    /// Volume is already V2 with PQC
    #[error("Volume is already V2 with post-quantum cryptography enabled")]
    AlreadyMigrated,

    /// Volume file not found
    #[error("Volume file not found: {0}")]
    VolumeNotFound(PathBuf),

    /// Failed to unlock volume with provided password
    #[error("Failed to unlock volume: incorrect password")]
    UnlockFailed,

    /// Verification failed after migration
    #[error("Migration verification failed: {0}")]
    VerificationFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Backup creation failed
    #[error("Backup creation failed: {0}")]
    BackupFailed(String),

    /// PQC error
    #[error("PQC error: {0}")]
    Pqc(#[from] crate::error::CryptorError),
}

/// Result type for migration operations
pub type Result<T> = std::result::Result<T, MigrationError>;

/// Migration backup containing original header and keyslots
#[derive(Debug)]
pub struct MigrationBackup {
    /// Original V1 header
    pub original_header: VolumeHeader,
    /// Original keyslots
    pub original_keyslots: KeySlots,
    /// Backup file path
    pub backup_path: PathBuf,
}

impl MigrationBackup {
    /// Save backup to disk
    pub fn save(&self) -> Result<()> {
        let mut file = File::create(&self.backup_path)
            .map_err(|e| MigrationError::BackupFailed(e.to_string()))?;

        // Write header
        let header_bytes = self.original_header.to_bytes()?;
        file.write_all(&header_bytes)?;

        // Write keyslots
        let keyslots_bytes = postcard::to_allocvec(&self.original_keyslots)
            .map_err(|e| MigrationError::Serialization(e.to_string()))?;
        file.write_all(&keyslots_bytes)?;

        Ok(())
    }

    /// Restore backup to volume
    pub fn restore(&self, volume_path: &Path) -> Result<()> {
        let mut file = OpenOptions::new().write(true).open(volume_path)?;

        // Restore header at offset 0
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let header_bytes = self.original_header.to_bytes()?;
        file.write_all(&header_bytes)?;

        // Restore keyslots at offset 8KB
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
        let keyslots_bytes = postcard::to_allocvec(&self.original_keyslots)
            .map_err(|e| MigrationError::Serialization(e.to_string()))?;
        file.write_all(&keyslots_bytes)?;

        file.sync_all()?;

        Ok(())
    }
}

/// Volume migration manager
pub struct VolumeMigration {
    /// Path to the volume file
    volume_path: PathBuf,
    /// Backup of original volume state
    backup: Option<MigrationBackup>,
}

impl VolumeMigration {
    /// Create a new migration manager for a volume
    pub fn new(volume_path: impl Into<PathBuf>) -> Self {
        Self {
            volume_path: volume_path.into(),
            backup: None,
        }
    }

    /// Read and verify V1 volume header
    fn read_v1_header(&self) -> Result<VolumeHeader> {
        let mut file = File::open(&self.volume_path)
            .map_err(|_| MigrationError::VolumeNotFound(self.volume_path.clone()))?;

        // Read header
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let mut header_bytes = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;

        let header = VolumeHeader::from_bytes(&header_bytes)?;

        // Verify it's V1 (not already migrated)
        if header.has_pqc() {
            return Err(MigrationError::AlreadyMigrated);
        }

        Ok(header)
    }

    /// Read keyslots from volume
    fn read_keyslots(&self) -> Result<KeySlots> {
        let mut file = File::open(&self.volume_path)?;

        // Read keyslots at offset 8KB
        file.seek(SeekFrom::Start(KEYSLOTS_OFFSET))?;
        let mut keyslots_bytes = vec![0u8; KEYSLOTS_SIZE];
        file.read_exact(&mut keyslots_bytes)?;

        let keyslots: KeySlots = postcard::from_bytes(&keyslots_bytes)
            .map_err(|e| MigrationError::Serialization(e.to_string()))?;

        Ok(keyslots)
    }

    /// Create backup of current volume state
    fn create_backup(&mut self, header: VolumeHeader, keyslots: KeySlots) -> Result<()> {
        let backup_path = self.volume_path.with_extension("backup");

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path,
        };

        backup.save()?;
        self.backup = Some(backup);

        Ok(())
    }

    /// Migrate volume to V2 with PQC support
    ///
    /// # Arguments
    ///
    /// * `password` - Password to unlock the volume
    ///
    /// # Returns
    ///
    /// The generated PQC keypair (caller should save the private key securely)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Volume is already V2
    /// - Password is incorrect
    /// - Migration fails
    /// - Verification fails
    pub fn migrate(&mut self, password: &str) -> Result<MlKemKeyPair> {
        // 1. Read V1 header
        let v1_header = self.read_v1_header()?;

        // 2. Read keyslots
        let mut keyslots = self.read_keyslots()?;

        // 3. Unlock to get master key
        // WARNING: This may destroy all keys if duress password is entered
        let master_key = keyslots
            .unlock(password)
            .map_err(|_| MigrationError::UnlockFailed)?;

        // 4. Create backup before making changes
        self.create_backup(v1_header.clone(), keyslots)?;

        // 5. Generate PQC keypair
        let pqc_keypair = MlKemKeyPair::generate();

        // 6. Encrypt the decapsulation key with the master key
        let encrypted_dk = self.encrypt_decapsulation_key(&master_key, &pqc_keypair)?;

        // 7. Perform encapsulation to create ciphertext
        // Using unchecked version since keypair was locally generated (safe)
        let (ciphertext, _shared_secret) = encapsulate_unchecked(pqc_keypair.encapsulation_key())?;

        // 8. Create PQC metadata with raw byte arrays
        let mut ek_bytes = [0u8; 1568];
        let mut ct_bytes = [0u8; 1568];
        let mut edk_bytes = [0u8; 3196]; // nonce (12) + encrypted DK (3168) + tag (16)

        ek_bytes.copy_from_slice(pqc_keypair.encapsulation_key());
        ct_bytes.copy_from_slice(&ciphertext);
        edk_bytes[..encrypted_dk.len()].copy_from_slice(&encrypted_dk);

        let pqc_metadata = PqVolumeMetadata {
            algorithm: PqAlgorithm::MlKem1024,
            encapsulation_key: ek_bytes,
            ciphertext: ct_bytes,
            encrypted_decapsulation_key: edk_bytes,
            reserved_padding: [0u8; PQC_PADDING_SIZE],
        };

        let pqc_metadata_bytes = pqc_metadata.to_bytes()?;
        let pqc_metadata_size = pqc_metadata_bytes.len() as u32;

        // 9. Create V2 header preserving volume settings
        let v2_header = VolumeHeader::new_with_pqc(
            v1_header.volume_size(),
            v1_header.sector_size(),
            *v1_header.salt(),
            *v1_header.header_iv(),
            pqc_metadata_size,
        );

        // 10. Write V2 header and PQC metadata to volume
        self.write_v2_volume(&v2_header, &pqc_metadata_bytes)?;

        // 11. Verify migration
        self.verify_migration(password, &pqc_keypair)?;

        Ok(pqc_keypair)
    }

    /// Encrypt the PQC decapsulation key with the master key
    ///
    /// Uses a random nonce prepended to the ciphertext to avoid nonce reuse (CWE-329).
    /// Output format: nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
    fn encrypt_decapsulation_key(
        &self,
        master_key: &MasterKey,
        keypair: &MlKemKeyPair,
    ) -> Result<Vec<u8>> {
        let encryptor = AesGcmEncryptor;

        // Generate random nonce to prevent nonce reuse attack (CWE-329)
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|e| MigrationError::Encryption(format!("Failed to generate nonce: {}", e)))?;

        let (_, dk_bytes) = keypair.to_bytes();

        // Convert master key bytes to fixed-size array reference
        let key_array: &[u8; 32] = master_key
            .as_bytes()
            .try_into()
            .map_err(|_| MigrationError::Encryption("Invalid master key size".to_string()))?;

        let ciphertext = encryptor
            .encrypt(key_array, &nonce, &dk_bytes)
            .map_err(|e| MigrationError::Encryption(e.to_string()))?;

        // Prepend nonce to ciphertext for storage
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Write V2 header and PQC metadata to volume
    fn write_v2_volume(&self, header: &VolumeHeader, pqc_metadata: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new().write(true).open(&self.volume_path)?;

        // Write V2 header at offset 0
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let header_bytes = header.to_bytes()?;
        file.write_all(&header_bytes)?;

        // Write PQC metadata at offset 4KB (HEADER_SIZE)
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        file.write_all(pqc_metadata)?;

        // Sync to disk
        file.sync_all()?;

        Ok(())
    }

    /// Verify that migration succeeded
    fn verify_migration(&self, password: &str, _keypair: &MlKemKeyPair) -> Result<()> {
        // Read back the header
        let mut file = File::open(&self.volume_path)?;
        file.seek(SeekFrom::Start(PRIMARY_HEADER_OFFSET))?;
        let mut header_bytes = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;

        let header = VolumeHeader::from_bytes(&header_bytes)?;

        // Verify it's V2 with PQC
        if !header.has_pqc() {
            return Err(MigrationError::VerificationFailed(
                "Header does not have PQC enabled".to_string(),
            ));
        }

        if header.pq_algorithm() != PqAlgorithm::MlKem1024 {
            return Err(MigrationError::VerificationFailed(
                "PQ algorithm is not ML-KEM-1024".to_string(),
            ));
        }

        // Verify keyslots still work
        let mut keyslots = self.read_keyslots()?;
        keyslots.unlock(password).map_err(|_| {
            MigrationError::VerificationFailed("Cannot unlock volume after migration".to_string())
        })?;

        // Verify PQC metadata exists and is valid
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        let mut pqc_bytes = vec![0u8; header.pq_metadata_size() as usize];
        file.read_exact(&mut pqc_bytes)?;

        let _pqc_metadata = PqVolumeMetadata::from_bytes(&pqc_bytes).map_err(|e| {
            MigrationError::VerificationFailed(format!("Invalid PQC metadata: {}", e))
        })?;

        Ok(())
    }

    /// Rollback migration using backup
    pub fn rollback(&self) -> Result<()> {
        let backup = self.backup.as_ref().ok_or_else(|| {
            MigrationError::BackupFailed("No backup available for rollback".to_string())
        })?;

        backup.restore(&self.volume_path)?;

        Ok(())
    }

    /// Get the backup path if backup exists
    pub fn backup_path(&self) -> Option<&Path> {
        self.backup.as_ref().map(|b| b.backup_path.as_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_migration_manager_creation() {
        let migration = VolumeMigration::new("test.vol");
        assert_eq!(migration.volume_path, PathBuf::from("test.vol"));
        assert!(migration.backup.is_none());
    }

    #[test]
    fn test_migration_manager_creation_pathbuf() {
        let path = PathBuf::from("/some/path/volume.vol");
        let migration = VolumeMigration::new(path.clone());
        assert_eq!(migration.volume_path, path);
        assert!(migration.backup_path().is_none());
    }

    #[test]
    fn test_migration_error_display() {
        let io_err = MigrationError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let already_migrated = MigrationError::AlreadyMigrated;
        assert!(already_migrated.to_string().contains("already V2"));

        let volume_not_found = MigrationError::VolumeNotFound(PathBuf::from("/test/path"));
        assert!(volume_not_found.to_string().contains("/test/path"));

        let unlock_failed = MigrationError::UnlockFailed;
        assert!(unlock_failed.to_string().contains("incorrect password"));

        let verification_failed = MigrationError::VerificationFailed("test failure".to_string());
        assert!(verification_failed.to_string().contains("test failure"));

        let serialization = MigrationError::Serialization("ser error".to_string());
        assert!(serialization.to_string().contains("ser error"));

        let encryption = MigrationError::Encryption("enc error".to_string());
        assert!(encryption.to_string().contains("enc error"));

        let backup_failed = MigrationError::BackupFailed("backup error".to_string());
        assert!(backup_failed.to_string().contains("backup error"));
    }

    #[test]
    fn test_migration_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let migration_err: MigrationError = io_err.into();
        assert!(matches!(migration_err, MigrationError::Io(_)));
    }

    #[test]
    fn test_read_v1_header_file_not_found() {
        let migration = VolumeMigration::new("/nonexistent/path/volume.vol");
        let result = migration.read_v1_header();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MigrationError::VolumeNotFound(_)
        ));
    }

    #[test]
    fn test_read_keyslots_file_not_found() {
        let migration = VolumeMigration::new("/nonexistent/path/volume.vol");
        let result = migration.read_keyslots();
        assert!(result.is_err());
    }

    #[test]
    fn test_rollback_no_backup() {
        let migration = VolumeMigration::new("test.vol");
        let result = migration.rollback();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MigrationError::BackupFailed(_)
        ));
    }

    #[test]
    fn test_migration_backup_save_invalid_path() {
        use super::super::header::VolumeHeader;
        use super::super::keyslot::KeySlots;

        let salt = [0u8; 32];
        let header_iv = [0u8; 12];
        let header = VolumeHeader::new(1024 * 1024, 4096, salt, header_iv);
        let keyslots = KeySlots::new();

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path: PathBuf::from("/nonexistent/directory/backup.bak"),
        };

        let result = backup.save();
        assert!(result.is_err());
    }

    #[test]
    fn test_migration_backup_restore_invalid_path() {
        use super::super::header::VolumeHeader;
        use super::super::keyslot::KeySlots;

        let salt = [0u8; 32];
        let header_iv = [0u8; 12];
        let header = VolumeHeader::new(1024 * 1024, 4096, salt, header_iv);
        let keyslots = KeySlots::new();

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path: PathBuf::from("test.backup"),
        };

        let result = backup.restore(Path::new("/nonexistent/volume.vol"));
        assert!(result.is_err());
    }

    #[test]
    fn test_migration_backup_debug() {
        use super::super::header::VolumeHeader;
        use super::super::keyslot::KeySlots;

        let salt = [0u8; 32];
        let header_iv = [0u8; 12];
        let header = VolumeHeader::new(1024 * 1024, 4096, salt, header_iv);
        let keyslots = KeySlots::new();

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path: PathBuf::from("test.backup"),
        };

        let debug_str = format!("{:?}", backup);
        assert!(debug_str.contains("MigrationBackup"));
    }

    #[test]
    fn test_read_v1_header_invalid_header() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write invalid header data
        temp_file.write_all(&[0u8; 4096]).unwrap();
        temp_file.flush().unwrap();

        let migration = VolumeMigration::new(temp_file.path());
        let result = migration.read_v1_header();
        // Should fail due to invalid header format
        assert!(result.is_err());
    }

    // ========================================================================
    // MigrationError Tests
    // ========================================================================

    #[test]
    fn test_migration_error_from_header() {
        use super::super::header::HeaderError;
        let header_err = HeaderError::InvalidMagic;
        let migration_err: MigrationError = header_err.into();
        assert!(matches!(migration_err, MigrationError::Header(_)));
    }

    #[test]
    fn test_migration_error_from_keyslot() {
        use super::super::keyslot::KeySlotError;
        let ks_err = KeySlotError::AllSlotsFull;
        let migration_err: MigrationError = ks_err.into();
        assert!(matches!(migration_err, MigrationError::KeySlot(_)));
    }

    #[test]
    fn test_migration_error_display_pqc() {
        use crate::error::CryptorError;
        let pqc_err = MigrationError::Pqc(CryptorError::Cryptography("test".to_string()));
        assert!(pqc_err.to_string().contains("PQC error"));
    }

    // ========================================================================
    // MigrationBackup Tests
    // ========================================================================

    #[test]
    fn test_migration_backup_save_success() {
        use super::super::header::VolumeHeader;
        use super::super::keyslot::KeySlots;

        let salt = [0u8; 32];
        let header_iv = [0u8; 12];
        let header = VolumeHeader::new(1024 * 1024, 4096, salt, header_iv);
        let keyslots = KeySlots::new();

        let temp_file = NamedTempFile::new().unwrap();
        let backup_path = temp_file.path().to_path_buf();

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path,
        };

        // Should succeed
        let result = backup.save();
        assert!(result.is_ok());
    }

    #[test]
    fn test_migration_backup_fields() {
        use super::super::header::VolumeHeader;
        use super::super::keyslot::KeySlots;

        let salt = [0u8; 32];
        let header_iv = [0u8; 12];
        let header = VolumeHeader::new(2 * 1024 * 1024, 4096, salt, header_iv);
        let keyslots = KeySlots::new();

        let backup = MigrationBackup {
            original_header: header,
            original_keyslots: keyslots,
            backup_path: PathBuf::from("/test/backup.bak"),
        };

        assert_eq!(backup.backup_path, PathBuf::from("/test/backup.bak"));
        assert_eq!(backup.original_header.volume_size(), 2 * 1024 * 1024);
    }

    // ========================================================================
    // VolumeMigration Tests
    // ========================================================================

    #[test]
    fn test_volume_migration_backup_path_none() {
        let migration = VolumeMigration::new("/test/volume.vol");
        assert!(migration.backup_path().is_none());
    }

    #[test]
    fn test_volume_migration_new_with_string() {
        let migration = VolumeMigration::new("test_volume.vol");
        assert_eq!(migration.volume_path, PathBuf::from("test_volume.vol"));
    }

    #[test]
    fn test_read_keyslots_invalid_data() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write enough data for header + keyslots region but invalid format
        temp_file.write_all(&[0xFFu8; 64 * 1024]).unwrap();
        temp_file.flush().unwrap();

        let migration = VolumeMigration::new(temp_file.path());
        let result = migration.read_keyslots();
        // Should fail due to invalid keyslots format
        assert!(result.is_err());
    }

    #[test]
    fn test_migrate_nonexistent_file() {
        let mut migration = VolumeMigration::new("/nonexistent/path/volume.vol");
        let result = migration.migrate("password");
        match result {
            Err(MigrationError::VolumeNotFound(_)) => {}
            Err(other) => panic!("Expected VolumeNotFound, got: {}", other),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    // ========================================================================
    // Result Type Tests
    // ========================================================================

    #[test]
    fn test_result_type_ok() {
        let result: Result<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_err() {
        let result: Result<i32> = Err(MigrationError::UnlockFailed);
        assert!(result.is_err());
    }

    // ========================================================================
    // Error Conversion Chain Tests
    // ========================================================================

    #[test]
    fn test_error_chain_io_to_migration() {
        fn may_fail() -> Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            ))?
        }

        let result = may_fail();
        assert!(result.is_err());
    }

    #[test]
    fn test_migration_error_already_migrated_message() {
        let err = MigrationError::AlreadyMigrated;
        let msg = err.to_string();
        assert!(msg.contains("already V2"));
        assert!(msg.contains("post-quantum"));
    }

    #[test]
    fn test_migration_error_unlock_failed_message() {
        let err = MigrationError::UnlockFailed;
        let msg = err.to_string();
        assert!(msg.contains("incorrect password") || msg.contains("unlock"));
    }

    #[test]
    fn test_migration_error_verification_contains_detail() {
        let err = MigrationError::VerificationFailed("custom detail here".to_string());
        let msg = err.to_string();
        assert!(msg.contains("custom detail here"));
        assert!(msg.contains("verification failed") || msg.contains("Verification"));
    }

    #[test]
    fn test_migration_error_serialization_contains_detail() {
        let err = MigrationError::Serialization("postcard failed".to_string());
        let msg = err.to_string();
        assert!(msg.contains("postcard failed"));
    }

    #[test]
    fn test_migration_error_encryption_contains_detail() {
        let err = MigrationError::Encryption("AES-GCM error".to_string());
        let msg = err.to_string();
        assert!(msg.contains("AES-GCM error"));
    }

    #[test]
    fn test_migration_error_backup_failed_contains_detail() {
        let err = MigrationError::BackupFailed("disk full".to_string());
        let msg = err.to_string();
        assert!(msg.contains("disk full"));
    }

    // ========================================================================
    // Full Migration Flow Tests (using temp containers)
    // Note: Container::create() now creates V2 containers with PQC by default.
    // These tests verify migration correctly detects and handles V2 containers.
    // ========================================================================

    #[test]
    fn test_migrate_v2_container_returns_already_migrated() {
        use super::super::container::Container;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let container_path = temp_dir.path().join("test_v2.scv");
        let password = "TestPassword123!@#Strong";

        // Container::create() creates V2 (PQC-enabled) containers by default
        Container::create(&container_path, 1024 * 1024, password, 4096).unwrap();

        // Migration should detect this is already V2 and return AlreadyMigrated
        let mut migration = VolumeMigration::new(&container_path);
        let result = migration.migrate(password);
        match result {
            Err(MigrationError::AlreadyMigrated) => {}
            Err(other) => panic!("Expected AlreadyMigrated, got: {}", other),
            Ok(_) => panic!("Expected AlreadyMigrated error, got Ok"),
        }
    }

    #[test]
    fn test_migrate_nonexistent_returns_volume_not_found() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let container_path = temp_dir.path().join("nonexistent.scv");

        let mut migration = VolumeMigration::new(&container_path);
        let result = migration.migrate("password");

        match result {
            Err(MigrationError::VolumeNotFound(_)) => {}
            Err(other) => panic!("Expected VolumeNotFound, got: {}", other),
            Ok(_) => panic!("Expected VolumeNotFound error, got Ok"),
        }
    }

    #[test]
    fn test_rollback_on_v2_container_fails_gracefully() {
        use super::super::container::Container;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let container_path = temp_dir.path().join("test_rollback.scv");
        let password = "TestPassword123!@#Strong";

        // Create V2 container
        Container::create(&container_path, 1024 * 1024, password, 4096).unwrap();

        // Create migration but don't migrate (already V2)
        let migration = VolumeMigration::new(&container_path);

        // Rollback without migration should fail (no backup exists)
        let rollback_result = migration.rollback();
        assert!(rollback_result.is_err());
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_migration_backup_path_initially_none() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let container_path = temp_dir.path().join("volume.scv");

        // Before any migration, backup_path should be None
        let migration = VolumeMigration::new(&container_path);
        assert!(migration.backup_path().is_none());
    }

    #[test]
    fn test_migration_manager_with_pathbuf() {
        use std::path::PathBuf;

        let path = PathBuf::from("/some/path/volume.scv");
        let migration = VolumeMigration::new(&path);

        // Should initialize correctly with PathBuf
        assert!(migration.backup_path().is_none());
    }
}
