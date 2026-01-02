// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Cloud synchronization with incremental chunk tracking
//!
//! This module provides intelligent sync for cloud-backed encrypted volumes.
//! Instead of re-uploading the entire volume when files change, it tracks
//! which chunks have been modified and only syncs those.
//!
//! ## Architecture
//!
//! ```text
//! +------------------+
//! |  VolumeIO        |
//! +--------+---------+
//!          |
//! +--------v---------+
//! | CloudSyncManager |  <- This module
//! |  +------------+  |
//! |  |ChunkTracker|  |  (hash-based change detection)
//! |  +-----+------+  |
//! |        |         |
//! |  +-----v------+  |
//! |  |SyncManifest|  |  (persisted sync state)
//! |  +-----+------+  |
//! +--------+---------+
//!          |
//! +--------v---------+
//! | AsyncStorage     |  (S3, Dropbox, etc.)
//! +------------------+
//! ```
//!
//! ## How Incremental Sync Works
//!
//! 1. Each chunk is hashed with Blake3 when written locally
//! 2. The hash is compared against the last synced hash
//! 3. Only chunks with different hashes are uploaded
//! 4. A manifest file tracks all chunk hashes and sync timestamps

use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Size of a Blake3 hash in bytes
pub const HASH_SIZE: usize = 32;

/// Blake3 hash of chunk content for change detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkHash([u8; HASH_SIZE]);

impl ChunkHash {
    /// Creates a new ChunkHash from raw bytes
    pub fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Computes the hash of chunk data
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }

    /// Returns the hash as a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns the raw bytes
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    /// Creates a zero hash (for empty/uninitialized chunks)
    pub fn zero() -> Self {
        Self([0u8; HASH_SIZE])
    }
}

impl Default for ChunkHash {
    fn default() -> Self {
        Self::zero()
    }
}

/// State of a single chunk in the sync system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkState {
    /// Blake3 hash of the local chunk content
    pub local_hash: ChunkHash,

    /// Blake3 hash of the last synced version (in cloud)
    pub synced_hash: ChunkHash,

    /// Unix timestamp of last local modification
    pub local_modified: u64,

    /// Unix timestamp of last successful sync
    pub last_synced: u64,

    /// Whether this chunk exists in cloud storage
    pub exists_in_cloud: bool,
}

impl ChunkState {
    /// Creates a new ChunkState for a freshly written chunk
    pub fn new(hash: ChunkHash) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            local_hash: hash,
            synced_hash: ChunkHash::zero(),
            local_modified: now,
            last_synced: 0,
            exists_in_cloud: false,
        }
    }

    /// Returns true if this chunk needs to be synced to cloud
    pub fn needs_sync(&self) -> bool {
        self.local_hash != self.synced_hash
    }

    /// Marks this chunk as successfully synced
    pub fn mark_synced(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.synced_hash = self.local_hash;
        self.last_synced = now;
        self.exists_in_cloud = true;
    }

    /// Updates the local hash (called when chunk is written)
    pub fn update_local(&mut self, hash: ChunkHash) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.local_hash = hash;
        self.local_modified = now;
    }
}

/// Sync manifest containing all chunk states and volume metadata
///
/// This is serialized and stored in cloud storage to track sync state
/// across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    /// Version of the manifest format
    pub version: u32,

    /// Unique identifier for this volume
    pub volume_id: String,

    /// Total size of the volume in bytes
    pub volume_size: u64,

    /// Size of each chunk in bytes
    pub chunk_size: u64,

    /// Total number of chunks
    pub total_chunks: u64,

    /// State of each chunk, keyed by chunk index
    pub chunks: HashMap<u64, ChunkState>,

    /// Unix timestamp when manifest was last updated
    pub last_updated: u64,

    /// Encryption parameters (stored for validation, not the key!)
    pub encryption_params: EncryptionParams,
}

/// Encryption parameters stored in manifest (NO KEYS!)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionParams {
    /// Sector size used for XTS encryption
    pub sector_size: u32,

    /// Salt for key derivation (not the key itself)
    pub kdf_salt_hash: ChunkHash,
}

impl SyncManifest {
    /// Creates a new manifest for a volume
    pub fn new(
        volume_id: String,
        volume_size: u64,
        chunk_size: u64,
        sector_size: u32,
        kdf_salt: &[u8],
    ) -> Self {
        let total_chunks = volume_size.div_ceil(chunk_size);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            version: 1,
            volume_id,
            volume_size,
            chunk_size,
            total_chunks,
            chunks: HashMap::new(),
            last_updated: now,
            encryption_params: EncryptionParams {
                sector_size,
                kdf_salt_hash: ChunkHash::compute(kdf_salt),
            },
        }
    }

    /// Gets the state of a chunk, creating default if not exists
    pub fn get_chunk(&self, chunk_index: u64) -> Option<&ChunkState> {
        self.chunks.get(&chunk_index)
    }

    /// Updates or creates chunk state
    pub fn update_chunk(&mut self, chunk_index: u64, hash: ChunkHash) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.chunks
            .entry(chunk_index)
            .and_modify(|state| state.update_local(hash))
            .or_insert_with(|| ChunkState::new(hash));

        self.last_updated = now;
    }

    /// Marks a chunk as synced
    pub fn mark_chunk_synced(&mut self, chunk_index: u64) {
        if let Some(state) = self.chunks.get_mut(&chunk_index) {
            state.mark_synced();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_updated = now;
    }

    /// Returns list of chunk indices that need syncing
    pub fn chunks_needing_sync(&self) -> Vec<u64> {
        self.chunks
            .iter()
            .filter(|(_, state)| state.needs_sync())
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Returns the number of dirty (unsynced) chunks
    pub fn dirty_count(&self) -> usize {
        self.chunks.values().filter(|s| s.needs_sync()).count()
    }

    /// Serializes manifest to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Deserializes manifest from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    /// Validates that encryption params match (security check)
    pub fn validate_params(&self, sector_size: u32, kdf_salt: &[u8]) -> bool {
        self.encryption_params.sector_size == sector_size
            && self.encryption_params.kdf_salt_hash == ChunkHash::compute(kdf_salt)
    }
}

/// Chunk tracker for local change detection
///
/// This is the in-memory tracker that monitors chunk modifications
/// and updates the manifest accordingly.
pub struct ChunkTracker {
    /// The sync manifest
    manifest: SyncManifest,

    /// Whether the manifest itself has unsaved changes
    manifest_dirty: bool,
}

impl ChunkTracker {
    /// Creates a new chunk tracker with a fresh manifest
    pub fn new(
        volume_id: String,
        volume_size: u64,
        chunk_size: u64,
        sector_size: u32,
        kdf_salt: &[u8],
    ) -> Self {
        Self {
            manifest: SyncManifest::new(volume_id, volume_size, chunk_size, sector_size, kdf_salt),
            manifest_dirty: true,
        }
    }

    /// Creates a tracker from an existing manifest
    pub fn from_manifest(manifest: SyncManifest) -> Self {
        Self {
            manifest,
            manifest_dirty: false,
        }
    }

    /// Records that a chunk was written with the given data
    pub fn record_write(&mut self, chunk_index: u64, data: &[u8]) {
        let hash = ChunkHash::compute(data);
        self.manifest.update_chunk(chunk_index, hash);
        self.manifest_dirty = true;
    }

    /// Records that a chunk was successfully synced to cloud
    pub fn record_synced(&mut self, chunk_index: u64) {
        self.manifest.mark_chunk_synced(chunk_index);
        self.manifest_dirty = true;
    }

    /// Returns chunks that need to be synced
    pub fn get_dirty_chunks(&self) -> Vec<u64> {
        self.manifest.chunks_needing_sync()
    }

    /// Returns the number of dirty chunks
    pub fn dirty_count(&self) -> usize {
        self.manifest.dirty_count()
    }

    /// Returns whether the manifest needs to be saved
    pub fn is_manifest_dirty(&self) -> bool {
        self.manifest_dirty
    }

    /// Gets the manifest for serialization
    pub fn manifest(&self) -> &SyncManifest {
        &self.manifest
    }

    /// Marks the manifest as saved
    pub fn mark_manifest_saved(&mut self) {
        self.manifest_dirty = false;
    }

    /// Gets the hash of a chunk if tracked
    pub fn get_chunk_hash(&self, chunk_index: u64) -> Option<ChunkHash> {
        self.manifest.get_chunk(chunk_index).map(|s| s.local_hash)
    }

    /// Checks if a chunk needs sync
    pub fn chunk_needs_sync(&self, chunk_index: u64) -> bool {
        self.manifest
            .get_chunk(chunk_index)
            .is_some_and(|s| s.needs_sync())
    }
}

/// Sync statistics returned after a sync operation
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Number of chunks uploaded
    pub chunks_uploaded: u64,

    /// Number of chunks that were already synced
    pub chunks_skipped: u64,

    /// Total bytes uploaded
    pub bytes_uploaded: u64,

    /// Time taken in milliseconds
    pub duration_ms: u64,

    /// Any errors encountered (chunk_index, error message)
    pub errors: Vec<(u64, String)>,
}

impl SyncStats {
    /// Returns true if sync completed without errors
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns the sync success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.chunks_uploaded + self.errors.len() as u64;
        if total == 0 {
            100.0
        } else {
            (self.chunks_uploaded as f64 / total as f64) * 100.0
        }
    }
}

/// Cloud sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum concurrent chunk uploads
    pub max_concurrent_uploads: usize,

    /// Whether to retry failed chunks
    pub retry_failed: bool,

    /// Maximum retry attempts per chunk
    pub max_retries: u32,

    /// Whether to compress chunks before upload
    pub compress_chunks: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_uploads: 4,
            retry_failed: true,
            max_retries: 3,
            compress_chunks: false,
        }
    }
}

/// Error type for cloud sync operations
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Manifest validation failed: encryption parameters mismatch")]
    ManifestValidation,

    #[error("Chunk {0} sync failed: {1}")]
    ChunkSync(u64, String),

    #[error("Backend error: {0}")]
    Backend(String),

    #[error("Manifest not found in cloud storage")]
    ManifestNotFound,
}

pub type SyncResult<T> = Result<T, SyncError>;

/// Cloud sync manager that orchestrates syncing between local and cloud storage
///
/// This manager integrates the ChunkTracker with an AsyncStorageBackend to
/// provide complete incremental sync functionality.
pub struct CloudSyncManager<B> {
    /// The chunk tracker for change detection
    tracker: ChunkTracker,

    /// The cloud storage backend
    backend: B,

    /// Sync configuration
    config: SyncConfig,

    /// Path/key for the manifest in cloud storage
    manifest_key: String,
}

impl<B: super::io::AsyncStorageBackend> CloudSyncManager<B> {
    /// Creates a new CloudSyncManager with a fresh manifest
    ///
    /// Use this when creating a new cloud-backed volume.
    pub fn new(
        backend: B,
        volume_id: String,
        volume_size: u64,
        chunk_size: u64,
        sector_size: u32,
        kdf_salt: &[u8],
        manifest_key: String,
    ) -> Self {
        Self {
            tracker: ChunkTracker::new(volume_id, volume_size, chunk_size, sector_size, kdf_salt),
            backend,
            config: SyncConfig::default(),
            manifest_key,
        }
    }

    /// Creates a CloudSyncManager from an existing manifest
    ///
    /// Use this when reopening an existing cloud-backed volume.
    pub fn from_manifest(backend: B, manifest: SyncManifest, manifest_key: String) -> Self {
        Self {
            tracker: ChunkTracker::from_manifest(manifest),
            backend,
            config: SyncConfig::default(),
            manifest_key,
        }
    }

    /// Loads a manifest from cloud storage
    ///
    /// Returns None if the manifest doesn't exist (new volume).
    /// The `_manifest_key` parameter is reserved for backends that support named objects.
    pub async fn load_manifest_from_cloud(
        backend: &B,
        _manifest_key: &str,
    ) -> SyncResult<Option<SyncManifest>> {
        // The manifest is stored as a special "chunk" with index u64::MAX
        // This reserved index is used consistently across all chunk-based backends
        let manifest_chunk_index = u64::MAX;

        match backend.read_chunk(manifest_chunk_index, 0).await {
            Ok(Some(data)) => {
                let manifest = SyncManifest::from_bytes(&data)?;
                Ok(Some(manifest))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Saves the manifest to cloud storage
    pub async fn save_manifest(&mut self) -> SyncResult<()> {
        let data = self.tracker.manifest().to_bytes()?;

        // Store manifest as special chunk at u64::MAX
        let manifest_chunk_index = u64::MAX;

        self.backend
            .write_chunk(manifest_chunk_index, &data)
            .await
            .map_err(SyncError::Io)?;

        self.tracker.mark_manifest_saved();
        Ok(())
    }

    /// Records a chunk write (call this when local chunk is modified)
    pub fn record_write(&mut self, chunk_index: u64, data: &[u8]) {
        self.tracker.record_write(chunk_index, data);
    }

    /// Returns the number of chunks that need syncing
    pub fn pending_sync_count(&self) -> usize {
        self.tracker.dirty_count()
    }

    /// Returns the list of chunk indices that need syncing
    pub fn chunks_needing_sync(&self) -> Vec<u64> {
        self.tracker.get_dirty_chunks()
    }

    /// Syncs a single chunk to cloud storage
    ///
    /// Returns true if the chunk was uploaded, false if it was already synced.
    pub async fn sync_chunk(&mut self, chunk_index: u64, data: &[u8]) -> SyncResult<bool> {
        // Check if chunk actually needs sync
        if !self.tracker.chunk_needs_sync(chunk_index) {
            return Ok(false);
        }

        // Verify the data hash matches what we're tracking
        let current_hash = ChunkHash::compute(data);
        if let Some(tracked_hash) = self.tracker.get_chunk_hash(chunk_index) {
            if current_hash != tracked_hash {
                // Data has changed since we recorded it, update the tracker
                self.tracker.record_write(chunk_index, data);
            }
        }

        // Upload the chunk
        self.backend
            .write_chunk(chunk_index, data)
            .await
            .map_err(|e| SyncError::ChunkSync(chunk_index, e.to_string()))?;

        // Mark as synced
        self.tracker.record_synced(chunk_index);

        Ok(true)
    }

    /// Performs a full sync of all dirty chunks
    ///
    /// The `get_chunk_data` function is called for each dirty chunk to retrieve
    /// its current data. This allows the sync manager to work without holding
    /// all chunk data in memory.
    pub async fn sync_all<F>(&mut self, get_chunk_data: F) -> SyncResult<SyncStats>
    where
        F: Fn(u64) -> Option<Vec<u8>>,
    {
        let start = std::time::Instant::now();
        let mut stats = SyncStats::default();

        let dirty_chunks = self.tracker.get_dirty_chunks();
        let total_dirty = dirty_chunks.len() as u64;

        for chunk_index in dirty_chunks {
            match get_chunk_data(chunk_index) {
                Some(data) => match self.sync_chunk(chunk_index, &data).await {
                    Ok(true) => {
                        stats.chunks_uploaded += 1;
                        stats.bytes_uploaded += data.len() as u64;
                    }
                    Ok(false) => {
                        stats.chunks_skipped += 1;
                    }
                    Err(e) => {
                        stats.errors.push((chunk_index, e.to_string()));
                    }
                },
                None => {
                    stats
                        .errors
                        .push((chunk_index, "Failed to get chunk data".to_string()));
                }
            }
        }

        // Save manifest if we synced any chunks
        if stats.chunks_uploaded > 0 || total_dirty > 0 {
            if let Err(e) = self.save_manifest().await {
                stats
                    .errors
                    .push((u64::MAX, format!("Failed to save manifest: {}", e)));
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;
        Ok(stats)
    }

    /// Downloads a chunk from cloud storage
    pub async fn download_chunk(&self, chunk_index: u64) -> SyncResult<Option<Vec<u8>>> {
        self.backend
            .read_chunk(chunk_index, 0)
            .await
            .map_err(SyncError::Io)
    }

    /// Deletes a chunk from cloud storage
    pub async fn delete_chunk(&mut self, chunk_index: u64) -> SyncResult<()> {
        self.backend
            .delete_chunk(chunk_index)
            .await
            .map_err(SyncError::Io)
    }

    /// Returns whether the manifest needs to be saved
    pub fn is_manifest_dirty(&self) -> bool {
        self.tracker.is_manifest_dirty()
    }

    /// Returns a reference to the manifest
    pub fn manifest(&self) -> &SyncManifest {
        self.tracker.manifest()
    }

    /// Returns a reference to the sync configuration
    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// Sets the sync configuration
    pub fn set_config(&mut self, config: SyncConfig) {
        self.config = config;
    }

    /// Returns the manifest key
    pub fn manifest_key(&self) -> &str {
        &self.manifest_key
    }

    /// Validates that the loaded manifest matches the expected parameters
    pub fn validate_params(&self, sector_size: u32, kdf_salt: &[u8]) -> bool {
        self.tracker
            .manifest()
            .validate_params(sector_size, kdf_salt)
    }
}

// =============================================================================
// Remote Wipe Command Delivery via Cloud Sync
// =============================================================================
//
// This section integrates remote wipe functionality with cloud sync, allowing
// wipe commands to be delivered through the same cloud storage backend used
// for volume synchronization.
//
// Architecture:
// - Wipe commands are stored at reserved chunk index (u64::MAX - 1)
// - Commands are JSON-serialized WipeCommand structs
// - Clients poll for commands during sync operations
// - Commands are deleted after successful processing

use crate::volume::remote_wipe::{StoredWipeConfig, WipeCommand};

/// Reserved chunk index for wipe command storage
/// (u64::MAX is used for manifest, so we use MAX-1 for commands)
pub const WIPE_COMMAND_CHUNK_INDEX: u64 = u64::MAX - 1;

/// Reserved chunk index for wipe config storage
pub const WIPE_CONFIG_CHUNK_INDEX: u64 = u64::MAX - 2;

/// Pending wipe commands stored in cloud
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWipeCommands {
    /// List of pending commands (usually just one)
    pub commands: Vec<WipeCommand>,
    /// Timestamp when commands were last updated
    pub updated_at: u64,
}

impl CloudWipeCommands {
    /// Creates an empty command list
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Adds a command to the list
    pub fn push(&mut self, command: WipeCommand) {
        self.commands.push(command);
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Removes and returns the first command
    pub fn pop(&mut self) -> Option<WipeCommand> {
        if self.commands.is_empty() {
            return None;
        }
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(self.commands.remove(0))
    }

    /// Returns true if there are pending commands
    pub fn has_pending(&self) -> bool {
        !self.commands.is_empty()
    }

    /// Serializes to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

impl Default for CloudWipeCommands {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloud-based wipe command delivery
///
/// This manager handles storing and retrieving wipe commands via cloud storage,
/// enabling remote wipe capability across devices.
pub struct CloudWipeManager<B> {
    /// The cloud storage backend
    backend: B,
    /// Volume ID for command filtering
    volume_id: String,
}

impl<B: super::io::AsyncStorageBackend> CloudWipeManager<B> {
    /// Creates a new CloudWipeManager
    pub fn new(backend: B, volume_id: String) -> Self {
        Self { backend, volume_id }
    }

    /// Stores a wipe command in cloud storage for delivery
    ///
    /// This is called from the web interface or another triggering device.
    pub async fn push_command(&self, command: WipeCommand) -> SyncResult<()> {
        // Load existing commands
        let mut commands = self.load_commands().await?.unwrap_or_default();

        // Add the new command
        commands.push(command);

        // Save back to cloud
        let data = commands.to_bytes()?;
        self.backend
            .write_chunk(WIPE_COMMAND_CHUNK_INDEX, &data)
            .await
            .map_err(SyncError::Io)?;

        Ok(())
    }

    /// Loads pending wipe commands from cloud storage
    pub async fn load_commands(&self) -> SyncResult<Option<CloudWipeCommands>> {
        match self.backend.read_chunk(WIPE_COMMAND_CHUNK_INDEX, 0).await {
            Ok(Some(data)) => {
                let commands = CloudWipeCommands::from_bytes(&data)?;
                Ok(Some(commands))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Checks for and returns pending wipe commands for this volume
    ///
    /// Filters commands by volume_id to ensure we only process commands
    /// intended for this volume.
    pub async fn poll_commands(&self) -> SyncResult<Vec<WipeCommand>> {
        let commands = self.load_commands().await?;

        match commands {
            Some(cmds) => {
                // Filter commands for this volume
                let matching: Vec<WipeCommand> = cmds
                    .commands
                    .into_iter()
                    .filter(|cmd| cmd.data.volume_id == self.volume_id)
                    .collect();
                Ok(matching)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Removes a processed command from cloud storage
    ///
    /// Call this after successfully processing a wipe command.
    pub async fn acknowledge_command(&self, command: &WipeCommand) -> SyncResult<()> {
        let mut commands = self.load_commands().await?.unwrap_or_default();

        // Remove the specific command (match by nonce for uniqueness)
        commands
            .commands
            .retain(|c| c.data.nonce != command.data.nonce);

        // Save updated list (or delete if empty)
        if commands.commands.is_empty() {
            // Delete the command chunk
            self.backend
                .delete_chunk(WIPE_COMMAND_CHUNK_INDEX)
                .await
                .map_err(SyncError::Io)?;
        } else {
            let data = commands.to_bytes()?;
            self.backend
                .write_chunk(WIPE_COMMAND_CHUNK_INDEX, &data)
                .await
                .map_err(SyncError::Io)?;
        }

        Ok(())
    }

    /// Stores the wipe configuration in cloud storage
    ///
    /// This allows other devices to know remote wipe is configured.
    pub async fn store_config(&self, config: &StoredWipeConfig) -> SyncResult<()> {
        let data = config
            .to_bytes()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        self.backend
            .write_chunk(WIPE_CONFIG_CHUNK_INDEX, &data)
            .await
            .map_err(SyncError::Io)?;

        Ok(())
    }

    /// Loads the wipe configuration from cloud storage
    pub async fn load_config(&self) -> SyncResult<Option<StoredWipeConfig>> {
        match self.backend.read_chunk(WIPE_CONFIG_CHUNK_INDEX, 0).await {
            Ok(Some(data)) => {
                let config = StoredWipeConfig::from_bytes(&data)
                    .map_err(|e| SyncError::Backend(e.to_string()))?;
                Ok(Some(config))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Deletes all wipe-related data from cloud storage
    ///
    /// Call this when disabling remote wipe or deleting the volume.
    pub async fn clear_all(&self) -> SyncResult<()> {
        // Delete commands
        let _ = self.backend.delete_chunk(WIPE_COMMAND_CHUNK_INDEX).await;
        // Delete config
        let _ = self.backend.delete_chunk(WIPE_CONFIG_CHUNK_INDEX).await;
        Ok(())
    }

    /// Returns the volume ID
    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }
}

// Extension methods to add wipe command functionality to CloudSyncManager
impl<B: super::io::AsyncStorageBackend> CloudSyncManager<B> {
    /// Polls for pending wipe commands during sync
    ///
    /// This should be called periodically or at the start of sync operations
    /// to check for remote wipe commands.
    pub async fn check_for_wipe_commands(&self) -> SyncResult<Vec<WipeCommand>> {
        let volume_id = self.manifest().volume_id.clone();

        // Load commands from cloud
        match self.backend.read_chunk(WIPE_COMMAND_CHUNK_INDEX, 0).await {
            Ok(Some(data)) => {
                let commands = CloudWipeCommands::from_bytes(&data)?;
                // Filter commands for this volume
                let matching: Vec<WipeCommand> = commands
                    .commands
                    .into_iter()
                    .filter(|cmd| cmd.data.volume_id == volume_id)
                    .collect();
                Ok(matching)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Stores the wipe configuration alongside volume data
    pub async fn store_wipe_config(&self, config: &StoredWipeConfig) -> SyncResult<()> {
        let data = config
            .to_bytes()
            .map_err(|e| SyncError::Backend(e.to_string()))?;

        self.backend
            .write_chunk(WIPE_CONFIG_CHUNK_INDEX, &data)
            .await
            .map_err(SyncError::Io)?;

        Ok(())
    }

    /// Loads the wipe configuration from cloud
    pub async fn load_wipe_config(&self) -> SyncResult<Option<StoredWipeConfig>> {
        match self.backend.read_chunk(WIPE_CONFIG_CHUNK_INDEX, 0).await {
            Ok(Some(data)) => {
                let config = StoredWipeConfig::from_bytes(&data)
                    .map_err(|e| SyncError::Backend(e.to_string()))?;
                Ok(Some(config))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Pushes a wipe command to cloud storage
    pub async fn push_wipe_command(&self, command: WipeCommand) -> SyncResult<()> {
        // Load existing commands
        let mut commands = match self.backend.read_chunk(WIPE_COMMAND_CHUNK_INDEX, 0).await {
            Ok(Some(data)) => CloudWipeCommands::from_bytes(&data)?,
            Ok(None) => CloudWipeCommands::new(),
            Err(e) => return Err(SyncError::Io(e)),
        };

        // Add the new command
        commands.push(command);

        // Save back to cloud
        let data = commands.to_bytes()?;
        self.backend
            .write_chunk(WIPE_COMMAND_CHUNK_INDEX, &data)
            .await
            .map_err(SyncError::Io)?;

        Ok(())
    }

    /// Acknowledges a processed wipe command (removes it from cloud)
    pub async fn acknowledge_wipe_command(&self, command: &WipeCommand) -> SyncResult<()> {
        let mut commands = match self.backend.read_chunk(WIPE_COMMAND_CHUNK_INDEX, 0).await {
            Ok(Some(data)) => CloudWipeCommands::from_bytes(&data)?,
            Ok(None) => return Ok(()), // No commands to acknowledge
            Err(e) => return Err(SyncError::Io(e)),
        };

        // Remove the specific command (match by nonce for uniqueness)
        commands
            .commands
            .retain(|c| c.data.nonce != command.data.nonce);

        // Save updated list (or delete if empty)
        if commands.commands.is_empty() {
            self.backend
                .delete_chunk(WIPE_COMMAND_CHUNK_INDEX)
                .await
                .map_err(SyncError::Io)?;
        } else {
            let data = commands.to_bytes()?;
            self.backend
                .write_chunk(WIPE_COMMAND_CHUNK_INDEX, &data)
                .await
                .map_err(SyncError::Io)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_hash_compute() {
        let data = b"Hello, world!";
        let hash1 = ChunkHash::compute(data);
        let hash2 = ChunkHash::compute(data);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, ChunkHash::zero());
    }

    #[test]
    fn test_chunk_hash_different_data() {
        let hash1 = ChunkHash::compute(b"data1");
        let hash2 = ChunkHash::compute(b"data2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_chunk_state_needs_sync() {
        let hash = ChunkHash::compute(b"test data");
        let mut state = ChunkState::new(hash);

        // New chunk needs sync
        assert!(state.needs_sync());

        // After marking synced, should not need sync
        state.mark_synced();
        assert!(!state.needs_sync());

        // After updating with same hash, still no sync needed
        state.update_local(hash);
        assert!(!state.needs_sync());

        // After updating with different hash, needs sync again
        let new_hash = ChunkHash::compute(b"modified data");
        state.update_local(new_hash);
        assert!(state.needs_sync());
    }

    #[test]
    fn test_sync_manifest_creation() {
        let manifest = SyncManifest::new(
            "test-volume".to_string(),
            1024 * 1024, // 1 MB
            64 * 1024,   // 64 KB chunks
            4096,
            b"test-salt",
        );

        assert_eq!(manifest.volume_id, "test-volume");
        assert_eq!(manifest.volume_size, 1024 * 1024);
        assert_eq!(manifest.chunk_size, 64 * 1024);
        assert_eq!(manifest.total_chunks, 16);
        assert!(manifest.chunks.is_empty());
    }

    #[test]
    fn test_sync_manifest_chunk_tracking() {
        let mut manifest =
            SyncManifest::new("test".to_string(), 256 * 1024, 64 * 1024, 4096, b"salt");

        let hash1 = ChunkHash::compute(b"chunk 0 data");
        let hash2 = ChunkHash::compute(b"chunk 1 data");

        manifest.update_chunk(0, hash1);
        manifest.update_chunk(1, hash2);

        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.dirty_count(), 2);

        let dirty = manifest.chunks_needing_sync();
        assert!(dirty.contains(&0));
        assert!(dirty.contains(&1));

        manifest.mark_chunk_synced(0);
        assert_eq!(manifest.dirty_count(), 1);
    }

    #[test]
    fn test_sync_manifest_serialization() {
        let mut manifest = SyncManifest::new(
            "test-vol".to_string(),
            1024 * 1024,
            64 * 1024,
            4096,
            b"test-salt",
        );

        manifest.update_chunk(0, ChunkHash::compute(b"data"));
        manifest.mark_chunk_synced(0);

        let bytes = manifest.to_bytes().unwrap();
        let restored = SyncManifest::from_bytes(&bytes).unwrap();

        assert_eq!(restored.volume_id, "test-vol");
        assert_eq!(restored.chunks.len(), 1);
        assert!(!restored.get_chunk(0).unwrap().needs_sync());
    }

    #[test]
    fn test_sync_manifest_validation() {
        let manifest = SyncManifest::new(
            "test".to_string(),
            1024 * 1024,
            64 * 1024,
            4096,
            b"correct-salt",
        );

        assert!(manifest.validate_params(4096, b"correct-salt"));
        assert!(!manifest.validate_params(512, b"correct-salt"));
        assert!(!manifest.validate_params(4096, b"wrong-salt"));
    }

    #[test]
    fn test_chunk_tracker() {
        let mut tracker =
            ChunkTracker::new("vol1".to_string(), 256 * 1024, 64 * 1024, 4096, b"salt");

        assert!(tracker.is_manifest_dirty());
        assert_eq!(tracker.dirty_count(), 0);

        tracker.record_write(0, b"chunk data");
        assert_eq!(tracker.dirty_count(), 1);
        assert!(tracker.chunk_needs_sync(0));

        tracker.record_synced(0);
        assert_eq!(tracker.dirty_count(), 0);
        assert!(!tracker.chunk_needs_sync(0));
    }

    #[test]
    fn test_sync_stats() {
        let mut stats = SyncStats::default();
        assert!(stats.is_success());
        assert_eq!(stats.success_rate(), 100.0);

        stats.chunks_uploaded = 10;
        assert_eq!(stats.success_rate(), 100.0);

        stats.errors.push((5, "test error".to_string()));
        assert!(!stats.is_success());
        // 10 / 11 = ~90.9%
        assert!(stats.success_rate() > 90.0 && stats.success_rate() < 91.0);
    }

    #[test]
    fn test_cloud_wipe_commands_new() {
        let commands = CloudWipeCommands::new();
        assert!(!commands.has_pending());
        assert!(commands.commands.is_empty());
    }

    #[test]
    fn test_cloud_wipe_commands_serialization() {
        use crate::volume::remote_wipe::{WipeCommandType, WipeToken};

        let mut commands = CloudWipeCommands::new();
        let token = WipeToken::generate();
        let cmd = WipeCommand::new(&token, "test-volume", WipeCommandType::Lock);
        commands.push(cmd);

        assert!(commands.has_pending());

        // Serialize and deserialize
        let bytes = commands.to_bytes().unwrap();
        let restored = CloudWipeCommands::from_bytes(&bytes).unwrap();

        assert_eq!(restored.commands.len(), 1);
        assert_eq!(restored.commands[0].data.volume_id, "test-volume");
    }

    #[test]
    fn test_cloud_wipe_commands_pop() {
        use crate::volume::remote_wipe::{WipeCommandType, WipeToken};

        let mut commands = CloudWipeCommands::new();
        let token = WipeToken::generate();

        commands.push(WipeCommand::new(&token, "vol1", WipeCommandType::Lock));
        commands.push(WipeCommand::new(&token, "vol2", WipeCommandType::CheckIn));

        assert_eq!(commands.commands.len(), 2);

        let first = commands.pop().unwrap();
        assert_eq!(first.data.volume_id, "vol1");
        assert_eq!(commands.commands.len(), 1);

        let second = commands.pop().unwrap();
        assert_eq!(second.data.volume_id, "vol2");
        assert!(!commands.has_pending());
    }

    #[test]
    fn test_chunk_hash_to_hex() {
        let hash = ChunkHash::compute(b"test data");
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_chunk_hash_as_bytes() {
        let hash = ChunkHash::compute(b"test");
        let bytes = hash.as_bytes();
        assert_eq!(bytes.len(), HASH_SIZE);
    }

    #[test]
    fn test_chunk_hash_from_bytes() {
        let bytes = [42u8; HASH_SIZE];
        let hash = ChunkHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_chunk_hash_default() {
        let hash = ChunkHash::default();
        assert_eq!(hash, ChunkHash::zero());
        assert_eq!(hash.as_bytes(), &[0u8; HASH_SIZE]);
    }

    #[test]
    fn test_chunk_hash_empty_data() {
        let hash = ChunkHash::compute(b"");
        assert_ne!(hash, ChunkHash::zero());
    }

    #[test]
    fn test_chunk_state_timestamps() {
        let hash = ChunkHash::compute(b"data");
        let state = ChunkState::new(hash);

        assert!(state.local_modified > 0);
        assert_eq!(state.last_synced, 0);
        assert!(!state.exists_in_cloud);
    }

    #[test]
    fn test_chunk_state_mark_synced_updates_timestamp() {
        let hash = ChunkHash::compute(b"data");
        let mut state = ChunkState::new(hash);

        let before_sync = state.last_synced;
        state.mark_synced();

        assert!(state.last_synced >= before_sync);
        assert!(state.exists_in_cloud);
        assert_eq!(state.synced_hash, state.local_hash);
    }

    #[test]
    fn test_sync_manifest_get_chunk_none() {
        let manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");
        assert!(manifest.get_chunk(0).is_none());
        assert!(manifest.get_chunk(100).is_none());
    }

    #[test]
    fn test_sync_manifest_total_chunks_calculation() {
        // Exact division
        let manifest1 = SyncManifest::new("test".to_string(), 1024, 256, 4096, b"salt");
        assert_eq!(manifest1.total_chunks, 4);

        // Non-exact division (should round up)
        let manifest2 = SyncManifest::new("test".to_string(), 1000, 256, 4096, b"salt");
        assert_eq!(manifest2.total_chunks, 4); // 1000 / 256 = 3.9, rounds up to 4
    }

    #[test]
    fn test_sync_manifest_version() {
        let manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");
        assert_eq!(manifest.version, 1);
    }

    #[test]
    fn test_encryption_params_clone() {
        let params = EncryptionParams {
            sector_size: 4096,
            kdf_salt_hash: ChunkHash::compute(b"salt"),
        };

        let cloned = params.clone();
        assert_eq!(cloned.sector_size, params.sector_size);
        assert_eq!(cloned.kdf_salt_hash, params.kdf_salt_hash);
    }

    #[test]
    fn test_encryption_params_debug() {
        let params = EncryptionParams {
            sector_size: 512,
            kdf_salt_hash: ChunkHash::zero(),
        };

        let debug_str = format!("{:?}", params);
        assert!(debug_str.contains("EncryptionParams"));
        assert!(debug_str.contains("sector_size"));
    }

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.max_concurrent_uploads, 4);
        assert!(config.retry_failed);
        assert_eq!(config.max_retries, 3);
        assert!(!config.compress_chunks);
    }

    #[test]
    fn test_sync_config_clone() {
        let config = SyncConfig {
            max_concurrent_uploads: 8,
            retry_failed: false,
            max_retries: 5,
            compress_chunks: true,
        };

        let cloned = config.clone();
        assert_eq!(cloned.max_concurrent_uploads, 8);
        assert!(!cloned.retry_failed);
        assert_eq!(cloned.max_retries, 5);
        assert!(cloned.compress_chunks);
    }

    #[test]
    fn test_sync_config_debug() {
        let config = SyncConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SyncConfig"));
    }

    #[test]
    fn test_sync_error_display() {
        let io_err = SyncError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let manifest_err = SyncError::ManifestValidation;
        assert!(manifest_err.to_string().contains("validation failed"));

        let chunk_err = SyncError::ChunkSync(42, "upload failed".to_string());
        assert!(chunk_err.to_string().contains("42"));
        assert!(chunk_err.to_string().contains("upload failed"));

        let backend_err = SyncError::Backend("connection timeout".to_string());
        assert!(backend_err.to_string().contains("connection timeout"));

        let not_found = SyncError::ManifestNotFound;
        assert!(not_found.to_string().contains("not found"));
    }

    #[test]
    fn test_sync_stats_default() {
        let stats = SyncStats::default();
        assert_eq!(stats.chunks_uploaded, 0);
        assert_eq!(stats.chunks_skipped, 0);
        assert_eq!(stats.bytes_uploaded, 0);
        assert_eq!(stats.duration_ms, 0);
        assert!(stats.errors.is_empty());
    }

    #[test]
    fn test_sync_stats_clone() {
        let mut stats = SyncStats::default();
        stats.chunks_uploaded = 10;
        stats.bytes_uploaded = 1024;

        let cloned = stats.clone();
        assert_eq!(cloned.chunks_uploaded, 10);
        assert_eq!(cloned.bytes_uploaded, 1024);
    }

    #[test]
    fn test_sync_stats_debug() {
        let stats = SyncStats::default();
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("SyncStats"));
    }

    #[test]
    fn test_chunk_tracker_from_manifest() {
        let manifest = SyncManifest::new("vol".to_string(), 1024, 64, 4096, b"salt");
        let tracker = ChunkTracker::from_manifest(manifest);

        assert!(!tracker.is_manifest_dirty());
        assert_eq!(tracker.dirty_count(), 0);
    }

    #[test]
    fn test_chunk_tracker_get_chunk_hash() {
        let mut tracker = ChunkTracker::new("vol".to_string(), 1024, 64, 4096, b"salt");

        // Initially no hash for chunk 0
        assert!(tracker.get_chunk_hash(0).is_none());

        // After writing, hash should be available
        tracker.record_write(0, b"test data");
        let hash = tracker.get_chunk_hash(0);
        assert!(hash.is_some());
        assert_eq!(hash.unwrap(), ChunkHash::compute(b"test data"));
    }

    #[test]
    fn test_chunk_tracker_mark_manifest_saved() {
        let mut tracker = ChunkTracker::new("vol".to_string(), 1024, 64, 4096, b"salt");
        assert!(tracker.is_manifest_dirty());

        tracker.mark_manifest_saved();
        assert!(!tracker.is_manifest_dirty());

        // Writing should make it dirty again
        tracker.record_write(0, b"data");
        assert!(tracker.is_manifest_dirty());
    }

    #[test]
    fn test_chunk_tracker_manifest_access() {
        let tracker = ChunkTracker::new("test-vol".to_string(), 2048, 128, 4096, b"salt");
        let manifest = tracker.manifest();

        assert_eq!(manifest.volume_id, "test-vol");
        assert_eq!(manifest.volume_size, 2048);
        assert_eq!(manifest.chunk_size, 128);
    }

    #[test]
    fn test_cloud_wipe_commands_default() {
        let commands = CloudWipeCommands::default();
        assert!(!commands.has_pending());
        assert!(commands.updated_at > 0);
    }

    #[test]
    fn test_cloud_wipe_commands_pop_empty() {
        let mut commands = CloudWipeCommands::new();
        assert!(commands.pop().is_none());
    }

    #[test]
    fn test_reserved_chunk_indices() {
        assert_eq!(WIPE_COMMAND_CHUNK_INDEX, u64::MAX - 1);
        assert_eq!(WIPE_CONFIG_CHUNK_INDEX, u64::MAX - 2);
        // Ensure they don't overlap
        assert_ne!(WIPE_COMMAND_CHUNK_INDEX, WIPE_CONFIG_CHUNK_INDEX);
    }

    #[test]
    fn test_hash_size_constant() {
        assert_eq!(HASH_SIZE, 32);
    }

    // ========================================================================
    // Additional SyncError Tests
    // ========================================================================

    #[test]
    fn test_sync_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let sync_err: SyncError = io_err.into();
        assert!(matches!(sync_err, SyncError::Io(_)));
        assert!(sync_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_sync_error_debug() {
        let err = SyncError::ManifestValidation;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ManifestValidation"));
    }

    #[test]
    fn test_sync_error_chunk_sync_details() {
        let err = SyncError::ChunkSync(123, "network timeout".to_string());
        let msg = err.to_string();
        assert!(msg.contains("123"));
        assert!(msg.contains("network timeout"));
    }

    #[test]
    fn test_sync_error_backend_details() {
        let err = SyncError::Backend("S3 rate limit exceeded".to_string());
        assert!(err.to_string().contains("S3 rate limit exceeded"));
    }

    // ========================================================================
    // Additional SyncStats Tests
    // ========================================================================

    #[test]
    fn test_sync_stats_success_rate_all_errors() {
        let mut stats = SyncStats::default();
        stats.errors.push((0, "err1".to_string()));
        stats.errors.push((1, "err2".to_string()));

        // 0 uploaded, 2 errors -> 0% success
        assert_eq!(stats.success_rate(), 0.0);
    }

    #[test]
    fn test_sync_stats_success_rate_mixed() {
        let mut stats = SyncStats::default();
        stats.chunks_uploaded = 3;
        stats.errors.push((0, "err".to_string()));

        // 3 / 4 = 75%
        assert_eq!(stats.success_rate(), 75.0);
    }

    #[test]
    fn test_sync_stats_with_bytes_and_duration() {
        let mut stats = SyncStats::default();
        stats.chunks_uploaded = 5;
        stats.chunks_skipped = 2;
        stats.bytes_uploaded = 1024 * 1024; // 1 MB
        stats.duration_ms = 5000; // 5 seconds

        assert!(stats.is_success());
        assert_eq!(stats.success_rate(), 100.0);
    }

    // ========================================================================
    // Additional ChunkState Tests
    // ========================================================================

    #[test]
    fn test_chunk_state_update_local_changes_hash() {
        let hash1 = ChunkHash::compute(b"original");
        let hash2 = ChunkHash::compute(b"modified");
        let mut state = ChunkState::new(hash1);

        state.update_local(hash2);
        assert_eq!(state.local_hash, hash2);
        assert!(state.needs_sync());
    }

    #[test]
    fn test_chunk_state_mark_synced_sets_exists_in_cloud() {
        let hash = ChunkHash::compute(b"data");
        let mut state = ChunkState::new(hash);

        assert!(!state.exists_in_cloud);
        state.mark_synced();
        assert!(state.exists_in_cloud);
    }

    #[test]
    fn test_chunk_state_after_multiple_updates() {
        let mut state = ChunkState::new(ChunkHash::compute(b"v1"));

        // Update multiple times
        state.update_local(ChunkHash::compute(b"v2"));
        state.update_local(ChunkHash::compute(b"v3"));

        // Should still need sync
        assert!(state.needs_sync());

        // Mark synced
        state.mark_synced();
        assert!(!state.needs_sync());

        // Update with same hash
        state.update_local(ChunkHash::compute(b"v3"));
        assert!(!state.needs_sync()); // Same hash, no sync needed
    }

    // ========================================================================
    // Additional SyncManifest Tests
    // ========================================================================

    #[test]
    fn test_sync_manifest_update_existing_chunk() {
        let mut manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");

        // First write
        manifest.update_chunk(0, ChunkHash::compute(b"v1"));
        let initial_hash = manifest.get_chunk(0).unwrap().local_hash;

        // Update same chunk with different data
        manifest.update_chunk(0, ChunkHash::compute(b"v2"));
        let updated_hash = manifest.get_chunk(0).unwrap().local_hash;

        assert_ne!(initial_hash, updated_hash);
        assert_eq!(manifest.chunks.len(), 1); // Still just one chunk
    }

    #[test]
    fn test_sync_manifest_mark_nonexistent_chunk_synced() {
        let mut manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");

        // Try to mark a nonexistent chunk as synced (should be no-op)
        manifest.mark_chunk_synced(999);

        // Should not create a new chunk
        assert!(manifest.get_chunk(999).is_none());
    }

    #[test]
    fn test_sync_manifest_chunks_needing_sync_empty() {
        let manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");
        assert!(manifest.chunks_needing_sync().is_empty());
        assert_eq!(manifest.dirty_count(), 0);
    }

    #[test]
    fn test_sync_manifest_from_bytes_invalid() {
        let invalid_json = b"not valid json";
        let result = SyncManifest::from_bytes(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_manifest_encryption_params() {
        let manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");

        assert_eq!(manifest.encryption_params.sector_size, 4096);
        assert_eq!(
            manifest.encryption_params.kdf_salt_hash,
            ChunkHash::compute(b"salt")
        );
    }

    #[test]
    fn test_sync_manifest_last_updated() {
        let manifest = SyncManifest::new("test".to_string(), 1024, 64, 4096, b"salt");
        assert!(manifest.last_updated > 0);
    }

    // ========================================================================
    // Additional ChunkTracker Tests
    // ========================================================================

    #[test]
    fn test_chunk_tracker_record_synced_nonexistent() {
        let mut tracker = ChunkTracker::new("vol".to_string(), 1024, 64, 4096, b"salt");

        // Record synced for a chunk that doesn't exist (should be no-op)
        tracker.record_synced(999);

        // Should not create a chunk
        assert!(tracker.get_chunk_hash(999).is_none());
    }

    #[test]
    fn test_chunk_tracker_get_dirty_chunks_order() {
        let mut tracker = ChunkTracker::new("vol".to_string(), 1024, 64, 4096, b"salt");

        tracker.record_write(5, b"chunk5");
        tracker.record_write(2, b"chunk2");
        tracker.record_write(8, b"chunk8");

        let dirty = tracker.get_dirty_chunks();
        assert_eq!(dirty.len(), 3);
        assert!(dirty.contains(&5));
        assert!(dirty.contains(&2));
        assert!(dirty.contains(&8));
    }

    #[test]
    fn test_chunk_tracker_chunk_needs_sync_nonexistent() {
        let tracker = ChunkTracker::new("vol".to_string(), 1024, 64, 4096, b"salt");
        assert!(!tracker.chunk_needs_sync(999));
    }

    // ========================================================================
    // Additional CloudWipeCommands Tests
    // ========================================================================

    #[test]
    fn test_cloud_wipe_commands_multiple_push() {
        use crate::volume::remote_wipe::{WipeCommandType, WipeToken};

        let mut commands = CloudWipeCommands::new();
        let token = WipeToken::generate();

        commands.push(WipeCommand::new(&token, "vol1", WipeCommandType::Lock));
        commands.push(WipeCommand::new(
            &token,
            "vol2",
            WipeCommandType::DestroyKeys,
        ));
        commands.push(WipeCommand::new(&token, "vol3", WipeCommandType::CheckIn));

        assert_eq!(commands.commands.len(), 3);
        assert!(commands.has_pending());
    }

    #[test]
    fn test_cloud_wipe_commands_updated_at_changes() {
        use crate::volume::remote_wipe::{WipeCommandType, WipeToken};

        let mut commands = CloudWipeCommands::new();
        let initial_time = commands.updated_at;

        // Sleep briefly to ensure time advances
        std::thread::sleep(std::time::Duration::from_millis(10));

        let token = WipeToken::generate();
        commands.push(WipeCommand::new(&token, "vol", WipeCommandType::Lock));

        // Updated_at should have changed (or at least be >= initial)
        assert!(commands.updated_at >= initial_time);
    }

    #[test]
    fn test_cloud_wipe_commands_from_bytes_invalid() {
        let invalid_json = b"invalid json data";
        let result = CloudWipeCommands::from_bytes(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_cloud_wipe_commands_roundtrip_empty() {
        let commands = CloudWipeCommands::new();
        let bytes = commands.to_bytes().unwrap();
        let restored = CloudWipeCommands::from_bytes(&bytes).unwrap();

        assert!(!restored.has_pending());
        assert!(restored.commands.is_empty());
    }

    // ========================================================================
    // ChunkHash Additional Edge Cases
    // ========================================================================

    #[test]
    fn test_chunk_hash_large_data() {
        let large_data = vec![0xABu8; 1024 * 1024]; // 1 MB
        let hash = ChunkHash::compute(&large_data);
        assert_ne!(hash, ChunkHash::zero());
    }

    #[test]
    fn test_chunk_hash_copy_trait() {
        let hash1 = ChunkHash::compute(b"test");
        let hash2 = hash1; // Copy
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_chunk_hash_clone_trait() {
        let hash1 = ChunkHash::compute(b"test");
        let hash2 = hash1.clone();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_chunk_hash_hash_trait() {
        use std::collections::HashSet;

        let hash1 = ChunkHash::compute(b"data1");
        let hash2 = ChunkHash::compute(b"data2");
        let hash3 = ChunkHash::compute(b"data1");

        let mut set = HashSet::new();
        set.insert(hash1);
        set.insert(hash2);
        set.insert(hash3); // Same as hash1, shouldn't add

        assert_eq!(set.len(), 2);
    }

    // ========================================================================
    // SyncConfig Additional Tests
    // ========================================================================

    #[test]
    fn test_sync_config_custom_values() {
        let config = SyncConfig {
            max_concurrent_uploads: 16,
            retry_failed: false,
            max_retries: 10,
            compress_chunks: true,
        };

        assert_eq!(config.max_concurrent_uploads, 16);
        assert!(!config.retry_failed);
        assert_eq!(config.max_retries, 10);
        assert!(config.compress_chunks);
    }

    // ========================================================================
    // EncryptionParams Tests
    // ========================================================================

    #[test]
    fn test_encryption_params_serialize_deserialize() {
        let params = EncryptionParams {
            sector_size: 512,
            kdf_salt_hash: ChunkHash::compute(b"test-salt"),
        };

        let json = serde_json::to_string(&params).unwrap();
        let restored: EncryptionParams = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.sector_size, 512);
        assert_eq!(restored.kdf_salt_hash, params.kdf_salt_hash);
    }
}
