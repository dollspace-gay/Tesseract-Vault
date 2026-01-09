// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Encrypted volume management module
//!
//! This module provides functionality for creating and managing encrypted
//! volumes that can be mounted as filesystems using FUSE (Linux)
//! or WinFsp (Windows).

pub mod automount;
pub mod chunk;
pub mod cloud_sync;
#[cfg(feature = "post-quantum")]
pub mod container;

#[cfg(feature = "cloud-storage")]
pub mod s3_client;

#[cfg(feature = "cloud-storage")]
pub mod dropbox_client;
pub mod filesystem;
pub mod format;
pub mod header;
#[cfg(kani)]
mod header_kani;
pub mod io;
pub mod keyslot;
#[cfg(kani)]
mod keyslot_kani;
pub mod manager;
#[cfg(feature = "post-quantum")]
pub mod migration;
pub mod mount;
pub mod operations;
pub mod remote_wipe;
pub mod sector;
pub mod volumeio_fs;

pub use automount::{
    AutoMountAuth, AutoMountConfig, AutoMountService, VolumeConfig, VolumeConfigBuilder,
};
pub use chunk::{ChunkError, ChunkLocation, ChunkMapper, ChunkRange, DEFAULT_CHUNK_SIZE};
#[cfg(feature = "post-quantum")]
pub use container::{Container, KEYSLOTS_SIZE, METADATA_SIZE};
pub use filesystem::{DirEntry, EncryptedFilesystem, FileAttr, FileType, FilesystemError};
pub use header::{
    CipherAlgorithm, HeaderError, PqAlgorithm, PqVolumeMetadata, VolumeHeader, HEADER_SIZE,
    MAX_PQC_METADATA_SIZE, PQC_PADDING_SIZE, PQ_METADATA_SIZE,
};
pub use io::{
    AsyncMemoryBackend, AsyncResult, AsyncStorageBackend, BlockingAdapter, CacheStats, FileBackend,
    MemoryBackend, StorageBackend, VolumeIO, VolumeIOError, DEFAULT_CACHE_CAPACITY,
};
pub use keyslot::{KeySlots, MasterKey, MAX_KEY_SLOTS};
pub use manager::{MountedVolumeInfo, VolumeManager, VolumeManagerError};
#[cfg(feature = "post-quantum")]
pub use migration::{MigrationBackup, MigrationError, VolumeMigration};
pub use mount::{MountError, MountOptions};
pub use operations::InMemoryFilesystem;
pub use sector::{SectorCipher, SECTOR_SIZE_4K, SECTOR_SIZE_512};

#[cfg(feature = "cloud-storage")]
pub use s3_client::{S3Client, S3Config, S3Credentials, S3Region, S3StorageBackend};

pub use cloud_sync::{
    ChunkHash, ChunkState, ChunkTracker, CloudSyncManager, EncryptionParams, SyncConfig, SyncError,
    SyncManifest, SyncResult, SyncStats,
};
#[cfg(feature = "cloud-storage")]
pub use dropbox_client::{DropboxClient, DropboxConfig, DropboxCredentials, DropboxStorageBackend};
pub use format::{
    Bitmap, DirEntry as FsDirEntry, FormatError, FsState, Inode, InodeType, JournalEntry,
    JournalHeader, JournalOpType, Superblock, DATA_BLOCKS_START, DIRECT_BLOCKS, FS_BLOCK_SIZE,
    FS_MAGIC, FS_VERSION, INODES_PER_BLOCK, INODE_SIZE, MAX_FILENAME_LEN, ROOT_INODE,
};
pub use volumeio_fs::{VolumeIOFilesystem, VolumeIOFsError};

#[cfg(feature = "encrypted-volumes")]
pub use mount::{mount, MountHandle};
