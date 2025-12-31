//! Encrypted volume management module
//!
//! This module provides functionality for creating and managing encrypted
//! volumes that can be mounted as filesystems using FUSE (Linux)
//! or WinFsp (Windows).

pub mod automount;
pub mod chunk;
pub mod cloud_sync;
pub mod container;

#[cfg(feature = "cloud-storage")]
pub mod s3_client;

#[cfg(feature = "cloud-storage")]
pub mod dropbox_client;
pub mod filesystem;
pub mod format;
pub mod header;
pub mod io;
pub mod keyslot;
pub mod manager;
pub mod migration;
pub mod mount;
pub mod operations;
pub mod remote_wipe;
pub mod sector;
pub mod volumeio_fs;

pub use automount::{AutoMountConfig, AutoMountService, AutoMountAuth, VolumeConfig, VolumeConfigBuilder};
pub use chunk::{ChunkMapper, ChunkLocation, ChunkRange, ChunkError, DEFAULT_CHUNK_SIZE};
pub use container::{Container, METADATA_SIZE, KEYSLOTS_SIZE};
pub use filesystem::{EncryptedFilesystem, FileAttr, FileType, FilesystemError, DirEntry};
pub use header::{
    VolumeHeader, PqVolumeMetadata, PqAlgorithm, CipherAlgorithm, HeaderError,
    HEADER_SIZE, PQ_METADATA_SIZE,
};
pub use keyslot::{KeySlots, MasterKey, MAX_KEY_SLOTS};
pub use manager::{VolumeManager, VolumeManagerError, MountedVolumeInfo};
pub use migration::{VolumeMigration, MigrationBackup, MigrationError};
pub use mount::{MountOptions, MountError};
pub use operations::InMemoryFilesystem;
pub use sector::{SectorCipher, SECTOR_SIZE_512, SECTOR_SIZE_4K};
pub use io::{
    VolumeIO, VolumeIOError, StorageBackend, FileBackend, MemoryBackend, CacheStats, DEFAULT_CACHE_CAPACITY,
    AsyncStorageBackend, AsyncResult, BlockingAdapter, AsyncMemoryBackend,
};

#[cfg(feature = "cloud-storage")]
pub use s3_client::{S3Client, S3Config, S3Credentials, S3Region, S3StorageBackend};

#[cfg(feature = "cloud-storage")]
pub use dropbox_client::{DropboxClient, DropboxConfig, DropboxCredentials, DropboxStorageBackend};
pub use format::{
    Superblock, Inode, InodeType, DirEntry as FsDirEntry, Bitmap,
    JournalEntry, JournalHeader, JournalOpType, FsState, FormatError,
    FS_BLOCK_SIZE, FS_MAGIC, FS_VERSION, ROOT_INODE, MAX_FILENAME_LEN,
    DIRECT_BLOCKS, DATA_BLOCKS_START, INODE_SIZE, INODES_PER_BLOCK,
};
pub use volumeio_fs::{VolumeIOFilesystem, VolumeIOFsError};
pub use cloud_sync::{
    ChunkHash, ChunkState, SyncManifest, ChunkTracker, SyncStats, SyncConfig, SyncError, SyncResult,
    CloudSyncManager, EncryptionParams,
};

#[cfg(feature = "encrypted-volumes")]
pub use mount::{mount, MountHandle};
