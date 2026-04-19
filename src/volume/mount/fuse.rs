// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! FUSE filesystem implementation for Linux
//!
//! This module implements a FUSE (Filesystem in Userspace) adapter that
//! allows mounting encrypted containers as regular filesystems.
//!
//! Uses VolumeIOFilesystem for persistent, encrypted storage.

use fuser::{
    BsdFileFlags, Config, Errno, FileAttr as FuseFileAttr, FileHandle, FileType as FuseFileType,
    Filesystem, FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyWrite, Request, SessionACL, TimeOrNow,
    WriteFlags,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::super::container::Container;
use super::super::filesystem::FilesystemError;
use super::super::format::{Inode, InodeType, FS_BLOCK_SIZE};
use super::super::io::{FileBackend, StorageBackend};
use super::super::volumeio_fs::{VolumeIOFilesystem, VolumeIOFsError};
use super::{MountError, MountOptions, Result};

/// FUSE filesystem adapter using VolumeIOFilesystem
///
/// This adapter works directly with inodes, providing efficient access
/// to the encrypted filesystem without path resolution overhead.
struct PersistentFuseAdapter {
    fs: VolumeIOFilesystem,
}

impl PersistentFuseAdapter {
    fn new(fs: VolumeIOFilesystem) -> Self {
        Self { fs }
    }

    /// Converts InodeType to FUSE FileType
    fn inode_type_to_fuse(it: InodeType) -> FuseFileType {
        match it {
            InodeType::File => FuseFileType::RegularFile,
            InodeType::Directory => FuseFileType::Directory,
            InodeType::Symlink => FuseFileType::Symlink,
        }
    }

    /// Converts an Inode to FUSE FileAttr
    fn inode_to_fuse_attr(&self, inode: &Inode, ino: u64) -> FuseFileAttr {
        let kind = if inode.is_dir() {
            FuseFileType::Directory
        } else if inode.is_symlink() {
            FuseFileType::Symlink
        } else {
            FuseFileType::RegularFile
        };

        FuseFileAttr {
            ino: INodeNo(ino),
            size: inode.size,
            blocks: inode.blocks,
            atime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.atime),
            mtime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.mtime),
            ctime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.ctime),
            crtime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.ctime),
            kind,
            perm: inode.mode,
            nlink: inode.nlink as u32,
            uid: inode.uid,
            gid: inode.gid,
            rdev: 0,
            blksize: FS_BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Converts VolumeIOFsError to errno
    fn error_to_errno(err: VolumeIOFsError) -> Errno {
        Errno::from_i32(match err {
            VolumeIOFsError::Filesystem(fe) => Self::fs_error_to_errno(fe),
            VolumeIOFsError::VolumeIO(_) => EIO,
            VolumeIOFsError::Format(_) => EIO,
            VolumeIOFsError::Serialization(_) => EIO,
            VolumeIOFsError::InvalidOperation(_) => EINVAL,
            VolumeIOFsError::LockPoisoned => EIO,
            VolumeIOFsError::NotInitialized => EIO,
        })
    }

    /// Converts FilesystemError to errno
    fn fs_error_to_errno(err: FilesystemError) -> libc::c_int {
        match err {
            FilesystemError::NotFound(_) => ENOENT,
            FilesystemError::AlreadyExists(_) => EEXIST,
            FilesystemError::PermissionDenied(_) => libc::EACCES,
            FilesystemError::NotADirectory(_) => ENOTDIR,
            FilesystemError::IsADirectory(_) => EISDIR,
            FilesystemError::DirectoryNotEmpty(_) => ENOTEMPTY,
            FilesystemError::InvalidFileName(_) => EINVAL,
            FilesystemError::Io(_) => EIO,
            FilesystemError::CryptoError(_) => EIO,
            FilesystemError::NotSupported(_) => libc::ENOTSUP,
            FilesystemError::Other(_) => EIO,
        }
    }
}

impl Filesystem for PersistentFuseAdapter {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        match self.fs.lookup(parent.0 as u32, name_str) {
            Ok(Some(inode_num)) => match self.fs.get_inode(inode_num) {
                Ok(inode) => {
                    let fuse_attr = self.inode_to_fuse_attr(&inode, inode_num as u64);
                    let ttl = Duration::from_secs(1);
                    reply.entry(&ttl, &fuse_attr, Generation(0));
                }
                Err(e) => {
                    reply.error(Self::error_to_errno(e));
                }
            },
            Ok(None) => {
                reply.error(Errno::ENOENT);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.fs.get_inode(ino.0 as u32) {
            Ok(inode) => {
                let fuse_attr = self.inode_to_fuse_attr(&inode, ino.0);
                let ttl = Duration::from_secs(1);
                reply.attr(&ttl, &fuse_attr);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.fs.read_by_inode(ino.0 as u32, offset, size) {
            Ok(data) => {
                reply.data(&data);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.fs.write_by_inode(ino.0 as u32, offset, data) {
            Ok(written) => {
                reply.written(written);
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self.fs.readdir_by_inode(ino.0 as u32) {
            Ok(entries) => {
                for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
                    let name = match entry.name_str() {
                        Ok(n) => n,
                        Err(_) => continue,
                    };

                    let file_type = Self::inode_type_to_fuse(InodeType::from(entry.file_type));

                    // The offset is the index of the next entry
                    if reply.add(INodeNo(entry.inode as u64), (i + 1) as u64, file_type, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        match self
            .fs
            .create_directory(parent.0 as u32, name_str, mode as u16)
        {
            Ok(inode_num) => match self.fs.get_inode(inode_num) {
                Ok(inode) => {
                    let fuse_attr = self.inode_to_fuse_attr(&inode, inode_num as u64);
                    let ttl = Duration::from_secs(1);
                    reply.entry(&ttl, &fuse_attr, Generation(0));
                }
                Err(e) => {
                    reply.error(Self::error_to_errno(e));
                }
            },
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: fuser::ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        match self.fs.remove_file(parent.0 as u32, name_str) {
            Ok(()) => {
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: fuser::ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        match self.fs.remove_directory(parent.0 as u32, name_str) {
            Ok(()) => {
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let old_name = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let new_name = match newname.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        match self
            .fs
            .rename_entry(parent.0 as u32, old_name, newparent.0 as u32, new_name)
        {
            Ok(()) => {
                reply.ok();
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        match self.fs.create_file(parent.0 as u32, name_str, mode as u16) {
            Ok(inode_num) => match self.fs.get_inode(inode_num) {
                Ok(inode) => {
                    let fuse_attr = self.inode_to_fuse_attr(&inode, inode_num as u64);
                    let ttl = Duration::from_secs(1);
                    reply.created(
                        &ttl,
                        &fuse_attr,
                        Generation(0),
                        FileHandle(0),
                        FopenFlags::empty(),
                    );
                }
                Err(e) => {
                    reply.error(Self::error_to_errno(e));
                }
            },
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // Get current inode
        let mut inode = match self.fs.get_inode(ino.0 as u32) {
            Ok(i) => i,
            Err(e) => {
                reply.error(Self::error_to_errno(e));
                return;
            }
        };

        if let Some(mode) = mode {
            inode.mode = mode as u16;
        }

        if let Some(uid) = uid {
            inode.uid = uid;
        }
        if let Some(gid) = gid {
            inode.gid = gid;
        }

        if let Some(size) = size {
            if let Err(e) = self.fs.truncate_file(ino.0 as u32, size) {
                reply.error(Self::error_to_errno(e));
                return;
            }
            inode = match self.fs.get_inode(ino.0 as u32) {
                Ok(i) => i,
                Err(e) => {
                    reply.error(Self::error_to_errno(e));
                    return;
                }
            };
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(atime_val) = atime {
            inode.atime = match atime_val {
                TimeOrNow::SpecificTime(t) => t
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                TimeOrNow::Now => now,
            };
        }

        if let Some(mtime_val) = mtime {
            inode.mtime = match mtime_val {
                TimeOrNow::SpecificTime(t) => t
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                TimeOrNow::Now => now,
            };
        }

        if mode.is_some() || uid.is_some() || gid.is_some() || atime.is_some() || mtime.is_some() {
            if let Err(e) = self.fs.set_inode(ino.0 as u32, &inode) {
                reply.error(Self::error_to_errno(e));
                return;
            }
        }

        let fuse_attr = self.inode_to_fuse_attr(&inode, ino.0);
        let ttl = Duration::from_secs(1);
        reply.attr(&ttl, &fuse_attr);
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        match self.fs.sync() {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Self::error_to_errno(e)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        match self.fs.get_statfs() {
            Ok((total_bytes, free_bytes, _available)) => {
                let block_size = FS_BLOCK_SIZE as u64;
                let total_blocks = total_bytes / block_size;
                let free_blocks = free_bytes / block_size;

                reply.statfs(
                    total_blocks,      // Total blocks
                    free_blocks,       // Free blocks
                    free_blocks,       // Available blocks (same as free for now)
                    0,                 // Total inodes (0 = unlimited)
                    0,                 // Free inodes
                    block_size as u32, // Block size
                    255,               // Max filename length
                    block_size as u32, // Fragment size
                );
            }
            Err(e) => {
                reply.error(Self::error_to_errno(e));
            }
        }
    }

    fn destroy(&mut self) {
        // Sync filesystem on unmount
        let _ = self.fs.sync();
    }
}

/// FUSE mount handle
pub struct FuseMountHandle {
    mount_point: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl FuseMountHandle {
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    pub fn unmount(mut self) -> Result<()> {
        if let Some(session) = self.session.take() {
            drop(session);
        }
        Ok(())
    }
}

impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
        }
    }
}

/// Mounts a container using FUSE with persistent VolumeIOFilesystem
pub fn mount(
    container_path: impl AsRef<Path>,
    password: &str,
    options: MountOptions,
) -> Result<FuseMountHandle> {
    use std::fs::OpenOptions;

    let container_path = container_path.as_ref();

    let container = if let Some(hidden_offset) = options.hidden_offset {
        let hidden_pwd = options.hidden_password.as_deref().ok_or_else(|| {
            MountError::Other("Hidden password required for hidden volume mount".to_string())
        })?;

        let outer = Container::open(container_path, password)?;
        outer.open_hidden_volume(hidden_pwd, hidden_offset)?
    } else {
        Container::open(container_path, password)?
    };

    let master_key = container
        .master_key()
        .ok_or_else(|| MountError::Other("Container is locked".to_string()))?
        .clone();

    let data_offset = container.data_offset();
    let data_size = container.data_size();

    let file = OpenOptions::new()
        .read(true)
        .write(!options.read_only)
        .open(container_path)
        .map_err(MountError::Io)?;

    let backend: Box<dyn StorageBackend> = Box::new(FileBackend::new(file, data_offset));

    let fs = match VolumeIOFilesystem::open(&master_key, data_size, backend) {
        Ok(fs) => fs,
        Err(_) => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(container_path)
                .map_err(MountError::Io)?;

            let backend: Box<dyn StorageBackend> = Box::new(FileBackend::new(file, data_offset));

            let volume_name = options.fs_name.as_deref().unwrap_or("Tesseract");
            VolumeIOFilesystem::mkfs(&master_key, data_size, backend, volume_name)
                .map_err(|e| MountError::Other(format!("Failed to create filesystem: {}", e)))?
        }
    };

    let adapter = PersistentFuseAdapter::new(fs);

    let mut mount_options = vec![
        MountOption::FSName(
            options
                .fs_name
                .clone()
                .unwrap_or_else(|| "Tesseract".to_string()),
        ),
        MountOption::NoAtime,
    ];

    if options.read_only {
        mount_options.push(MountOption::RO);
    }

    if options.auto_unmount {
        mount_options.push(MountOption::AutoUnmount);
    }

    // In fuser 0.17 the allow_other flag moved from MountOption::AllowOther
    // to the SessionACL field on Config.
    let acl = if options.allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };

    let mut config = Config::default();
    config.mount_options = mount_options;
    config.acl = acl;

    let session = fuser::spawn_mount2(adapter, &options.mount_point, &config)
        .map_err(|e| MountError::Other(format!("FUSE mount failed: {}", e)))?;

    Ok(FuseMountHandle {
        mount_point: options.mount_point.clone(),
        session: Some(session),
    })
}
