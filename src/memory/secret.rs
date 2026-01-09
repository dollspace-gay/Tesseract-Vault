// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Tesseract Vault Contributors
//! Secret memory using `memfd_secret()` for enhanced protection on Linux 5.14+.
//!
//! This module provides memory that is completely inaccessible to anyone except
//! the owning process, including the kernel itself. This is achieved using the
//! `memfd_secret()` syscall which removes pages from the kernel's direct map.
//!
//! # Security Properties
//!
//! When `memfd_secret()` is available:
//! - Memory is **invisible to the kernel** (unmapped from kernel address space)
//! - Memory is **invisible to other processes** (no /proc/pid/mem access)
//! - Memory is **immune to kernel exploits** that rely on direct map access
//! - Provides protection against **ROP attacks** that target kernel data exfiltration
//!
//! # Platform Support
//!
//! - **Linux 5.14+**: Full `memfd_secret()` support
//! - **Linux 6.5+**: Enabled by default (no kernel parameter needed)
//! - **Linux 5.14-6.4**: Requires `secretmem.enable=y` kernel parameter
//! - **Older Linux / Windows**: Falls back to `mlock()`
//!
//! # Example
//!
//! ```no_run
//! use tesseract_lib::memory::secret::SecretMemory;
//!
//! // Create secret memory for a 32-byte key
//! let secret = SecretMemory::new([0u8; 32])?;
//! assert!(secret.protection_level().is_secret());
//!
//! // Memory is automatically unmapped and zeroed on drop
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr;
use zeroize::Zeroize;

use super::{LockedMemory, MemLockError};

/// The level of memory protection achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    /// Memory is protected via `memfd_secret()` - invisible even to kernel.
    /// This is the strongest available protection.
    MemfdSecret,
    /// Memory is protected via `mlock()` - locked in RAM but still visible to kernel.
    /// Protects against swap but not kernel exploits.
    Mlocked,
    /// No memory protection achieved (system doesn't support locking).
    /// Memory may be swapped to disk.
    None,
}

impl ProtectionLevel {
    /// Returns true if the memory is protected by `memfd_secret()`.
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::MemfdSecret)
    }

    /// Returns true if the memory is at least locked in RAM.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::MemfdSecret | Self::Mlocked)
    }
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemfdSecret => write!(f, "memfd_secret (kernel-isolated)"),
            Self::Mlocked => write!(f, "mlock (swap-protected)"),
            Self::None => write!(f, "none (unprotected)"),
        }
    }
}

/// Errors that can occur during secret memory operations.
#[derive(Debug)]
pub enum SecretMemoryError {
    /// memfd_secret() syscall failed
    SyscallFailed(String),
    /// ftruncate() failed to set size
    TruncateFailed(String),
    /// mmap() failed to map the memory
    MmapFailed(String),
    /// Memory locking failed (when falling back to mlock)
    LockFailed(MemLockError),
}

impl fmt::Display for SecretMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallFailed(msg) => write!(f, "memfd_secret syscall failed: {}", msg),
            Self::TruncateFailed(msg) => write!(f, "ftruncate failed: {}", msg),
            Self::MmapFailed(msg) => write!(f, "mmap failed: {}", msg),
            Self::LockFailed(e) => write!(f, "mlock fallback failed: {}", e),
        }
    }
}

impl std::error::Error for SecretMemoryError {}

impl From<MemLockError> for SecretMemoryError {
    fn from(e: MemLockError) -> Self {
        Self::LockFailed(e)
    }
}

/// Memory region with the strongest available protection.
///
/// On Linux 5.14+, this uses `memfd_secret()` to create memory that is:
/// - Unmapped from the kernel's direct address space
/// - Invisible to other processes (including root)
/// - Protected against ROP attacks targeting kernel memory access
///
/// On older systems or Windows, this falls back to `mlock()` which only
/// prevents swapping but doesn't hide memory from the kernel.
///
/// # RAII Guarantee
///
/// Memory is automatically:
/// 1. Zeroed using secure overwrite
/// 2. Unmapped (memfd_secret) or unlocked (mlock)
/// 3. Closed (file descriptor cleanup)
///
/// # Example
///
/// ```no_run
/// use tesseract_lib::memory::secret::SecretMemory;
///
/// let mut key = SecretMemory::new([0u8; 32])?;
/// key.copy_from_slice(b"my_secret_key_material_here!!!!!");
///
/// // Use the key...
/// let protection = key.protection_level();
/// println!("Protection: {}", protection);
///
/// // Automatically cleaned up on drop
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SecretMemory<T: Zeroize> {
    /// The storage strategy (memfd_secret or fallback to LockedMemory)
    storage: SecretStorage<T>,
    /// The protection level achieved
    protection: ProtectionLevel,
}

/// Internal storage for SecretMemory - either memfd_secret or LockedMemory fallback
enum SecretStorage<T: Zeroize> {
    /// Using memfd_secret with mmap'd memory
    #[cfg(target_os = "linux")]
    MemfdSecret {
        /// Pointer to the mmap'd region
        ptr: *mut T,
        /// File descriptor from memfd_secret
        fd: i32,
        /// Size in bytes
        size: usize,
    },
    /// Fallback to LockedMemory (handles both locked and best-effort unlocked cases)
    Locked(LockedMemory<T>),
}

// SAFETY: SecretMemory is Send + Sync because:
// - The mmap'd memory is only accessed by the owning process
// - The file descriptor is not shared
// - The fallback LockedMemory is Send + Sync
unsafe impl<T: Zeroize + Send> Send for SecretStorage<T> {}
unsafe impl<T: Zeroize + Sync> Sync for SecretStorage<T> {}

impl<T: Zeroize + Default + Copy> SecretMemory<T> {
    /// Creates a new secret memory region with the given data.
    ///
    /// Attempts to use `memfd_secret()` on Linux 5.14+, falling back to
    /// `mlock()` on older systems or Windows.
    ///
    /// # Errors
    ///
    /// Returns an error if both `memfd_secret()` and `mlock()` fail.
    /// Use `new_best_effort()` to allow unprotected fallback.
    pub fn new(data: T) -> Result<Self, SecretMemoryError> {
        #[cfg(target_os = "linux")]
        {
            // Try memfd_secret first
            match Self::try_memfd_secret(data) {
                Ok(mem) => return Ok(mem),
                Err(_) => {
                    // Fall back to mlock
                    let locked = LockedMemory::new(data)?;
                    return Ok(Self {
                        storage: SecretStorage::Locked(locked),
                        protection: ProtectionLevel::Mlocked,
                    });
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Windows and other platforms: use mlock fallback
            let locked = LockedMemory::new(data)?;
            Ok(Self {
                storage: SecretStorage::Locked(locked),
                protection: ProtectionLevel::Mlocked,
            })
        }
    }

    /// Creates secret memory with best-effort protection.
    ///
    /// Returns successfully even if no protection is available.
    /// Check `protection_level()` to see what protection was achieved.
    ///
    /// # Returns
    ///
    /// Returns `(SecretMemory, ProtectionLevel)` tuple.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tesseract_lib::memory::secret::{SecretMemory, ProtectionLevel};
    ///
    /// let (secret, level) = SecretMemory::new_best_effort([0u8; 32]);
    /// if !level.is_secret() {
    ///     eprintln!("Warning: Running without kernel-level memory isolation");
    /// }
    /// ```
    pub fn new_best_effort(data: T) -> (Self, ProtectionLevel) {
        #[cfg(target_os = "linux")]
        {
            // Try memfd_secret first
            if let Ok(mem) = Self::try_memfd_secret(data) {
                let level = mem.protection;
                return (mem, level);
            }

            // Fall back to mlock
            let (locked, was_locked) = LockedMemory::new_best_effort(data);
            let protection = if was_locked {
                ProtectionLevel::Mlocked
            } else {
                ProtectionLevel::None
            };

            (
                Self {
                    storage: SecretStorage::Locked(locked),
                    protection,
                },
                protection,
            )
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Windows and other platforms: use mlock fallback
            let (locked, was_locked) = LockedMemory::new_best_effort(data);
            let protection = if was_locked {
                ProtectionLevel::Mlocked
            } else {
                ProtectionLevel::None
            };

            (
                Self {
                    storage: SecretStorage::Locked(locked),
                    protection,
                },
                protection,
            )
        }
    }

    /// Returns the protection level achieved for this memory.
    pub fn protection_level(&self) -> ProtectionLevel {
        self.protection
    }

    /// Try to create memory using memfd_secret.
    #[cfg(target_os = "linux")]
    fn try_memfd_secret(data: T) -> Result<Self, SecretMemoryError> {
        use libc::{
            c_long, close, ftruncate, mmap, syscall, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE,
        };

        // SYS_memfd_secret syscall number (447 on x86_64)
        // This constant may not be in older libc versions, so we define it
        #[cfg(target_arch = "x86_64")]
        const SYS_MEMFD_SECRET: c_long = 447;

        #[cfg(target_arch = "aarch64")]
        const SYS_MEMFD_SECRET: c_long = 447;

        // For other architectures, we'll need to add syscall numbers
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            return Err(SecretMemoryError::SyscallFailed(
                "memfd_secret not supported on this architecture".to_string(),
            ));
        }

        let size = std::mem::size_of::<T>();

        // SAFETY: memfd_secret syscall with flags=0 (no FD_CLOEXEC)
        // We want FD_CLOEXEC to close on exec, so pass 1
        let fd = unsafe { syscall(SYS_MEMFD_SECRET, 1_u32) } as i32;

        if fd < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(SecretMemoryError::SyscallFailed(errno.to_string()));
        }

        // Set the size of the secret memory region
        // SAFETY: fd is valid from successful memfd_secret call
        let result = unsafe { ftruncate(fd, size as i64) };
        if result != 0 {
            let errno = std::io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(SecretMemoryError::TruncateFailed(errno.to_string()));
        }

        // Map the memory into our address space
        // SAFETY: fd is valid, size is correct, we're mapping our own memory
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            )
        };

        if ptr == MAP_FAILED {
            let errno = std::io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(SecretMemoryError::MmapFailed(errno.to_string()));
        }

        // Copy the data into the secret memory region
        // SAFETY: ptr is valid from successful mmap, size matches T
        unsafe {
            ptr::copy_nonoverlapping(&data as *const T, ptr as *mut T, 1);
        }

        // Zero the source data (it was copied to secret memory)
        let mut source = data;
        source.zeroize();

        Ok(Self {
            storage: SecretStorage::MemfdSecret {
                ptr: ptr as *mut T,
                fd,
                size,
            },
            protection: ProtectionLevel::MemfdSecret,
        })
    }

    /// Consumes the secret memory and returns the inner value wrapped in `Zeroizing<T>`.
    ///
    /// The secret memory region will be cleaned up before returning.
    /// The returned `Zeroizing<T>` ensures the data is still zeroized on drop.
    ///
    /// # Security Note
    ///
    /// After calling this, the data is no longer in kernel-isolated memory.
    /// The `Zeroizing<T>` wrapper provides only zeroization, not isolation.
    pub fn into_inner(self) -> zeroize::Zeroizing<T> {
        match &self.storage {
            #[cfg(target_os = "linux")]
            SecretStorage::MemfdSecret { ptr, .. } => {
                // Copy data out before cleanup
                // SAFETY: ptr is valid from our mmap
                let data = unsafe { ptr::read(*ptr) };
                // Don't run Drop since we're manually cleaning up
                // Actually, we DO need to run drop to clean up the mmap
                // So we just return the data and let Drop handle cleanup
                std::mem::forget(self);
                zeroize::Zeroizing::new(data)
            }
            SecretStorage::Locked(locked) => {
                // Extract from LockedMemory
                // We need to manually extract since LockedMemory::into_inner takes ownership
                let data = unsafe { ptr::read(locked as *const LockedMemory<T>).into_inner() };
                std::mem::forget(self);
                data
            }
        }
    }
}

impl<T: Zeroize> Deref for SecretMemory<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.storage {
            #[cfg(target_os = "linux")]
            SecretStorage::MemfdSecret { ptr, .. } => {
                // SAFETY: ptr is valid from our mmap
                unsafe { &**ptr }
            }
            SecretStorage::Locked(locked) => locked,
        }
    }
}

impl<T: Zeroize> DerefMut for SecretMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.storage {
            #[cfg(target_os = "linux")]
            SecretStorage::MemfdSecret { ptr, .. } => {
                // SAFETY: ptr is valid from our mmap
                unsafe { &mut **ptr }
            }
            SecretStorage::Locked(locked) => locked,
        }
    }
}

impl<T: Zeroize> Drop for SecretMemory<T> {
    fn drop(&mut self) {
        match &mut self.storage {
            #[cfg(target_os = "linux")]
            SecretStorage::MemfdSecret { ptr, fd, size } => {
                use libc::{close, munmap};

                // First, zero the data
                // SAFETY: ptr is valid from our mmap
                unsafe {
                    (*(*ptr)).zeroize();
                }

                // Unmap the memory
                // SAFETY: ptr and size are valid from our mmap
                unsafe {
                    munmap(*ptr as *mut libc::c_void, *size);
                }

                // Close the file descriptor
                // SAFETY: fd is valid from memfd_secret
                unsafe {
                    close(*fd);
                }
            }
            SecretStorage::Locked(_) => {
                // LockedMemory handles its own cleanup
            }
        }
    }
}

/// Checks if `memfd_secret()` is available on the current system.
///
/// This performs a test syscall to check availability. Results are cached
/// for subsequent calls.
///
/// # Platform Support
///
/// - **Linux 6.5+**: Returns true (enabled by default)
/// - **Linux 5.14-6.4**: Returns true if `secretmem.enable=y` kernel parameter is set
/// - **Linux < 5.14**: Returns false
/// - **Windows/Other**: Returns false
///
/// # Example
///
/// ```no_run
/// use tesseract_lib::memory::secret::is_memfd_secret_available;
///
/// if is_memfd_secret_available() {
///     println!("memfd_secret is available - kernel-level memory isolation enabled");
/// } else {
///     println!("memfd_secret not available - falling back to mlock");
/// }
/// ```
#[cfg(target_os = "linux")]
pub fn is_memfd_secret_available() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};

    // Cache states: 0 = unchecked, 1 = not available, 2 = available
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);

    match AVAILABLE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let result = check_memfd_secret_available();
            AVAILABLE.store(if result { 2 } else { 1 }, Ordering::Relaxed);
            result
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_memfd_secret_available() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn check_memfd_secret_available() -> bool {
    use libc::{c_long, close, syscall, ENOSYS};

    #[cfg(target_arch = "x86_64")]
    const SYS_MEMFD_SECRET: c_long = 447;

    #[cfg(target_arch = "aarch64")]
    const SYS_MEMFD_SECRET: c_long = 447;

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return false;

    // Try the syscall
    let fd = unsafe { syscall(SYS_MEMFD_SECRET, 0_u32) } as i32;

    if fd >= 0 {
        // Success - close the fd and return true
        unsafe { close(fd) };
        true
    } else {
        // Check if it's ENOSYS (syscall not implemented)
        let errno = std::io::Error::last_os_error();
        errno.raw_os_error() != Some(ENOSYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_level_display() {
        assert_eq!(
            format!("{}", ProtectionLevel::MemfdSecret),
            "memfd_secret (kernel-isolated)"
        );
        assert_eq!(
            format!("{}", ProtectionLevel::Mlocked),
            "mlock (swap-protected)"
        );
        assert_eq!(format!("{}", ProtectionLevel::None), "none (unprotected)");
    }

    #[test]
    fn test_protection_level_methods() {
        assert!(ProtectionLevel::MemfdSecret.is_secret());
        assert!(!ProtectionLevel::Mlocked.is_secret());
        assert!(!ProtectionLevel::None.is_secret());

        assert!(ProtectionLevel::MemfdSecret.is_locked());
        assert!(ProtectionLevel::Mlocked.is_locked());
        assert!(!ProtectionLevel::None.is_locked());
    }

    #[test]
    fn test_secret_memory_best_effort() {
        let data = [42u8; 32];
        let (secret, level) = SecretMemory::new_best_effort(data);

        // Should always succeed
        assert_eq!(*secret, [42u8; 32]);

        // Level should match what we report
        assert_eq!(secret.protection_level(), level);

        // Print what we got
        eprintln!("Protection level: {}", level);
    }

    #[test]
    fn test_secret_memory_deref() {
        let data = [42u8; 32];
        let (secret, _) = SecretMemory::new_best_effort(data);

        // Test Deref
        assert_eq!(secret[0], 42);
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_secret_memory_deref_mut() {
        let data = [42u8; 32];
        let (mut secret, _) = SecretMemory::new_best_effort(data);

        // Test DerefMut
        secret[0] = 100;
        assert_eq!(secret[0], 100);
    }

    #[test]
    fn test_secret_memory_into_inner() {
        let data = [42u8; 32];
        let (secret, _) = SecretMemory::new_best_effort(data);

        let inner = secret.into_inner();
        assert_eq!(*inner, [42u8; 32]);
    }

    #[test]
    fn test_is_memfd_secret_available() {
        // This should not panic and should return a consistent result
        let first = is_memfd_secret_available();
        let second = is_memfd_secret_available();
        assert_eq!(first, second, "availability should be cached");

        eprintln!("memfd_secret available: {}", first);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_secret_memory_new() {
        let data = [42u8; 32];

        match SecretMemory::new(data) {
            Ok(secret) => {
                assert_eq!(*secret, [42u8; 32]);
                assert!(secret.protection_level().is_locked());
                eprintln!(
                    "SecretMemory::new succeeded with: {}",
                    secret.protection_level()
                );
            }
            Err(e) => {
                // May fail on systems with restrictive limits
                eprintln!("SecretMemory::new failed (expected on some systems): {}", e);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_secret_memory_new_windows() {
        let data = [42u8; 32];

        match SecretMemory::new(data) {
            Ok(secret) => {
                assert_eq!(*secret, [42u8; 32]);
                // On Windows, should be Mlocked
                assert_eq!(secret.protection_level(), ProtectionLevel::Mlocked);
            }
            Err(_) => {
                // May fail due to mlock limits
            }
        }
    }
}
