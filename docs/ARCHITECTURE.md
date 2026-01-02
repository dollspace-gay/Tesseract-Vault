# Tesseract Vault Architecture Guide

This document provides a comprehensive overview of the Tesseract Vault codebase for new contributors.

## Project Overview

Tesseract Vault is a security-focused file and volume encryption library written in Rust. It provides:
- AES-256-GCM authenticated encryption
- Argon2id memory-hard key derivation
- ML-KEM-1024 post-quantum key encapsulation
- ML-DSA post-quantum digital signatures
- Encrypted volume containers with virtual filesystem mounting
- Hardware security module (YubiKey) support

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACES                                 │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────┤
│   CLI Binary    │   GUI Binary    │  WASM Module    │   System Services     │
│ tesseract-vault │tesseract-gui    │  (browsers)     │   (daemon/tray)       │
└────────┬────────┴────────┬────────┴────────┬────────┴──────────┬────────────┘
         │                 │                 │                   │
         └─────────────────┴─────────────────┴───────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           tesseract_lib (Core Library)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         PUBLIC API (lib.rs)                           │   │
│  │  encrypt_file() decrypt_file() encrypt_bytes() decrypt_bytes()       │   │
│  │  encrypt_file_with_hsm() decrypt_file_with_hsm()                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         ▼                          ▼                          ▼             │
│  ┌─────────────┐          ┌─────────────────┐         ┌─────────────┐       │
│  │   crypto/   │          │     volume/     │         │   memory/   │       │
│  │             │          │                 │         │             │       │
│  │ - AES-GCM   │          │ - Containers    │         │ - Allocator │       │
│  │ - Argon2id  │◄────────►│ - Filesystem    │◄───────►│ - Scrubbing │       │
│  │ - ML-KEM    │          │ - Cloud Sync    │         │ - Pool      │       │
│  │ - ML-DSA    │          │ - Remote Wipe   │         │ - Guards    │       │
│  │ - Streaming │          │ - Key Slots     │         │ - Locking   │       │
│  └─────────────┘          └─────────────────┘         └─────────────┘       │
│         │                          │                          │             │
│         └──────────────────────────┼──────────────────────────┘             │
│                                    ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        SUPPORTING MODULES                             │   │
│  ├────────────┬────────────┬────────────┬────────────┬─────────────────┤   │
│  │  storage/  │   daemon/  │   power/   │    hsm/    │     luks/       │   │
│  │            │            │            │            │   (Linux)       │   │
│  │ - Atomic   │ - IPC      │ - Sleep    │ - YubiKey  │ - TPM binding   │   │
│  │   writes   │ - Service  │ - Hibernate│ - HMAC     │ - Duress pwd    │   │
│  │ - Format   │ - Signals  │ - Callback │ - Challenge│ - Keyfile       │   │
│  └────────────┴────────────┴────────────┴────────────┴─────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PLATFORM ABSTRACTIONS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Windows: WinFsp, Win32 API, Registry     │  Linux: FUSE, TPM2, systemd     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
Tesseract/
├── src/
│   ├── lib.rs              # Library entry point, public API
│   ├── main.rs             # CLI binary entry point
│   │
│   ├── crypto/             # Cryptographic operations
│   │   ├── mod.rs          # Encryptor/KeyDerivation traits
│   │   ├── aes_gcm.rs      # AES-256-GCM implementation
│   │   ├── kdf.rs          # Argon2id key derivation
│   │   ├── pqc.rs          # Post-quantum (ML-KEM, ML-DSA)
│   │   ├── streaming.rs    # Chunked encryption for large files
│   │   ├── signatures.rs   # Digital signature support
│   │   └── hardware.rs     # Hardware crypto acceleration
│   │
│   ├── memory/             # Secure memory management
│   │   ├── mod.rs          # LockedMemory type
│   │   ├── allocator.rs    # SecureAllocator (zeroizing)
│   │   ├── pool.rs         # EncryptedMemoryPool
│   │   ├── scrub.rs        # Memory scrubbing patterns
│   │   ├── guard.rs        # Guard pages
│   │   ├── dump_protection.rs  # Core dump prevention
│   │   ├── debugger.rs     # Anti-debugging
│   │   └── tme.rs          # Total Memory Encryption
│   │
│   ├── volume/             # Encrypted volume containers
│   │   ├── mod.rs          # Volume API
│   │   ├── container.rs    # Container file format
│   │   ├── header.rs       # Volume header structure
│   │   ├── keyslot.rs      # Key slot management
│   │   ├── filesystem.rs   # Virtual filesystem interface
│   │   ├── operations.rs   # FUSE/WinFsp operations
│   │   ├── cloud_sync.rs   # Cloud storage sync
│   │   ├── s3_client.rs    # S3 backend
│   │   ├── dropbox_client.rs # Dropbox backend
│   │   └── remote_wipe.rs  # Remote destruction
│   │
│   ├── storage/            # File I/O and formats
│   │   ├── mod.rs          # Atomic writes, format detection
│   │   └── format.rs       # File header serialization
│   │
│   ├── daemon/             # Background service
│   │   └── mod.rs          # IPC, signal handling
│   │
│   ├── power/              # Power state monitoring
│   │   └── mod.rs          # Sleep/hibernate callbacks
│   │
│   ├── hsm/                # Hardware Security Modules
│   │   └── mod.rs          # YubiKey integration
│   │
│   ├── luks/               # LUKS integration (Linux only)
│   │   └── mod.rs          # TPM, duress passwords
│   │
│   ├── validation.rs       # Password validation (zxcvbn)
│   ├── progress.rs         # Progress reporting
│   ├── error.rs            # Error types
│   ├── config.rs           # Configuration constants
│   │
│   └── bin/                # Additional binaries
│       ├── gui/            # GUI application
│       └── tray.rs         # System tray
│
├── tests/                  # Integration tests
│   └── wycheproof_tests.rs # Cryptographic test vectors
│
├── benches/                # Performance benchmarks
│
├── fuzz/                   # Fuzzing targets
│
├── docs/                   # Documentation
│
└── .github/workflows/      # CI/CD pipelines
```

## Cryptographic Data Flow

### File Encryption Flow

```
                    ┌─────────────┐
                    │  Password   │
                    └──────┬──────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Argon2id KDF                            │
│  memory: 64MB, iterations: 3, parallelism: 4                 │
│                                                              │
│  password + salt (22 bytes, base64) ──► 256-bit key         │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Post-Quantum Hybrid (if enabled)                │
│                                                              │
│  ML-KEM-1024 encapsulation ──► shared_secret                │
│  final_key = HKDF(classical_key || pq_shared_secret)        │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Streaming Encryption                      │
│                                                              │
│  For each 64KB chunk:                                        │
│    chunk_nonce = base_nonce XOR chunk_counter               │
│    ciphertext = AES-256-GCM(key, chunk_nonce, plaintext)    │
│                                                              │
│  File Format (V3):                                           │
│  ┌──────────┬──────────┬────────┬────────────────────────┐  │
│  │ Magic(8) │ Salt(22) │Nonce(12)│ Encrypted Chunks...   │  │
│  │"TESS_V03"│ base64   │         │ [len][ciphertext][tag]│  │
│  └──────────┴──────────┴────────┴────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Volume Container Structure

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         VOLUME CONTAINER FILE                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      HEADER (4KB encrypted)                          │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │  Magic: "TESSERACT"                                                  │ │
│  │  Version: 2                                                          │ │
│  │  Cipher: AES-256-GCM | ChaCha20-Poly1305                            │ │
│  │  KDF: Argon2id (params: memory, iterations, parallelism)            │ │
│  │  PQC: ML-KEM-1024 ciphertext (if enabled)                           │ │
│  │  Volume size, sector size, creation time                             │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      KEY SLOTS (2 slots)                             │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │  Slot 0: Primary password (required) ──► encrypted master key        │ │
│  │  Slot 1: Recovery key (optional) ──► encrypted master key            │ │
│  │                                                                       │ │
│  │  + Separate duress password slot (triggers key destruction)          │ │
│  │  + Optional YubiKey 2FA (HMAC-SHA1 challenge-response)               │ │
│  │                                                                       │ │
│  │  Each slot contains:                                                  │ │
│  │    - Salt for this slot's KDF (32 bytes)                             │ │
│  │    - Nonce for AES-GCM (12 bytes)                                    │ │
│  │    - Encrypted master key + auth tag (48 bytes)                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      HIDDEN VOLUME (optional)                        │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │  Separate header hidden in unused space                              │ │
│  │  Different password, plausible deniability                           │ │
│  │  Cannot be detected without correct password                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      DATA SECTORS                                    │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │  Sector 0    │  Sector 1    │  Sector 2    │  ...  │  Sector N      │ │
│  │  (4KB each, XTS-AES-256 encryption)                                  │ │
│  │                                                                       │ │
│  │  Each sector encrypted independently for random access               │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

## Memory Security Model

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SECURE MEMORY LIFECYCLE                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  1. ALLOCATION                                                            │
│     ┌──────────────────────────────────────────────────────────────────┐ │
│     │  SecureAllocator                                                  │ │
│     │    - Allocates page-aligned memory                                │ │
│     │    - Calls mlock() to prevent swapping to disk                   │ │
│     │    - Adds guard pages before/after (PROT_NONE)                   │ │
│     │    - Disables core dumps for the region                          │ │
│     └──────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  2. USAGE                                                                 │
│     ┌──────────────────────────────────────────────────────────────────┐ │
│     │  LockedMemory<T> / Zeroizing<T>                                   │ │
│     │    - RAII wrapper ensures cleanup                                 │ │
│     │    - Constant-time operations for crypto                          │ │
│     │    - No accidental copies (Clone disabled)                        │ │
│     └──────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│                              ▼                                            │
│  3. DESTRUCTION                                                           │
│     ┌──────────────────────────────────────────────────────────────────┐ │
│     │  Drop implementation (automatic on scope exit)                    │ │
│     │    - Multi-pass scrubbing: 0x00, 0xFF, random, 0x00              │ │
│     │    - Memory barrier to prevent optimization                       │ │
│     │    - Verification read to confirm overwrite                       │ │
│     │    - munlock() and deallocation                                  │ │
│     └──────────────────────────────────────────────────────────────────┘ │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

## Key Module Details

### crypto/streaming.rs - Chunked Encryption

The streaming module handles large files without loading them entirely into memory:

```rust
// Simplified flow
ChunkedEncryptor::new(reader, encryptor, key, base_nonce, salt)
    .encrypt_to(output_file)

// For each chunk:
// 1. Read up to 64KB from input
// 2. Derive chunk nonce: base_nonce XOR chunk_counter
// 3. Encrypt with AES-256-GCM
// 4. Write: [chunk_length: u32][ciphertext][tag: 16 bytes]
```

### memory/allocator.rs - Secure Allocator

Custom allocator that ensures secrets are never leaked:

```rust
pub struct SecureAllocator;

impl SecureAllocator {
    pub fn allocate<T>(&self, count: usize) -> SecureAllocation<T> {
        // 1. mmap with MAP_PRIVATE | MAP_ANONYMOUS
        // 2. mlock() to prevent swap
        // 3. Add guard pages
        // 4. Return wrapper with Drop that scrubs
    }
}
```

### volume/keyslot.rs - Key Slot Management

Simple 2-slot model: primary password + optional recovery key:

```rust
pub const MAX_KEY_SLOTS: usize = 2;  // Slot 0: password, Slot 1: recovery

pub struct KeySlot {
    active: bool,
    salt: [u8; 32],           // Argon2id salt
    nonce: [u8; 12],          // AES-GCM nonce
    encrypted_master_key: [u8; 48],  // 32-byte key + 16-byte tag
}

pub struct KeySlots {
    slots: [KeySlot; 2],
    duress_password_slot: Option<KeySlot>,  // Triggers key destruction
}

// To unlock:
// 1. Check if password is duress password (if yes, destroy all keys!)
// 2. Derive slot key from password + slot.salt via Argon2id
// 3. Decrypt slot.encrypted_master_key with AES-GCM
// 4. Use decrypted master key for volume
```

## Testing Infrastructure

### Test Categories

| Type | Location | Purpose |
|------|----------|---------|
| Unit tests | `src/**/*.rs` (`#[cfg(test)]`) | Module-level correctness |
| Integration | `tests/` | End-to-end workflows |
| Wycheproof | `tests/wycheproof_tests.rs` | Cryptographic edge cases |
| Property | `#[proptest]` attributes | Invariant verification |
| Fuzzing | `fuzz/` | Crash/panic discovery |
| Benchmarks | `benches/` | Performance regression |

### Running Tests

```bash
# Unit tests
cargo test --lib

# All tests
cargo test

# Wycheproof crypto vectors
cargo test --test wycheproof_tests

# With coverage
cargo tarpaulin --out Html

# Fuzzing (requires nightly)
cargo +nightly fuzz run fuzz_encrypt
```

### Formal Verification

```bash
# Kani (memory safety, panic-freedom)
cargo kani --lib --harness verify_nonce_len

# Prusti (pre/post conditions)
# Requires Prusti installation
```

## Platform-Specific Code

Platform differences are handled with `#[cfg]` attributes:

```rust
// Windows-specific
#[cfg(target_os = "windows")]
mod windows {
    // WinFsp filesystem, Win32 memory APIs
}

// Linux-specific
#[cfg(target_os = "linux")]
mod linux {
    // FUSE filesystem, TPM2, mlock
}

// Shared implementation
#[cfg(not(target_arch = "wasm32"))]
fn platform_agnostic_function() {
    // Works on both Windows and Linux
}
```

**Important**: All features must work on both Windows and Linux. Test on both platforms before submitting PRs.

## Security Invariants

These invariants must NEVER be violated:

1. **No plaintext keys in logs** - Keys, passwords, and plaintexts must never be logged
2. **Zeroization on drop** - All sensitive data types implement `Zeroize` and scrub on drop
3. **Constant-time comparisons** - Use `subtle::ConstantTimeEq` for password/MAC checks
4. **No panics in library** - All fallible operations return `Result<T, CryptorError>`
5. **Atomic file writes** - Files are written to temp location then renamed
6. **Memory locking** - Sensitive data is mlock'd to prevent swapping

## Common Development Tasks

### Adding a New Cipher

1. Implement the `Encryptor` trait in `crypto/mod.rs`
2. Add tests with Wycheproof vectors if available
3. Add formal verification harness
4. Update volume format if needed

### Adding a New Storage Backend

1. Implement trait in `volume/cloud_sync.rs`
2. Add client module (e.g., `volume/azure_client.rs`)
3. Add feature flag in `Cargo.toml`
4. Test with real service (mock for CI)

### Debugging Memory Issues

```bash
# Run with address sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Check for leaks
valgrind --leak-check=full ./target/debug/tesseract-vault ...
```

## Getting Help

- **Code questions**: Read the doc comments (`///`) in source files
- **Architecture decisions**: Check git history for context
- **Security concerns**: Open a private security advisory on GitHub
- **General questions**: Open a GitHub issue

## Quick Reference

| Task | Command |
|------|---------|
| Build library | `cargo build --lib` |
| Build CLI | `cargo build --bin tesseract-vault` |
| Build GUI | `cargo build --bin tesseract-vault-gui` |
| Run tests | `cargo test` |
| Format code | `cargo fmt` |
| Lint | `cargo clippy -- -D warnings` |
| Generate docs | `cargo doc --open` |
| Security audit | `cargo audit` |
| Cross-platform | See CLAUDE.md for WSL commands |
