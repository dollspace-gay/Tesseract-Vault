# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- Creusot formal verification - removed due to incompatibility with codebase patterns (dyn Error, chunks_exact iterator, String struct fields)

### Fixed
- Race condition in concurrent filesystem operations - added inode table lock to protect read-modify-write cycles on shared inode blocks (32 inodes per 4KB block)

## [1.6.0] - 2026-01-06

### Added
- Creusot deductive formal verification with Why3find provers
- Creusot annotations for cryptographic functions (ensures/requires contracts)

### Changed
- Updated Creusot annotation paths to use `creusot_contracts::macros::` namespace
- Excluded modules with unsupported patterns from Creusot verification scope

### Security
- **[CRITICAL]** Fixed DoS via memory exhaustion in streaming decryption - added chunk size validation before allocation (CWE-789)
- **[CRITICAL]** Fixed static nonce reuse in migration - now generates random nonce per encryption (CWE-329)
- **[HIGH]** Fixed insecure PQC API - public encapsulate() now validates keys by default, unsafe version renamed to encapsulate_unchecked() (CWE-676)
- **[HIGH]** Fixed YubiKey backup bypass - allow_backup now defaults to false to prevent hardware 2FA bypass (CWE-287)
- **[HIGH]** Fixed ineffective Windows crash dump protection - now returns error instead of silently succeeding (CWE-693)
- **[HIGH]** Fixed PATH injection in Linux power management - uses absolute paths for systemctl/busctl/gdbus (CWE-78)
- **[HIGH]** Fixed CSP injection via spaces - added space character filtering to additional_sources validation (CWE-79)
- **[MEDIUM]** Added Argon2 parameter validation - enforces minimum secure values (8MB memory, 1 iteration) to prevent weak configs (CWE-326)
- **[MEDIUM]** Added fallible salt generation - try_generate_salt_string() returns Result instead of panicking (CWE-248)
- **[MEDIUM]** Replaced Argon2 with HKDF for XTS key derivation - HKDF is more appropriate for strong key material (CWE-327)
- **[MEDIUM]** Documented PowerStateMonitor as stub implementation with security warning (CWE-693)
- **[CRITICAL]** Added token-based IPC authentication - daemon generates 256-bit random token saved to user-only file; all commands require valid token (CWE-276)
- **[HIGH]** Fixed unbounded memory allocation DoS - added 16MB MAX_MESSAGE_SIZE limit before buffer allocation (CWE-770)
- **[HIGH]** Fixed password exposure via Debug trait - custom Debug impl redacts password fields with `<REDACTED>` (CWE-532)
- **[HIGH]** Fixed memory leak in CSP generation - replaced Box::leak with owned String values (CWE-401)
- **[HIGH]** Fixed path traversal vulnerability - normalize_path now filters out `..` components to prevent filesystem escape (CWE-22)
- **[HIGH]** Fixed TOCTOU race condition in mount - lock held for entire operation to prevent concurrent mount attacks (CWE-367)
- **[HIGH]** Replaced weak XOR encryption with AES-256-GCM authenticated encryption in TPM utils (CWE-327)
- **[MEDIUM]** Fixed thread exhaustion DoS - added connection limiting with MAX_CONCURRENT_CONNECTIONS=32 (CWE-400)
- **[MEDIUM]** Replaced eval() with Reflect.has() in WASM security checks - CSP compatible (CWE-95)
- **[MEDIUM]** Added CSP injection validation - rejects semicolons, newlines, carriage returns in additional_sources (CWE-116)
- **[MEDIUM]** Fixed timing side-channel in constant_time_compare - now uses `subtle` crate's ConstantTimeEq (CWE-208)
- **[MEDIUM]** Fixed unquoted executable path in Linux .desktop file - prevents execution with paths containing spaces (CWE-428)
- **[MEDIUM]** Fixed password not zeroized after use - passwords now explicitly zeroized after mount operations (CWE-316)
- **[MEDIUM]** Fixed decrypt returning non-zeroizing Vec - decrypt now returns Zeroizing<Vec<u8>> for automatic memory clearing (CWE-316)
- **[HIGH]** Fixed TOCTOU race in Windows token file permissions - uses temp file with permissions set before atomic rename (CWE-367)
- **[HIGH]** Fixed symlink attack in Unix token file - added symlink check and create_new to prevent attacks (CWE-59)
- **[HIGH]** Fixed client unbounded memory allocation - added MAX_RESPONSE_SIZE (16MB) check before buffer allocation (CWE-770)
- **[HIGH]** Fixed insecure socket/token path in /tmp - now uses XDG_RUNTIME_DIR or ~/.local/share/tesseract (CWE-377)
- **[HIGH]** Added zeroization to auth tokens - AuthManager, DaemonClient, and AuthenticatedRequest now zeroize tokens on drop (CWE-316)
- **[MEDIUM]** Fixed unbounded file read in storage - added MAX_FILE_SIZE (1GB) limit to prevent memory exhaustion (CWE-770)
- **[LOW]** Fixed desktop entry file permissions from 0o755 to 0o644 - config files should not be executable (CWE-732)
- **[LOW]** Fixed potential integer overflow in unix_to_filetime - uses saturating arithmetic (CWE-190)
- **[LOW]** Made Windows daemon port configurable via TESSERACT_DAEMON_PORT environment variable (CWE-798)
- **[LOW]** Fixed salt length integer truncation - explicit validation before u8 cast prevents silent truncation (CWE-197)
- **[MEDIUM]** Fixed integer overflow in allocation size calculation - uses saturating arithmetic (CWE-190)
- **[HIGH]** Removed /tmp socket fallback - now uses /var/run/user/{uid} to prevent symlink attacks (CWE-377)
- **[HIGH]** Added password zeroization in daemon client - passwords now zeroized after serialization (CWE-316)
- **[HIGH]** Added key pair consistency verification in ML-DSA from_bytes - verifying key now validated against seed (CWE-502)
- **[CRITICAL]** Fixed nonce reuse in EncryptedAllocation::write - generates fresh nonce per write, prepends to ciphertext (CWE-329)
- **[CRITICAL]** Added validation to remote wipe command polling - checks freshness and nonce replay before returning commands (CWE-345)
- **[CRITICAL]** Fixed wrong password used for hidden volume mount - now correctly uses hidden volume password (CWE-287)
- **[CRITICAL]** Fixed AWS SigV4 using BLAKE3 instead of HMAC-SHA256 - now uses proper SHA-256 and HMAC-SHA256 per AWS spec (CWE-327)
- **[HIGH]** Fixed CSP injection via tab/whitespace - now uses char::is_whitespace() for comprehensive filtering (CWE-79)
- **[MEDIUM]** Added pq_metadata_size validation in header - prevents memory exhaustion via untrusted size field (CWE-770)
- **[MEDIUM]** Added MountOptions password zeroization - hidden_password now zeroized on drop (CWE-316)

## [1.5.0] - 2024-12-31

### Added
- Hidden volumes GUI support for plausible deniability
- Entropy-based password validation using zxcvbn
- Time-window based nonce replay protection
- ClusterFuzzLite continuous fuzzing integration
- Remote wipe GUI integration
- Remote wipe with HMAC authentication and cloud-triggered duress destruction
- LUKS2 integration with post-quantum encryption
- Linux TPM key sealing support
- Cloud storage backends (S3, Dropbox) with incremental chunk-level sync
- YubiKey hardware security module integration
- Daemon shutdown signal handling
- Indirect block handling for large files
- Code coverage reporting with Codecov integration
- SPDX license headers on all source files
- CONTRIBUTING.md with development guidelines
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- SECURITY.md with vulnerability reporting policy

### Changed
- Improved replay protection from count-based to time-window based nonce pruning
- Enhanced password validation to reject common patterns like "Password123!"
- Adjusted Codecov thresholds to 70%/80% (platform-specific code reduces CI coverage)

### Security
- Added Kani formal verification harnesses for streaming encryption nonce handling
- Added ClusterFuzzLite for continuous fuzzing
- Added differential testing against reference implementations
- Added dudect timing attack detection
- Improved memory scrubbing with multi-pass overwrite

### Fixed
- Various test fixes for cross-platform compatibility
- Fuzzing target fixes

## [0.1.0] - Initial Release

### Added
- AES-256-GCM authenticated encryption
- ChaCha20-Poly1305 alternative cipher
- Argon2id memory-hard key derivation
- ML-KEM-1024 post-quantum key encapsulation
- ML-DSA post-quantum digital signatures
- Streaming encryption for large files
- Encrypted volume containers
- Cross-platform support (Windows, Linux)
- Native GUI application
- Command-line interface
- Secure memory allocation
- Memory locking and scrubbing
- Wycheproof cryptographic test vectors
- NIST CAVP validation tests
- Formal verification with Kani and Prusti

[Unreleased]: https://github.com/dollspace-gay/Tesseract/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/dollspace-gay/Tesseract/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/dollspace-gay/Tesseract/compare/v0.1.0...v1.5.0
[0.1.0]: https://github.com/dollspace-gay/Tesseract/releases/tag/v0.1.0
