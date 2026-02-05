# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Bump ml-dsa 0.1.0-rc.2 → 0.1.0-rc.4** — fixes signature malleability vulnerability where duplicate hint indices were incorrectly accepted (`<=` instead of `<` in monotonic check). Affects all ML-DSA security levels. (RUSTSEC advisory, severity: Medium)

### Changed
- Bump time crate from 0.3.46 to 0.3.47 (#268)
- Audit and fix tautological/flawed tests across codebase (#267)
- Add CodeQL config to exclude test paths from code scanning (#266)
- Bump ml-dsa from 0.1.0-rc.2 to 0.1.0-rc.4 (security fix: signature malleability) (#265)
- Upgrade RustCrypto dependency ecosystem for ml-dsa compatibility:
  - `ml-dsa` 0.1.0-rc.2 → 0.1.0-rc.4
  - `ml-kem` 0.3.0-pre.2 → 0.3.0-pre.5 (now uses rand_core 0.10; removes rand 0.9 compat shim)
  - `rand` 0.10.0-rc.5 → 0.10.0-rc.8 (`OsRng` → `SysRng`, `os_rng` → `sys_rng`)
  - `rand_core` 0.10.0-rc-2 → 0.10.0-rc-6 (`TryRngCore` → `TryRng`, `RngCore` → `Rng`)
  - `chacha20` 0.10.0-rc.5 → 0.10.0-rc.9
  - `argon2` 0.6.0-rc.2 → 0.6.0-rc.6 (`SaltString`/`Salt` moved to `phc` submodule)

### Added
- **GUI Keyfile Generator** - integrated keyfile generation window in GUI for creating ML-KEM-1024 quantum-resistant keyfiles (.tkf) with optional password protection
- **Dead Man's Switch** - automatic key destruction after configurable inactivity period:
  - Configurable timeout (default 30 days), warning period (7 days), and grace period (3 days)
  - Check-in via CLI command or remote wipe protocol
  - Status tracking: Ok → Warning → GracePeriod → Expired (triggers destruction)
  - Integrates with existing RemoteWipeManager for key destruction
- **Dead Man's Switch Daemon Integration**:
  - Background monitoring thread checks all volumes every hour
  - Automatic key destruction when deadlines expire
  - Persistent config storage survives daemon restarts (Windows: `%LOCALAPPDATA%\Tesseract\wipe_configs`, Linux: `~/.local/share/tesseract/wipe_configs`)
  - New daemon protocol commands: `DeadManEnable`, `DeadManDisable`, `DeadManCheckin`, `DeadManStatus`
  - Client-side API methods for dead man's switch management
- Docker TPM testing environment using swtpm (Software TPM 2.0 emulator) for CI validation of TPM functionality
- `.dockerignore` file to optimize Docker build context (21GB → 212MB)
- `tesseract-luks` CLI tool for Linux Full Disk Encryption with Tesseract security features:
  - Password-based key slot with Argon2id key derivation + AES-256-GCM encryption
  - PQC hybrid key slot with ML-KEM-1024 post-quantum encryption
  - Duress password slot that securely destroys all keys when used
  - TPM 2.0 sealing with PCR-bound policy (PCR 0, 7 for Secure Boot chain)
  - Keyfile wrapper approach compatible with standard cryptsetup/LUKS2

### Changed
- Improve code coverage (#261)
- Add tests to daemon/server.rs (#264)
- Add tests to daemon/client.rs (#263)
- Exclude WASM from coverage (#262)
- Expand Kani harnesses to cover daemon and volume operations (#257)
- Keyslot Kani harnesses (#260)
- Daemon auth Kani harnesses (#259)
- Daemon protocol Kani harnesses (#258)
- Add keyfile generation to GUI (#235)
- PQC Keyfile Support - True Quantum Resistance (#227)
- Make PQC keyfile mandatory for encryption (#234)
- Update encrypt flow to require keyfile (#237)
- Make keyfile required for CLI encrypt command (#236)
- Memory Security Model Improvements (review.md Section 3.2) (#238)
- Evaluate EncryptedMemoryPool complexity vs benefit (#243)
- Document Spectre/Meltdown limitations (#242)
- Implemented SecretMemory<T> with memfd_secret() Support (#240)
- Document mlock limits prominently (#239)
- Fix into_inner() RAII gap - return Zeroizing<T> (#241)
- **BREAKING**: Keyfile now mandatory for encryption/decryption when `post-quantum` feature is enabled:
  - CLI: `tesseract-vault encrypt` requires `--keyfile <path.tkf>` argument
  - CLI: `tesseract-vault decrypt` requires `--keyfile <path.tkf>` argument
  - GUI: Encrypt/Decrypt buttons disabled until keyfile is selected
  - Provides NIST Level 5 quantum resistance via hybrid key derivation (Argon2id + ML-KEM-1024)
- CLI: --keyfile flag for encrypt/decrypt/volume commands (#232)
- Volume: Store encapsulation ciphertext in header (#231)
- CLI: tesseract keyfile generate command (#228)
- Core: Hybrid key derivation with keyfile (#230)
- Core: Keyfile format and serialization (#229)
- Deprecate WASM feature flags (#225)
- Write critical design review document (#224)
- Handle edge cases and contingencies (#223)
- Add CLI commands for Dead Man's Switch (#222)
- Wire up Dead Man's Switch to daemon (#219)
- Define persistent storage paths for wipe configs (#221)
- Add background monitoring thread to daemon server (#220)
- Dead Man's Switch - Auto-destruct after inactivity (#72)
- Replaced `bincode` serialization with `postcard` - more compact varint encoding, actively maintained (RUSTSEC-2025-0141)
- Updated `lru` from 0.16 to 0.16.3 to fix soundness issue with IterMut (RUSTSEC-2026-0002)
- Migrated fuzz targets from `bincode` to `postcard` deserialization

### Deprecated
- **WASM support** (`wasm-minimal`, `wasm-full` features) - Browser security model cannot provide mlock, guard pages, or anti-debugging protections that are core to Tesseract's security guarantees. Will be removed in v2.0 (#225, #226)

### Removed
- Creusot formal verification - removed due to incompatibility with codebase patterns (dyn Error, chunks_exact iterator, String struct fields)
- Orphaned `yubikey_stub.rs` - dead code never wired into module system (replaced by real `yubikey.rs` implementation long ago)
- Unused `bincode` dependency from fuzz crate

### Fixed
- Race condition in concurrent filesystem operations - added inode table lock to protect read-modify-write cycles on shared inode blocks (32 inodes per 4KB block)
- Filesystem corruption after postcard migration - inode serialization now pads to fixed INODE_SIZE (128 bytes) to ensure consistent disk layout with variable-length encoding

### Security
- **[HIGH]** Enforced mandatory PQC keyfile for all encryption operations - eliminates weak password-only encryption path, ensuring all encrypted data has NIST Level 5 quantum resistance
- **[MEDIUM]** Fixed RUSTSEC-2025-0141 - replaced unmaintained `bincode` crate with `postcard` for serialization
- **[MEDIUM]** Fixed RUSTSEC-2026-0002 - upgraded `lru` to 0.16.3 to fix soundness issue in IterMut (main and fuzz crates)
- **[MEDIUM]** Fixed CWE-807 (Reliance on Untrusted Inputs) - replaced `%USERNAME%` environment variable with Windows `GetUserNameW` API for secure username retrieval in daemon auth
- **[MEDIUM]** Added server identity verification to daemon IPC - clients can now verify they're communicating with the legitimate daemon using BLAKE3 keyed challenge-response before sending sensitive commands (prevents daemon impersonation attacks)

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
