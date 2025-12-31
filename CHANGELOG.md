# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
- Improved replay protection from count-based to time-window based nonce pruning
- Enhanced password validation to reject common patterns like "Password123!"

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

[Unreleased]: https://github.com/dollspace-gay/Tesseract/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dollspace-gay/Tesseract/releases/tag/v0.1.0
