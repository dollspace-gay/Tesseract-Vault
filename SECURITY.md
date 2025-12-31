# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **dollspacegay@gmail.com**

Include the following information in your report:

- Type of vulnerability (e.g., buffer overflow, cryptographic weakness, timing attack)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment and potential attack scenarios

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 90 days (coordinated disclosure)

### What to Expect

1. **Acknowledgment**: You will receive confirmation that we received your report
2. **Assessment**: We will investigate and determine the severity
3. **Updates**: We will keep you informed of our progress
4. **Credit**: With your permission, we will credit you in the security advisory

## Security Practices

Tesseract Vault employs multiple layers of security validation:

### Cryptographic Security
- **Audited Libraries**: All cryptographic primitives from RustCrypto ecosystem
- **No Custom Crypto**: We do not implement our own cryptographic algorithms
- **Constant-Time Operations**: Protects against timing side-channel attacks
- **Memory Safety**: Secure zeroization, locked memory pages, guard pages

### Verification Methods
- **Formal Verification**: Kani and Prusti for proving correctness
- **Fuzz Testing**: Continuous fuzzing with libFuzzer and ClusterFuzzLite
- **Test Vectors**: Wycheproof and NIST CAVP cryptographic test suites
- **Timing Analysis**: dudect for detecting timing leaks

### Supply Chain Security
- **Dependency Auditing**: cargo-audit for known vulnerabilities
- **License Compliance**: cargo-deny for policy enforcement
- **Reproducible Builds**: Deterministic compilation where possible

## Security Features

- AES-256-GCM authenticated encryption
- Argon2id memory-hard key derivation
- ML-KEM-1024 post-quantum key encapsulation
- ML-DSA post-quantum digital signatures
- Secure memory allocation with encryption and scrubbing
- Remote wipe with HMAC authentication and replay protection
- Hidden volumes for plausible deniability
- Duress passwords for coercion scenarios

## Threat Model

Tesseract is designed to protect against:
- Brute-force password attacks
- Quantum computer attacks (via post-quantum cryptography)
- Cold boot attacks (via memory locking and scrubbing)
- Timing side-channel attacks (via constant-time operations)
- Swap file exposure (via memory locking)

Tesseract does NOT protect against:
- Malware on the host system
- Hardware keyloggers
- Physical access to a running system with mounted volumes
- Rubber hose cryptanalysis

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities.
