# Security Assurance Case

This document provides a formal security assurance case for Tesseract Vault, demonstrating that security requirements are met through systematic evidence and argumentation.

## 1. Executive Summary

Tesseract Vault is a file encryption library and CLI tool designed to protect sensitive data at rest. This assurance case demonstrates that:

- Security requirements are derived from identified threats
- Trust boundaries are clearly defined and enforced
- Secure design principles are systematically applied
- Common implementation weaknesses are mitigated

## 2. Threat Model

### 2.1 Protected Assets

| Asset | Sensitivity | Protection Goal |
|-------|-------------|-----------------|
| User files | High | Confidentiality, Integrity |
| Encryption keys | Critical | Confidentiality |
| Passwords | Critical | Confidentiality |
| Volume metadata | Medium | Integrity, Confidentiality |
| Memory contents | High | Confidentiality |

### 2.2 Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Remote attacker | Network access, exploit development | Data theft, ransomware |
| Local attacker | Physical access to powered-off device | Data theft |
| Privileged attacker | Admin/root access to running system | Espionage |
| Future attacker | Quantum computer | Decrypt stored data |
| Coercive attacker | Legal/physical coercion | Forced decryption |

### 2.3 Threats and Mitigations

| Threat | Description | Mitigation | Evidence |
|--------|-------------|------------|----------|
| T1: Brute-force | Password guessing | Argon2id with 256MB memory, 4 iterations | Wycheproof tests |
| T2: Cryptanalysis | Breaking AES-256 | NIST-approved algorithm, RustCrypto implementation | NIST CAVP tests |
| T3: Quantum attack | Shor's algorithm | ML-KEM-1024 hybrid encryption | NIST PQC compliance |
| T4: Cold boot | Memory extraction | mlock(), guard pages, multi-pass scrubbing | Memory tests |
| T5: Timing attack | Side-channel leakage | Constant-time operations (subtle crate) | dudect analysis |
| T6: Swap exposure | Sensitive data in swap | Memory locking prevents swap | OS API verification |
| T7: Coercion | Forced decryption | Duress passwords, hidden volumes | Feature tests |
| T8: Supply chain | Malicious dependencies | cargo-audit, cargo-deny, signed releases | CI workflows |

### 2.4 Explicit Non-Goals

Tesseract does NOT protect against:
- **Malware on host**: Keyloggers, screen capture, memory inspection by privileged malware
- **Hardware attacks**: Evil maid, hardware keyloggers, JTAG debugging
- **Running system**: Physical access to system with mounted volumes
- **Rubber hose**: Physical coercion (though duress passwords provide limited protection)

## 3. Trust Boundaries

### 3.1 Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        UNTRUSTED ZONE                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │ User Input  │  │ File System │  │   Network   │                  │
│  │ (passwords, │  │ (encrypted  │  │  (cloud     │                  │
│  │  commands)  │  │   volumes)  │  │   sync)     │                  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │
│         │                │                │                          │
├─────────┼────────────────┼────────────────┼──────────────────────────┤
│         │     TRUST BOUNDARY 1: Input Validation                     │
├─────────┼────────────────┼────────────────┼──────────────────────────┤
│         ▼                ▼                ▼                          │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                   APPLICATION LAYER                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │    │
│  │  │    CLI      │  │    GUI      │  │   WASM      │          │    │
│  │  │  (clap)     │  │  (eframe)   │  │  (browser)  │          │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │    │
│  └─────────┼────────────────┼────────────────┼──────────────────┘    │
│            │                │                │                       │
├────────────┼────────────────┼────────────────┼───────────────────────┤
│            │     TRUST BOUNDARY 2: API Layer                         │
├────────────┼────────────────┼────────────────┼───────────────────────┤
│            ▼                ▼                ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    CORE LIBRARY                              │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │    │
│  │  │   Volume    │  │   Crypto    │  │   Memory    │          │    │
│  │  │  Manager    │  │   Module    │  │   Module    │          │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │    │
│  └─────────┼────────────────┼────────────────┼──────────────────┘    │
│            │                │                │                       │
├────────────┼────────────────┼────────────────┼───────────────────────┤
│            │     TRUST BOUNDARY 3: Secure Memory                     │
├────────────┼────────────────┼────────────────┼───────────────────────┤
│            ▼                ▼                ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  SECURE MEMORY ZONE                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │    │
│  │  │  Derived    │  │   Master    │  │  Plaintext  │          │    │
│  │  │   Keys      │  │    Key      │  │   Buffer    │          │    │
│  │  │  (locked)   │  │  (locked)   │  │  (locked)   │          │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘          │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                        TRUSTED ZONE                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Trust Boundary Enforcement

| Boundary | Enforcement Mechanism | Verification |
|----------|----------------------|--------------|
| TB1: Input Validation | Type checking, bounds validation, UTF-8 verification | Unit tests, fuzz testing |
| TB2: API Layer | Result types, no panic on invalid input | Proptest, Kani proofs |
| TB3: Secure Memory | mlock(), guard pages, zeroize on drop | Memory tests, Miri |

### 3.3 Data Flow Across Boundaries

**Encryption Flow:**
```
User Password (untrusted)
    → [TB1: UTF-8 validation, length check]
    → Password (validated)
    → [TB2: Argon2id derivation]
    → Derived Key
    → [TB3: Store in locked memory]
    → Master Key (secure)
```

**Decryption Flow:**
```
Encrypted Volume (untrusted)
    → [TB1: Magic byte check, version check]
    → Volume Header (validated)
    → [TB2: HMAC verification]
    → Authenticated Header
    → [TB3: Decrypt with locked key]
    → Plaintext (secure, temporary)
```

## 4. Secure Design Principles

### 4.1 Saltzer and Schroeder Principles

| Principle | Implementation | Evidence |
|-----------|---------------|----------|
| **Economy of Mechanism** | Single cipher suite (AES-256-GCM), minimal code paths | Code review, LOC metrics |
| **Fail-Safe Defaults** | Encryption enabled by default, secure memory by default | Default config analysis |
| **Complete Mediation** | Every decrypt requires authentication | Code flow analysis |
| **Open Design** | No secret algorithms, public test vectors | Public repository |
| **Separation of Privilege** | Password + optional 2FA (YubiKey/TPM) | Feature documentation |
| **Least Privilege** | Minimal permissions requested, no network for core ops | Capability analysis |
| **Least Common Mechanism** | Isolated crypto core, no shared state | Module boundary audit |
| **Psychological Acceptability** | CLI and GUI interfaces, reasonable defaults | Usability review |

### 4.2 Defense in Depth

```
Layer 1: Cryptographic
├── AES-256-GCM (authenticated encryption)
├── Argon2id (memory-hard KDF)
├── ML-KEM-1024 (post-quantum KEX)
└── BLAKE3 (fast hashing)

Layer 2: Memory Protection
├── mlock() - prevent swapping
├── Guard pages - detect overflow
├── Multi-pass scrubbing - prevent recovery
└── Zeroize on drop - automatic cleanup

Layer 3: Hardware Security
├── TPM 2.0 key sealing (optional)
├── YubiKey HMAC-SHA1 2FA (optional)
└── Secure Boot attestation (planned)

Layer 4: Verification
├── Formal proofs (Kani, Prusti)
├── Fuzz testing (libFuzzer)
├── Timing analysis (dudect)
└── Cryptographic test vectors (Wycheproof, NIST)
```

## 5. Common Weakness Mitigations

### 5.1 CWE/SANS Top 25 Coverage

| CWE | Weakness | Applicability | Mitigation |
|-----|----------|---------------|------------|
| CWE-787 | Out-of-bounds Write | Medium | Rust memory safety, bounds checking |
| CWE-79 | XSS | N/A | No web interface in core |
| CWE-89 | SQL Injection | N/A | No SQL database |
| CWE-416 | Use After Free | High | Rust ownership model prevents UAF |
| CWE-78 | OS Command Injection | Low | No shell execution in core library |
| CWE-20 | Improper Input Validation | High | Type system + explicit validation |
| CWE-125 | Out-of-bounds Read | Medium | Rust slice bounds checking |
| CWE-22 | Path Traversal | Medium | Path canonicalization, validation |
| CWE-352 | CSRF | N/A | No web interface |
| CWE-434 | Dangerous File Upload | N/A | No file upload feature |
| CWE-306 | Missing Authentication | High | All decryption requires auth |
| CWE-502 | Deserialization | Medium | Validated serde schemas |
| CWE-190 | Integer Overflow | Medium | Rust checked arithmetic in debug |
| CWE-798 | Hardcoded Credentials | High | No credentials in source |
| CWE-862 | Missing Authorization | Medium | Volume-level access control |
| CWE-77 | Command Injection | Low | No command execution |
| CWE-476 | NULL Dereference | High | Rust Option types prevent null |
| CWE-287 | Improper Authentication | High | Argon2id + HMAC verification |
| CWE-732 | Incorrect Permission | Medium | Restrictive file permissions |
| CWE-611 | XXE | N/A | No XML parsing |
| CWE-918 | SSRF | Low | No user-controlled URLs in core |
| CWE-77 | Improper Neutralization | Medium | Input validation |
| CWE-295 | Certificate Validation | Low | TLS verification enabled by default |
| CWE-400 | Resource Exhaustion | Medium | Memory limits, timeout handling |
| CWE-522 | Weak Credentials | High | Password strength enforcement |

### 5.2 OWASP Top 10 (2021) Coverage

| ID | Risk | Applicability | Mitigation |
|----|------|---------------|------------|
| A01 | Broken Access Control | Medium | Volume authentication required |
| A02 | Cryptographic Failures | High | NIST-approved algorithms, secure defaults |
| A03 | Injection | Low | No SQL, minimal shell interaction |
| A04 | Insecure Design | High | Threat model, secure design review |
| A05 | Security Misconfiguration | Medium | Secure defaults, validation |
| A06 | Vulnerable Components | Medium | cargo-audit, dependency scanning |
| A07 | Auth Failures | High | Argon2id, rate limiting in daemon |
| A08 | Data Integrity Failures | Medium | HMAC verification, signed releases |
| A09 | Logging Failures | Low | Audit logging (optional feature) |
| A10 | SSRF | Low | No user-controlled external requests |

## 6. Verification Evidence

### 6.1 Formal Verification

| Tool | Scope | Harnesses | Status |
|------|-------|-----------|--------|
| Kani | Crypto core | 21 | Passing |
| Prusti | Memory safety | 8 | Passing |
| Miri | Undefined behavior | Full test suite | Passing |

### 6.2 Testing Coverage

| Test Type | Coverage | Status |
|-----------|----------|--------|
| Unit tests | 77%+ | Passing |
| Integration tests | Key flows | Passing |
| Fuzz testing | Continuous | Active |
| Property tests | Crypto operations | Passing |

### 6.3 Cryptographic Validation

| Suite | Tests | Status |
|-------|-------|--------|
| Wycheproof | 66/66 | Passing |
| NIST CAVP | AES-GCM vectors | Passing |
| NIST PQC | ML-KEM test vectors | Passing |

### 6.4 Security Analysis

| Analysis | Tool | Result |
|----------|------|--------|
| Timing leaks | dudect | No leaks detected |
| Dependency vulns | cargo-audit | 0 vulnerabilities |
| License compliance | cargo-deny | Compliant |

## 7. Security Requirements Traceability

| Requirement | Source | Implementation | Test |
|-------------|--------|----------------|------|
| REQ-1: Confidentiality | Threat Model | AES-256-GCM encryption | Wycheproof |
| REQ-2: Integrity | Threat Model | HMAC authentication | Unit tests |
| REQ-3: Key Protection | Threat Model | Locked memory, zeroization | Memory tests |
| REQ-4: Quantum Resistance | Threat Model | ML-KEM-1024 hybrid | PQC tests |
| REQ-5: Timing Safety | Threat Model | Constant-time operations | dudect |
| REQ-6: Memory Safety | Threat Model | Rust + mlock + guard pages | Miri |
| REQ-7: Supply Chain | Threat Model | cargo-audit, signed releases | CI |

## 8. Continuous Assurance

### 8.1 CI/CD Security Gates

Every commit must pass:
- [ ] `cargo test` - All tests pass
- [ ] `cargo clippy` - No warnings
- [ ] `cargo audit` - No vulnerabilities
- [ ] `cargo deny check` - License/advisory compliance
- [ ] Wycheproof tests - Crypto correctness
- [ ] Kani verification - Formal proofs

### 8.2 Periodic Reviews

| Review | Frequency | Scope |
|--------|-----------|-------|
| Dependency audit | Weekly (automated) | All dependencies |
| Security assessment | Quarterly | Threat model, new features |
| Assurance case update | Per release | This document |

## 9. References

- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management
- [OWASP Top 10](https://owasp.org/Top10/) - Web Application Security Risks
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) - Most Dangerous Software Weaknesses
- [Saltzer & Schroeder](https://ieeexplore.ieee.org/document/1451869) - Secure Design Principles
- [NIST FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) - AES Specification
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Specification

---

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Next Review**: Upon next major release
