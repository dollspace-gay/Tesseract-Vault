# Tesseract Vault Roadmap

This document outlines the development direction for Tesseract Vault over the next 12+ months.

**Last Updated:** January 2026

## Current Status (v1.5.0)

Tesseract Vault is a stable, security-focused encryption suite with:
- AES-256-GCM and ChaCha20-Poly1305 encryption
- Post-quantum cryptography (ML-KEM-1024, ML-DSA-87)
- Encrypted volume containers with hidden volumes
- Cross-platform support (Windows, Linux, macOS)
- Native GUI and CLI interfaces
- Comprehensive security testing (fuzzing, formal verification, differential testing)

## Short-Term Goals (Q1-Q2 2026)

### Security Hardening
- [ ] Complete OpenSSF Silver badge certification
- [ ] External security audit (seeking funding/sponsors)
- [ ] Expand Wycheproof test vector coverage
- [ ] Add NIST post-quantum test vectors when available

### Stability & Quality
- [ ] Achieve 90%+ code coverage
- [ ] Reduce unsafe code blocks (target: zero in core crypto paths)
- [ ] Performance benchmarking and optimization
- [ ] Memory usage profiling and optimization

### Documentation
- [ ] API documentation improvements
- [ ] User guide with tutorials
- [ ] Security model whitepaper

## Medium-Term Goals (Q3-Q4 2026)

### Features
- [ ] Hardware security module (HSM) integration
- [ ] Smart card support beyond YubiKey
- [ ] Network-attached encrypted volumes (experimental)
- [ ] Mobile companion app for remote wipe triggers

### Platform Support
- [ ] FreeBSD support
- [ ] ARM64 optimization
- [ ] WebAssembly improvements for browser-based encryption

### Ecosystem
- [ ] Plugin architecture for custom key derivation functions
- [ ] Integration with popular backup solutions
- [ ] Cloud storage provider integrations (encrypted-at-rest)

## Long-Term Vision (2027+)

### Research & Innovation
- [ ] Hybrid PQC schemes as NIST standards finalize
- [ ] Threshold cryptography for distributed key management
- [ ] Secure multi-party computation for shared volumes
- [ ] Hardware-backed secure enclaves (Intel SGX, ARM TrustZone)

### Community & Governance
- [ ] Grow contributor base (bus factor > 2)
- [ ] Establish security response team
- [ ] Regular security audit cadence
- [ ] Consider foundation governance if community grows

## Explicit Non-Goals

The following are **out of scope** for Tesseract Vault:

### Will NOT Implement
- **Custom cryptographic primitives** - We use audited libraries (RustCrypto) exclusively
- **Blockchain/cryptocurrency features** - Not a wallet or blockchain tool
- **DRM or copy protection** - This is user encryption, not content restriction
- **Backdoors or key escrow** - No government or corporate key recovery mechanisms
- **Telemetry or analytics** - Zero data collection, ever
- **Cloud-managed keys** - Keys never leave user's control
- **Closed-source components** - Everything remains MIT licensed

### Architectural Constraints
- **No network-required encryption** - Core encryption always works offline
- **No mandatory accounts** - No sign-up, no login, no tracking
- **No automatic updates** - User controls when to update
- **No weakened defaults** - Security is not configurable to be weak

### Platform Limitations
- **iOS app** - Apple's restrictions on encryption apps make this impractical
- **Kernel-mode drivers** - User-space only for security and portability
- **Legacy OS support** - No Windows 7/8, no pre-systemd Linux

## Version Planning

| Version | Target | Focus |
|---------|--------|-------|
| 1.6.0 | Q1 2026 | Security hardening, OpenSSF Silver |
| 1.7.0 | Q2 2026 | Performance, documentation |
| 2.0.0 | Q4 2026 | HSM support, plugin architecture |
| 2.1.0 | 2027 | Threshold cryptography |

## How to Influence the Roadmap

Community input shapes our direction:

1. **Feature requests** - Open a GitHub Issue with the "enhancement" label
2. **Security concerns** - See [SECURITY.md](SECURITY.md) for reporting
3. **Discussions** - Use GitHub Discussions for broader topics
4. **Contributions** - PRs welcome for roadmap items (see [CONTRIBUTING.md](CONTRIBUTING.md))

## Funding & Sustainability

Tesseract Vault is developed by volunteers. To accelerate roadmap items:

- **Sponsor the project** - GitHub Sponsors (coming soon)
- **Fund security audits** - Contact maintainers directly
- **Corporate contributions** - Developer time or resources welcome

---

*This roadmap is a living document and will be updated quarterly. Priorities may shift based on security needs, community feedback, and resource availability.*
