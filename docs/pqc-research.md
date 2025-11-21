# Post-Quantum Cryptography Research

## Executive Summary

**Selected Algorithms:**
- **ML-KEM-1024** (formerly Kyber-1024) - Key Encapsulation Mechanism - FIPS 203
- **ML-DSA-87** (formerly Dilithium5) - Digital Signature Algorithm - FIPS 204

**Selected Rust Implementation:**
- **RustCrypto/ml-kem** v0.3.0+ - Pure Rust FIPS 203 implementation
- **RustCrypto/ml-dsa** v0.1.0+ - Pure Rust FIPS 204 implementation

---

## NIST Post-Quantum Cryptography Standardization

### Background

In 2024, NIST finalized the first set of post-quantum cryptographic standards:

1. **FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
2. **FIPS 204** - Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
3. **FIPS 205** - Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)

These algorithms are designed to be secure against attacks from both classical and quantum computers.

---

## Algorithm Selection

### ML-KEM (Module Lattice-Based Key Encapsulation Mechanism)

**Formerly:** CRYSTALS-Kyber

**Security Levels:**
- ML-KEM-512: NIST Level 1 (equivalent to AES-128)
- ML-KEM-768: NIST Level 3 (equivalent to AES-192)
- ML-KEM-1024: NIST Level 5 (equivalent to AES-256)

**Selected:** ML-KEM-1024

**Rationale:**
- Highest security level (NIST Level 5)
- Matches our current AES-256 security target
- Reasonable performance (encapsulation/decapsulation in <1ms on modern CPUs)
- Small ciphertext size (~1568 bytes for ML-KEM-1024)
- Based on Module-LWE lattice problem (well-studied, conservative)

**Use Case:** Key encapsulation for volume master keys

### ML-DSA (Module Lattice-Based Digital Signature Algorithm)

**Formerly:** CRYSTALS-Dilithium

**Security Levels:**
- ML-DSA-44: NIST Level 2
- ML-DSA-65: NIST Level 3
- ML-DSA-87: NIST Level 5

**Selected:** ML-DSA-87

**Rationale:**
- Highest security level (NIST Level 5)
- Matches our security target
- Fast signing and verification (<1ms)
- Moderate signature size (~4595 bytes for ML-DSA-87)
- Same lattice family as ML-KEM (code reuse, simpler auditing)

**Use Case:** Digital signatures for:
- Volume header integrity verification
- Key slot authentication
- Audit log entries
- Software distribution signing

### Why Not SPHINCS+?

**SPHINCS+ (SLH-DSA)** is a hash-based signature scheme standardized in FIPS 205.

**Pros:**
- Extremely conservative security assumptions (only requires secure hash functions)
- No structured problems (lattices, isogenies) that might have hidden weaknesses

**Cons:**
- **Much larger signatures** (~17KB for SLH-DSA-256f, ~49KB for SLH-DSA-256s)
- **Much slower** signing times (10-100ms depending on variant)
- Our use case doesn't require the extreme conservatism

**Decision:** Use ML-DSA for now. Can add SPHINCS+ as optional upgrade path later if concerns about lattice assumptions emerge.

---

## Rust Implementation Selection

### RustCrypto Organization

**Selected:** `ml-kem` and `ml-dsa` from RustCrypto

**Rationale:**
1. **Reputation:** RustCrypto maintains the de-facto standard Rust crypto libraries
   - We already use their `aes-gcm` fork
   - High-quality, audited code

2. **Standards Compliance:** Implements final FIPS 203 and FIPS 204 standards
   - Not draft versions
   - Will track any future standard updates

3. **Pure Rust:** No C dependencies
   - Easier to audit
   - Memory-safe by default
   - Cross-platform (Windows, Linux, macOS)

4. **Feature Support:**
   - Supports `zeroize` for secure key erasure
   - Optional `alloc` support for no_std environments
   - PKCS#8 serialization support

5. **Active Maintenance:**
   - Regular updates
   - Security-focused development
   - Responsive to issues

### Alternative Implementations Considered

#### pqcrypto (0.18.1)
- Older umbrella crate
- Bindings to C implementations
- Less maintained than RustCrypto
- **Rejected:** C dependencies, less active

#### pqc_kyber / pqc_dilithium
- Pure Rust implementations
- Less formal backing than RustCrypto
- Multiple forks with different fixes
- **Rejected:** Fragmentation concerns, prefer RustCrypto

#### libcrux-ml-kem
- Formal verification in F*
- Extracted to Rust
- **Interesting but rejected:** Still early, prefer mature RustCrypto

---

## Hybrid Mode Design

### Why Hybrid?

**Defense in Depth:** Combine classical (AES-256, RSA, X25519) with post-quantum (ML-KEM).

**Rationale:**
1. If PQC algorithms are broken → Classical crypto still protects data
2. If quantum computers break classical crypto → PQC protects data
3. Both must be broken simultaneously for compromise

### Recommended Approach

**Key Encapsulation:**
```
Classical: X25519 ECDH (32-byte shared secret)
PQC:      ML-KEM-1024 encapsulation (32-byte shared secret)
Combined: KDF(X25519_secret || ML-KEM_secret) → Master Key
```

**Digital Signatures:**
```
Classical: Ed25519 signature (64 bytes)
PQC:      ML-DSA-87 signature (~4595 bytes)
Verify:   Both signatures must be valid
```

**Volume Header:**
- Store both X25519 public key and ML-KEM public key
- Store both Ed25519 signature and ML-DSA signature
- ~4-5KB overhead per volume header

---

## Performance Characteristics

### ML-KEM-1024

| Operation       | Time (approx) | Size          |
|----------------|---------------|---------------|
| Key Generation | ~0.5ms        | 2400 bytes    |
| Encapsulation  | ~0.6ms        | 1568 bytes    |
| Decapsulation  | ~0.7ms        | -             |

### ML-DSA-87

| Operation       | Time (approx) | Size          |
|----------------|---------------|---------------|
| Key Generation | ~1.0ms        | 4896 bytes    |
| Sign           | ~2.5ms        | ~4595 bytes   |
| Verify         | ~1.0ms        | -             |

**Note:** Times are approximate on modern x86_64 CPUs. Actual performance depends on CPU, compiler optimizations, and workload.

---

## Integration Plan

### Phase 1: Core Integration
1. Add `ml-kem` and `ml-dsa` dependencies
2. Implement ML-KEM key encapsulation/decapsulation
3. Implement ML-DSA signing/verification
4. Write comprehensive tests

### Phase 2: Volume Format Extension
1. Design PQC volume header format
2. Add fields for ML-KEM public keys and ciphertexts
3. Add fields for ML-DSA signatures
4. Maintain backward compatibility (PQC optional)

### Phase 3: Hybrid Mode
1. Implement X25519 + ML-KEM hybrid key exchange
2. Implement Ed25519 + ML-DSA hybrid signatures
3. Configuration option: classical-only, PQC-only, hybrid

### Phase 4: Migration
1. Tool to upgrade existing volumes to PQC
2. Key re-encapsulation for all slots
3. Header re-signing with ML-DSA

---

## Security Considerations

### Quantum Threat Timeline

**Conservative Estimate:** 10-15 years until large-scale quantum computers threaten current encryption

**Harvest Now, Decrypt Later:** Adversaries may be collecting encrypted data today to decrypt when quantum computers become available.

**Action:** Implement PQC now for long-term sensitive data.

### Key Management

- PQC keys must be protected with same zeroization as classical keys
- Larger key sizes (2-5KB) require careful memory management
- Public keys can be stored plaintext (they're public)

### Algorithm Agility

- Design system to support algorithm replacement
- If ML-KEM/ML-DSA are broken, can swap to SPHINCS+ or future algorithms
- Version fields in headers critical for forward compatibility

---

## References

1. NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard
   https://csrc.nist.gov/pubs/fips/203/final

2. NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard
   https://csrc.nist.gov/pubs/fips/204/final

3. CRYSTALS-Kyber Website
   https://pq-crystals.org/kyber/

4. CRYSTALS-Dilithium Website
   https://pq-crystals.org/dilithium/

5. RustCrypto KEMs Repository
   https://github.com/RustCrypto/KEMs

6. RustCrypto Signatures Repository
   https://github.com/RustCrypto/signatures

---

## Conclusion

**Recommendation:** Proceed with ML-KEM-1024 and ML-DSA-87 from RustCrypto.

**Benefits:**
- Future-proof against quantum computers
- Standards-based (FIPS 203/204)
- Mature Rust implementation
- Reasonable performance overhead
- Hybrid mode provides defense-in-depth

**Next Steps:**
1. Add dependencies to Cargo.toml
2. Implement basic key generation and operations
3. Design PQC volume format extension
4. Comprehensive testing

---

*Document Version: 1.0*
*Last Updated: 2025-11-21*
*Author: Claude (Security Research)*
