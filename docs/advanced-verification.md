# Advanced Verification Infrastructure for Tesseract Vault

This document describes the comprehensive verification and security testing suite implemented for Tesseract Vault's cryptographic core.

## Overview

Tesseract Vault employs a multi-layered verification strategy combining formal methods, property-based testing, security auditing, and code quality tools to ensure the highest level of assurance for cryptographic operations.

## Verification Layers

### 1. Formal Verification (Mathematical Proof)

#### **Kani (Bounded Model Checking)**
- **Purpose**: Bit-precise verification of Rust code
- **Coverage**: 21 proof harnesses across AES-GCM and Argon2id implementations
- **Properties Verified**:
  - Memory safety (no buffer overflows, use-after-free)
  - Integer overflow safety
  - Panic-freedom
  - Encryption/decryption round-trip correctness
  - Authentication rejection of tampered ciphertext
  - Deterministic key derivation

**Example Harness**:
```rust
#[kani::proof]
#[kani::unwind(8)]
fn verify_roundtrip() {
    let key: [u8; 32] = kani::any();
    let nonce: [u8; 12] = kani::any();
    let plaintext_len: usize = kani::any();
    kani::assume(plaintext_len <= 64);

    let plaintext = vec![0u8; plaintext_len];
    let encryptor = AesGcmEncryptor::new();

    if let Ok(ciphertext) = encryptor.encrypt(&key, &nonce, &plaintext) {
        if let Ok(decrypted) = encryptor.decrypt(&key, &nonce, &ciphertext) {
            assert_eq!(decrypted, plaintext);
        }
    }
}
```

#### **Prusti (Deductive Verification)**
- **Purpose**: Contract-based verification using Viper intermediate verification language
- **Status**: Configuration in place, contracts to be added incrementally
- **Target**: Pre/postcondition contracts on public APIs

**Example Contract**:
```rust
#[requires(key.len() == 32)]
#[requires(nonce.len() == NONCE_LEN)]
#[ensures(result.is_ok() ==> result.unwrap().len() == plaintext.len() + 16)]
fn encrypt(&self, key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>
```

### 2. Cryptographic Test Vectors

#### **Wycheproof (Known Attack Resistance)**
- **Source**: C2SP Wycheproof test suite
- **Coverage**: 66 AES-256-GCM test vectors
- **Test Types**:
  - Valid ciphertexts (must decrypt successfully)
  - Invalid ciphertexts (must reject authentication)
  - Edge cases (empty messages, large AAD, etc.)
- **Implementation**: `tests/wycheproof_tests.rs`
- **Results**: 100% pass rate (66/66 applicable tests)

**Test Categories**:
- Empty message encryption
- AAD (Additional Authenticated Data) handling
- Tag truncation attacks
- IV reuse detection
- Ciphertext manipulation rejection

### 3. Undefined Behavior Detection

#### **Miri (Interpreter-Based UB Detection)**
- **Purpose**: Detect undefined behavior that compiler may not catch
- **Checks**:
  - Uninitialized memory reads
  - Use-after-free
  - Double-free
  - Data races (in unsafe code)
  - Misaligned pointer dereferences
  - Out-of-bounds pointer arithmetic
  - Invalid enum discriminants
  - Violations of `std::ptr` safety contracts
- **CI Job**: Runs on Rust nightly with `cargo miri test --lib`

**What Miri Catches**:
```rust
// Example: Miri would catch this UB
let mut v = vec![1, 2, 3];
let ptr = v.as_mut_ptr();
drop(v);  // v deallocated
unsafe {
    *ptr = 42;  // ❌ Use-after-free - Miri ERROR
}
```

### 4. Supply Chain Security

#### **cargo-audit (Vulnerability Scanning)**
- **Purpose**: Detect known security vulnerabilities in dependencies
- **Database**: RustSec Advisory Database
- **CI Integration**: `rustsec/audit-check@v1.4.1` action
- **Frequency**: Every push/PR + scheduled daily scans

**What It Detects**:
- CVEs in dependencies
- Unmaintained crates
- Yanked versions
- Security advisories from RustSec

#### **cargo-vet (Trust Verification)** *(Planned - sc-19ry)*
- **Purpose**: First-party code review auditing
- **Strategy**: Import Mozilla's supply chain audits
- **Critical Dependencies**:
  - `aes-gcm`
  - `argon2`
  - `chacha20poly1305`
  - `ed25519-dalek`
  - `ml-kem`

#### **cargo-deny (Policy Enforcement)** *(Planned - sc-t8sd)*
- **Purpose**: Enforce organizational policies
- **Policies**:
  - License compliance (only MIT/Apache-2.0/BSD-3-Clause)
  - No copyleft licenses
  - No unmaintained dependencies
  - Sources restricted to crates.io + approved git repos
  - Minimize duplicate dependencies

### 5. Side-Channel Attack Prevention

#### **Constant-Time Execution Verification** *(Planned - sc-ko0i)*
- **Tool**: `dudect` (Rust port of DudeCT)
- **Purpose**: Detect timing leaks in cryptographic operations
- **Target Functions**:
  - AES-GCM encryption/decryption
  - Argon2id key derivation
  - Tag comparison operations
  - Nonce validation
- **Method**: Statistical t-test on execution time distributions

**Example Test**:
```rust
use dudect::*;

#[test]
fn test_constant_time_decrypt() {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    // Class A: Valid tags
    // Class B: Invalid tags (first byte differs)
    dudect::ctbench::main(|class| {
        let nonce = [1u8; 12];
        let mut ciphertext = vec![0u8; 32];

        if class == Class::Left {
            // Valid tag
            ciphertext[16..].copy_from_slice(&valid_tag);
        } else {
            // Invalid tag (single bit flip)
            ciphertext[16..].copy_from_slice(&invalid_tag);
        }

        // This MUST take constant time regardless of tag validity
        let _ = decrypt(&key, &nonce, &ciphertext);
    });
}
```

### 6. Fuzzing (Automated Edge Case Discovery) *(Planned - sc-ehoh)*

#### **cargo-fuzz (LibFuzzer Integration)**
- **Purpose**: Discover crashes, panics, and edge cases
- **Targets**:
  - Volume header parsing
  - Encrypted metadata deserialization
  - Nonce construction
  - Key derivation with malformed inputs
  - Ciphertext decryption with mutations

**Example Fuzz Target**:
```rust
// fuzz/fuzz_targets/volume_header.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use tesseract_lib::container::VolumeHeader;

fuzz_target!(|data: &[u8]| {
    // Should never panic, only return Err on invalid input
    let _ = VolumeHeader::from_bytes(data);
});
```

**OSS-Fuzz Integration**: Continuous fuzzing on Google infrastructure (proposed)

### 7. Mutation Testing (Test Suite Quality) *(Planned - sc-iyfk)*

#### **cargo-mutants**
- **Purpose**: Verify test suite catches code mutations
- **Process**:
  1. Mutate source code (e.g., change `==` to `!=`)
  2. Run test suite
  3. If tests still pass → **weak test coverage**
  4. If tests fail → **mutation killed** ✓
- **Target**: >90% mutation score for crypto modules

**Example Mutations**:
```rust
// Original code
if tag_valid {
    Ok(plaintext)
} else {
    Err(CryptorError::Authentication)
}

// Mutation 1: Invert condition
if !tag_valid {  // ❌ Tests MUST catch this
    Ok(plaintext)
} else {
    Err(CryptorError::Authentication)
}

// Mutation 2: Change error type
if tag_valid {
    Ok(plaintext)
} else {
    Err(CryptorError::Decryption)  // ❌ Tests should catch this
}
```

## CI/CD Pipeline

### GitHub Actions Workflow: `.github/workflows/formal-verification.yml`

```yaml
jobs:
  kani-verify:           # Formal verification
  wycheproof-verify:     # Cryptographic test vectors
  prusti-verify:         # Contract verification
  miri-check:            # UB detection
  security-audit:        # Vulnerability scanning
  verification-summary:  # Aggregate results
```

### Verification Matrix

| Layer | Tool | Status | Coverage |
|-------|------|--------|----------|
| Formal Verification | Kani | ✅ Active | 21 harnesses |
| Formal Verification | Prusti | 🟡 Config only | TBD |
| Crypto Test Vectors | Wycheproof | ✅ Active | 66 tests |
| Undefined Behavior | Miri | ✅ Active | Library tests |
| Supply Chain | cargo-audit | ✅ Active | All dependencies |
| Supply Chain | cargo-vet | 📋 Planned | Critical deps |
| Supply Chain | cargo-deny | 📋 Planned | Policy enforcement |
| Side-Channel | dudect | 📋 Planned | Crypto functions |
| Fuzzing | cargo-fuzz | 📋 Planned | Parsers + crypto |
| Test Quality | cargo-mutants | 📋 Planned | Crypto modules |

## Security Properties Verified

### Memory Safety
- **Tools**: Kani, Miri, Rust compiler
- **Properties**:
  - No buffer overflows
  - No use-after-free
  - No double-free
  - No null pointer dereferences
  - No data races

### Cryptographic Correctness
- **Tools**: Kani, Wycheproof
- **Properties**:
  - Encryption/decryption identity: `decrypt(encrypt(m)) = m`
  - Authentication: Invalid ciphertext rejected with probability 1 - 2^-128
  - Key derivation determinism: `derive(p, s) = derive(p, s)`
  - Nonce uniqueness: No (key, nonce) pair reused

### Side-Channel Resistance
- **Tools**: dudect (planned)
- **Properties**:
  - Tag comparison is constant-time
  - Decryption failure timing independent of error type
  - Key derivation time independent of password content

### Code Quality
- **Tools**: cargo-mutants (planned), Clippy
- **Properties**:
  - Test suite catches >90% of mutations
  - No Clippy warnings on `pedantic` level
  - All public APIs documented

## Implementation Checklist

### Completed ✅
- [x] Kani proof harnesses (21 harnesses)
- [x] Wycheproof test integration (66 tests passing)
- [x] Miri CI job
- [x] cargo-audit CI job
- [x] Formal specification document
- [x] Prusti configuration

### In Progress 🟡
- [ ] Prusti contract annotations (ongoing)

### Planned 📋
- [ ] dudect constant-time verification (sc-ko0i)
- [ ] cargo-fuzz targets (sc-ehoh)
- [ ] cargo-mutants integration (sc-iyfk)
- [ ] cargo-vet setup (sc-19ry)
- [ ] cargo-deny configuration (sc-t8sd)
- [ ] OSS-Fuzz integration

## Running Verification Locally

### Kani
```bash
# Install Kani
cargo install --locked kani-verifier
cargo kani setup

# Run specific harness
cargo kani --harness verify_roundtrip

# Run all harnesses (slow)
cargo kani
```

### Wycheproof
```bash
# Clone test vectors
git clone --depth 1 https://github.com/C2SP/wycheproof.git tests/wycheproof

# Run tests
cargo test --test wycheproof_tests
```

### Miri
```bash
# Install Miri
rustup +nightly component add miri

# Run UB detection
cargo +nightly miri test --lib
```

### cargo-audit
```bash
# Install cargo-audit
cargo install cargo-audit

# Scan dependencies
cargo audit
```

## References

- **Kani**: https://model-checking.github.io/kani/
- **Prusti**: https://www.pm.inf.ethz.ch/research/prusti.html
- **Wycheproof**: https://github.com/C2SP/wycheproof
- **Miri**: https://github.com/rust-lang/miri
- **dudect**: https://github.com/rozbb/rust-dudect
- **cargo-fuzz**: https://github.com/rust-fuzz/cargo-fuzz
- **cargo-mutants**: https://github.com/sourcefrog/cargo-mutants
- **cargo-audit**: https://github.com/rustsec/rustsec
- **cargo-vet**: https://mozilla.github.io/cargo-vet/
- **cargo-deny**: https://embarkstudios.github.io/cargo-deny/

---

**Document Version**: 1.0
**Last Updated**: 2025-11-27
**Status**: Living document - updated as verification infrastructure evolves
