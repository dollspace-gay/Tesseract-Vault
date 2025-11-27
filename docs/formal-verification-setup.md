# Formal Verification Toolchain Setup

## Overview

This document describes the installation and configuration of formal verification tools for Tesseract Vault. Based on the tool analysis, we are deploying Kani (primary) and Prusti (complementary).

## Platform Considerations

Tesseract is cross-platform (Windows, Linux, macOS), but verification tools have platform-specific limitations:

- **Kani**: Linux/macOS only (no Windows support)
- **Prusti**: Windows/Linux/macOS supported via VS Code extension

Given the Windows development environment, we will:
1. Use **Prusti** for Windows-based development verification
2. Use **Kani** in CI/CD pipeline (Linux containers)
3. Document dual-tool workflow for cross-platform coverage

## Installation

### Prusti (Windows/Linux/macOS)

#### Prerequisites
- Java JDK 11+ (64-bit) - [Download OpenJDK](https://adoptium.net/)
- Rustup 1.23.0+ (already installed)
- VS Code

#### Installation Steps

**Method 1: VS Code Extension (Recommended)**

1. Install Java JDK 11+:
   ```powershell
   # Check if Java is installed
   java -version

   # If not installed, download from https://adoptium.net/
   # Or use winget:
   winget install EclipseAdoptium.Temurin.11.JDK
   ```

2. Install Prusti Assistant in VS Code:
   - Open VS Code Extensions (Ctrl+Shift+X)
   - Search for "Prusti Assistant"
   - Click Install
   - Extension will auto-download Prusti on first activation

3. Verify installation:
   - Open any Rust file in Tesseract
   - Extension should activate and download Prusti
   - Check VS Code output panel for "Prusti" logs

**Method 2: Command Line**

```powershell
# Download precompiled binaries from GitHub releases
# https://github.com/viperproject/prusti-dev/releases

# Extract to a directory (e.g., C:\Tools\prusti)
# Add to PATH or use cargo-prusti directly
```

**Linux (CI/CD)**

```bash
# In CI environment (Ubuntu/Debian)
cargo install prusti-cli
prusti-rustc --version
```

### Kani (Linux Only)

**Note**: Kani is NOT available on Windows. It will be used exclusively in CI/CD pipeline.

#### CI/CD Installation (GitHub Actions)

```yaml
# .github/workflows/verification.yml
- name: Install Kani
  run: |
    cargo install --locked kani-verifier
    cargo kani setup
```

#### Local Linux Development (Optional)

```bash
# On Linux or WSL with Rust installed
cargo install --locked kani-verifier
cargo kani setup

# Verify installation
cargo kani --version
```

**WSL Setup** (if needed):

```bash
# Install Rust in WSL first
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Then install Kani
cargo install --locked kani-verifier
cargo kani setup
```

## Configuration

### Prusti Configuration

#### VS Code Settings

Add to `.vscode/settings.json`:

```json
{
  "prusti.buildChannel": "nightly",
  "prusti.checkOverflows": true,
  "prusti.enablePureFunctions": true,
  "prusti.encodeBitvectorSize": true,
  "prusti.encodeUnsignedNumConstraint": true
}
```

#### Project Configuration

Create `Prusti.toml` in project root:

```toml
# Prusti verification configuration
[prusti]
check_overflows = true
encode_unsigned_num_constraint = true
enable_pure_functions = true
encode_bitvector_size = true

# Cryptography-specific settings
[verification]
# Verify arithmetic operations don't overflow
check_arithmetic_overflow = true
# Check array bounds
check_bounds = true
# Verify pointer safety
check_null_dereference = true
```

### Kani Configuration

Create `kani.toml` in project root:

```toml
# Kani verification configuration
[kani]
# Default settings for all verification
default-unwind = 5
enable-unstable = true

[[kani.profile.crypto]]
# Crypto-specific profile with higher bounds
unwind = 10
cbmc-args = [
    "--bounds-check",
    "--pointer-check",
    "--memory-leak-check",
    "--div-by-zero-check",
    "--signed-overflow-check",
    "--unsigned-overflow-check",
    "--conversion-check",
    "--nan-check"
]
```

## Verification Workflow

### Development Workflow (Windows + Prusti)

1. **Write Code**: Implement crypto primitives in `src/crypto/`
2. **Add Specifications**: Annotate with Prusti contracts
   ```rust
   #[requires(key.len() == 32)]
   #[ensures(result.is_ok() -> result.unwrap().len() > 0)]
   pub fn derive_key(key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
       // implementation
   }
   ```
3. **Run Prusti**: VS Code will show verification status in real-time
4. **Fix Issues**: Address verification failures
5. **Commit**: Code with verified contracts

### CI/CD Workflow (Linux + Kani + Prusti)

```yaml
# .github/workflows/verification.yml
name: Formal Verification

on: [push, pull_request]

jobs:
  kani-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install Kani
        run: |
          cargo install --locked kani-verifier
          cargo kani setup

      - name: Run Kani Verification
        run: |
          cargo kani --workspace

  prusti-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly

      - name: Install Java (for Prusti)
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '11'

      - name: Install Prusti
        run: cargo install prusti-cli

      - name: Run Prusti Verification
        run: prusti-cargo
```

## Verification Coverage Plan

### Phase 1: Core Cryptography (Priority)

**Kani Verification Targets**:
- `src/crypto/aes.rs` - AES-256 implementation
- `src/crypto/gcm.rs` - GCM mode operations
- `src/crypto/xts.rs` - XTS mode operations
- `src/crypto/argon2.rs` - Argon2id KDF

**Prusti Specification Targets**:
- Public API contracts in `src/crypto/mod.rs`
- Key derivation invariants
- Master key zeroization guarantees

### Phase 2: Volume Management

**Kani Verification Targets**:
- `src/volume/volumeio_fs.rs` - Filesystem operations
- `src/volume/container.rs` - Container format handling

**Prusti Specification Targets**:
- VolumeManager access control
- Filesystem consistency invariants

### Phase 3: Security Properties

**Kani Verification Targets**:
- `src/memory/secure.rs` - Secure memory handling
- `src/crypto/streaming.rs` - Stream cipher operations

**Prusti Specification Targets**:
- Key confidentiality properties
- Authentication guarantees

## Tool-Specific Usage

### Prusti Usage

**Verify single module**:
```powershell
prusti-cargo --crate-type=lib --module=crypto::aes
```

**Verify entire workspace**:
```powershell
prusti-cargo
```

**Generate verification report**:
```powershell
prusti-cargo --json > verification-report.json
```

### Kani Usage

**Verify specific harness**:
```bash
cargo kani --harness verify_aes_encryption
```

**Verify with higher unwind bound**:
```bash
cargo kani --unwind 20 --harness verify_gcm_authentication
```

**Generate coverage report**:
```bash
cargo kani --coverage --harness verify_argon2_derivation
```

**Verify entire crate**:
```bash
cargo kani --workspace
```

## Writing Verification Harnesses

### Kani Proof Harness Example

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_aes_encryption_safety() {
        // Create symbolic inputs
        let key: [u8; 32] = kani::any();
        let plaintext: [u8; 16] = kani::any();

        // Call function under test
        let result = aes_encrypt(&key, &plaintext);

        // Kani automatically checks:
        // - No panics
        // - No undefined behavior
        // - No memory safety violations

        // Add custom assertions
        if let Ok(ciphertext) = result {
            assert_eq!(ciphertext.len(), 16);
        }
    }

    #[kani::proof]
    #[kani::unwind(32)]  // Higher bound for complex loops
    fn verify_gcm_no_overflow() {
        let key: [u8; 32] = kani::any();
        let nonce: [u8; 12] = kani::any();
        let data_len: usize = kani::any();
        kani::assume(data_len <= 1024);  // Bound input size

        let mut data = vec![0u8; data_len];
        for i in 0..data_len {
            data[i] = kani::any();
        }

        // Verify no integer overflow in GCM operations
        let _ = gcm_encrypt(&key, &nonce, &data);
    }
}
```

### Prusti Specification Example

```rust
use prusti_contracts::*;

#[pure]
#[ensures(result >= 0)]
fn buffer_len(buf: &[u8]) -> usize {
    buf.len()
}

#[requires(key.len() == 32)]
#[requires(salt.len() >= 16)]
#[ensures(result.is_ok() ==> result.unwrap().len() == output_len)]
#[ensures(result.is_err() ==> old(key.len()) != 32)]
pub fn derive_key(key: &[u8], salt: &[u8], output_len: usize) -> Result<Vec<u8>> {
    // Preconditions are checked by Prusti
    // Postconditions are verified by Prusti

    argon2_kdf(key, salt, output_len)
}

#[requires(master_key.len() == 32)]
#[after_expiry(master_key.iter().all(|&b| b == 0))]  // Zeroization guarantee
pub fn use_and_zeroize(mut master_key: Vec<u8>) {
    // Use key
    encrypt_with_key(&master_key);

    // Zero memory
    for byte in &mut master_key {
        *byte = 0;
    }
}  // Prusti verifies zeroization happened
```

## Troubleshooting

### Prusti Issues

**Java not found**:
```
Error: Java is required but not found
```
Solution: Install Java JDK 11+, restart terminal/IDE

**Viper timeout**:
```
Verification timeout after 60s
```
Solution: Simplify specifications or increase timeout in Prusti.toml

**Nightly toolchain mismatch**:
```
Prusti requires nightly-YYYY-MM-DD
```
Solution: VS Code extension manages this automatically, or manually install required nightly

### Kani Issues

**Unwind bound exceeded**:
```
Error: unwinding assertion loop.0
```
Solution: Increase `--unwind` bound or add `kani::assume` to limit input space

**State explosion**:
```
CBMC out of memory
```
Solution: Reduce input sizes with `kani::assume`, simplify data structures, or stub complex dependencies

**Solver timeout**:
```
SAT solver timeout
```
Solution: Break verification into smaller harnesses, add stronger assumptions

## Next Steps

1. ✅ Install Java JDK 11+ on Windows
2. ✅ Install Prusti Assistant VS Code extension
3. ⏳ Create CI/CD workflow with Kani + Prusti
4. ⏳ Write initial Prusti specifications for `src/crypto/aes.rs`
5. ⏳ Write initial Kani harnesses for `src/crypto/gcm.rs`
6. ⏳ Integrate verification into PR review process

## References

- [Kani Installation Guide](https://model-checking.github.io/kani/install-guide.html)
- [Kani GitHub Repository](https://github.com/model-checking/kani)
- [Prusti GitHub Repository](https://github.com/viperproject/prusti-dev)
- [Prusti VS Code Extension](https://marketplace.visualstudio.com/items?itemName=viper-admin.prusti-assistant)
- [Prusti User Guide](https://viperproject.github.io/prusti-dev/user-guide/)
- [OpenJDK Downloads](https://adoptium.net/)

---

**Status**: Setup in progress
**Primary Tool**: Prusti (Windows development)
**CI Tool**: Kani + Prusti (Linux containers)
**Next**: Install Java and Prusti extension
