# Contributing to Tesseract Vault

Thank you for your interest in contributing to Tesseract Vault! This document provides guidelines for contributing to this security-focused encryption project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) to ensure that contributors have the legal right to submit their contributions.

By making a contribution to this project, you certify that:

1. The contribution was created in whole or in part by you and you have the right to submit it under the MIT license; or
2. The contribution is based upon previous work that, to the best of your knowledge, is covered under an appropriate open source license and you have the right to submit that work with modifications; or
3. The contribution was provided directly to you by some other person who certified (1) or (2) and you have not modified it.

### How to Sign Off

**All commits must be signed off** using the `-s` flag:

```bash
git commit -s -m "Your commit message"
```

This adds a `Signed-off-by` line to your commit message:

```
Your commit message

Signed-off-by: Your Name <your.email@example.com>
```

If you forget to sign off, you can amend your last commit:

```bash
git commit --amend -s
```

Or sign off multiple commits:

```bash
git rebase --signoff HEAD~3  # Sign off last 3 commits
```

## Security First

Tesseract Vault handles encryption and sensitive data. All contributions must prioritize security:

- **Never introduce known vulnerabilities** (OWASP Top 10, CWE Top 25)
- **No custom cryptography** - use audited libraries (RustCrypto ecosystem)
- **Memory safety** - avoid `unsafe` unless absolutely necessary with `// SAFETY:` comments
- **Constant-time operations** for cryptographic comparisons
- **Secure defaults** - security should not require configuration

## Getting Started

### Prerequisites

- Rust stable toolchain (latest)
- For Windows development: Native Windows environment
- For cross-platform testing: WSL with FedoraLinux-42 or equivalent

### Development Setup

```bash
# Clone the repository
git clone https://github.com/dollspace-gay/Tesseract.git
cd Tesseract

# Build the library
cargo build --lib

# Build the CLI
cargo build --bin tesseract-vault

# Run tests
cargo test --lib
```

### Cross-Platform Testing

This project **must** work on Windows and Linux. Before submitting a PR:

**Windows:**
```bash
cargo build --lib
cargo build --bin tesseract-vault
cargo test --lib
cargo test --test wycheproof_tests
```

**Linux (WSL):**
```bash
wsl -d FedoraLinux-42 -- bash -c "cd /mnt/c/path/to/Tesseract && cargo build --lib"
wsl -d FedoraLinux-42 -- bash -c "cd /mnt/c/path/to/Tesseract && cargo test --lib"
```

## Code Standards

### Formatting and Linting

- Run `cargo fmt` before every commit
- Run `cargo clippy` and address all warnings
- Code should pass `clippy::all` and `clippy::pedantic` where reasonable

### Rust Best Practices

- **No panics in library code** - return `Result<T, E>` for fallible operations
- **Handle errors explicitly** - use `?` for propagation, avoid `.unwrap()` except in tests
- **Follow naming conventions:**
  - `PascalCase` for types (structs, enums, traits)
  - `snake_case` for functions, methods, variables, modules
  - `UPPER_SNAKE_CASE` for constants
- **Document public APIs** - all `pub` items need `///` doc comments

### Security Review Requirements

For changes involving:
- Cryptographic operations
- Memory handling
- Authentication/authorization
- Key management

Ensure:
1. Code is constant-time where needed (use `subtle` crate)
2. Secrets are zeroized on drop (use `zeroize` crate)
3. Memory is locked when holding sensitive data
4. No timing side-channels

## Pull Request Process

1. **Fork** the repository
2. **Create a feature branch** from `main`
3. **Make your changes** following the guidelines above
4. **Write tests** for new functionality
5. **Update documentation** if needed
6. **Run the full test suite** on both Windows and Linux
7. **Submit a pull request** with:
   - Clear title describing the change
   - Description of what and why
   - Reference to any related issues

### PR Requirements

- **All commits must be signed off (DCO)**
- All CI checks must pass
- Tests must pass on all platforms
- No decrease in code coverage
- Documentation for new public APIs
- Changelog entry for user-facing changes

## Testing Policy

**Formal Requirement:** All new functionality MUST include corresponding tests in the automated test suite before it can be merged.

This policy applies to:
- New features and capabilities
- New public APIs and functions
- New cryptographic operations
- Bug fixes (regression tests required)
- Security-related changes (comprehensive test coverage required)

### Test Requirements for New Functionality

1. **Unit tests** - Test individual functions and modules in isolation
2. **Integration tests** - Test feature interactions where applicable
3. **Edge case coverage** - Test boundary conditions, error paths, and invalid inputs
4. **Security tests** - For crypto code, include tests against known test vectors (Wycheproof, NIST CAVP)

### Enforcement

- Pull requests without tests for new functionality will not be merged
- CI pipelines automatically verify test coverage does not decrease
- Reviewers will verify appropriate test coverage before approval

## Running Tests

### Unit Tests

```bash
cargo test --lib
```

### Cryptographic Validation

```bash
cargo test --test wycheproof_tests
```

### Formal Verification (Linux only)

```bash
cargo kani --lib --harness verify_nonce_len
```

### Security Audit

```bash
cargo audit
cargo deny check
```

## Reporting Bugs

Use GitHub Issues with:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Rust version)
- Relevant error messages or logs

## Reporting Security Vulnerabilities

**Do NOT report security vulnerabilities through public GitHub issues.**

See [SECURITY.md](SECURITY.md) for vulnerability reporting procedures.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
