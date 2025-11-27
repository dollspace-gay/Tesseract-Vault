# Formal Verification Tools for Rust: Comparative Analysis

## Executive Summary

This document evaluates three leading formal verification tools for Rust: Prusti (ETH Zurich), Kani (Amazon), and Creusot (Inria). The analysis focuses on their suitability for verifying cryptographic primitives (AES-GCM, Argon2id, XTS-AES) in the Tesseract Vault encryption suite.

**Recommendation**: **Kani** is the recommended primary tool, with **Prusti** as a complementary tool for contract-based verification.

## Tool Comparison

### 1. Kani Rust Verifier (Amazon)

**Developer**: Amazon Web Services
**Approach**: Bounded model checking
**Status**: Active development, production use at AWS (2024-2025)

#### Strengths
- **Bit-precise verification**: Exact modeling of low-level operations critical for cryptography
- **Production-proven**: Used in AWS Firecracker and s2n-quic security-critical projects
- **Undefined behavior detection**: Automatically checks for memory safety violations
- **Unsafe code support**: Specifically designed to verify unsafe blocks where compiler guarantees don't apply
- **Active community**: Major 2024 initiative verifying Rust standard library (35K functions, 7.5K unsafe)
- **Integration**: Works seamlessly with Cargo build system
- **No annotation overhead**: Can verify existing code without extensive modifications

#### Limitations
- **Bounded verification**: Must specify bounds for loops and recursion
- **State explosion**: Complex data structures can lead to verification timeouts
- **Limited abstraction**: Less support for high-level mathematical reasoning

#### Cryptographic Verification Capability
- Excellent for verifying implementation-level properties (no buffer overflows, correct byte operations)
- Can verify absence of undefined behavior in crypto implementations
- Strong support for verifying unsafe code blocks common in optimized crypto
- Successfully used for verifying side-channel resistance properties

#### Best Use Cases
- Verifying memory safety in crypto implementations
- Checking unsafe code blocks in AES-GCM, XTS-AES implementations
- Proving absence of panics and integer overflows
- Validating security boundaries in volume encryption

### 2. Prusti (ETH Zurich)

**Developer**: ETH Zurich Programming Methodology Group
**Approach**: Deductive verification via Viper intermediate language
**Status**: Active research project with IDE support

#### Strengths
- **Expressive specifications**: Rich specification language for pre/post-conditions and invariants
- **Type-system integration**: Leverages Rust's ownership for verification
- **Modular verification**: Compositional reasoning for large codebases
- **Prophecy variables**: Advanced feature for reasoning about mutable state
- **IDE integration**: Visual Studio Code "Prusti Assistant" extension
- **Modest annotation overhead**: Efficient specification syntax

#### Limitations
- **Research maturity**: Less production deployment than Kani
- **Specification burden**: Requires writing formal specifications
- **Trait system complexity**: Advanced features may have learning curve
- **Limited crypto-specific examples**: No documented crypto primitive verifications

#### Cryptographic Verification Capability
- Strong support for algorithmic correctness properties
- Can specify and verify complex invariants in key derivation functions
- Suitable for high-level security properties (key confidentiality, authentication)
- Less suited for low-level bit manipulation verification

#### Best Use Cases
- Verifying Argon2id KDF correctness properties
- Proving key derivation security properties
- Contract-based verification of high-level crypto APIs
- Ensuring ownership-based security guarantees

### 3. Creusot (Inria)

**Developer**: Inria Toccata team (Université Paris-Saclay, CNRS)
**Approach**: Deductive verification via Why3 proof assistant
**Status**: Active research, ICFEM 2022 publication

#### Strengths
- **Why3 integration**: Access to mature proof infrastructure and SMT solvers
- **Prophecy support**: Novel approach to reasoning about mutation and ownership
- **Trait-based abstraction**: Advanced abstraction features via Rust traits
- **Academic rigor**: Strong theoretical foundations

#### Limitations
- **Research tool**: Less production adoption than Kani or Prusti
- **Manual proof effort**: Why3 may require interactive proof for complex properties
- **Smaller community**: Fewer examples and less documentation
- **Specification complexity**: Steeper learning curve for Why3 integration

#### Cryptographic Verification Capability
- Capable of deep mathematical reasoning about algorithms
- Can leverage Why3's proven crypto verification capabilities
- Suitable for proving correctness of crypto protocols
- Requires significant expertise in proof assistants

#### Best Use Cases
- Deep mathematical verification of crypto algorithms
- Proving algorithmic correctness theorems
- Research-level security proofs
- Protocol-level verification

## Comparative Matrix

| Feature | Kani | Prusti | Creusot |
|---------|------|--------|---------|
| **Maturity** | Production | Research+ | Research |
| **Learning Curve** | Low | Medium | High |
| **Annotation Overhead** | None-Low | Medium | Medium-High |
| **Bit-level Precision** | Excellent | Good | Good |
| **Unsafe Code** | Excellent | Good | Good |
| **Automation** | High | High | Medium |
| **Proof Complexity** | Low | Medium | High |
| **IDE Support** | VS Code | VS Code | Limited |
| **Community** | Large | Medium | Small |
| **Crypto Focus** | Implicit | Explicit | Explicit |
| **AWS/Industry Use** | Yes | No | No |

## Recommendation for Tesseract Vault

### Primary Tool: Kani

**Rationale**:
1. **Immediate value**: Can verify existing code without extensive refactoring
2. **Critical properties**: Excellent for memory safety and undefined behavior in crypto
3. **Unsafe code**: Tesseract Vault uses unsafe blocks in performance-critical paths
4. **Production confidence**: AWS production use demonstrates reliability
5. **Low barrier**: Minimal annotation burden enables rapid deployment
6. **Active development**: 2024 Rust stdlib verification shows strong momentum

**Implementation Plan**:
- Phase 1: Verify memory safety in AES-GCM and XTS-AES implementations
- Phase 2: Check all unsafe blocks for undefined behavior
- Phase 3: Verify Argon2id for integer overflows and panics
- Phase 4: Validate VolumeIOFilesystem operations
- Phase 5: Continuous verification in CI/CD pipeline

### Complementary Tool: Prusti

**Rationale**:
1. **High-level properties**: Can specify security invariants (key zeroization, access control)
2. **Contract verification**: Validate public API contracts
3. **Ownership guarantees**: Prove security through Rust's type system
4. **Future-proofing**: Academic backing ensures long-term development

**Implementation Plan**:
- Phase 1: Specify contracts for key derivation functions
- Phase 2: Verify master key handling invariants
- Phase 3: Prove access control properties in VolumeManager
- Phase 4: Document security properties as Prusti specifications

### Not Recommended: Creusot

**Rationale**:
- Requires Why3 expertise (significant learning curve)
- Smaller community and less documentation
- Manual proof burden impractical for CI/CD integration
- Kani + Prusti combination covers use cases adequately

## Tool Selection Decision

**Selected**: **Kani** (primary) + **Prusti** (complementary)

### Kani Justification
- Zero-overhead verification of existing unsafe crypto code
- Production-proven at AWS in security-critical contexts
- Automatic detection of undefined behavior
- Bit-precise reasoning essential for crypto correctness
- Large community and active 2024-2025 development

### Prusti Justification
- Complements Kani with high-level correctness properties
- Specification language suitable for security invariants
- Modular verification for large codebase
- IDE integration improves developer experience
- Academic rigor without Why3 complexity

### Integration Strategy
1. **Development workflow**: Kani runs on every build to catch UB
2. **API contracts**: Prusti specifications document security guarantees
3. **CI pipeline**: Both tools run in verification stage
4. **Incremental adoption**: Start with critical modules (crypto core)
5. **Documentation**: Specifications serve as formal documentation

## Next Steps

1. **Install Kani**: `cargo install --locked kani-verifier`
2. **Install Prusti**: Via VS Code extension or cargo-prusti
3. **Pilot verification**: Select one crypto module (recommend AES-GCM)
4. **Write harnesses**: Create Kani proof harnesses for critical functions
5. **Add specifications**: Write Prusti contracts for public APIs
6. **CI integration**: Add verification to GitHub Actions workflow
7. **Document findings**: Track verification coverage and discovered issues

## References

### Kani
- [AWS Blog: How Open Source Projects are Using Kani](https://aws.amazon.com/blogs/opensource/how-open-source-projects-are-using-kani-to-write-better-software-in-rust/)
- [AWS Blog: Verify the Safety of the Rust Standard Library](https://aws.amazon.com/blogs/opensource/verify-the-safety-of-the-rust-standard-library/)
- [Kani GitHub Repository](https://github.com/model-checking/kani)
- [Getting Started - The Kani Rust Verifier](https://model-checking.github.io/kani/)
- [Rust Formal Methods Interest Group](https://rust-formal-methods.github.io/)

### Prusti
- [Prusti Project - ETH Zurich](https://www.pm.inf.ethz.ch/research/prusti.html)
- [The Prusti Project: Formal Verification for Rust (SpringerLink)](https://link.springer.com/chapter/10.1007/978-3-031-06773-0_5)
- [Prusti GitHub Repository](https://github.com/viperproject/prusti-dev)
- [The Prusti Project Paper (PDF)](https://pm.inf.ethz.ch/publications/AstrauskasBilyFialaGrannanMathejaMuellerPoliSummers22.pdf)

### Creusot
- [Creusot: A Foundry for the Deductive Verification of Rust Programs (Inria)](https://inria.hal.science/hal-03737878)
- [Program safely in Rust with the Why3 proof assistant (Inria)](https://www.inria.fr/en/digital-security-rust-proof-assistant-why3)
- [Creusot: A Foundry for the Deductive Verification of Rust Programs (SpringerLink)](https://link.springer.com/chapter/10.1007/978-3-031-17244-1_6)

---

**Document Version**: 1.0
**Date**: 2025-11-27
**Author**: Analysis for Tesseract Vault Formal Verification Initiative
**Status**: Tool selection complete - proceed to setup phase
