# Memory Scrubbing Best Practices

This document provides guidelines for securely handling sensitive data in memory using Secure Cryptor's memory scrubbing utilities.

## Overview

Memory scrubbing (also called memory wiping or sanitization) is the process of securely overwriting sensitive data in RAM before it's deallocated. This prevents:

- **Memory dumps** from exposing secrets
- **Cold boot attacks** from recovering data from RAM
- **Accidental leaks** via core dumps or crash reports
- **Side-channel attacks** that analyze memory access patterns

## Available Tools

Secure Cryptor provides multiple levels of memory protection:

### 1. Automatic Zeroization

The simplest and most common approach - using types that automatically zero themselves on drop:

```rust
use zeroize::Zeroizing;

fn process_key() {
    let key = Zeroizing::new([0u8; 32]);
    // Key is automatically zeroed when it goes out of scope
}
```

**When to use:**
- Cryptographic keys
- Passwords and passphrases
- Authentication tokens
- Any secret that should be automatically cleaned up

### 2. Manual Scrubbing

Explicit scrubbing for more control:

```rust
use secure_cryptor::memory::scrub::scrub_bytes;

fn process_data() {
    let mut sensitive_data = vec![0x42; 1024];

    // ... use the data ...

    // Explicitly scrub before returning
    scrub_bytes(&mut sensitive_data);
}
```

**When to use:**
- Large buffers that need explicit cleanup timing
- Data that outlives its containing scope
- Conditional scrubbing based on security level

### 3. Multi-Pass Scrubbing

For high-security contexts requiring defense-in-depth:

```rust
use secure_cryptor::memory::scrub::{scrub_bytes_pattern, ScrubPattern};

fn high_security_cleanup(data: &mut [u8]) {
    // DoD 5220.22-M standard (3 passes)
    scrub_bytes_pattern(data, ScrubPattern::Dod522022M);

    // Or paranoid mode (7 passes)
    scrub_bytes_pattern(data, ScrubPattern::Paranoid);
}
```

**When to use:**
- Classified or highly sensitive data
- Compliance with specific standards (DoD, NIST)
- Defense against advanced memory forensics

### 4. Scrub Guards

RAII pattern for automatic scrubbing with early returns:

```rust
use secure_cryptor::memory::scrub::ScrubGuard;

fn process_with_early_return(password: Vec<u8>) -> Result<(), Error> {
    let _guard = ScrubGuard::new(password);

    if some_condition() {
        return Err(Error::Failed); // Guard scrubs automatically
    }

    // ... use _guard.as_ref() or _guard.as_mut() ...

    Ok(()) // Guard scrubs on success too
}
```

**When to use:**
- Functions with multiple return paths
- Error-prone code that might panic
- Ensuring cleanup even with early returns

## Scrubbing Patterns

### Available Patterns

| Pattern | Passes | Use Case | Performance |
|---------|--------|----------|-------------|
| `Zero` | 1 | Default - single zero pass | Fastest |
| `Ones` | 2 | Write 0xFF then zero | Fast |
| `NistSp80088` | 1 | NIST SP 800-88 compliance | Fast |
| `Dod522022M` | 4 | DoD 5220.22-M standard | Moderate |
| `Paranoid` | 7 | Maximum security | Slowest |
| `Custom(byte)` | 2 | Write custom pattern then zero | Fast |

### Performance Considerations

**RAM vs. Disk:** Modern RAM doesn't have data remanence like magnetic media. Multi-pass scrubbing provides marginal security benefit for RAM but significant compliance value.

**Benchmark results** (10MB buffer on typical workstation):
- Single-pass (Zero): ~5 ms
- DoD 5220.22-M: ~20 ms
- Paranoid (7-pass): ~35 ms

**Recommendation:** Use `Zero` or `NistSp80088` for most cases. Reserve multi-pass for compliance requirements or maximum security scenarios.

## Integration Patterns

### With LockedMemory

Combine scrubbing with memory locking for complete protection:

```rust
use secure_cryptor::memory::LockedMemory;
use secure_cryptor::memory::scrub::scrub_bytes;

fn handle_master_key(key_data: Vec<u8>) {
    let mut locked = LockedMemory::new(key_data).unwrap();

    // Memory is locked (won't swap to disk)
    // ... use the key ...

    // Explicitly scrub before drop
    scrub_bytes(&mut *locked);

    // Drop unlocks and LockedMemory also zeroizes
}
```

### With Encrypted Memory Pool

The encrypted memory pool automatically handles scrubbing:

```rust
use secure_cryptor::memory::pool::{EncryptedMemoryPool, SecurityLevel};

fn use_encrypted_pool() {
    let pool = EncryptedMemoryPool::new(SecurityLevel::High).unwrap();
    let mut allocation = pool.allocate(1024).unwrap();

    allocation.write(b"sensitive data").unwrap();

    // No manual scrubbing needed - automatic on drop
    // Encryption key, nonce, and data all zeroed
}
```

### Stack Scrubbing

For sensitive stack variables:

```rust
use secure_cryptor::scrub_stack_variable;

fn process_password(password: &str) {
    let mut password_copy = password.to_string();

    // ... process password ...

    // Scrub stack variable before return
    scrub_stack_variable!(password_copy);
}
```

## Common Pitfalls

### ❌ DON'T: Rely on Drop for Error Paths Without Guards

```rust
// BAD: If process_data panics, data won't be scrubbed
fn bad_example() {
    let mut sensitive = vec![0x42; 1024];
    process_data(&mut sensitive); // Could panic
    scrub_bytes(&mut sensitive); // Might not execute
}
```

### ✅ DO: Use ScrubGuard for Safety

```rust
// GOOD: ScrubGuard ensures cleanup even on panic
fn good_example() {
    let sensitive = vec![0x42; 1024];
    let mut guard = ScrubGuard::new(sensitive);
    process_data(guard.as_mut()); // Safe even if panics
    // Automatically scrubbed on drop
}
```

### ❌ DON'T: Forget About Copies

```rust
// BAD: Original data isn't scrubbed
fn bad_copy() {
    let original = vec![0x42; 256];
    let copy = original.clone(); // Now in two places!
    scrub_bytes(&copy); // Only scrubs the copy
    // Original still in memory!
}
```

### ✅ DO: Track All Copies

```rust
// GOOD: Scrub all copies
fn good_copy() {
    let mut original = vec![0x42; 256];
    let mut copy = original.clone();

    // ... use both ...

    scrub_bytes(&mut copy);
    scrub_bytes(&mut original);
}
```

### ❌ DON'T: Assume Compiler Won't Optimize Away

```rust
// BAD: Compiler might optimize this away
fn naive_scrub(data: &mut [u8]) {
    for byte in data {
        *byte = 0; // Might be optimized out as "dead store"
    }
}
```

### ✅ DO: Use Volatile Writes

```rust
// GOOD: Our scrub_bytes uses volatile writes + compiler fences
use secure_cryptor::memory::scrub::scrub_bytes;

fn proper_scrub(data: &mut [u8]) {
    scrub_bytes(data); // Won't be optimized away
}
```

## Verification

Always verify scrubbing in critical code:

```rust
use secure_cryptor::memory::scrub::{scrub_and_verify, ScrubPattern};

fn critical_cleanup(data: &mut [u8]) {
    let stats = scrub_and_verify(data, ScrubPattern::Dod522022M);

    if stats.verified != Some(true) {
        panic!("Memory scrubbing verification failed!");
    }
}
```

## Compliance Mapping

### NIST SP 800-88

**Guideline:** Single-pass overwrite sufficient for RAM sanitization.

```rust
use secure_cryptor::memory::scrub::{scrub_bytes_pattern, ScrubPattern};

// NIST compliant
scrub_bytes_pattern(data, ScrubPattern::NistSp80088);
```

### DoD 5220.22-M

**Standard:** 3-pass overwrite (0x00, 0xFF, random).

```rust
// DoD 5220.22-M compliant
scrub_bytes_pattern(data, ScrubPattern::Dod522022M);
```

### Common Criteria (EAL4+)

**Requirement:** Demonstrable secure deletion of sensitive data.

```rust
// Use verification for audit trail
let stats = scrub_and_verify(data, ScrubPattern::Dod522022M);
log_security_event("Memory scrubbed", stats);
```

## Performance Optimization

### Batch Scrubbing

Scrub multiple buffers efficiently:

```rust
use secure_cryptor::memory::scrub::scrub_multiple;

fn cleanup_session(keys: &mut [u8], tokens: &mut [u8], cache: &mut [u8]) {
    scrub_multiple(&mut [keys, tokens, cache]);
}
```

### Deferred Scrubbing

For performance-critical paths, defer scrubbing to cleanup phase:

```rust
struct Session {
    sensitive_buffers: Vec<Vec<u8>>,
}

impl Session {
    fn cleanup(&mut self) {
        for buffer in &mut self.sensitive_buffers {
            scrub_bytes(buffer);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cleanup();
    }
}
```

## Testing Memory Scrubbing

While you can't reliably test that memory was actually zeroed without forensics tools, you can:

1. **Test the interface:**
```rust
#[test]
fn test_scrubbing_interface() {
    let mut data = vec![0x42; 256];
    scrub_bytes(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}
```

2. **Verify non-optimization:**
```rust
#[test]
fn test_volatile_writes() {
    let mut data = vec![0xFF; 1024];
    // Multiple scrubs should all execute
    for _ in 0..10 {
        scrub_bytes(&mut data);
    }
    assert!(data.iter().all(|&b| b == 0));
}
```

3. **Use verification mode:**
```rust
#[test]
fn test_with_verification() {
    let mut data = vec![0x42; 512];
    let stats = scrub_and_verify(&mut data, ScrubPattern::Zero);
    assert_eq!(stats.verified, Some(true));
}
```

## Platform Memory Locking Limits

### ⚠️ Important: Linux mlock Limits

On Linux systems, the `mlock()` system call is used to prevent sensitive data from being swapped to disk. However, most Linux distributions impose default limits on how much memory a process can lock:

| Distribution | Default Limit | Configuration |
|--------------|---------------|---------------|
| Ubuntu/Debian | 64 KB | `/etc/security/limits.conf` |
| Fedora/RHEL | 64 KB | `/etc/security/limits.conf` |
| Arch Linux | 64 KB | `/etc/security/limits.conf` |
| Docker containers | Unlimited* | `--ulimit memlock=-1` |

*Docker defaults vary by configuration.

### What Happens When Limits Are Exceeded

When Tesseract's `LockedMemory::new()` exceeds the mlock limit, it returns an error. The `new_best_effort()` fallback will succeed but **without memory locking**, meaning sensitive data may be swapped to disk.

You'll see this warning in the console:
```
⚠ Warning: mlock limit exceeded. Sensitive data may be swapped to disk.
  Increase limit: ulimit -l unlimited (or /etc/security/limits.conf)
```

### How to Increase mlock Limits

#### Temporary (Current Session)

```bash
# Increase to unlimited (requires root or CAP_IPC_LOCK)
ulimit -l unlimited

# Or set a specific limit in KB
ulimit -l 1048576  # 1 GB
```

#### Permanent (System-Wide)

Edit `/etc/security/limits.conf`:

```
# Add these lines (replace 'username' with actual user or use '*' for all)
username    soft    memlock    unlimited
username    hard    memlock    unlimited

# Or for a specific group (e.g., 'crypto')
@crypto     soft    memlock    unlimited
@crypto     hard    memlock    unlimited
```

Then log out and back in for changes to take effect.

#### For systemd Services

Create or edit the service file:

```ini
[Service]
LimitMEMLOCK=infinity
# Or a specific value
LimitMEMLOCK=1073741824  # 1 GB in bytes
```

#### For Docker Containers

```bash
# Run with unlimited mlock
docker run --ulimit memlock=-1:-1 your-image

# Or in docker-compose.yml:
services:
  your-service:
    ulimits:
      memlock:
        soft: -1
        hard: -1
```

### Windows Memory Locking

On Windows, `VirtualLock()` is used instead. Windows generally allows locking up to the process's working set size, which is typically sufficient. No special configuration is usually required.

However, under memory pressure, Windows may still fail to lock memory. Tesseract handles this gracefully with warnings.

### Verifying mlock Is Working

```bash
# Check current limit
ulimit -l

# Monitor locked memory for a process
cat /proc/<PID>/status | grep VmLck

# Or use this Rust code to verify
use tesseract_lib::memory::LockedMemory;

fn main() {
    match LockedMemory::new([0u8; 1024]) {
        Ok(mem) => {
            assert!(mem.is_locked());
            println!("✓ Memory locking is working");
        }
        Err(e) => {
            eprintln!("✗ Memory locking failed: {}", e);
            eprintln!("  Run: ulimit -l unlimited");
        }
    }
}
```

### Security Implications

When mlock fails and `new_best_effort()` is used:

| Risk | Description | Mitigation |
|------|-------------|------------|
| Swap exposure | Keys may be written to swap file | Disable swap or use encrypted swap |
| Hibernation | Keys may appear in hibernation image | Disable hibernation for high-security |
| Core dumps | Keys may appear in crash dumps | Disable or encrypt core dumps |
| Cold boot | RAM contents persist briefly after shutdown | Use memory encryption (TME/SME) |

**Recommendation**: For production security-critical deployments, always configure adequate mlock limits and verify they're working before processing sensitive data.

## Advanced: `memfd_secret()` for Kernel-Isolated Memory

### What is memfd_secret?

On Linux 5.14+, Tesseract provides `SecretMemory<T>` which uses the `memfd_secret()` syscall to create memory that is **completely isolated from the kernel**. Unlike `mlock()` which only prevents swapping, `memfd_secret()` removes pages from the kernel's direct map entirely.

### Security Properties

| Feature | mlock() | memfd_secret() |
|---------|---------|----------------|
| Prevents swap | ✓ | ✓ |
| Hidden from /proc/pid/mem | ✗ | ✓ |
| Hidden from kernel | ✗ | ✓ |
| Protection against kernel exploits | ✗ | ✓ |
| ROP attack resistance | Limited | Strong |

### When to Use SecretMemory

Use `SecretMemory<T>` instead of `LockedMemory<T>` for:
- Long-lived cryptographic keys
- Master secrets and root keys
- Highly sensitive credentials
- Memory that should survive kernel compromise

### Platform Availability

| Kernel Version | Availability |
|----------------|--------------|
| Linux 6.5+ | Enabled by default |
| Linux 5.14-6.4 | Requires `secretmem.enable=y` boot parameter |
| Linux < 5.14 | Falls back to `mlock()` |
| Windows | Falls back to `VirtualLock()` |

### Usage Example

```rust
use tesseract_lib::memory::secret::{SecretMemory, ProtectionLevel};

// Create secret memory for a 32-byte key
let (secret, level) = SecretMemory::new_best_effort([0u8; 32]);

match level {
    ProtectionLevel::MemfdSecret => {
        println!("✓ Kernel-isolated memory (strongest protection)");
    }
    ProtectionLevel::Mlocked => {
        println!("⚠ Using mlock fallback (swap-protected only)");
    }
    ProtectionLevel::None => {
        eprintln!("✗ No memory protection available!");
    }
}

// Check if memfd_secret is available before creating secrets
if tesseract_lib::memory::secret::is_memfd_secret_available() {
    let secret = SecretMemory::new([0u8; 32])
        .expect("memfd_secret should work");
    assert!(secret.protection_level().is_secret());
}
```

### Enabling memfd_secret on Linux 5.14-6.4

If your kernel is between 5.14 and 6.4, you need to enable the feature explicitly:

```bash
# Add to kernel boot parameters (GRUB example)
# Edit /etc/default/grub:
GRUB_CMDLINE_LINUX="secretmem.enable=y"

# Then update and reboot:
sudo update-grub
sudo reboot

# Verify it's enabled
cat /proc/cmdline | grep secretmem
```

### Checking Your Protection Level

```rust
use tesseract_lib::memory::secret::is_memfd_secret_available;

fn main() {
    println!("memfd_secret available: {}", is_memfd_secret_available());

    // This result is cached after the first call
}
```

---

## CPU Side-Channel Attacks (Spectre/Meltdown)

### Known Limitation

**Memory protection mechanisms like `mlock()`, `memfd_secret()`, and encryption-at-rest do NOT protect against CPU speculative execution attacks.**

This is a fundamental hardware architecture limitation that cannot be fully mitigated in software. Sensitive data in CPU cache or registers may be vulnerable to:

- **Spectre** (CVE-2017-5753, CVE-2017-5715): Exploits branch prediction to leak data
- **Meltdown** (CVE-2017-5754): Exploits out-of-order execution to read kernel memory
- **Spectre-NG variants**: L1TF, RIDL, Fallout, ZombieLoad, etc.

### What This Means for Tesseract

| Protection | Protects Against | Does NOT Protect Against |
|------------|------------------|--------------------------|
| `LockedMemory` | Swap/hibernation | Cache side-channels |
| `SecretMemory` | Kernel access, /proc | Speculative execution |
| `EncryptedMemoryPool` | RAM forensics | CPU-level attacks |
| Zeroization | Post-use disclosure | In-use cache access |

### Mitigations (Hardware/OS Level)

These attacks are primarily mitigated at the hardware and OS level:

1. **CPU Microcode Updates**: Install latest microcode from Intel/AMD
2. **Kernel KPTI**: Kernel Page Table Isolation (enabled by default on modern kernels)
3. **Retpolines**: Compiler mitigations for indirect branch speculation
4. **IBRS/IBPB/STIBP**: Hardware speculation barriers

To check your system's vulnerability status on Linux:
```bash
# Check for known vulnerabilities
cat /sys/devices/system/cpu/vulnerabilities/*

# Example output (mitigated system):
# spectre_v1: Mitigation: usercopy/swapgs barriers and __user pointer sanitization
# spectre_v2: Mitigation: Retpolines; IBPB: conditional; IBRS_FW; STIBP: conditional
# meltdown: Mitigation: PTI
```

### Hardware Memory Encryption

For defense-in-depth against physical and cache attacks, consider:

| Technology | Vendor | Protection |
|------------|--------|------------|
| Intel TME | Intel | Full memory encryption (transparent) |
| Intel MKTME | Intel | Multi-key memory encryption |
| AMD SME | AMD | Secure Memory Encryption |
| AMD SEV | AMD | Secure Encrypted Virtualization |

Tesseract's `memory::tme` module provides TME/SME detection:
```rust
use tesseract_lib::memory::tme::{is_tme_available, is_sme_available};

fn check_hardware_encryption() {
    if is_tme_available() {
        println!("Intel TME available - memory is hardware-encrypted");
    } else if is_sme_available() {
        println!("AMD SME available - memory is hardware-encrypted");
    } else {
        println!("No hardware memory encryption detected");
    }
}
```

### Practical Security Guidance

For high-security deployments:

1. **Keep systems updated**: Microcode, kernel, and compiler updates address new variants
2. **Use hardware encryption**: Enable TME/SME where available
3. **Minimize secret lifetime**: Keys in memory for shortest time possible
4. **Isolate sensitive operations**: Run on dedicated cores if possible (CPU pinning)
5. **Consider SGX/TDX**: Intel enclaves provide stronger isolation (separate attack surface)

### Threat Model Implications

When speculative execution attacks are in your threat model:

| Attack Scenario | Mitigation |
|-----------------|------------|
| Untrusted code on same machine | OS-level isolation, containers with seccomp |
| VM co-tenancy (cloud) | Use dedicated hosts or AMD SEV/Intel TDX |
| Physical access | Full disk encryption + TPM + measured boot |
| Malicious kernel module | Secure Boot, kernel lockdown |

**Tesseract's Position**: We implement all software-level protections available, but acknowledge that speculative execution attacks require hardware/OS mitigations. This is consistent with all major cryptographic libraries.

---

## When to Use Each Memory Protection

Tesseract provides multiple memory protection mechanisms. Choose based on your security requirements:

### Quick Reference

| Mechanism | Protection Level | Use Case | Overhead |
|-----------|------------------|----------|----------|
| `Zeroizing<T>` | Basic | General sensitive data | Minimal |
| `LockedMemory<T>` | Moderate | Keys, tokens | Low |
| `SecretMemory<T>` | **Highest** | Master keys, long-lived secrets | Low |
| `EncryptedMemoryPool` | Defense-in-depth | Multi-tenant, forensics protection | Moderate |

### Decision Tree

```
                    Is this sensitive data?
                           │
                   ┌───────┴───────┐
                   │               │
                  Yes              No → Use regular types
                   │
         ┌─────────┴─────────┐
         │                   │
    Short-lived         Long-lived
    (temporary)         (persistent)
         │                   │
    Zeroizing<T>     ┌───────┴───────┐
                     │               │
              On Linux 5.14+    Elsewhere
                     │               │
              SecretMemory     LockedMemory
              (memfd_secret)   (mlock fallback)
                     │
         Need additional protection?
         (defense-in-depth, forensics)
                     │
             ┌───────┴───────┐
             │               │
            Yes              No
             │               │
    EncryptedMemoryPool    Done
    + SecretMemory
```

### Detailed Comparison

#### `SecretMemory<T>` (Recommended for maximum security)

**Best for:**
- Master encryption keys
- Root credentials
- Long-lived cryptographic material
- Secrets that must survive kernel compromise

**Advantages:**
- Kernel-isolated (invisible to `/proc/pid/mem`)
- Strongest software protection available
- Automatic fallback to mlock on unsupported systems

**Limitations:**
- Linux 5.14+ only (falls back to mlock elsewhere)
- Requires `secretmem.enable=y` on kernels 5.14-6.4

```rust
use tesseract_lib::memory::secret::SecretMemory;

// Automatically uses memfd_secret on Linux 5.14+
let (key, level) = SecretMemory::new_best_effort([0u8; 32]);
```

#### `EncryptedMemoryPool` (Defense-in-depth)

**Best for:**
- Multi-tenant environments
- Protection against memory scanning
- Compliance with encryption-at-rest requirements
- Defense-in-depth layering

**Advantages:**
- Data encrypted with ChaCha20 while in RAM
- Fresh nonce per write (CWE-329 compliant)
- Configurable security levels

**Limitations:**
- Pool encryption key is in regular memory (not mlocked)
- Performance overhead from encrypt/decrypt operations
- Does not provide kernel-level isolation

**Recommendation:** Prefer `SecretMemory<T>` for the pool's encryption key, or use `SecretMemory<T>` directly for secrets. Use `EncryptedMemoryPool` as an additional layer, not a primary protection.

```rust
use tesseract_lib::memory::pool::{EncryptedMemoryPool, SecurityLevel};

// Use High or Maximum for memory locking + encryption
let pool = EncryptedMemoryPool::new(SecurityLevel::High)?;
let mut alloc = pool.allocate(1024)?;
alloc.write(b"protected data")?;
```

#### Combining Protections

For maximum security, layer protections:

```rust
use tesseract_lib::memory::secret::SecretMemory;
use tesseract_lib::memory::pool::{EncryptedMemoryPool, SecurityLevel};

// 1. Use SecretMemory for the most sensitive items
let (master_key, _) = SecretMemory::new_best_effort([0u8; 32]);

// 2. Use EncryptedMemoryPool for bulk sensitive data
let pool = EncryptedMemoryPool::new(SecurityLevel::Maximum)?;

// 3. Use LockedMemory for medium-sensitivity items
let (session_key, _) = LockedMemory::new_best_effort([0u8; 32]);
```

### Security Comparison

| Threat | Zeroizing | LockedMemory | SecretMemory | EncryptedPool |
|--------|-----------|--------------|--------------|---------------|
| Post-use disclosure | ✓ | ✓ | ✓ | ✓ |
| Swap to disk | ✗ | ✓ | ✓ | ✓* |
| Hibernation | ✗ | ✓ | ✓ | ✓* |
| Memory dump | ✗ | ✗ | ✓ | ✓ (encrypted) |
| /proc/pid/mem read | ✗ | ✗ | ✓ | ✗ |
| Kernel exploit | ✗ | ✗ | ✓ | ✗ |
| Memory scanner (user) | ✗ | ✗ | ✓ | ✓ (encrypted) |
| Spectre/Meltdown | ✗ | ✗ | ✗ | ✗ |

*With High/Maximum security level

---

## Summary

**Default Choice:**
- Use `Zeroizing<T>` for automatic scrubbing
- Use `scrub_bytes()` for explicit control
- Use `ScrubGuard` for error-prone code

**High Security:**
- Combine `LockedMemory` + scrubbing
- Use `EncryptedMemoryPool` for encrypted-at-rest
- Apply multi-pass patterns (DoD, Paranoid)

**Compliance:**
- NIST SP 800-88: `ScrubPattern::NistSp80088`
- DoD 5220.22-M: `ScrubPattern::Dod522022M`
- Custom standards: `ScrubPattern::Custom(byte)`

**Always:**
- Track all copies of sensitive data
- Use guards for panic safety
- Verify in critical code paths
- Test scrubbing interfaces

## Flash Memory Limitations

### Important Warning: SSDs and Flash Storage

Memory scrubbing is highly effective for RAM but has **significant limitations** when data has been written to flash-based storage (SSDs, NVMe drives, USB flash drives, SD cards, eMMC).

### Why Flash Storage is Different

Unlike RAM, flash memory has unique characteristics that make secure erasure challenging:

1. **Wear Leveling**: Flash controllers spread writes across cells to extend drive life. When you "overwrite" a sector, the controller may write to a new physical location, leaving the old data intact.

2. **Over-Provisioning**: SSDs reserve 7-28% of capacity for wear leveling and bad block replacement. This hidden space is inaccessible to the OS but may contain old data.

3. **Write Amplification**: A single logical write may result in multiple physical writes, creating multiple copies of sensitive data.

4. **Garbage Collection**: The flash controller decides when to actually erase blocks, which happens asynchronously and outside user control.

5. **TRIM Limitations**: While TRIM marks blocks as unused, it doesn't guarantee immediate or secure erasure. Some controllers delay or batch TRIM operations.

### Implications for Secure Cryptor

| Scenario | RAM Scrubbing | Flash Scrubbing |
|----------|---------------|-----------------|
| In-memory keys | ✅ Effective | N/A |
| Swap file on SSD | ⚠️ Limited | ⚠️ Limited |
| Volume file on SSD | ❌ Cannot guarantee | ❌ Cannot guarantee |
| Temporary files on SSD | ❌ Cannot guarantee | ❌ Cannot guarantee |

### Mitigations

#### 1. Disable Swap (Recommended for High Security)

Prevent sensitive data from being written to disk swap:

```rust
// Already implemented in LockedMemory
use secure_cryptor::memory::LockedMemory;
let locked = LockedMemory::new(sensitive_data)?; // Prevents swapping
```

On Linux:
```bash
sudo swapoff -a  # Temporary
# Or edit /etc/fstab to disable permanently
```

On Windows:
```powershell
# Disable page file (requires admin and reboot)
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset delete
```

#### 2. Use Encrypted Swap

If swap is required, enable encrypted swap:

- **Linux**: Use dm-crypt for swap encryption
- **Windows**: Enable BitLocker with swap encryption
- **macOS**: Encrypted swap is enabled by default with FileVault

#### 3. Full Disk Encryption

For volume files stored on flash:
- Use full disk encryption (BitLocker, LUKS, FileVault)
- When you delete the volume file, the encrypted data remains but is cryptographically inaccessible
- Rotate the FDE key if maximum security is required

#### 4. Hardware Secure Erase

For SSD decommissioning, use the drive's built-in secure erase:

```bash
# Linux (requires hdparm and drive support)
hdparm --user-master u --security-set-pass password /dev/sdX
hdparm --user-master u --security-erase password /dev/sdX
```

**Warning**: This erases the entire drive. Not suitable for individual file deletion.

#### 5. Use RAM Disk for Sensitive Operations

For maximum security, operate entirely in RAM:

```bash
# Linux: Create RAM disk
mount -t tmpfs -o size=512M,mode=700 tmpfs /secure_workspace

# Windows: Use third-party RAM disk software
# Or use Secure Cryptor's in-memory volume mode
```

### What Secure Cryptor Does

1. **Memory Locking**: Prevents sensitive data from being swapped to disk
2. **RAM Scrubbing**: Securely erases in-memory data using volatile writes
3. **Encrypted Memory Pool**: Encrypts sensitive data even while in RAM
4. **Minimal Disk Writes**: Key material never intentionally written to disk

### What Secure Cryptor Cannot Do

1. **Retroactive SSD Erasure**: Cannot securely erase data already written to flash
2. **Control Wear Leveling**: Cannot access SSD's internal block management
3. **Guarantee TRIM**: Cannot force immediate secure erasure via TRIM
4. **Access Over-Provisioned Space**: Cannot reach hidden SSD capacity

### Recommendations by Security Level

| Level | Storage | Swap | Additional |
|-------|---------|------|------------|
| Standard | Any | Encrypted | Use LockedMemory |
| High | HDD preferred | Disabled | FDE + memory locking |
| Maximum | RAM only | Disabled | Air-gapped + RAM disk |
| Decommission | N/A | N/A | Crypto shredding or physical destruction |

### Crypto Shredding

The most reliable method for flash storage is **crypto shredding**:

1. All data is encrypted with a master key
2. The master key is stored only in RAM (never on flash)
3. To "delete" data, simply destroy the master key
4. The encrypted data on flash is now cryptographically inaccessible

Secure Cryptor implements this pattern:
- Volume master keys are never written to disk unencrypted
- Key slots use Argon2id with high memory cost to derive keys
- Destroying the password/key makes volume data irrecoverable

### References

- NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
- Secure Deletion of Data from Magnetic and Solid-State Memory (IEEE S&P 2003)
- Reliably Erasing Data From Flash-Based Solid State Drives (USENIX FAST 2011)
