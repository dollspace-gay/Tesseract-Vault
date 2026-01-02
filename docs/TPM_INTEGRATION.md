# TPM 2.0 Integration Guide

This document describes Tesseract Vault's integration with TPM 2.0 (Trusted Platform Module) hardware security modules.

## Overview

Tesseract Vault supports TPM 2.0 for hardware-backed key protection. Keys can be sealed to the TPM with policies that bind them to specific Platform Configuration Register (PCR) measurements, ensuring keys are only accessible when the system is in a known trusted state.

## Features

- **Key sealing/unsealing** with PCR binding
- **Hardware random number generation** from TPM RNG
- **Platform integrity verification** via PCR reading
- **Cross-platform support**: Windows (TBS) and Linux (`/dev/tpm0`)

## Platform Support

| Platform | TPM Access Method | Status |
|----------|------------------|--------|
| Windows 10/11 | TBS (TPM Base Services) | Supported |
| Linux | `/dev/tpm0` or `/dev/tpmrm0` | Supported |
| macOS | N/A | Not supported (no TPM) |

## Architecture

### Core Types

```rust
// TPM 2.0 device handle
pub struct Tpm2Device {
    available: bool,
    capabilities: Option<TpmCapabilities>,
}

// PCR indices (0-23)
pub enum PcrIndex {
    Pcr0,  // SRTM, BIOS, Host Platform Extensions
    Pcr1,  // Host Platform Configuration
    Pcr2,  // UEFI driver and application Code
    Pcr3,  // UEFI driver and application Configuration
    Pcr4,  // UEFI Boot Manager Code
    Pcr5,  // UEFI Boot Manager Configuration
    Pcr6,  // Host Platform Manufacturer Specific
    Pcr7,  // Secure Boot State
    // Pcr8-15: Used by OS
    // Pcr16-23: Debug and application use
}

// Key sealing policy
pub struct TpmKeyPolicy {
    pub pcr_selection: Vec<PcrIndex>,
    pub hash_algorithm: TpmHashAlgorithm,
    pub auth_value: Option<Zeroizing<Vec<u8>>>,
    pub pcr_policy: bool,
}

// Sealed key blob (storable)
pub struct SealedKeyBlob {
    pub data: Vec<u8>,
    pub policy_digest: Vec<u8>,
    pub pcr_values: Vec<(PcrIndex, Vec<u8>)>,
    pub hash_algorithm: TpmHashAlgorithm,
}
```

### Hash Algorithms

| Algorithm | Digest Size | Recommendation |
|-----------|-------------|----------------|
| SHA-1 | 20 bytes | Legacy, not recommended |
| SHA-256 | 32 bytes | **Recommended** (default) |
| SHA-384 | 48 bytes | Supported |
| SHA-512 | 64 bytes | Supported |

## Usage

### Basic Operations

```rust
use tesseract_lib::hsm::tpm::{Tpm2Device, TpmKeyPolicy};

// Open TPM device
let tpm = Tpm2Device::open()?;

// Check if TPM is available
if !tpm.is_ready() {
    println!("TPM not available");
    return;
}

// Get TPM capabilities
if let Some(caps) = tpm.capabilities() {
    println!("TPM: {} v{}", caps.manufacturer, caps.firmware_version);
}
```

### Key Sealing

Seal a key to the current PCR state:

```rust
// Default policy: bind to PCR 0 and PCR 7
let policy = TpmKeyPolicy::default();
let sealed = tpm.seal_key(b"my_secret_key", &policy)?;

// Store sealed blob (safe to persist to disk)
let json = serde_json::to_string(&sealed)?;
std::fs::write("sealed_key.json", json)?;
```

### Key Unsealing

Unseal a previously sealed key (fails if PCR values changed):

```rust
// Load sealed blob
let json = std::fs::read_to_string("sealed_key.json")?;
let sealed: SealedKeyBlob = serde_json::from_str(&json)?;

// Unseal (will fail if boot state changed)
match tpm.unseal_key(&sealed) {
    Ok(key) => {
        // Use the key
        println!("Key unsealed successfully");
    }
    Err(e) => {
        println!("Unseal failed: {}", e);
        // PCR values may have changed (firmware update, etc.)
    }
}
```

### Predefined Policies

```rust
// Password-only (no PCR binding)
let policy = TpmKeyPolicy::password_only(b"my_password");

// Secure Boot state only (PCR 7)
let policy = TpmKeyPolicy::secure_boot();

// Full boot chain (PCR 0-7)
let policy = TpmKeyPolicy::full_boot_chain();
```

### Hardware Random Numbers

```rust
// Get 32 random bytes from TPM RNG
let random_bytes = tpm.get_random(32)?;
```

### PCR Reading

```rust
use tesseract_lib::hsm::tpm::{PcrIndex, TpmHashAlgorithm};

// Read a single PCR
let pcr7 = tpm.read_pcr(PcrIndex::Pcr7, TpmHashAlgorithm::Sha256)?;
println!("PCR 7: {}", hex::encode(&pcr7));

// Read multiple PCRs
let pcrs = tpm.read_pcrs(
    &[PcrIndex::Pcr0, PcrIndex::Pcr7],
    TpmHashAlgorithm::Sha256
)?;
```

## Platform Configuration Registers (PCRs)

PCRs measure different aspects of the boot process:

| PCR | Description | When to Use |
|-----|-------------|-------------|
| 0 | SRTM, BIOS, Option ROMs | Firmware updates will change this |
| 1 | Host Platform Configuration | Platform config changes |
| 2 | UEFI driver/app Code | Driver updates |
| 3 | UEFI driver/app Config | Driver config changes |
| 4 | Boot Manager Code | Bootloader updates |
| 5 | Boot Manager Config | Boot order changes |
| 6 | Manufacturer Specific | Vendor-specific measurements |
| 7 | Secure Boot State | Secure Boot enable/disable |
| 8-15 | OS-controlled | Linux IMA, BitLocker, etc. |
| 16-23 | Debug/Application | Application-specific |

### Recommended PCR Selections

| Use Case | PCRs | Notes |
|----------|------|-------|
| Auto-unlock | 0, 7 | Breaks on firmware or Secure Boot changes |
| High security | 0-7 | Breaks on any boot component change |
| Secure Boot only | 7 | Only Secure Boot state changes break it |
| Password-only | None | No PCR binding, just TPM-backed encryption |

## LUKS Integration

Tesseract provides `tesseract-luks` for integrating TPM with Linux full disk encryption:

```bash
# Create a Tesseract-protected keyfile
tesseract-luks create /etc/tesseract/root.keyfile

# Enroll TPM for passwordless boot
tesseract-luks enroll-tpm /etc/tesseract/root.keyfile --pcrs 0,7

# Unlock using TPM during boot
tesseract-luks unlock-tpm /etc/tesseract/root.keyfile | \
    cryptsetup open /dev/sda2 root --key-file -
```

## Error Handling

### Error Types

```rust
pub enum TpmError {
    DeviceNotFound,    // No TPM present
    DeviceDisabled,    // TPM disabled in BIOS
    AccessDenied,      // Permission error
    CommandFailed(String),  // TPM command error
    PcrMismatch,       // PCR values changed since sealing
    KeyNotFound,       // Key handle invalid
    InvalidHandle,     // Bad handle
    Lockout,           // TPM in lockout mode
    PlatformError(String),  // OS-specific error
}
```

### Recovery from PCR Mismatch

When `PcrMismatch` occurs:

1. **Firmware update**: The sealed key is permanently inaccessible. Use recovery key.
2. **Secure Boot change**: Re-enroll TPM after enabling/disabling Secure Boot.
3. **Boot order change**: Some PCR configurations are too strict. Use fewer PCRs.

## Security Considerations

### Key Protection

- Sealed keys never leave the TPM in plaintext
- TPM provides hardware-level protection against software attacks
- Keys are bound to specific system state via PCRs

### Limitations

- **Physical attacks**: TPM doesn't protect against hardware-level attacks
- **Firmware vulnerabilities**: Exploits before TPM measurements can bypass protection
- **Single point of failure**: If TPM is damaged, sealed keys are lost
- **Lockout**: Excessive failed authentications trigger TPM lockout

### Best Practices

1. **Always have recovery keys** stored securely offline
2. **Document PCR policy** so you know which updates will break unsealing
3. **Use password + PCR** for defense in depth
4. **Test after updates** before relying on TPM auto-unlock
5. **Monitor PCR values** to detect unexpected changes

## Windows-Specific Notes

### TPM Base Services (TBS)

Tesseract uses the Windows TBS API:

```rust
// TBS functions used
Tbsi_Context_Create()   // Open TPM context
Tbsip_Submit_Command()  // Send TPM commands
Tbsip_Context_Close()   // Close context
```

### Requirements

- Windows 10 version 1607 or later
- TPM 2.0 hardware
- TPM enabled in BIOS/UEFI

### Checking TPM Status

```powershell
# Check if TPM is present and enabled
Get-Tpm

# Check TPM version
Get-WmiObject -class Win32_Tpm -namespace root\cimv2\security\microsofttpm
```

## Linux-Specific Notes

### Device Files

- `/dev/tpm0`: Direct TPM access (requires root)
- `/dev/tpmrm0`: Resource Manager device (recommended)

### Requirements

- Linux kernel 4.x or later
- `tpm2-tss` library installed
- User in `tss` group or root access

### Checking TPM Status

```bash
# Check for TPM device
ls -la /dev/tpm*

# Get TPM info
tpm2_getcap properties-fixed

# Read PCR 7
tpm2_pcrread sha256:7
```

## Troubleshooting

### TPM Not Found

**Windows:**
1. Check BIOS/UEFI settings - enable TPM
2. Verify TPM is initialized: `tpm.msc`
3. Run as Administrator

**Linux:**
1. Check kernel support: `dmesg | grep -i tpm`
2. Load TPM module: `modprobe tpm_crb` or `modprobe tpm_tis`
3. Install `tpm2-tools`: `apt install tpm2-tools`

### Access Denied

**Windows:**
- Run application as Administrator
- Check TPM ownership in `tpm.msc`

**Linux:**
- Add user to `tss` group: `usermod -a -G tss $USER`
- Or run with `sudo`

### PCR Mismatch After Update

This is expected when:
- BIOS/UEFI firmware is updated
- Secure Boot configuration changes
- Boot order is modified
- Bootloader is updated

Solution: Re-enroll TPM or use recovery key.

## References

- [TCG TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Microsoft TPM Documentation](https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/tpm-fundamentals)
- [Linux TPM2 Software](https://github.com/tpm2-software)
- [Tesseract LUKS Integration](../README.md#luks-integration-linux)
