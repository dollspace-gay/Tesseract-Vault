# SSD Secure Deletion Limitations

## Overview

Traditional secure deletion methods designed for magnetic hard drives (HDDs) are **ineffective on solid-state drives (SSDs)**. This document explains why and provides guidance on actual secure deletion options for SSDs.

## Why Traditional Methods Fail on SSDs

### Wear Leveling

SSDs use wear leveling algorithms to distribute writes evenly across all flash cells, extending drive lifespan. When you "overwrite" a file:

1. The SSD writes new data to a **different physical location**
2. The original data remains in the old location
3. The old location is marked as "stale" but **not erased**
4. Data persists until the SSD's garbage collection eventually reclaims the block

This means overwriting a file multiple times (DoD 5220.22-M, Gutmann 35-pass, etc.) simply writes to new locations each time, leaving multiple copies of sensitive data scattered across the drive.

### Over-Provisioning

SSDs reserve 7-28% of their capacity for:
- Wear leveling operations
- Bad block replacement
- Performance optimization

This reserved space is **inaccessible to the operating system** but may contain copies of deleted data that cannot be overwritten through normal file operations.

### TRIM Limitations

While TRIM commands tell the SSD which blocks are no longer in use:
- TRIM is a **hint**, not a command - the SSD may delay actual erasure
- Not all SSDs implement TRIM the same way
- TRIM doesn't guarantee immediate or complete data destruction
- Some SSDs ignore TRIM entirely in certain conditions

## Ineffective Methods

The following methods provide **false security** on SSDs:

| Method | Why It Fails |
|--------|--------------|
| Single-pass overwrite | Writes to new location, original data preserved |
| DoD 5220.22-M (3-pass) | Creates 3 copies in different locations |
| Gutmann 35-pass | Creates 35 copies, wastes SSD lifespan |
| File shredders (shred, srm) | Same wear-leveling problem |
| Zero-filling free space | Doesn't reach over-provisioned areas |

## Effective Secure Deletion Methods

### 1. Full-Disk Encryption from the Start (Recommended)

**Best Practice**: Encrypt the entire drive before storing any sensitive data.

With Tesseract Vault or similar full-disk encryption:
- All data written to disk is encrypted
- Deleting the encryption key renders all data unrecoverable
- No need to overwrite - the ciphertext is useless without the key

```
Recommendation: Use Tesseract Vault's encrypted volumes for all sensitive data.
When done, securely delete the key material - the encrypted data becomes garbage.
```

### 2. Hardware Secure Erase (ATA Secure Erase)

SSDs support a built-in secure erase command that:
- Resets all flash cells to factory state
- Clears over-provisioned areas
- Resets the encryption key (for self-encrypting drives)

**Tools:**
- Linux: `hdparm --security-erase`
- Windows: Manufacturer utilities (Samsung Magician, Intel SSD Toolbox, etc.)
- BIOS/UEFI: Some systems offer secure erase in firmware

**Caveats:**
- Erases the **entire drive**
- Requires temporarily removing the drive's security freeze
- Some SSDs implement this poorly or not at all
- Verify with manufacturer documentation

### 3. NVMe Format Command

For NVMe SSDs, the Format NVM command with Secure Erase setting:

```bash
# Linux - Cryptographic erase (best if supported)
nvme format /dev/nvme0n1 --ses=2

# Linux - User data erase
nvme format /dev/nvme0n1 --ses=1
```

**Secure Erase Settings:**
- `ses=0`: No secure erase
- `ses=1`: User Data Erase - all user data erased
- `ses=2`: Cryptographic Erase - encryption key changed (fastest, most secure)

### 4. Physical Destruction

For highest security requirements:
- Shredding (industrial cross-cut shredders rated for SSDs)
- Disintegration
- Incineration
- Degaussing is **ineffective** on SSDs (no magnetic media)

## Tesseract Vault Recommendations

### For File-Level Security

Use Tesseract Vault's encrypted containers:
1. Create an encrypted container before storing sensitive files
2. Work with files only inside the mounted encrypted volume
3. When finished, unmount and optionally delete the container
4. The encryption key never touches plaintext areas of the SSD

### For Volume-Level Security

Use Tesseract Vault's encrypted volumes feature:
1. Create encrypted volume at drive/partition level
2. All writes are encrypted before reaching the SSD
3. Plaintext data never exists on the physical media

### Key Deletion Strategy

When decommissioning encrypted storage:
1. Ensure all key material is securely wiped from memory
2. Delete any key backup files using the encrypted volume itself
3. The encrypted data on the SSD is now cryptographically inaccessible
4. Optionally perform ATA Secure Erase for defense in depth

## Security Levels by Method

| Method | Security Level | Notes |
|--------|---------------|-------|
| File overwrite on SSD | None | Completely ineffective |
| TRIM + time | Low | May work eventually, no guarantees |
| Encrypted from start + key deletion | High | Recommended approach |
| ATA/NVMe Secure Erase | High | Drive-level, implementation varies |
| Cryptographic Erase (NVMe) | Very High | Instant, changes encryption key |
| Physical destruction | Absolute | For highest security requirements |

## References

- NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
- IEEE 2883-2022: Standard for Sanitizing Storage
- ATA/ATAPI Command Set (ACS-4) - Security Feature Set
- NVMe Specification - Format NVM Command

## Summary

**Do not rely on file overwriting for secure deletion on SSDs.**

Instead:
1. **Encrypt data before it's written** (primary recommendation)
2. Use **hardware secure erase** when decommissioning drives
3. Consider **physical destruction** for highest security needs

Tesseract Vault's encryption-first approach is the most practical solution for day-to-day secure data handling on SSDs.
