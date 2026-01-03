# Verifying Release Signatures

Tesseract Vault releases are cryptographically signed using [Sigstore](https://www.sigstore.dev/) to ensure authenticity and integrity.

## Why Sigstore?

Sigstore provides "keyless" signing using OpenID Connect (OIDC) identities. This means:

- **No long-lived keys to manage or compromise**
- **Signatures are tied to GitHub Actions workflow identity**
- **All signatures are logged in the public Rekor transparency log**
- **Anyone can verify without trusting private keys**

## Quick Verification

### Prerequisites

Install [cosign](https://docs.sigstore.dev/cosign/installation/):

```bash
# macOS
brew install cosign

# Linux (Debian/Ubuntu)
sudo apt-get install cosign

# Windows (via Chocolatey)
choco install cosign

# Or download directly from GitHub releases
# https://github.com/sigstore/cosign/releases
```

### Verify a Release

Each release includes these files for each binary:
- `tesseract-vault-*` - The binary
- `tesseract-vault-*.sha256` - SHA256 checksum
- `tesseract-vault-*.sig` - Detached signature
- `tesseract-vault-*.pem` - Signing certificate
- `tesseract-vault-*.bundle` - Combined signature bundle (recommended)

**Option 1: Using the bundle (recommended)**

```bash
cosign verify-blob tesseract-vault-linux-x86_64 \
  --bundle tesseract-vault-linux-x86_64.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/dollspace-gay/Tesseract/.*'
```

**Option 2: Using separate signature and certificate**

```bash
cosign verify-blob tesseract-vault-linux-x86_64 \
  --signature tesseract-vault-linux-x86_64.sig \
  --certificate tesseract-vault-linux-x86_64.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/dollspace-gay/Tesseract/.*'
```

### Expected Output

Successful verification shows:

```
Verified OK
```

If verification fails, you'll see an error. **Do not use binaries that fail verification.**

## Understanding the Verification

### What's Being Verified

1. **Signature validity** - The signature was created with the certificate's private key
2. **Certificate identity** - The certificate was issued to our GitHub Actions workflow
3. **OIDC issuer** - GitHub Actions issued the identity token
4. **Transparency log** - The signature is recorded in Rekor

### Certificate Identity

The `--certificate-identity-regexp` flag ensures the binary was signed by:
- A GitHub Actions workflow
- Running in the `dollspace-gay/Tesseract` repository

This prevents someone from signing a malicious binary with their own GitHub identity.

### OIDC Issuer

The `--certificate-oidc-issuer` flag ensures:
- The identity token came from GitHub Actions
- Not from another OIDC provider

## Verifying SHA256 Checksums

In addition to signature verification, you can verify checksums:

**Linux/macOS:**
```bash
sha256sum -c tesseract-vault-linux-x86_64.sha256
```

**Windows (PowerShell):**
```powershell
$expected = (Get-Content tesseract-vault-windows-x86_64.exe.sha256).Split()[0]
$actual = (Get-FileHash -Algorithm SHA256 tesseract-vault-windows-x86_64.exe).Hash.ToLower()
if ($expected -eq $actual) { "OK" } else { "MISMATCH" }
```

## Inspecting Signatures

### View Certificate Details

```bash
cosign verify-blob tesseract-vault-linux-x86_64 \
  --bundle tesseract-vault-linux-x86_64.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/dollspace-gay/Tesseract/.*' \
  --output-certificate /dev/stdout 2>/dev/null | openssl x509 -text -noout
```

### Query Rekor Transparency Log

Every signature is recorded in the public Rekor log. To find entries:

```bash
# Get the log entry UUID from the bundle
cat tesseract-vault-linux-x86_64.bundle | jq -r '.rekorBundle.logId'

# Search Rekor for entries from this project
rekor-cli search --email 'github-actions[bot]@users.noreply.github.com'
```

### Verify Against Rekor Directly

```bash
cosign verify-blob tesseract-vault-linux-x86_64 \
  --bundle tesseract-vault-linux-x86_64.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/dollspace-gay/Tesseract/.*' \
  --rekor-url https://rekor.sigstore.dev
```

## Troubleshooting

### "certificate identity does not match"

This error means the binary was signed by a different identity than expected. Possible causes:
- Binary was signed by a fork
- Binary was tampered with
- Wrong verification flags

**Do not use the binary.**

### "signature verification failed"

The signature doesn't match the binary. The file may have been:
- Corrupted during download
- Tampered with

**Do not use the binary.** Re-download and try again.

### "no matching entries found in rekor log"

The signature wasn't recorded in the transparency log. This could mean:
- Very old release signed before transparency logging
- Network issue during signing
- Tampered signature

Consider this a verification failure unless you have other trust sources.

### Cosign Version Issues

Some older cosign versions have different flags. If you encounter errors:

```bash
# Check your version
cosign version

# Update to latest
# See https://docs.sigstore.dev/cosign/installation/
```

## Security Considerations

### What Sigstore Protects Against

- **Compromised build server** - Signatures prove the binary came from our workflow
- **Man-in-the-middle attacks** - Signature verification detects tampering
- **Key theft** - No long-lived keys to steal
- **Replay attacks** - Transparency log provides timestamp evidence

### What Sigstore Does NOT Protect Against

- **Compromised source code** - Review the source before trusting
- **Compromised GitHub Actions** - GitHub's infrastructure is trusted
- **Supply chain attacks on dependencies** - Use cargo-audit for this

### Best Practices

1. **Always verify signatures** before running downloaded binaries
2. **Check the certificate identity** matches the expected repository
3. **Verify checksums** as an additional layer
4. **Review release notes** for any security advisories
5. **Build from source** if you need maximum assurance

## Further Reading

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Cosign User Guide](https://docs.sigstore.dev/cosign/overview/)
- [Rekor Transparency Log](https://docs.sigstore.dev/rekor/overview/)
- [GitHub's Sigstore Integration](https://github.blog/2022-04-07-slsa-3-compliance-with-github-actions/)
