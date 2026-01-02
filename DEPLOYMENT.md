# Tesseract Vault Deployment Guide

This guide covers deployment options for Tesseract Vault across different environments.

## Table of Contents

- [Binary Installation](#binary-installation)
- [System Service (Daemon)](#system-service-daemon)
- [Volume Mounting in Production](#volume-mounting-in-production)
- [WebAssembly Deployment](#webassembly-deployment)
- [Enterprise Deployment](#enterprise-deployment)

## Binary Installation

### From Source

```bash
# Install to ~/.cargo/bin (Linux) or %USERPROFILE%\.cargo\bin (Windows)
cargo install --path .

# With specific features
cargo install --path . --no-default-features --features "post-quantum compression"

# Install to custom location
cargo install --path . --root /usr/local
```

### Manual Installation

**Linux:**
```bash
cargo build --release
sudo cp target/release/tesseract-vault /usr/local/bin/
sudo cp target/release/tesseract-vault-gui /usr/local/bin/  # Optional
sudo cp target/release/tesseract-luks /usr/local/bin/       # Optional, Linux FDE
```

**Windows:**
```powershell
cargo build --release
copy target\release\tesseract-vault.exe C:\Program Files\TesseractVault\
# Add to PATH or use full path
```

### Verification

```bash
tesseract-vault --version
tesseract-vault encrypt --help
```

## System Service (Daemon)

The Tesseract daemon provides background volume management, power state monitoring, and automatic unmounting.

### Windows Service

**Install and start:**
```powershell
# Requires Administrator privileges
tesseract daemon install-service
tesseract daemon start-service
```

**Check status:**
```powershell
tesseract daemon status
sc query TesseractVault
```

**Uninstall:**
```powershell
tesseract daemon stop-service
tesseract daemon uninstall-service
```

### Linux systemd Service

**Install:**
```bash
sudo tesseract daemon install-service
# Or manually copy the service file:
# sudo cp docs/services/secure-cryptor-automount.service /etc/systemd/system/tesseract.service
sudo systemctl daemon-reload
```

**Start and enable:**
```bash
sudo systemctl start tesseract
sudo systemctl enable tesseract  # Start on boot
```

**Check status:**
```bash
sudo systemctl status tesseract
journalctl -u tesseract -f  # View logs
```

**Uninstall:**
```bash
sudo systemctl stop tesseract
sudo systemctl disable tesseract
sudo rm /etc/systemd/system/tesseract.service
sudo systemctl daemon-reload
```

### Daemon Features

- Automatic volume unmounting on sleep/hibernate
- Power state monitoring with callbacks
- IPC socket for inter-process communication
- Graceful shutdown on SIGTERM/SIGINT

## Volume Mounting in Production

### Prerequisites

**Windows:**
- [WinFsp](https://winfsp.dev/) installed

**Linux:**
- FUSE kernel driver and libraries (`fuse3`, `libfuse3-dev`)

### Creating and Mounting Volumes

```bash
# Create a 10GB encrypted volume
tesseract-vault volume create --container /data/secure.enc --size 10G

# Mount the volume
tesseract-vault volume mount --container /data/secure.enc --mount-point /mnt/secure

# Verify mount
tesseract-vault volume list

# Unmount
tesseract-vault volume unmount /mnt/secure
```

### Automount Configuration

For automatic mounting at startup, use the daemon service with a configuration file:

```bash
# /etc/tesseract/config.toml (Linux)
# C:\ProgramData\TesseractVault\config.toml (Windows)

[automount]
enabled = true

[[volumes]]
container = "/data/secure.enc"
mount_point = "/mnt/secure"
read_only = false
```

### Production Best Practices

1. **Separate key storage**: Store passphrases/recovery keys in secure locations (HSM, vault)
2. **Regular backups**: Back up volume headers and recovery keys
3. **Monitoring**: Monitor daemon logs for unmount events
4. **Access control**: Use filesystem permissions on mount points
5. **Hidden volumes**: Consider for high-security scenarios

## WebAssembly Deployment

Tesseract Vault can be compiled to WebAssembly for browser-based encryption.

### Building WASM

```bash
# Minimal build (~100KB)
wasm-pack build --target web --release -- --no-default-features --features wasm-minimal

# Full build with PQC
wasm-pack build --target web --release -- --features wasm-full
```

### GitHub Pages Deployment

**Using GitHub Actions** (recommended):

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

      - name: Build WASM
        run: wasm-pack build --target web --out-dir pkg/web

      - name: Setup Pages
        uses: actions/configure-pages@v4

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: 'examples/wasm'

      - name: Deploy to GitHub Pages
        uses: actions/deploy-pages@v4
```

**Enable GitHub Pages:**
1. Go to repository Settings > Pages
2. Source: GitHub Actions
3. Visit: `https://yourusername.github.io/tesseract-vault/`

### Security Headers

Add Content Security Policy for production:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self';">
```

Generate Subresource Integrity hashes:

```bash
openssl dgst -sha384 -binary pkg/web/tesseract_bg.wasm | openssl base64 -A
```

## Enterprise Deployment

### File Associations (Windows)

Register `.enc` file associations for seamless integration:

```powershell
# Requires Administrator
.\target\release\tesseract-vault-register.exe install
```

This registers:
- Double-click `.enc` files to open in Tesseract GUI
- Right-click context menu for encryption/decryption

### File Associations (Linux)

```bash
./target/release/tesseract-vault-register install
```

Creates:
- Desktop entry in `~/.local/share/applications/`
- MIME type for `.enc` files
- File associations in `~/.config/mimeapps.list`

### LUKS Integration (Linux FDE)

For full disk encryption with post-quantum security:

```bash
# Create Tesseract-protected LUKS keyfile
tesseract-luks create /etc/tesseract/root.keyfile

# Enroll TPM for passwordless boot
tesseract-luks enroll-tpm /etc/tesseract/root.keyfile --pcrs 0,7

# Integrate with initramfs (distribution-specific)
# See docs/preboot-auth-design.md for details
```

### Monitoring and Logging

**Windows Event Log:**
```powershell
Get-EventLog -LogName Application -Source TesseractVault
```

**Linux journald:**
```bash
journalctl -u tesseract --since "1 hour ago"
```

### Uninstallation

**Complete removal:**

```bash
# Stop and remove service
tesseract daemon uninstall-service

# Remove file associations
tesseract-vault-register uninstall

# Remove binaries (Linux)
sudo rm /usr/local/bin/tesseract-vault*
sudo rm /usr/local/bin/tesseract-luks

# Remove binaries (Windows)
del "C:\Program Files\TesseractVault\*"
```

**Config and data locations:**
- Linux: `~/.config/tesseract/`, `/etc/tesseract/`
- Windows: `%APPDATA%\TesseractVault\`, `C:\ProgramData\TesseractVault\`

## Support

For deployment issues:
1. Check logs (`journalctl` or Event Viewer)
2. Verify dependencies (WinFsp/FUSE installed)
3. Test commands manually before automating
4. See [README.md](README.md) for usage details
