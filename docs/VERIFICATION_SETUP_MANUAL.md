# Manual Formal Verification Setup Steps

## Prerequisites Installation (Windows)

### 1. Install Java JDK 11+

Prusti requires Java 11 or later (64-bit).

**Option A: Download from Adoptium**
1. Visit https://adoptium.net/
2. Download "Eclipse Temurin 11 (LTS)"
3. Run installer
4. Verify installation:
   ```powershell
   java -version
   ```
   Should show: `openjdk version "11.x.x"` or higher

**Option B: Use Chocolatey** (if installed)
```powershell
choco install temurin11
```

**Option C: Use Scoop** (if installed)
```powershell
scoop bucket add java
scoop install temurin11-jdk
```

### 2. Install Prusti VS Code Extension

1. Open Visual Studio Code
2. Press `Ctrl+Shift+X` to open Extensions
3. Search for "Prusti Assistant"
4. Click "Install" on the extension by `viper-admin`
5. Reload VS Code when prompted
6. Open any `.rs` file in Tesseract Vault project
7. Extension will automatically download Prusti (may take a few minutes)
8. Check Output panel → Select "Prusti" to see installation progress

### 3. Verify Prusti Installation

1. Open `src/lib.rs` in VS Code
2. Look for Prusti status in bottom status bar
3. Should show "Prusti: Ready" or similar
4. If errors, check Output → Prusti for details

## Verification Enabled!

Once setup is complete:

- **Prusti** will verify code as you type in VS Code
- **Kani** will run in CI/CD pipeline on GitHub Actions
- Configuration files are already in place:
  - `Prusti.toml` - Prusti settings
  - `.vscode/settings.json` - VS Code Prusti settings
  - `.github/workflows/formal-verification.yml` - CI workflow

## Next Steps

1. See `docs/formal-verification-setup.md` for detailed usage
2. See `docs/formal-verification-tools-analysis.md` for tool comparison
3. Start adding specifications to crypto modules
4. Write Kani harnesses for critical functions

## Troubleshooting

### Prusti Extension Not Activating

**Symptom**: Extension installed but not showing in Output panel

**Solutions**:
1. Check Java is in PATH: `java -version` in PowerShell
2. Restart VS Code completely
3. Check extension logs: Help → Toggle Developer Tools → Console
4. Try reinstalling extension

### Java Not Found

**Symptom**: `Java is required but not found`

**Solutions**:
1. Ensure Java JDK 11+ is installed (not JRE)
2. Restart terminal/IDE after Java installation
3. Check JAVA_HOME environment variable is set
4. Add Java bin directory to PATH manually if needed

### Verification Timeout

**Symptom**: Prusti times out during verification

**Solutions**:
1. Increase timeout in `Prusti.toml`: `verification_timeout = 240`
2. Simplify specifications (break into smaller functions)
3. Add intermediate assertions to guide verifier

### Nightly Toolchain Issues

**Symptom**: Prusti requires specific nightly version

**Solutions**:
1. VS Code extension handles this automatically
2. If using command line, install required nightly:
   ```powershell
   rustup install nightly-YYYY-MM-DD
   ```
   (Check Prusti error message for exact date)

## Manual CLI Usage (Optional)

If you want to use Prusti from command line:

### Install Prusti CLI

```powershell
cargo install prusti-cli
```

**Note**: May fail on Windows. Use VS Code extension instead.

### Run Verification

```powershell
# Verify entire crate
cargo prusti

# Verify specific module
prusti-rustc --crate-type=lib src/crypto/aes.rs
```

## WSL Setup for Kani (Optional)

If you want to run Kani locally on Windows via WSL:

### 1. Install Rust in WSL

```bash
# In WSL terminal (Ubuntu/Debian)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Install Kani in WSL

```bash
cargo install --locked kani-verifier
cargo kani setup
```

### 3. Run Kani Verification

```bash
# Navigate to project in WSL
cd /mnt/c/Users/texas/Tesseract/Tesseract

# Run verification
cargo kani --workspace
```

## CI/CD Pipeline

GitHub Actions workflow is already configured in `.github/workflows/formal-verification.yml`.

**What it does**:
- Runs on every push and pull request
- Installs Kani and Prusti in Linux environment
- Verifies entire workspace
- Generates coverage reports
- Posts summary to PR

**No additional setup required** - it will run automatically when you push to GitHub.

## Status Checklist

- [ ] Java JDK 11+ installed (`java -version` works)
- [ ] Prusti Assistant VS Code extension installed
- [ ] Prusti showing "Ready" in VS Code status bar
- [ ] `Prusti.toml` configuration file present
- [ ] `.github/workflows/formal-verification.yml` committed
- [ ] First PR with verification workflow triggered

## Support

If you encounter issues:
1. Check `docs/formal-verification-setup.md` for detailed troubleshooting
2. Review Prusti logs in VS Code Output panel
3. Check GitHub Actions workflow logs for CI issues
4. Consult tool documentation:
   - Prusti: https://viperproject.github.io/prusti-dev/
   - Kani: https://model-checking.github.io/kani/

---

**Document**: Manual Setup Guide
**Status**: Ready for setup
**Next**: Install Java and Prusti extension
