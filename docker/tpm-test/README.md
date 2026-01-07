# Tesseract TPM Testing with Software TPM

This Docker environment uses `swtpm` (Software TPM 2.0 emulator) to test TPM functionality without requiring physical TPM hardware.

## Quick Start

```bash
# Build the image
cd docker/tpm-test
docker compose build

# Run TPM tests
docker compose run --rm tpm-test cargo test tpm --lib

# Run LUKS tests
docker compose run --rm tpm-test cargo test luks --lib

# Interactive shell (for debugging)
docker compose run --rm tpm-test bash
```

## What Gets Tested

- TPM device detection (`/dev/tpm0`)
- PCR (Platform Configuration Register) reading
- Key sealing with PCR binding
- Key unsealing (PCR policy verification)
- TPM random number generation
- LUKS keyfile TPM enrollment

## How It Works

1. The entrypoint script starts `swtpm` in socket mode
2. swtpm creates a virtual TPM device at `/dev/tpm0`
3. Tesseract's TPM code communicates with swtpm via standard TPM commands
4. All operations work identically to a real TPM 2.0

## Manual Testing

Inside the container:

```bash
# Check TPM is available
ls -la /dev/tpm0

# Read PCR values using tpm2-tools
export TPM2TOOLS_TCTI="device:/dev/tpm0"
tpm2_pcrread sha256:0,7

# Test with tesseract-luks CLI
./target/release/tesseract_luks create /tmp/test.keyfile
./target/release/tesseract_luks info /tmp/test.keyfile
```

## CI Integration

Add to `.github/workflows/tpm-test.yml`:

```yaml
name: TPM Tests
on: [push, pull_request]
jobs:
  tpm-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build TPM test environment
        run: docker compose -f docker/tpm-test/docker-compose.yml build
      - name: Run TPM tests
        run: docker compose -f docker/tpm-test/docker-compose.yml run --rm tpm-test
```

## Limitations

- swtpm doesn't provide real hardware security guarantees
- PCR values are simulated (not real boot measurements)
- Suitable for functional testing only, not security validation
