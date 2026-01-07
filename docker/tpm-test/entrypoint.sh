#!/bin/bash
# Tesseract TPM Test Environment Entrypoint
# Starts software TPM and runs the provided command

set -e

TPM_STATE_DIR="/tmp/tpmstate"
TPM_SOCKET="/tmp/swtpm-sock"

echo "=== Tesseract TPM Test Environment ==="
echo ""

# Initialize TPM state if needed
if [ ! -f "$TPM_STATE_DIR/tpm2-00.permall" ]; then
    echo "[*] Initializing software TPM state..."
    swtpm_setup --tpmstate "$TPM_STATE_DIR" --tpm2 --createek --decryption --create-ek-cert --create-platform-cert --lock-nvram
fi

# Start software TPM in the background
echo "[*] Starting software TPM (swtpm)..."
swtpm socket \
    --tpmstate dir="$TPM_STATE_DIR" \
    --tpm2 \
    --ctrl type=unixio,path="$TPM_SOCKET" \
    --server type=unixio,path=/dev/tpm0 \
    --flags startup-clear \
    &

SWTPM_PID=$!

# Wait for TPM to be ready
echo "[*] Waiting for TPM to initialize..."
sleep 2

# Verify TPM is working
if [ -S /dev/tpm0 ]; then
    echo "[*] TPM device available at /dev/tpm0"
else
    echo "[!] Warning: TPM device not available"
fi

# Check TPM with tpm2_getcap if available
if command -v tpm2_getcap &> /dev/null; then
    echo "[*] TPM capabilities:"
    export TPM2TOOLS_TCTI="device:/dev/tpm0"
    tpm2_getcap properties-fixed 2>/dev/null | head -10 || echo "[!] Could not query TPM"
fi

echo ""
echo "[*] Running command: $@"
echo ""

# Run the provided command
"$@"
EXIT_CODE=$?

# Cleanup
echo ""
echo "[*] Stopping software TPM..."
kill $SWTPM_PID 2>/dev/null || true

exit $EXIT_CODE
