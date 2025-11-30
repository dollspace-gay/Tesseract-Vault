# Fuzzing Targets for Tesseract Vault

This directory contains fuzzing infrastructure using `cargo-fuzz` and libFuzzer
to test parsing and cryptographic operations with arbitrary input data.

## Prerequisites

- Linux environment (or WSL2 on Windows)
- Rust nightly toolchain
- cargo-fuzz: `cargo install cargo-fuzz`

## Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_volume_header` | Tests VolumeHeader deserialization from arbitrary bytes |
| `fuzz_pq_metadata` | Tests post-quantum metadata (ML-KEM-1024) deserialization |
| `fuzz_superblock` | Tests filesystem superblock parsing |
| `fuzz_inode` | Tests filesystem inode deserialization |
| `fuzz_keyslots` | Tests KeySlots (encrypted master key storage) deserialization |
| `fuzz_stream_header` | Tests V3 streaming encryption header parsing |
| `fuzz_bitmap` | Tests filesystem block/inode bitmap operations |
| `fuzz_dir_entry` | Tests directory entry deserialization |
| `fuzz_chunk_mapper` | Tests chunk offset calculations with arbitrary inputs |
| `fuzz_aes_gcm_decrypt` | Tests AES-GCM decryption with malformed ciphertext |

## Running Fuzz Targets

### Quick Run (30 seconds)
```bash
cargo fuzz run fuzz_volume_header -- -max_total_time=30
```

### Extended Run (continuous until stopped)
```bash
cargo fuzz run fuzz_volume_header
```

### Run All Targets
```bash
for target in $(cargo fuzz list); do
    cargo fuzz run $target -- -max_total_time=60
done
```

### List Available Targets
```bash
cargo fuzz list
```

## Security-Critical Targets

Priority targets for security testing:

1. **fuzz_aes_gcm_decrypt** - Tests decryption of untrusted ciphertext
2. **fuzz_volume_header** - Tests parsing of volume files that could be malicious
3. **fuzz_pq_metadata** - Tests post-quantum cryptography parsing
4. **fuzz_keyslots** - Tests encrypted key slot parsing
5. **fuzz_stream_header** - Tests encrypted file header parsing

## Corpus Management

Fuzzing corpora are stored in `fuzz/corpus/<target_name>/`. These contain
interesting inputs that the fuzzer has discovered.

### Minimize Corpus
```bash
cargo fuzz cmin fuzz_volume_header
```

## Artifacts

Crash-causing inputs are stored in `fuzz/artifacts/<target_name>/`.
If you find a crash, please report it as a security issue.

## Adding New Fuzz Targets

1. Create a new file in `fuzz/fuzz_targets/`
2. Add the target to `fuzz/Cargo.toml`
3. Focus on parsing untrusted input, crypto operations, and memory safety
