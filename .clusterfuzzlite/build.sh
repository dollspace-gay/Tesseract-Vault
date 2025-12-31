#!/bin/bash -eu
# ClusterFuzzLite build script for Tesseract Vault
# Builds all fuzz targets using cargo-fuzz with optimizations

cd $SRC/tesseract-vault

# Build all fuzz targets in release mode with optimizations
# -O enables release mode for faster fuzzing
cargo fuzz build -O

# Copy all built fuzz targets to the output directory
FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    if [ -f "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" ]; then
        cp "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" "$OUT/"
    fi
done

# Copy seed corpus if available
for target_dir in fuzz/corpus/*/; do
    if [ -d "$target_dir" ]; then
        target_name=$(basename "$target_dir")
        if [ -f "$OUT/$target_name" ]; then
            zip -j "$OUT/${target_name}_seed_corpus.zip" "$target_dir"/* 2>/dev/null || true
        fi
    fi
done
