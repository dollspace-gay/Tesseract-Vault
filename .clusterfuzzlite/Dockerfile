# ClusterFuzzLite Dockerfile for Tesseract Vault
# Uses the official OSS-Fuzz Rust builder image with nightly Rust and cargo-fuzz

FROM gcr.io/oss-fuzz-base/base-builder-rust

# Copy project source
COPY . $SRC/tesseract-vault

# Set working directory
WORKDIR $SRC/tesseract-vault
