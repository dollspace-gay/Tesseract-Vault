# ClusterFuzzLite Dockerfile for Tesseract Vault
# Uses the official OSS-Fuzz Rust builder image with nightly Rust and cargo-fuzz

FROM gcr.io/oss-fuzz-base/base-builder-rust

# Patch compile script to create $OUT directory before copying into it.
# The base image compile script does `cp llvm-symbolizer $OUT/` before
# running our build.sh, which fails in ClusterFuzzLite DinD setups where
# $OUT is a volume-mounted path that doesn't exist yet.
RUN sed -i '1a mkdir -p "${OUT:-/out}"' /usr/local/bin/compile

# Copy project source
COPY . $SRC/tesseract-vault

# Copy build script to expected location
COPY .clusterfuzzlite/build.sh $SRC/build.sh

# Set working directory
WORKDIR $SRC/tesseract-vault
