# Tesseract TPM Testing Environment
# Uses swtpm (Software TPM 2.0 emulator) for testing TPM functionality
#
# Build: docker build -t tesseract-tpm-test .
# Run:   docker run -it --rm tesseract-tpm-test

FROM fedora:42

# Install dependencies
RUN dnf install -y \
    # Software TPM
    swtpm \
    swtpm-tools \
    tpm2-tools \
    tpm2-tss \
    # Build tools
    gcc \
    gcc-c++ \
    make \
    pkg-config \
    openssl-devel \
    # FUSE for encrypted volumes
    fuse3-devel \
    # Rust
    curl \
    && dnf clean all

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create TPM state directory
RUN mkdir -p /var/lib/swtpm-localca /tmp/tpmstate

# Copy project
WORKDIR /tesseract
COPY . .

# Build the project (disable GUI to avoid glib/gtk dependencies)
RUN cargo build --release --bin tesseract_luks --no-default-features --features "post-quantum,compression,encrypted-volumes"

# Copy entrypoint script
COPY docker/tpm-test/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["cargo", "test", "tpm", "--lib", "--no-default-features", "--features", "post-quantum,compression,encrypted-volumes"]
