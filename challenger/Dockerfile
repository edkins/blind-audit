FROM rust:1.93-slim

# Install wasm target and dependencies
RUN rustup target add wasm32-wasip1 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        curl \
        inotify-tools \
    && rm -rf /var/lib/apt/lists/*

# Create workspace
WORKDIR /challenges

# Install cargo-watch for optional auto-rebuild
RUN cargo install cargo-watch

# Copy the build script
COPY build.sh /build.sh
RUN chmod +x /build.sh

# Create output directory
RUN mkdir -p /output

ENTRYPOINT ["/build.sh"]
