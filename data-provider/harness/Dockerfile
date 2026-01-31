# TEE Dataset Safety Harness - Docker Build Environment
#
# This Dockerfile creates an environment with:
# - WAMR (WebAssembly Micro Runtime) built as a library
# - wasi-sdk for compiling WASM challengers
# - The harness CLI tool
#
# Build:
#   docker build -t tee-harness .
#
# Run:
#   docker run -v $(pwd)/dataset:/data/dataset \
#              -v $(pwd)/challengers:/data/challengers \
#              tee-harness --wasm /data/challengers/pii.wasm --dataset /data/dataset

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Download and install wasi-sdk
ENV WASI_VERSION=24
ENV WASI_VERSION_FULL=${WASI_VERSION}.0
RUN wget -q https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-x86_64-linux.tar.gz \
    && tar xzf wasi-sdk-${WASI_VERSION_FULL}-x86_64-linux.tar.gz -C /opt \
    && rm wasi-sdk-${WASI_VERSION_FULL}-x86_64-linux.tar.gz \
    && ln -s /opt/wasi-sdk-${WASI_VERSION_FULL}-x86_64-linux /opt/wasi-sdk

# Clone WAMR
WORKDIR /opt
RUN git clone --depth 1 --branch WAMR-2.1.0 \
    https://github.com/bytecodealliance/wasm-micro-runtime.git wamr

# Build WAMR library (interpreter mode only, minimal config)
WORKDIR /opt/wamr/product-mini/platforms/linux
RUN mkdir -p build && cd build && \
    cmake .. \
        -DWAMR_BUILD_INTERP=1 \
        -DWAMR_BUILD_AOT=0 \
        -DWAMR_BUILD_JIT=0 \
        -DWAMR_BUILD_LIBC_BUILTIN=1 \
        -DWAMR_BUILD_LIBC_WASI=0 \
        -DWAMR_BUILD_FAST_INTERP=1 \
        -DWAMR_BUILD_MINI_LOADER=0 && \
    make -j$(nproc)

# Copy harness source
WORKDIR /build
COPY include/ include/
COPY src/ src/
COPY wasm-challenger/ wasm-challenger/

# Build the harness
# We build manually since CMake FetchContent is complex in Docker
RUN gcc -O2 -Wall \
    -I./include \
    -I/opt/wamr/core/iwasm/include \
    -I/opt/wamr/core/shared/platform/include \
    -I/opt/wamr/core/shared/utils \
    -I/opt/wamr/core/shared/platform/linux \
    -DWASM_ENABLE_INTERP=1 \
    -DWASM_ENABLE_AOT=0 \
    -DWASM_ENABLE_LIBC_BUILTIN=1 \
    -DWASM_ENABLE_LIBC_WASI=0 \
    -DWASM_ENABLE_FAST_INTERP=1 \
    -DBH_MALLOC=wasm_runtime_malloc \
    -DBH_FREE=wasm_runtime_free \
    -c src/harness.c -o harness.o

RUN gcc -O2 -Wall \
    -I./include \
    -I/opt/wamr/core/iwasm/include \
    -I/opt/wamr/core/shared/platform/include \
    -I/opt/wamr/core/shared/utils \
    -I/opt/wamr/core/shared/platform/linux \
    -DWASM_ENABLE_INTERP=1 \
    -DWASM_ENABLE_AOT=0 \
    -DWASM_ENABLE_LIBC_BUILTIN=1 \
    -DWASM_ENABLE_LIBC_WASI=0 \
    -DWASM_ENABLE_FAST_INTERP=1 \
    -DBH_MALLOC=wasm_runtime_malloc \
    -DBH_FREE=wasm_runtime_free \
    -c src/wasm_runtime.c -o wasm_runtime.o

RUN gcc -O2 -Wall \
    -I./include \
    -c src/crypto_sim.c -o crypto_sim.o

RUN gcc -O2 -Wall \
    -I./include \
    -c src/main.c -o main.o

# Link everything
RUN gcc -o harness-cli \
    harness.o wasm_runtime.o crypto_sim.o main.o \
    /opt/wamr/product-mini/platforms/linux/build/libvmlib.a \
    -lssl -lcrypto -lpthread -lm -ldl

# Compile the sample PII detector WASM
RUN /opt/wasi-sdk/bin/clang \
    -O2 --target=wasm32-wasi \
    -Wl,--export=check_document \
    -Wl,--no-entry \
    -Wl,--allow-undefined \
    -o pii_detector.wasm \
    wasm-challenger/pii_detector.c

# ============================================================================
# Runtime image
# ============================================================================
FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy artifacts from builder
COPY --from=builder /build/harness-cli /usr/local/bin/
COPY --from=builder /build/pii_detector.wasm /usr/local/share/challengers/
COPY --from=builder /opt/wasi-sdk /opt/wasi-sdk

# Create directories for mounting
RUN mkdir -p /data/dataset /data/challengers /data/output

WORKDIR /data

# Default entrypoint
ENTRYPOINT ["harness-cli"]
CMD ["--help"]

# ============================================================================
# Development image (includes build tools)
# ============================================================================
FROM builder AS development

# Keep build tools for development
RUN apt-get update && apt-get install -y \
    vim \
    less \
    gdb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
CMD ["/bin/bash"]
