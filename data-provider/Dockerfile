FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install flask cryptography pynacl

# =============================================================================
# Build WAMR (WebAssembly Micro Runtime)
# We're building in interpreter mode for simplicity - no SGX hardware needed
# =============================================================================
WORKDIR /opt

RUN git clone --depth 1 https://github.com/bytecodealliance/wasm-micro-runtime.git wamr

WORKDIR /opt/wamr/product-mini/platforms/linux

# Build WAMR with WASI support
RUN mkdir build && cd build && \
    cmake .. \
        -DWAMR_BUILD_INTERP=1 \
        -DWAMR_BUILD_FAST_INTERP=1 \
        -DWAMR_BUILD_AOT=0 \
        -DWAMR_BUILD_LIBC_WASI=1 \
        -DWAMR_BUILD_LIBC_BUILTIN=1 \
    && make -j$(nproc)

# Make iwasm available
RUN cp build/iwasm /usr/local/bin/

# =============================================================================
# Application setup
# =============================================================================
WORKDIR /app

COPY app/ /app/

# Create directories
RUN mkdir -p /data /challenges /results

EXPOSE 8080

CMD ["python3", "server.py"]