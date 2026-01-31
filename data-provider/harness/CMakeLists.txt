# TEE Dataset Safety Harness - Build Configuration
#
# This can build in two modes:
#   1. Simulation mode (default): No SGX required, uses OpenSSL for crypto
#   2. SGX mode: Requires Intel SGX SDK, builds as enclave
#
# Usage:
#   mkdir build && cd build
#   cmake .. [-DSGX_MODE=ON]
#   make

cmake_minimum_required(VERSION 3.10)
project(tee-harness C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Build mode selection
option(SGX_MODE "Build for Intel SGX" OFF)

# Path to WAMR (WebAssembly Micro Runtime)
# Set this via -DWAMR_ROOT=/path/to/wasm-micro-runtime
set(WAMR_ROOT "" CACHE PATH "Path to WAMR source")

if(NOT WAMR_ROOT)
    # Default: assume WAMR is in ../wasm-micro-runtime or downloaded
    if(EXISTS "${CMAKE_SOURCE_DIR}/../wasm-micro-runtime")
        set(WAMR_ROOT "${CMAKE_SOURCE_DIR}/../wasm-micro-runtime")
    else()
        message(STATUS "WAMR_ROOT not set - will download WAMR")
        include(FetchContent)
        FetchContent_Declare(
            wamr
            GIT_REPOSITORY https://github.com/bytecodealliance/wasm-micro-runtime.git
            GIT_TAG        WAMR-2.1.0
        )
        FetchContent_MakeAvailable(wamr)
        set(WAMR_ROOT ${wamr_SOURCE_DIR})
    endif()
endif()

message(STATUS "WAMR_ROOT: ${WAMR_ROOT}")

# WAMR build configuration
set(WAMR_BUILD_PLATFORM "linux")
set(WAMR_BUILD_TARGET "X86_64")
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_AOT 0)       # Interpreter only for simplicity
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 0)  # Disable WASI - we don't want challengers to have I/O

# Include WAMR core
include(${WAMR_ROOT}/build-scripts/runtime_lib.cmake)

# Common sources
set(HARNESS_SOURCES
    src/harness.c
    src/wasm_runtime.c
    src/main.c
)

if(SGX_MODE)
    message(STATUS "Building for Intel SGX")
    
    # SGX mode would require:
    # - Intel SGX SDK
    # - Modified crypto implementation using sgx_* APIs
    # - EDL files and enclave configuration
    # 
    # For now, we just note it's a separate target
    message(FATAL_ERROR "SGX_MODE not yet implemented - use simulation mode")
    
else()
    message(STATUS "Building in simulation mode")
    
    # Simulation mode: use OpenSSL for crypto
    find_package(OpenSSL REQUIRED)
    
    set(HARNESS_SOURCES ${HARNESS_SOURCES} src/crypto_sim.c)
    
    add_executable(harness-cli 
        ${HARNESS_SOURCES}
        ${WAMR_RUNTIME_LIB_SOURCE}
    )
    
    target_include_directories(harness-cli PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${WAMR_ROOT}/core/iwasm/include
        ${SHARED_DIR}/include
        ${SHARED_DIR}/utils
        ${SHARED_DIR}/platform/include
    )
    
    target_link_libraries(harness-cli
        OpenSSL::Crypto
        pthread
        m
        dl
    )
    
    target_compile_definitions(harness-cli PRIVATE
        SIMULATION_MODE=1
        BH_MALLOC=wasm_runtime_malloc
        BH_FREE=wasm_runtime_free
    )
    
endif()

# Install target
install(TARGETS harness-cli DESTINATION bin)

# Documentation
message(STATUS "")
message(STATUS "Build configuration:")
message(STATUS "  Mode: ${SGX_MODE}")
message(STATUS "  WAMR: ${WAMR_ROOT}")
message(STATUS "")
message(STATUS "To build:")
message(STATUS "  mkdir build && cd build && cmake .. && make")
message(STATUS "")