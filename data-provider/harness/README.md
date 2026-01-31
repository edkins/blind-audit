# TEE Dataset Safety Harness

A Trusted Execution Environment (TEE) harness for proving dataset safety through challenger-submitted detection scripts.

## Overview

This system allows a **data provider** to prove that their dataset doesn't contain dangerous content by running **challenger-submitted WASM modules** inside a TEE and providing **cryptographic attestation** of the results.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     TEE (SGX Enclave or Simulation)                 │
│                                                                     │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐    │
│   │   Dataset   │───▶│   WAMR      │───▶│  Challenger WASM    │    │
│   │   (copied   │    │   Runtime   │    │  (check_document)   │    │
│   │   into TEE) │    │             │    │                     │    │
│   └─────────────┘    └─────────────┘    └─────────────────────┘    │
│          │                                        │                 │
│          │ hash                                   │ result          │
│          ▼                                        ▼                 │
│   ┌─────────────┐                         ┌─────────────┐          │
│   │ Merkle Root │────────────────────────▶│ Attestation │          │
│   └─────────────┘                         │   signed    │          │
│                                           └─────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Model

**What the TEE guarantees:**
- The harness code runs exactly as written (MRENCLAVE attestation)
- Documents are hashed before being shown to the challenger
- Results are signed with a key only the TEE can access
- The challenger WASM cannot be tampered with

**What the challenger WASM can do:**
- Read document bytes passed to `check_document()`
- Return a safety verdict (0=safe, 1=unsafe)
- Nothing else! No file I/O, no network, no host calls

## Quick Start

### Using Docker

```bash
# Build the container
./harness.sh build

# Run the included test (creates sample data with PII)
./harness.sh test

# Run your own challenge
./harness.sh run \
    --wasm ./my_checker.wasm \
    --dataset ./my_dataset \
    --output result.json
```

### Compiling a Challenger

Challengers are WASM modules that export a single function:

```c
// Must be exported as "check_document"
int32_t check_document(const char* ptr, uint32_t len);
// Returns: 1 if unsafe, 0 if safe
```

Compile with wasi-sdk:

```bash
# Using the helper script
./harness.sh compile --source my_checker.c --output my_checker.wasm

# Or manually
/opt/wasi-sdk/bin/clang \
    -O2 --target=wasm32-wasi \
    -Wl,--export=check_document \
    -Wl,--no-entry \
    -Wl,--allow-undefined \
    -o my_checker.wasm \
    my_checker.c
```

### Attestation Output

The harness produces a JSON attestation:

```json
{
  "quote": {
    "dataset_merkle_root": "a1b2c3...",
    "wasm_module_hash": "d4e5f6...",
    "challenger_nonce": "...",
    "timestamp": 1706745600,
    "total_documents": 100,
    "unsafe_count": 1,
    "flagged_doc_index": 42,
    "flagged_doc_hash": "..."
  },
  "signature": "..."
}
```

## Included Challengers

### PII Detector (`pii_detector.wasm`)

Detects potential personally identifiable information:
- Social Security Numbers (XXX-XX-XXXX pattern)
- Credit card numbers (13-19 digit sequences)
- Email addresses
- Sensitive keywords ("password", "secret key", etc.)

## Architecture

### Components

1. **Harness (`harness.c`)** - Main orchestration logic
   - Loads dataset and computes Merkle root
   - Iterates through documents
   - Collects results and signs attestation

2. **WASM Runtime (`wasm_runtime.c`)** - WAMR integration
   - Loads challenger WASM modules
   - Copies documents into WASM linear memory
   - Calls `check_document()` and retrieves results

3. **Crypto (`crypto_sim.c`)** - Cryptographic operations
   - SHA-256 hashing (OpenSSL in simulation, SGX APIs in hardware)
   - ECDSA signing
   - Timestamp generation

### File Structure

```
harness/
├── include/
│   └── harness.h           # API definitions
├── src/
│   ├── harness.c           # Main harness logic
│   ├── wasm_runtime.c      # WAMR integration
│   ├── crypto_sim.c        # Crypto (simulation mode)
│   └── main.c              # CLI entry point
├── wasm-challenger/
│   └── pii_detector.c      # Sample PII detector
├── Dockerfile              # Build environment
├── harness.sh              # Build/run helper
└── README.md
```

## SGX Deployment

### Simulation Mode (Current)

The current implementation runs in simulation mode - it doesn't require SGX hardware but also doesn't provide hardware-based security. Use this for:
- Development and testing
- Hackathon demos
- Understanding the protocol

### Hardware SGX Mode (Future)

For production deployment with real security guarantees:

1. **Azure Confidential Computing**
   - Use DCsv3 or DCdsv3 series VMs
   - Install Intel SGX SDK and PSW
   - Build with `SGX_MODE=HW`

2. **On-premises SGX**
   - Requires SGX-capable CPU (Intel Xeon Scalable, etc.)
   - Install SGX driver, SDK, and PSW
   - Configure attestation service (Intel IAS or DCAP)

### Key Differences in SGX Mode

| Aspect | Simulation | Hardware SGX |
|--------|------------|--------------|
| Signing key | Ephemeral or file | Derived from MRENCLAVE |
| Memory protection | None | CPU-encrypted (EPC) |
| Attestation | Self-signed | Intel-rooted quote |
| Trusted time | System clock | `sgx_get_trusted_time()` |

## Protocol Flow

1. **Challenger** provides:
   - WASM module implementing `check_document()`
   - Fresh nonce for replay protection

2. **Data Provider** runs harness in TEE:
   - Copies each document into TEE memory
   - Computes Merkle root of all document hashes
   - Runs WASM against each document
   - Signs attestation including results

3. **Judge** verifies:
   - Signature chain back to trusted root (in HW mode: Intel)
   - WASM module hash matches submitted challenger
   - Nonce is fresh
   - If unsafe document claimed: document hash is in Merkle tree

## Limitations & Future Work

### Current Limitations

- **Simulation only**: No hardware security guarantees
- **Single-document isolation**: WASM module persists state between documents
- **No remote attestation**: Would require Intel attestation service integration

### Future Enhancements

- [ ] Full SGX hardware mode with DCAP attestation
- [ ] Fresh WASM instance per document (stronger isolation)
- [ ] AOT compilation for better performance
- [ ] Multi-party verification protocol
- [ ] Reproducible builds for MRENCLAVE verification

## License

MIT License - See LICENSE file for details.

## References

- [WAMR (WebAssembly Micro Runtime)](https://github.com/bytecodealliance/wasm-micro-runtime)
- [Intel SGX Developer Guide](https://download.01.org/intel-sgx/sgx-linux/2.17.1/docs/)
- [Azure Confidential Computing](https://learn.microsoft.com/en-us/azure/confidential-computing/)
- [TWINE: SGX + WASM Research](https://arxiv.org/abs/2312.09087)
