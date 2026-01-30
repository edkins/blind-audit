# TEE Hackathon: AI Governance Challenge Framework

A demonstration framework for proving dataset safety using Trusted Execution Environments (TEEs).

## Overview

This project demonstrates a protocol where:

1. A **Data Provider** holds a private dataset and wants to prove it's "safe"
2. A **Challenger** writes detection scripts (as WebAssembly modules) to find unsafe content
3. The script runs inside a TEE, producing a signed attestation of results
4. A **Judge** (LLM-powered) verifies attestations and evaluates flagged documents
5. **Everyone** can see the public results

```
┌─────────────────┐     ┌─────────────────┐     ┌───────────────┐
│  Data Provider  │     │     Judge       │     │   Challenger  │
│  (TEE Host)     │────▶│  (Verifier)     │     │   (Auditor)   │
│                 │     │                 │     │               │
│  Port 8080      │     │  Port 8081      │     │  Browser      │
└─────────────────┘     └────────┬────────┘     └───────────────┘
                                 │
                        ┌────────▼────────┐
                        │  Results Board  │
                        │  Port 8082      │
                        └─────────────────┘
```

## Quick Start

```bash
# Build everything
./run.sh build

# Start services
./run.sh start

# View logs
./run.sh logs
```

Then open:
- http://localhost:8080 - Submit challenges
- http://localhost:8082 - View results

## Architecture

### Components

| Service | Port | Purpose |
|---------|------|---------|
| Data Provider | 8080 | Hosts dataset, runs WASM challenges in TEE, signs attestations |
| Judge | 8081 | Verifies attestations, evaluates flagged docs with LLM |
| Results Board | 8082 | Public display of all challenge results |

### Trust Model

```
Demo Root CA
    │
    └── Attestation Authority (Intermediate)
            │
            └── TEE Signing Key (Data Provider)
```

- **Judge** trusts only the Root CA certificate
- **Data Provider** has the TEE signing key
- **Challengers** trust the Judge (and by extension, the PKI)

### Attestation Package

When a challenge completes, the Data Provider creates:

```json
{
  "quote": {
    "mrenclave": "<hash of WASM module>",
    "dataset_merkle_root": "<hash of dataset>",
    "result_document_hash": "<hash of flagged doc or null>",
    "challenger_nonce": "<freshness proof>",
    "timestamp": "2024-..."
  },
  "signature": "<signed with TEE key>",
  "cert_chain": "<TEE cert -> Intermediate>",
  "wasm_module": "<base64 WASM>",
  "document": "<the flagged document, if any>"
}
```

## Writing Challenge Modules

Challenge modules are WebAssembly binaries that:

1. Read JSON lines from stdin:
   ```json
   {"filename": "doc.txt", "hash": "abc123...", "content": "<base64>"}
   ```

2. Output results to stdout:
   - `UNSAFE:<filename>` for each unsafe document
   - `SAFE` if no unsafe documents found

### Example (Rust)

See `shared/sample-challenges/pii_detector.rs` for a complete example.

Compile with:
```bash
rustup target add wasm32-wasi
cargo build --target wasm32-wasi --release
```

## Simulation vs Real TEE

This demo uses **simulated** TEE execution:

| Aspect | Simulation | Real SGX |
|--------|------------|----------|
| Code runs | In regular process | In hardware enclave |
| Attestation | Signed with software key | Signed by CPU |
| Trust | Demo PKI | Intel's PKI |
| Cheating | Data Provider could lie | Hardware prevents lying |

For a hackathon demo, simulation is sufficient to demonstrate the **protocol**. In production, you'd use real SGX hardware (available on Azure DCsv2/v3 VMs).

## Configuration

### Environment Variables

Create a `.env` file:

```bash
# For LLM-based document evaluation
ANTHROPIC_API_KEY=sk-ant-...
# Or
OPENAI_API_KEY=sk-...
```

Without an API key, the Judge will mark documents as "UNKNOWN" instead of evaluating them.

### Dataset

Place documents in `shared/dataset/`. The Data Provider will compute a Merkle root of all files.

## Development

```bash
# Rebuild after code changes
./run.sh build

# Reset PKI (regenerate certificates)
./run.sh reset-pki

# Clean everything
./run.sh clean
```

## Limitations & Future Work

- **No real SGX**: This is a simulation. Real hardware attestation requires SGX-capable CPUs.
- **Simple Merkle tree**: Production would use a proper Merkle tree with proofs.
- **Single document output**: Currently only one flagged document is sent to Judge.
- **No rate limiting**: A real system would limit challenge frequency.
- **Randomness**: The random document selection should use verifiable randomness.

## License

MIT - For hackathon/educational purposes.
