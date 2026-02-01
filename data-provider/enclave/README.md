# Nitro Enclave WASM Verifier

A TEE-based system for verifiable execution of WASM challenges against document datasets.

## Overview

This system allows:
1. A challenger to submit a WASM module that examines documents
2. The enclave to execute the module against each document
3. Attestation that proves the specific code ran against the specific data

## Files

- `enclave_server.c` - C server that runs inside the enclave
- `enclave_client.py` - Python client that runs on the parent instance
- `Dockerfile.enclave` - Docker build for the enclave image
- `Makefile` - Build automation
- `nsm.h` / `nsm.c` - NSM (Nitro Secure Module) interface for attestation

## Quick Start

### On your EC2 instance (with Nitro Enclaves enabled):

```bash
# 1. Copy all files to the instance
scp *.c *.h *.py Dockerfile.enclave Makefile ec2-user@<instance>:~/enclave/

# 2. SSH in
ssh ec2-user@<instance>
cd enclave

# 3. Build and run the enclave
make run-enclave-debug

# 4. In another terminal, view console output
make console

# 5. In another terminal, test the client
make test
```

### Manual steps:

```bash
# Build Docker image
docker build -f Dockerfile.enclave -t enclave-server .

# Build EIF
nitro-cli build-enclave --docker-uri enclave-server:latest --output-file enclave-server.eif

# Run enclave
nitro-cli run-enclave --eif-path enclave-server.eif --cpu-count 2 --memory 512 --debug-mode

# Get the CID
CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')

# Test
python3 enclave_client.py --cid $CID --test
```

## Protocol

### Request Format (binary, big-endian)

```
[4 bytes] total_length
[4 bytes] wasm_length
[wasm_length bytes] wasm_module
[4 bytes] num_documents
For each document:
  [4 bytes] doc_length
  [doc_length bytes] document_data
```

### Response Format

```
[4 bytes] total_length
[4 bytes] status (0 = success)
[32 bytes] wasm_hash (SHA-256)
[32 bytes] documents_hash (SHA-256 of concatenated doc hashes)
[4 bytes] result_length
[result_length bytes] result_data
[4 bytes] attestation_length
[attestation_length bytes] attestation_document
```

## Attestation

The attestation document is a COSE_Sign1 structure signed by AWS Nitro Attestation PKI containing:

- **PCR0**: Hash of the enclave image (your code)
- **PCR1**: Hash of the Linux kernel and bootstrap
- **PCR2**: Hash of the application
- **user_data**: Your custom data (we include wasm_hash + docs_hash + result_hash)

To verify attestation:
1. Parse the COSE_Sign1 structure
2. Verify signature against AWS Nitro root certificate
3. Check PCR0 matches your expected enclave measurement
4. Verify user_data matches what you expect

AWS root cert: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip

## Security Model

**What the enclave protects:**
- The parent EC2 instance (even root) cannot see inside the enclave
- The attestation proves specific code processed specific data

**What it doesn't protect (in this demo):**
- AWS itself could theoretically inspect enclave memory
- For full protection from cloud provider, use SGX (Azure DCsv3)

## Integration with Your Harness

Replace the dummy processing in `enclave_server.c`:

```c
/* In handle_request(), after parsing documents: */

/* TODO: Your WASM execution logic here */
/* 1. Load WASM module using your runtime (wasmtime, wasmer, etc.) */
/* 2. For each document, call the WASM challenge function */
/* 3. Collect results */

const char *result = "Your actual results here";
```

## Troubleshooting

**Enclave crashes immediately:**
- Check console with `nitro-cli console --enclave-id <id>`
- Ensure the Docker image runs standalone: `docker run -it enclave-server`

**Socket errors:**
- Enclave probably exited - check `nitro-cli describe-enclaves`
- Look at `/var/log/nitro_enclaves/nitro_enclaves.log`

**Can't connect from client:**
- Verify CID matches: `nitro-cli describe-enclaves | jq '.[0].EnclaveCID'`
- Ensure enclave is still running (not terminated)
