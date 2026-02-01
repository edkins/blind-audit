/*
 * TEE Dataset Safety Harness
 * 
 * This harness runs inside an SGX enclave (or simulation mode) and:
 * 1. Receives a dataset and a challenger WASM module
 * 2. Computes Merkle root of the dataset
 * 3. Runs the WASM challenger against each document
 * 4. Signs an attestation of the results
 * 
 * The WASM module exports: check_document(ptr, len) -> i32 (1=unsafe, 0=safe)
 */

#ifndef HARNESS_H
#define HARNESS_H

#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define MAX_DOCUMENT_SIZE    (1024 * 1024)   /* 1MB max per document */
#define MAX_DOCUMENTS        1024
#define HASH_SIZE            32              /* SHA-256 */
#define SIGNATURE_SIZE       64              /* ECDSA P-256 */
#define MAX_PATH_LEN         256

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/* Result of running challenger against dataset */
typedef struct {
    uint8_t  dataset_merkle_root[HASH_SIZE];
    uint8_t  wasm_module_hash[HASH_SIZE];
    uint8_t  challenger_nonce[32];
    uint64_t timestamp;
    
    uint32_t total_documents;
    uint32_t unsafe_count;
    
    /* If any document flagged unsafe, include first one found */
    bool     has_flagged_document;
    uint32_t flagged_doc_index;
    uint8_t  flagged_doc_hash[HASH_SIZE];
    
    /* Signature over the above fields */
    uint8_t  signature[SIGNATURE_SIZE];
} AttestationResult;

/* Document metadata for Merkle tree */
typedef struct {
    uint8_t  hash[HASH_SIZE];
    uint32_t size;
    bool     flagged_unsafe;
} DocumentMeta;

/* ============================================================================
 * Harness API (called from untrusted code via ECALL in real SGX)
 * ============================================================================ */

/**
 * Initialize the harness with signing key
 * In real SGX: key would be sealed or derived from enclave identity
 * In simulation: loaded from file
 * 
 * Returns 0 on success, negative on error
 */
int harness_init(const char* key_path);

/**
 * Run the challenger WASM against a dataset
 * 
 * @param wasm_bytes      The challenger WASM module bytes
 * @param wasm_len        Length of WASM module
 * @param dataset_path    Path to directory containing documents (or manifest)
 * @param nonce           Challenger-provided nonce for freshness
 * @param nonce_len       Length of nonce
 * @param result          Output: attestation result
 * @param flagged_doc     Output: if document flagged, its contents (caller allocates)
 * @param flagged_doc_len In/out: size of flagged_doc buffer / actual size
 * 
 * Returns 0 on success, negative on error
 */
int harness_run_challenge(
    const uint8_t* wasm_bytes,
    uint32_t wasm_len,
    const char* dataset_path,
    const uint8_t* nonce,
    uint32_t nonce_len,
    AttestationResult* result,
    uint8_t* flagged_doc,
    uint32_t* flagged_doc_len
);

/**
 * Cleanup harness resources
 */
void harness_cleanup(void);

/* ============================================================================
 * Internal functions (implemented differently for SGX vs simulation)
 * ============================================================================ */

/* Cryptographic operations */
int crypto_sha256(const uint8_t* data, uint32_t len, uint8_t* hash);
int crypto_sign(const uint8_t* data, uint32_t len, uint8_t* signature);
uint64_t crypto_timestamp(void);

/* WASM runtime operations */
int wasm_runtime_setup(void);
int wasm_load_module(const uint8_t* bytes, uint32_t len);
int wasm_call_check_document(const uint8_t* doc, uint32_t len);
void wasm_unload_module(void);
void wasm_runtime_teardown(void);

#endif /* HARNESS_H */