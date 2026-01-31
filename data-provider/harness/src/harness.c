/*
 * TEE Dataset Safety Harness - Main Implementation
 * 
 * This file contains the core logic that runs inside the TEE.
 * It's designed to work with both real SGX and simulation mode.
 */

#include "harness.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* ============================================================================
 * Merkle Tree Implementation
 * ============================================================================ */

static uint8_t g_merkle_leaves[MAX_DOCUMENTS][HASH_SIZE];
static uint32_t g_num_leaves = 0;

static void merkle_reset(void) {
    g_num_leaves = 0;
    memset(g_merkle_leaves, 0, sizeof(g_merkle_leaves));
}

static int merkle_add_leaf(const uint8_t* hash) {
    if (g_num_leaves >= MAX_DOCUMENTS) {
        return -1;
    }
    memcpy(g_merkle_leaves[g_num_leaves], hash, HASH_SIZE);
    g_num_leaves++;
    return 0;
}

/* Compute Merkle root from leaves */
static int merkle_compute_root(uint8_t* root) {
    if (g_num_leaves == 0) {
        memset(root, 0, HASH_SIZE);
        return 0;
    }
    
    if (g_num_leaves == 1) {
        memcpy(root, g_merkle_leaves[0], HASH_SIZE);
        return 0;
    }
    
    /* Work buffer for tree computation */
    uint8_t tree[MAX_DOCUMENTS][HASH_SIZE];
    uint32_t level_size = g_num_leaves;
    
    /* Copy leaves to working buffer */
    memcpy(tree, g_merkle_leaves, g_num_leaves * HASH_SIZE);
    
    /* Build tree bottom-up */
    while (level_size > 1) {
        uint32_t next_level_size = 0;
        
        for (uint32_t i = 0; i < level_size; i += 2) {
            uint8_t concat[HASH_SIZE * 2];
            
            if (i + 1 < level_size) {
                /* Hash pair */
                memcpy(concat, tree[i], HASH_SIZE);
                memcpy(concat + HASH_SIZE, tree[i + 1], HASH_SIZE);
            } else {
                /* Odd node - duplicate it */
                memcpy(concat, tree[i], HASH_SIZE);
                memcpy(concat + HASH_SIZE, tree[i], HASH_SIZE);
            }
            
            if (crypto_sha256(concat, HASH_SIZE * 2, tree[next_level_size]) != 0) {
                return -1;
            }
            next_level_size++;
        }
        
        level_size = next_level_size;
    }
    
    memcpy(root, tree[0], HASH_SIZE);
    return 0;
}

/* ============================================================================
 * Document Processing
 * ============================================================================ */

static DocumentMeta g_documents[MAX_DOCUMENTS];
static uint32_t g_num_documents = 0;

/* Read and process a single document */
static int process_document(const char* path, uint32_t index) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[harness] Failed to open document: %s\n", path);
        return -1;
    }
    
    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size > MAX_DOCUMENT_SIZE) {
        fprintf(stderr, "[harness] Document too large: %s (%ld bytes)\n", path, size);
        fclose(f);
        return -1;
    }
    
    /* Read document */
    uint8_t* buffer = malloc(size);
    if (!buffer) {
        fclose(f);
        return -1;
    }
    
    if (fread(buffer, 1, size, f) != (size_t)size) {
        free(buffer);
        fclose(f);
        return -1;
    }
    fclose(f);
    
    /* Compute hash */
    if (crypto_sha256(buffer, size, g_documents[index].hash) != 0) {
        free(buffer);
        return -1;
    }
    
    /* Add to Merkle tree */
    merkle_add_leaf(g_documents[index].hash);
    
    g_documents[index].size = size;
    g_documents[index].flagged_unsafe = false;
    
    /* Run WASM challenger on this document */
    int result = wasm_call_check_document(buffer, size);
    
    if (result > 0) {
        printf("[harness] Document %u flagged as UNSAFE\n", index);
        g_documents[index].flagged_unsafe = true;
    } else if (result == 0) {
        printf("[harness] Document %u: safe\n", index);
    } else {
        fprintf(stderr, "[harness] WASM error checking document %u\n", index);
    }
    
    free(buffer);
    return result >= 0 ? 0 : -1;
}

/* ============================================================================
 * Main Harness Entry Points
 * ============================================================================ */

static bool g_initialized = false;

int harness_init(const char* key_path) {
    if (g_initialized) {
        return 0;  /* Already initialized */
    }
    
    printf("[harness] Initializing TEE harness...\n");
    
    /* Initialize WASM runtime */
    if (wasm_runtime_setup() != 0) {
        fprintf(stderr, "[harness] Failed to initialize WASM runtime\n");
        return -1;
    }
    
    /* In real SGX: would load sealed key or derive from MRENCLAVE 
     * In simulation: we might load from key_path if provided */
    (void)key_path;  /* TODO: implement key loading */
    
    g_initialized = true;
    printf("[harness] Initialization complete\n");
    return 0;
}

int harness_run_challenge(
    const uint8_t* wasm_bytes,
    uint32_t wasm_len,
    const char* dataset_path,
    const uint8_t* nonce,
    uint32_t nonce_len,
    AttestationResult* result,
    uint8_t* flagged_doc,
    uint32_t* flagged_doc_len
) {
    if (!g_initialized) {
        fprintf(stderr, "[harness] Not initialized\n");
        return -1;
    }
    
    printf("[harness] Starting challenge run\n");
    printf("[harness]   WASM module: %u bytes\n", wasm_len);
    printf("[harness]   Dataset: %s\n", dataset_path);
    
    /* Clear result */
    memset(result, 0, sizeof(AttestationResult));
    
    /* Store nonce */
    if (nonce_len > sizeof(result->challenger_nonce)) {
        nonce_len = sizeof(result->challenger_nonce);
    }
    memcpy(result->challenger_nonce, nonce, nonce_len);
    
    /* Compute WASM module hash */
    if (crypto_sha256(wasm_bytes, wasm_len, result->wasm_module_hash) != 0) {
        return -1;
    }
    printf("[harness] WASM hash computed\n");
    
    /* Load WASM module */
    if (wasm_load_module(wasm_bytes, wasm_len) != 0) {
        fprintf(stderr, "[harness] Failed to load WASM module\n");
        return -1;
    }
    printf("[harness] WASM module loaded\n");
    
    /* Reset document tracking */
    merkle_reset();
    g_num_documents = 0;
    
    /* Process all documents in the dataset directory */
    DIR* dir = opendir(dataset_path);
    if (!dir) {
        fprintf(stderr, "[harness] Failed to open dataset directory\n");
        wasm_unload_module();
        return -1;
    }
    
    struct dirent* entry;
    char filepath[MAX_PATH_LEN];
    
    while ((entry = readdir(dir)) != NULL && g_num_documents < MAX_DOCUMENTS) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') continue;
        
        /* Build full path */
        snprintf(filepath, sizeof(filepath), "%s/%s", dataset_path, entry->d_name);
        
        /* Check if it's a regular file */
        struct stat st;
        if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        
        printf("[harness] Processing: %s\n", entry->d_name);
        
        if (process_document(filepath, g_num_documents) == 0) {
            /* Check if this document was flagged */
            if (g_documents[g_num_documents].flagged_unsafe) {
                result->unsafe_count++;
                
                /* Store first flagged document */
                if (!result->has_flagged_document) {
                    result->has_flagged_document = true;
                    result->flagged_doc_index = g_num_documents;
                    memcpy(result->flagged_doc_hash, 
                           g_documents[g_num_documents].hash, 
                           HASH_SIZE);
                    
                    /* Copy document content if buffer provided */
                    if (flagged_doc && flagged_doc_len && *flagged_doc_len > 0) {
                        FILE* f = fopen(filepath, "rb");
                        if (f) {
                            size_t to_read = g_documents[g_num_documents].size;
                            if (to_read > *flagged_doc_len) {
                                to_read = *flagged_doc_len;
                            }
                            *flagged_doc_len = fread(flagged_doc, 1, to_read, f);
                            fclose(f);
                        }
                    }
                }
            }
            g_num_documents++;
        }
    }
    
    closedir(dir);
    
    result->total_documents = g_num_documents;
    printf("[harness] Processed %u documents, %u flagged unsafe\n",
           result->total_documents, result->unsafe_count);
    
    /* Compute Merkle root */
    if (merkle_compute_root(result->dataset_merkle_root) != 0) {
        wasm_unload_module();
        return -1;
    }
    printf("[harness] Merkle root computed\n");
    
    /* Get timestamp */
    result->timestamp = crypto_timestamp();
    
    /* Sign the attestation 
     * We sign: merkle_root || wasm_hash || nonce || timestamp || counts || flagged_hash */
    uint8_t to_sign[256];
    uint32_t offset = 0;
    
    memcpy(to_sign + offset, result->dataset_merkle_root, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(to_sign + offset, result->wasm_module_hash, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(to_sign + offset, result->challenger_nonce, 32);
    offset += 32;
    memcpy(to_sign + offset, &result->timestamp, 8);
    offset += 8;
    memcpy(to_sign + offset, &result->total_documents, 4);
    offset += 4;
    memcpy(to_sign + offset, &result->unsafe_count, 4);
    offset += 4;
    if (result->has_flagged_document) {
        memcpy(to_sign + offset, result->flagged_doc_hash, HASH_SIZE);
        offset += HASH_SIZE;
    }
    
    if (crypto_sign(to_sign, offset, result->signature) != 0) {
        fprintf(stderr, "[harness] Failed to sign attestation\n");
        wasm_unload_module();
        return -1;
    }
    
    printf("[harness] Attestation signed\n");
    
    /* Cleanup */
    wasm_unload_module();
    
    return 0;
}

void harness_cleanup(void) {
    if (g_initialized) {
        wasm_runtime_teardown();
        g_initialized = false;
    }
}
