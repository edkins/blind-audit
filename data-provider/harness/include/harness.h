/*
 * TEE Harness CLI - Test Tool
 * 
 * This provides a command-line interface to test the harness
 * without the full HTTP server infrastructure.
 * 
 * Usage:
 *   ./harness-cli --wasm <challenger.wasm> --dataset <dir> [--key <key.pem>]
 */

#include "harness.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

/* External crypto init (from crypto_sim.c) */
extern int crypto_init(const char* key_path);
extern void crypto_cleanup(void);
extern int crypto_export_public_key(char* pem_buf, size_t buf_len);

/* Print usage */
static void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\nRequired:\n");
    printf("  --wasm <file>      Path to challenger WASM module\n");
    printf("  --dataset <dir>    Path to dataset directory\n");
    printf("\nOptional:\n");
    printf("  --key <file>       Path to signing key PEM (default: generate ephemeral)\n");
    printf("  --nonce <hex>      Challenge nonce in hex (default: random)\n");
    printf("  --output <file>    Write attestation JSON to file\n");
    printf("  --help             Show this help\n");
}

/* Convert bytes to hex string */
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i*2, "%02x", bytes[i]);
    }
}

/* Read file into buffer */
static uint8_t* read_file(const char* path, uint32_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", path);
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* buffer = malloc(*size);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    if (fread(buffer, 1, *size, f) != *size) {
        free(buffer);
        fclose(f);
        return NULL;
    }
    
    fclose(f);
    return buffer;
}

/* Generate random nonce */
static void generate_nonce(uint8_t* nonce, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(nonce, 1, len, f);
        fclose(f);
    } else {
        /* Fallback to time-based (not cryptographically secure) */
        srand(time(NULL));
        for (size_t i = 0; i < len; i++) {
            nonce[i] = rand() & 0xFF;
        }
    }
}

int main(int argc, char** argv) {
    const char* wasm_path = NULL;
    const char* dataset_path = NULL;
    const char* key_path = NULL;
    const char* output_path = NULL;
    uint8_t nonce[32];
    int nonce_provided = 0;
    
    /* Parse arguments */
    static struct option long_opts[] = {
        {"wasm",    required_argument, 0, 'w'},
        {"dataset", required_argument, 0, 'd'},
        {"key",     required_argument, 0, 'k'},
        {"nonce",   required_argument, 0, 'n'},
        {"output",  required_argument, 0, 'o'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "w:d:k:n:o:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'w':
                wasm_path = optarg;
                break;
            case 'd':
                dataset_path = optarg;
                break;
            case 'k':
                key_path = optarg;
                break;
            case 'n':
                /* Parse hex nonce */
                if (strlen(optarg) != 64) {
                    fprintf(stderr, "Nonce must be 64 hex characters (32 bytes)\n");
                    return 1;
                }
                for (int i = 0; i < 32; i++) {
                    unsigned int byte;
                    sscanf(optarg + i*2, "%02x", &byte);
                    nonce[i] = byte;
                }
                nonce_provided = 1;
                break;
            case 'o':
                output_path = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    /* Validate required args */
    if (!wasm_path || !dataset_path) {
        fprintf(stderr, "Error: --wasm and --dataset are required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Generate nonce if not provided */
    if (!nonce_provided) {
        generate_nonce(nonce, sizeof(nonce));
    }
    
    printf("=== TEE Dataset Safety Harness ===\n\n");
    
    /* Initialize crypto */
    if (crypto_init(key_path) != 0) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return 1;
    }
    
    /* Initialize harness */
    if (harness_init(key_path) != 0) {
        fprintf(stderr, "Failed to initialize harness\n");
        crypto_cleanup();
        return 1;
    }
    
    /* Load WASM module */
    uint32_t wasm_len;
    uint8_t* wasm_bytes = read_file(wasm_path, &wasm_len);
    if (!wasm_bytes) {
        harness_cleanup();
        crypto_cleanup();
        return 1;
    }
    
    printf("Loaded WASM: %s (%u bytes)\n", wasm_path, wasm_len);
    printf("Dataset: %s\n", dataset_path);
    
    char nonce_hex[65];
    bytes_to_hex(nonce, 32, nonce_hex);
    printf("Nonce: %s\n\n", nonce_hex);
    
    /* Run the challenge */
    AttestationResult result;
    uint8_t flagged_doc[MAX_DOCUMENT_SIZE];
    uint32_t flagged_doc_len = sizeof(flagged_doc);
    
    int ret = harness_run_challenge(
        wasm_bytes, wasm_len,
        dataset_path,
        nonce, sizeof(nonce),
        &result,
        flagged_doc, &flagged_doc_len
    );
    
    free(wasm_bytes);
    
    if (ret != 0) {
        fprintf(stderr, "Challenge failed\n");
        harness_cleanup();
        crypto_cleanup();
        return 1;
    }
    
    /* Print results */
    printf("\n=== Attestation Result ===\n\n");
    
    char hex[128];
    
    bytes_to_hex(result.dataset_merkle_root, HASH_SIZE, hex);
    printf("Dataset Merkle Root: %s\n", hex);
    
    bytes_to_hex(result.wasm_module_hash, HASH_SIZE, hex);
    printf("WASM Module Hash:    %s\n", hex);
    
    printf("Timestamp:           %lu\n", (unsigned long)result.timestamp);
    printf("Total Documents:     %u\n", result.total_documents);
    printf("Unsafe Documents:    %u\n", result.unsafe_count);
    
    if (result.has_flagged_document) {
        printf("\n--- First Flagged Document ---\n");
        printf("Index: %u\n", result.flagged_doc_index);
        bytes_to_hex(result.flagged_doc_hash, HASH_SIZE, hex);
        printf("Hash:  %s\n", hex);
        printf("Size:  %u bytes\n", flagged_doc_len);
        
        /* Show preview */
        printf("Preview (first 200 chars):\n");
        size_t preview_len = flagged_doc_len < 200 ? flagged_doc_len : 200;
        printf("---\n");
        fwrite(flagged_doc, 1, preview_len, stdout);
        if (flagged_doc_len > preview_len) printf("...");
        printf("\n---\n");
    } else {
        printf("\nNo unsafe documents found.\n");
    }
    
    bytes_to_hex(result.signature, SIGNATURE_SIZE, hex);
    printf("\nSignature: %s\n", hex);
    
    /* Write JSON output if requested */
    if (output_path) {
        FILE* out = fopen(output_path, "w");
        if (out) {
            char merkle_hex[65], wasm_hex[65], nonce_hex[65], sig_hex[129];
            char flagged_hex[65] = "";
            
            bytes_to_hex(result.dataset_merkle_root, HASH_SIZE, merkle_hex);
            bytes_to_hex(result.wasm_module_hash, HASH_SIZE, wasm_hex);
            bytes_to_hex(result.challenger_nonce, 32, nonce_hex);
            bytes_to_hex(result.signature, SIGNATURE_SIZE, sig_hex);
            
            if (result.has_flagged_document) {
                bytes_to_hex(result.flagged_doc_hash, HASH_SIZE, flagged_hex);
            }
            
            fprintf(out, "{\n");
            fprintf(out, "  \"quote\": {\n");
            fprintf(out, "    \"dataset_merkle_root\": \"%s\",\n", merkle_hex);
            fprintf(out, "    \"wasm_module_hash\": \"%s\",\n", wasm_hex);
            fprintf(out, "    \"challenger_nonce\": \"%s\",\n", nonce_hex);
            fprintf(out, "    \"timestamp\": %lu,\n", (unsigned long)result.timestamp);
            fprintf(out, "    \"total_documents\": %u,\n", result.total_documents);
            fprintf(out, "    \"unsafe_count\": %u,\n", result.unsafe_count);
            fprintf(out, "    \"flagged_doc_index\": %d,\n", 
                    result.has_flagged_document ? (int)result.flagged_doc_index : -1);
            fprintf(out, "    \"flagged_doc_hash\": \"%s\"\n", flagged_hex);
            fprintf(out, "  },\n");
            fprintf(out, "  \"signature\": \"%s\"\n", sig_hex);
            fprintf(out, "}\n");
            
            fclose(out);
            printf("\nWrote attestation to: %s\n", output_path);
        }
    }
    
    /* Cleanup */
    harness_cleanup();
    crypto_cleanup();
    
    printf("\nDone.\n");
    return 0;
}