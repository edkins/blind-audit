/*
 * Crypto Implementation - Simulation Mode
 * 
 * This provides the crypto_* functions for non-SGX builds.
 * Uses OpenSSL for SHA-256 and ECDSA.
 * 
 * In real SGX: These would be replaced with SGX-specific implementations
 * that use sealed keys and the enclave's trusted time source.
 */

#include "harness.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Key Management (Simulation Mode)
 * 
 * In simulation, we generate an ephemeral key or load from file.
 * In real SGX, the key would be:
 *   - Derived from MRENCLAVE (deterministic for this enclave binary)
 *   - Or sealed and stored, retrieved via sgx_unseal_data()
 * ============================================================================ */

static EVP_PKEY* g_signing_key = NULL;

/* Generate a new ECDSA P-256 key (for demo purposes) */
static int generate_signing_key(void) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return -1;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_PKEY_keygen(ctx, &g_signing_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    printf("[crypto] Generated ephemeral ECDSA P-256 signing key\n");
    return 0;
}

/* Load signing key from PEM file */
static int load_signing_key(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[crypto] Cannot open key file: %s\n", path);
        return -1;
    }
    
    g_signing_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    
    if (!g_signing_key) {
        fprintf(stderr, "[crypto] Failed to load key from %s\n", path);
        return -1;
    }
    
    printf("[crypto] Loaded signing key from %s\n", path);
    return 0;
}

/* Initialize crypto (called from harness_init) */
int crypto_init(const char* key_path) {
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (key_path && key_path[0] != '\0') {
        return load_signing_key(key_path);
    } else {
        return generate_signing_key();
    }
}

/* Cleanup crypto resources */
void crypto_cleanup(void) {
    if (g_signing_key) {
        EVP_PKEY_free(g_signing_key);
        g_signing_key = NULL;
    }
    EVP_cleanup();
    ERR_free_strings();
}

/* ============================================================================
 * Cryptographic Operations
 * ============================================================================ */

int crypto_sha256(const uint8_t* data, uint32_t len, uint8_t* hash) {
    SHA256_CTX ctx;
    
    if (!SHA256_Init(&ctx)) return -1;
    if (!SHA256_Update(&ctx, data, len)) return -1;
    if (!SHA256_Final(hash, &ctx)) return -1;
    
    return 0;
}

int crypto_sign(const uint8_t* data, uint32_t len, uint8_t* signature) {
    if (!g_signing_key) {
        fprintf(stderr, "[crypto] No signing key available\n");
        return -1;
    }
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return -1;
    
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, g_signing_key) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    
    if (EVP_DigestSignUpdate(md_ctx, data, len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    
    /* Get signature length */
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    
    /* ECDSA signatures are DER-encoded, typically 70-72 bytes for P-256 */
    uint8_t* der_sig = malloc(sig_len);
    if (!der_sig) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    
    if (EVP_DigestSignFinal(md_ctx, der_sig, &sig_len) <= 0) {
        free(der_sig);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(md_ctx);
    
    /* For simplicity, we store the DER-encoded signature
     * Truncate or pad to SIGNATURE_SIZE (64 bytes)
     * In production, you'd want proper handling */
    memset(signature, 0, SIGNATURE_SIZE);
    size_t copy_len = sig_len < SIGNATURE_SIZE ? sig_len : SIGNATURE_SIZE;
    memcpy(signature, der_sig, copy_len);
    
    free(der_sig);
    return 0;
}

uint64_t crypto_timestamp(void) {
    /* In real SGX: would use sgx_get_trusted_time() or similar 
     * In simulation: just use system time */
    return (uint64_t)time(NULL);
}

/* Export public key for verification (helper for demo) */
int crypto_export_public_key(char* pem_buf, size_t buf_len) {
    if (!g_signing_key) return -1;
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    
    if (!PEM_write_bio_PUBKEY(bio, g_signing_key)) {
        BIO_free(bio);
        return -1;
    }
    
    size_t pem_len = BIO_pending(bio);
    if (pem_len >= buf_len) {
        BIO_free(bio);
        return -1;
    }
    
    BIO_read(bio, pem_buf, pem_len);
    pem_buf[pem_len] = '\0';
    
    BIO_free(bio);
    return 0;
}