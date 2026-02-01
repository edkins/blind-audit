/*
 * Nitro Enclave vsock server
 * 
 * Listens for requests containing WASM modules + documents,
 * processes them, and returns attestation-backed responses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/vm_sockets.h>
#include <openssl/sha.h>
#include <cbor.h>

/* WASM Runtime Function Declarations */
int wasm_runtime_setup(void);
void wasm_runtime_teardown(void);
int wasm_load_module(const uint8_t* bytes, uint32_t len);
int wasm_call_check_document(const uint8_t* doc, uint32_t len);
void wasm_unload_module(void);

#define LISTEN_PORT 5000
#define BUFFER_SIZE (16 * 1024 * 1024)  /* 16 MB max message size */
#define NSM_DEVICE_PATH "/dev/nsm"
#define NSM_MAX_ATTESTATION_SIZE (16 * 1024)

/* NSM ioctl command - uses iovec-style structure */
/* Magic is 0x0A, command 0, read/write */
#define NSM_IOCTL_MAGIC 0x0A
#define NSM_IO_REQUEST _IOWR(NSM_IOCTL_MAGIC, 0, struct nsm_message)

/* 
 * NSM message structure - matches the Rust IoSlice/IoSliceMut layout
 * which is equivalent to struct iovec
 */
struct nsm_iovec {
    void *iov_base;
    size_t iov_len;
};

struct nsm_message {
    struct nsm_iovec request;
    struct nsm_iovec response;
};

/* Helper to read big-endian uint32 */
static uint32_t read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

/* Helper to write big-endian uint32 */
static void write_u32_be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

/* Read exactly n bytes from socket */
static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, buf + total, n - total);
        if (r <= 0) {
            if (r < 0) perror("read");
            return -1;
        }
        total += r;
    }
    return 0;
}

/* Write exactly n bytes to socket */
static int write_exact(int fd, const uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, buf + total, n - total);
        if (w <= 0) {
            if (w < 0) perror("write");
            return -1;
        }
        total += w;
    }
    return 0;
}

/* Hash helper */
static void sha256(const uint8_t *data, size_t len, uint8_t *out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

/*
 * Build CBOR attestation request
 * 
 * Structure: { "Attestation": { "user_data": <bytes>, "nonce": null, "public_key": null } }
 */
static int build_attestation_request(const uint8_t *user_data, size_t user_data_len,
                                      uint8_t **out_buf, size_t *out_len) {
    /* Build inner map: { "user_data": <bytes> } */
    cbor_item_t *inner_map = cbor_new_definite_map(1);
    if (!inner_map) return -1;
    
    cbor_item_t *key_user_data = cbor_build_string("user_data");
    cbor_item_t *val_user_data = cbor_build_bytestring(user_data, user_data_len);
    
    if (!key_user_data || !val_user_data) {
        cbor_decref(&inner_map);
        return -1;
    }
    
    cbor_map_add(inner_map, (struct cbor_pair){
        .key = key_user_data,
        .value = val_user_data
    });
    
    /* Build outer map: { "Attestation": <inner_map> } */
    cbor_item_t *outer_map = cbor_new_definite_map(1);
    if (!outer_map) {
        cbor_decref(&inner_map);
        return -1;
    }
    
    cbor_item_t *key_attestation = cbor_build_string("Attestation");
    
    cbor_map_add(outer_map, (struct cbor_pair){
        .key = key_attestation,
        .value = inner_map  /* inner_map ownership transferred */
    });
    
    /* Serialize to bytes */
    *out_len = cbor_serialize_alloc(outer_map, out_buf, out_len);
    
    cbor_decref(&outer_map);
    
    return (*out_len > 0) ? 0 : -1;
}

/*
 * Parse CBOR attestation response and extract the document
 * 
 * Expected structure: { "Attestation": { "document": <bytes> } }
 */
static int parse_attestation_response(const uint8_t *response, size_t response_len,
                                       uint8_t *doc_out, size_t *doc_len) {
    struct cbor_load_result result;
    cbor_item_t *root = cbor_load(response, response_len, &result);
    
    if (!root || result.error.code != CBOR_ERR_NONE) {
        fprintf(stderr, "Failed to parse CBOR response: error %d\n", result.error.code);
        if (root) cbor_decref(&root);
        return -1;
    }
    
    if (!cbor_isa_map(root)) {
        fprintf(stderr, "Response is not a map\n");
        cbor_decref(&root);
        return -1;
    }
    
    /* Look for "Attestation" key */
    size_t map_size = cbor_map_size(root);
    struct cbor_pair *pairs = cbor_map_handle(root);
    
    cbor_item_t *attestation_val = NULL;
    for (size_t i = 0; i < map_size; i++) {
        if (cbor_isa_string(pairs[i].key)) {
            size_t key_len = cbor_string_length(pairs[i].key);
            const char *key_str = (const char *)cbor_string_handle(pairs[i].key);
            if (key_len == 11 && strncmp(key_str, "Attestation", 11) == 0) {
                attestation_val = pairs[i].value;
                break;
            }
        }
    }
    
    if (!attestation_val || !cbor_isa_map(attestation_val)) {
        fprintf(stderr, "No Attestation map in response\n");
        cbor_decref(&root);
        return -1;
    }
    
    /* Look for "document" key in the Attestation map */
    size_t att_size = cbor_map_size(attestation_val);
    struct cbor_pair *att_pairs = cbor_map_handle(attestation_val);
    
    cbor_item_t *document_val = NULL;
    for (size_t i = 0; i < att_size; i++) {
        if (cbor_isa_string(att_pairs[i].key)) {
            size_t key_len = cbor_string_length(att_pairs[i].key);
            const char *key_str = (const char *)cbor_string_handle(att_pairs[i].key);
            if (key_len == 8 && strncmp(key_str, "document", 8) == 0) {
                document_val = att_pairs[i].value;
                break;
            }
        }
    }
    
    if (!document_val || !cbor_isa_bytestring(document_val)) {
        fprintf(stderr, "No document bytestring in Attestation\n");
        cbor_decref(&root);
        return -1;
    }
    
    /* Extract document bytes */
    size_t doc_size = cbor_bytestring_length(document_val);
    uint8_t *doc_data = cbor_bytestring_handle(document_val);
    
    if (doc_size > *doc_len) {
        fprintf(stderr, "Document too large: %zu > %zu\n", doc_size, *doc_len);
        cbor_decref(&root);
        return -1;
    }
    
    memcpy(doc_out, doc_data, doc_size);
    *doc_len = doc_size;
    
    cbor_decref(&root);
    return 0;
}

/*
 * Get attestation document from Nitro hypervisor
 */
static int get_attestation_document(const uint8_t *user_data, size_t user_data_len,
                                     uint8_t *attestation_out, size_t *attestation_len) {
    int fd = open(NSM_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Warning: /dev/nsm not available (%s), using placeholder attestation\n",
                strerror(errno));
        
        const char *placeholder = "PLACEHOLDER_ATTESTATION_NSM_NOT_AVAILABLE";
        size_t plen = strlen(placeholder);
        
        if (plen > *attestation_len) {
            return -1;
        }
        
        memcpy(attestation_out, placeholder, plen);
        *attestation_len = plen;
        return 0;
    }
    
    /* Build CBOR request */
    uint8_t *request_buf = NULL;
    size_t request_len = 0;
    
    if (build_attestation_request(user_data, user_data_len, &request_buf, &request_len) < 0) {
        fprintf(stderr, "Failed to build attestation request\n");
        close(fd);
        return -1;
    }
    
    /* Prepare response buffer */
    uint8_t *response_buf = malloc(NSM_MAX_ATTESTATION_SIZE);
    if (!response_buf) {
        free(request_buf);
        close(fd);
        return -1;
    }
    
    /* Make ioctl request */
    struct nsm_message msg = {
        .request = {
            .iov_base = request_buf,
            .iov_len = request_len,
        },
        .response = {
            .iov_base = response_buf,
            .iov_len = NSM_MAX_ATTESTATION_SIZE,
        },
    };
    
    int ret = ioctl(fd, NSM_IO_REQUEST, &msg);
    close(fd);
    free(request_buf);
    
    if (ret < 0) {
        fprintf(stderr, "NSM ioctl failed: %s\n", strerror(errno));
        free(response_buf);
        return -1;
    }
    
    fprintf(stderr, "NSM returned %zu bytes\n", msg.response.iov_len);
    
    /* Parse CBOR response to extract attestation document */
    ret = parse_attestation_response(response_buf, msg.response.iov_len,
                                      attestation_out, attestation_len);
    
    free(response_buf);
    return ret;
}

/* Process a request */
static int handle_request(int client_fd, uint8_t *buffer) {
    uint8_t header[4];
    
    /* Read total length */
    if (read_exact(client_fd, header, 4) < 0) {
        return -1;
    }
    uint32_t total_len = read_u32_be(header);
    
    fprintf(stderr, "Received request, total length: %u\n", total_len);
    
    if (total_len > BUFFER_SIZE) {
        fprintf(stderr, "Request too large: %u > %d\n", total_len, BUFFER_SIZE);
        return -1;
    }
    
    /* Read the rest of the message */
    if (read_exact(client_fd, buffer, total_len) < 0) {
        return -1;
    }
    
    size_t offset = 0;
    
    /* Parse WASM module */
    uint32_t wasm_len = read_u32_be(buffer + offset);
    offset += 4;
    
    uint8_t *wasm_data = buffer + offset;
    offset += wasm_len;
    
    fprintf(stderr, "WASM module size: %u bytes\n", wasm_len);
    
    /* Hash the WASM module */
    uint8_t wasm_hash[32];
    sha256(wasm_data, wasm_len, wasm_hash);
    
    /* Load WASM module */
    if (wasm_load_module(wasm_data, wasm_len) != 0) {
        fprintf(stderr, "Failed to load WASM module\n");
        return -1;
    }
    fprintf(stderr, "WASM module loaded\n");
    
    /* Parse documents */
    uint32_t num_docs = read_u32_be(buffer + offset);
    offset += 4;
    
    fprintf(stderr, "Number of documents: %u\n", num_docs);
    
    /* Track flagged documents */
    uint32_t unsafe_count = 0;
    uint32_t first_flagged_index = 0;
    uint8_t first_flagged_hash[32];
    bool has_flagged = false;
    
    /* Hash all documents (hash of hashes) */
    SHA256_CTX docs_ctx;
    SHA256_Init(&docs_ctx);
    
    for (uint32_t i = 0; i < num_docs; i++) {
        uint32_t doc_len = read_u32_be(buffer + offset);
        offset += 4;
        
        uint8_t *doc_data = buffer + offset;
        offset += doc_len;
        
        /* Hash this document and add to combined hash */
        uint8_t doc_hash[32];
        sha256(doc_data, doc_len, doc_hash);
        SHA256_Update(&docs_ctx, doc_hash, 32);
        
        fprintf(stderr, "  Document %u: %u bytes\n", i, doc_len);
        
        /* Run WASM challenger on this document */
        int wasm_result = wasm_call_check_document(doc_data, doc_len);
        
        if (wasm_result > 0) {
            fprintf(stderr, "  Document %u flagged as UNSAFE\n", i);
            unsafe_count++;
            
            /* Track first flagged document */
            if (!has_flagged) {
                has_flagged = true;
                first_flagged_index = i;
                memcpy(first_flagged_hash, doc_hash, 32);
            }
        } else if (wasm_result == 0) {
            fprintf(stderr, "  Document %u: safe\n", i);
        } else {
            fprintf(stderr, "  WARNING: WASM error checking document %u\n", i);
        }
    }
    
    uint8_t documents_hash[32];
    SHA256_Final(documents_hash, &docs_ctx);
    
    /* Unload WASM module */
    wasm_unload_module();
    fprintf(stderr, "WASM module unloaded\n");
    
    /* Build result string */
    char result_buf[256];
    snprintf(result_buf, sizeof(result_buf), 
             "Documents processed: %u total, %u flagged unsafe", 
             num_docs, unsafe_count);
    const char *result = result_buf;
    size_t result_len = strlen(result);
    
    /* Prepare user data for attestation (combine hashes + result hash) */
    uint8_t user_data[96];  /* wasm_hash + docs_hash + result_hash */
    memcpy(user_data, wasm_hash, 32);
    memcpy(user_data + 32, documents_hash, 32);
    
    uint8_t result_hash[32];
    sha256((const uint8_t *)result, result_len, result_hash);
    memcpy(user_data + 64, result_hash, 32);
    
    /* Get attestation document */
    uint8_t attestation[NSM_MAX_ATTESTATION_SIZE];
    size_t attestation_len = sizeof(attestation);
    
    if (get_attestation_document(user_data, sizeof(user_data), 
                                  attestation, &attestation_len) < 0) {
        fprintf(stderr, "Failed to get attestation document\n");
        /* Continue with empty attestation rather than failing */
        attestation_len = 0;
    } else {
        fprintf(stderr, "Got attestation document: %zu bytes\n", attestation_len);
    }
    
    /* Build response */
    uint8_t *response = buffer;
    size_t resp_offset = 4;  /* Skip length field for now */
    
    /* Status = 0 (success) */
    write_u32_be(response + resp_offset, 0);
    resp_offset += 4;
    
    /* WASM hash */
    memcpy(response + resp_offset, wasm_hash, 32);
    resp_offset += 32;
    
    /* Documents hash */
    memcpy(response + resp_offset, documents_hash, 32);
    resp_offset += 32;
    
    /* Result */
    write_u32_be(response + resp_offset, result_len);
    resp_offset += 4;
    memcpy(response + resp_offset, result, result_len);
    resp_offset += result_len;
    
    /* Flagged document info */
    write_u32_be(response + resp_offset, has_flagged ? 1 : 0);
    resp_offset += 4;
    if (has_flagged) {
        write_u32_be(response + resp_offset, first_flagged_index);
        resp_offset += 4;
        memcpy(response + resp_offset, first_flagged_hash, 32);
        resp_offset += 32;
    }
    
    /* Attestation document */
    write_u32_be(response + resp_offset, attestation_len);
    resp_offset += 4;
    memcpy(response + resp_offset, attestation, attestation_len);
    resp_offset += attestation_len;
    
    /* Write total length at start */
    uint32_t response_len = resp_offset - 4;
    write_u32_be(response, response_len);
    
    fprintf(stderr, "Sending response, total length: %u\n", response_len);
    
    /* Send response */
    if (write_exact(client_fd, response, resp_offset) < 0) {
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int listen_fd, client_fd;
    struct sockaddr_vm listen_addr, client_addr;
    socklen_t client_addr_len;
    
    (void)argc;
    (void)argv;
    
    /* Redirect stderr to console for debug mode */
    FILE *console = fopen("/dev/console", "w");
    if (console) {
        setvbuf(console, NULL, _IONBF, 0);
        stderr = console;
    }
    
    fprintf(stderr, "Enclave server starting...\n");
    
    /* Initialize WASM runtime */
    if (wasm_runtime_setup() != 0) {
        fprintf(stderr, "Failed to initialize WASM runtime\n");
        return 1;
    }
    fprintf(stderr, "WASM runtime initialized\n");
    
    /* Allocate buffer */
    uint8_t *buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }
    
    /* Create vsock socket */
    listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    
    /* Bind to VMADDR_CID_ANY (accept from parent) on our port */
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.svm_family = AF_VSOCK;
    listen_addr.svm_cid = VMADDR_CID_ANY;
    listen_addr.svm_port = LISTEN_PORT;
    
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        return 1;
    }
    
    fprintf(stderr, "Listening on vsock port %d...\n", LISTEN_PORT);
    
    /* Main server loop */
    while (1) {
        client_addr_len = sizeof(client_addr);
        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        fprintf(stderr, "Accepted connection from CID %u\n", client_addr.svm_cid);
        
        /* Handle requests on this connection until it closes */
        while (handle_request(client_fd, buffer) == 0) {
            /* Keep handling requests */
        }
        
        fprintf(stderr, "Connection closed\n");
        close(client_fd);
    }
    
    free(buffer);
    close(listen_fd);
    
    /* Cleanup WASM runtime */
    wasm_runtime_teardown();
    
    return 0;
}
