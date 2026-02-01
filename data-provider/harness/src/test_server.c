/*
 * Test server - can run outside enclave with TCP sockets
 * 
 * Usage:
 *   ./harness-cli --server --tcp --port 5000
 * 
 * This allows testing the WASM execution logic without the enclave.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Try to include vsock header - may not be available everywhere */
#ifdef __linux__
#include <linux/vm_sockets.h>
#define HAVE_VSOCK 1
#else
#define HAVE_VSOCK 0
#endif

#define DEFAULT_PORT 5000
#define BUFFER_SIZE (16 * 1024 * 1024)

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

/*
 * Placeholder for WASM execution - replace with your actual implementation
 */
int wasm_check_document(const uint8_t *doc, uint32_t len, int32_t *result) {
    *result = wasm_call_check_document(doc, len);
    return 0;
}

/* Process a single request */
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
    
    /* Load the WASM module */
    if (wasm_load_module(wasm_data, wasm_len) < 0) {
        fprintf(stderr, "Failed to load WASM module\n");
        /* Send error response */
        uint8_t err_response[8];
        write_u32_be(err_response, 4);      /* length */
        write_u32_be(err_response + 4, 1);  /* status = error */
        write_exact(client_fd, err_response, 8);
        return 0;  /* Continue accepting connections */
    }
    
    fprintf(stderr, "WASM module loaded\n");
    
    /* Parse and process documents */
    uint32_t num_docs = read_u32_be(buffer + offset);
    offset += 4;
    
    fprintf(stderr, "Number of documents: %u\n", num_docs);
    
    /* Simple result tracking */
    int suspicious_count = 0;
    
    for (uint32_t i = 0; i < num_docs; i++) {
        uint32_t doc_len = read_u32_be(buffer + offset);
        offset += 4;
        
        uint8_t *doc_data = buffer + offset;
        offset += doc_len;
        
        fprintf(stderr, "  Document %u: %u bytes\n", i, doc_len);
        
        /* Run WASM check on document */
        int32_t result = 0;
        if (wasm_check_document(doc_data, doc_len, &result) < 0) {
            fprintf(stderr, "  WASM check failed for document %u\n", i);
        } else {
            fprintf(stderr, "  Document %u result: %d\n", i, result);
            if (result != 0) {
                suspicious_count++;
            }
        }
    }
    
    /* Unload WASM module */
    wasm_unload_module();
    
    /* Build result string */
    char result_str[256];
    snprintf(result_str, sizeof(result_str), 
             "Processed %u documents, %d suspicious", num_docs, suspicious_count);
    size_t result_len = strlen(result_str);
    
    /* Build response (simplified - no attestation in test mode) */
    uint8_t *response = buffer;
    size_t resp_offset = 4;  /* Skip length field */
    
    /* Status = 0 (success) */
    write_u32_be(response + resp_offset, 0);
    resp_offset += 4;
    
    /* WASM hash placeholder (32 bytes of zeros) */
    memset(response + resp_offset, 0, 32);
    resp_offset += 32;
    
    /* Documents hash placeholder (32 bytes of zeros) */
    memset(response + resp_offset, 0, 32);
    resp_offset += 32;
    
    /* Result */
    write_u32_be(response + resp_offset, result_len);
    resp_offset += 4;
    memcpy(response + resp_offset, result_str, result_len);
    resp_offset += result_len;
    
    /* Attestation (empty in test mode) */
    write_u32_be(response + resp_offset, 0);
    resp_offset += 4;
    
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

/* Create TCP listening socket */
static int create_tcp_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    
    if (listen(fd, 1) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    
    return fd;
}

#if HAVE_VSOCK
/* Create vsock listening socket */
static int create_vsock_socket(int port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket (vsock)");
        return -1;
    }
    
    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = port;
    
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind (vsock)");
        close(fd);
        return -1;
    }
    
    if (listen(fd, 1) < 0) {
        perror("listen (vsock)");
        close(fd);
        return -1;
    }
    
    return fd;
}
#endif

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --server [--tcp|--vsock] [--port PORT]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --server       Run in server mode\n");
    fprintf(stderr, "  --tcp          Use TCP sockets (for testing outside enclave)\n");
    fprintf(stderr, "  --vsock        Use vsock (for enclave mode, default)\n");
    fprintf(stderr, "  --port PORT    Port to listen on (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
    int use_tcp = 0;
    int port = DEFAULT_PORT;
    int server_mode = 0;
    
    static struct option long_options[] = {
        {"server", no_argument, 0, 's'},
        {"tcp", no_argument, 0, 't'},
        {"vsock", no_argument, 0, 'v'},
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "stvp:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                server_mode = 1;
                break;
            case 't':
                use_tcp = 1;
                break;
            case 'v':
                use_tcp = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    if (!server_mode) {
        usage(argv[0]);
        return 1;
    }
    
    fprintf(stderr, "Test server starting...\n");
    
    /* Initialize WASM runtime */
    if (wasm_runtime_setup() < 0) {
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
    
    /* Create socket */
    int listen_fd;
    if (use_tcp) {
        fprintf(stderr, "Using TCP socket on port %d\n", port);
        listen_fd = create_tcp_socket(port);
    } else {
#if HAVE_VSOCK
        fprintf(stderr, "Using vsock on port %d\n", port);
        listen_fd = create_vsock_socket(port);
#else
        fprintf(stderr, "vsock not supported on this platform, use --tcp\n");
        return 1;
#endif
    }
    
    if (listen_fd < 0) {
        return 1;
    }
    
    fprintf(stderr, "Listening on port %d...\n", port);
    
    /* Main server loop */
    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        fprintf(stderr, "Accepted connection\n");
        
        /* Handle requests until connection closes */
        while (handle_request(client_fd, buffer) == 0) {
            /* Keep handling */
        }
        
        fprintf(stderr, "Connection closed\n");
        close(client_fd);
    }
    
    free(buffer);
    close(listen_fd);
    wasm_runtime_teardown();
    return 0;
}