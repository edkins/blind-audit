/*
 * WAMR Integration for TEE Harness
 * 
 * This file handles embedding WAMR (WebAssembly Micro Runtime) and provides
 * the wasm_* functions declared in harness.h.
 * 
 * The WASM challenger module is expected to export:
 *   - check_document(ptr: i32, len: i32) -> i32
 *     Returns: 1 if unsafe, 0 if safe, negative on error
 * 
 * We provide NO host functions to the WASM - it's purely computational.
 * The document bytes are copied into WASM linear memory before calling.
 */

#include "harness.h"
#include "wasm_export.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * WAMR Runtime State
 * ============================================================================ */

/* Runtime configuration */
#define WASM_STACK_SIZE     (32 * 1024)    /* 32KB stack */
#define WASM_HEAP_SIZE      (512 * 1024)   /* 512KB heap for WASM */
#define GLOBAL_HEAP_SIZE    (2 * 1024 * 1024)  /* 2MB for WAMR runtime */

/* Global runtime state */
static bool g_wasm_initialized = false;
static char g_global_heap[GLOBAL_HEAP_SIZE];

/* Per-module state */
static wasm_module_t g_module = NULL;
static wasm_module_inst_t g_module_inst = NULL;
static wasm_exec_env_t g_exec_env = NULL;
static wasm_function_inst_t g_check_document_func = NULL;

/* ============================================================================
 * Host Functions (intentionally minimal for security)
 * 
 * For this protocol, we deliberately provide NO host functions.
 * The challenger WASM runs in pure computation mode - it cannot:
 *   - Access files
 *   - Make network calls  
 *   - Call back into the host
 * 
 * It can ONLY process the document bytes passed to check_document().
 * ============================================================================ */

/* If we wanted to provide host functions, we'd define them like this:
 *
 * static void log_message(wasm_exec_env_t exec_env, const char* msg) {
 *     printf("[wasm] %s\n", msg);
 * }
 * 
 * static NativeSymbol g_native_symbols[] = {
 *     { "log", (void*)log_message, "($)", NULL }
 * };
 * 
 * But for security, we provide none.
 */

/* ============================================================================
 * WASM Runtime Functions
 * ============================================================================ */

int wasm_runtime_setup(void) {
    if (g_wasm_initialized) {
        return 0;
    }
    
    printf("[wasm] Setting up WAMR runtime...\n");
    
    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    
    /* Use a pool allocator - important for embedded/TEE environments */
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = g_global_heap;
    init_args.mem_alloc_option.pool.heap_size = sizeof(g_global_heap);
    
    /* No native functions - pure sandbox */
    init_args.n_native_symbols = 0;
    init_args.native_symbols = NULL;
    
    if (!wasm_runtime_full_init(&init_args)) {
        fprintf(stderr, "[wasm] Failed to initialize WAMR runtime\n");
        return -1;
    }
    
    g_wasm_initialized = true;
    printf("[wasm] Runtime initialized\n");
    return 0;
}

int wasm_load_module(const uint8_t* bytes, uint32_t len) {
    char error_buf[128];
    
    if (!g_wasm_initialized) {
        fprintf(stderr, "[wasm] Runtime not initialized\n");
        return -1;
    }
    
    /* Unload any existing module */
    wasm_unload_module();
    
    printf("[wasm] Loading module (%u bytes)...\n", len);
    
    /* Load the WASM module from buffer */
    g_module = wasm_runtime_load((uint8_t*)bytes, len, error_buf, sizeof(error_buf));
    if (!g_module) {
        fprintf(stderr, "[wasm] Failed to load module: %s\n", error_buf);
        return -1;
    }
    
    /* Instantiate the module */
    g_module_inst = wasm_runtime_instantiate(
        g_module,
        WASM_STACK_SIZE,
        WASM_HEAP_SIZE,
        error_buf,
        sizeof(error_buf)
    );
    if (!g_module_inst) {
        fprintf(stderr, "[wasm] Failed to instantiate module: %s\n", error_buf);
        wasm_runtime_unload(g_module);
        g_module = NULL;
        return -1;
    }
    
    /* Create execution environment */
    g_exec_env = wasm_runtime_create_exec_env(g_module_inst, WASM_STACK_SIZE);
    if (!g_exec_env) {
        fprintf(stderr, "[wasm] Failed to create exec env\n");
        wasm_runtime_deinstantiate(g_module_inst);
        wasm_runtime_unload(g_module);
        g_module_inst = NULL;
        g_module = NULL;
        return -1;
    }
    
    /* Look up the check_document function */
    g_check_document_func = wasm_runtime_lookup_function(
        g_module_inst, 
        "check_document"
    );
    if (!g_check_document_func) {
        fprintf(stderr, "[wasm] Module doesn't export 'check_document' function\n");
        wasm_runtime_destroy_exec_env(g_exec_env);
        wasm_runtime_deinstantiate(g_module_inst);
        wasm_runtime_unload(g_module);
        g_exec_env = NULL;
        g_module_inst = NULL;
        g_module = NULL;
        return -1;
    }
    
    printf("[wasm] Module loaded and instantiated\n");
    return 0;
}

int wasm_call_check_document(const uint8_t* doc, uint32_t len) {
    if (!g_module_inst || !g_exec_env || !g_check_document_func) {
        fprintf(stderr, "[wasm] No module loaded\n");
        return -1;
    }
    
    /* Allocate buffer in WASM linear memory */
    void* native_ptr = NULL;
    uint64_t wasm_ptr = wasm_runtime_module_malloc(g_module_inst, len, &native_ptr);
    
    if (wasm_ptr == 0 || native_ptr == NULL) {
        fprintf(stderr, "[wasm] Failed to allocate %u bytes in WASM memory\n", len);
        return -1;
    }
    
    /* Copy document into WASM memory */
    memcpy(native_ptr, doc, len);
    
    /* Prepare arguments: check_document(ptr: i32, len: i32) -> i32 */
    uint32_t argv[2];
    argv[0] = (uint32_t)wasm_ptr;  /* pointer in WASM address space */
    argv[1] = len;
    
    /* Call the function */
    if (!wasm_runtime_call_wasm(g_exec_env, g_check_document_func, 2, argv)) {
        const char* exception = wasm_runtime_get_exception(g_module_inst);
        fprintf(stderr, "[wasm] Call failed: %s\n", exception ? exception : "unknown");
        wasm_runtime_module_free(g_module_inst, wasm_ptr);
        return -1;
    }
    
    /* Get return value (stored in argv[0]) */
    int32_t result = (int32_t)argv[0];
    
    /* Free the WASM memory */
    wasm_runtime_module_free(g_module_inst, wasm_ptr);
    
    return result;
}

void wasm_unload_module(void) {
    if (g_exec_env) {
        wasm_runtime_destroy_exec_env(g_exec_env);
        g_exec_env = NULL;
    }
    
    if (g_module_inst) {
        wasm_runtime_deinstantiate(g_module_inst);
        g_module_inst = NULL;
    }
    
    if (g_module) {
        wasm_runtime_unload(g_module);
        g_module = NULL;
    }
    
    g_check_document_func = NULL;
}

void wasm_runtime_teardown(void) {
    wasm_unload_module();
    
    if (g_wasm_initialized) {
        wasm_runtime_destroy();
        g_wasm_initialized = false;
        printf("[wasm] Runtime destroyed\n");
    }
}
