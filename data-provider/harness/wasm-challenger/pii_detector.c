/*
 * PII Detector - WASM Challenger Module
 * 
 * Compile with wasi-sdk:
 *   /opt/wasi-sdk/bin/clang \
 *     -O2 --target=wasm32-wasi \
 *     -Wl,--export=check_document \
 *     -Wl,--no-entry \
 *     -o pii_detector.wasm \
 *     pii_detector.c
 * 
 * This module checks documents for potential PII:
 *   - Social Security Numbers (XXX-XX-XXXX pattern)
 *   - Credit card numbers (sequences of 13-19 digits)
 *   - Email addresses (basic pattern matching)
 */

#include <stdint.h>
#include <stdbool.h>

/* Helper: check if character is a digit */
static inline bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

/* Helper: check if character is alphanumeric */
static inline bool is_alnum(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
}

/* Check for SSN pattern: XXX-XX-XXXX */
static bool check_ssn(const char* data, uint32_t len) {
    if (len < 11) return false;
    
    for (uint32_t i = 0; i <= len - 11; i++) {
        if (is_digit(data[i]) && is_digit(data[i+1]) && is_digit(data[i+2]) &&
            data[i+3] == '-' &&
            is_digit(data[i+4]) && is_digit(data[i+5]) &&
            data[i+6] == '-' &&
            is_digit(data[i+7]) && is_digit(data[i+8]) && 
            is_digit(data[i+9]) && is_digit(data[i+10])) {
            
            /* Make sure it's not part of a longer number */
            bool prefix_ok = (i == 0) || !is_digit(data[i-1]);
            bool suffix_ok = (i + 11 >= len) || !is_digit(data[i+11]);
            
            if (prefix_ok && suffix_ok) {
                return true;  /* Found SSN! */
            }
        }
    }
    
    return false;
}

/* Check for credit card patterns: 13-19 consecutive digits 
 * (possibly with spaces or dashes) */
static bool check_credit_card(const char* data, uint32_t len) {
    uint32_t digit_count = 0;
    uint32_t start = 0;
    
    for (uint32_t i = 0; i < len; i++) {
        if (is_digit(data[i])) {
            if (digit_count == 0) start = i;
            digit_count++;
        } else if (data[i] == ' ' || data[i] == '-') {
            /* Allow separators within card number */
            if (digit_count > 0) continue;
        } else {
            /* Check if we had a valid card-length sequence */
            if (digit_count >= 13 && digit_count <= 19) {
                return true;  /* Found credit card! */
            }
            digit_count = 0;
        }
    }
    
    /* Check final sequence */
    if (digit_count >= 13 && digit_count <= 19) {
        return true;
    }
    
    return false;
}

/* Check for email pattern: xxx@xxx.xxx */
static bool check_email(const char* data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        if (data[i] == '@' && i > 0 && i < len - 4) {
            /* Check for valid characters before @ */
            bool valid_prefix = is_alnum(data[i-1]) || 
                               data[i-1] == '.' || 
                               data[i-1] == '_';
            
            /* Look for .xxx after @ */
            bool found_dot = false;
            bool valid_domain = false;
            
            for (uint32_t j = i + 1; j < len; j++) {
                if (data[j] == '.') {
                    found_dot = true;
                } else if (found_dot && is_alnum(data[j])) {
                    valid_domain = true;
                } else if (!is_alnum(data[j]) && data[j] != '.' && data[j] != '-') {
                    break;
                }
            }
            
            if (valid_prefix && valid_domain) {
                return true;  /* Found email! */
            }
        }
    }
    
    return false;
}

/* Check for keywords that indicate PII */
static bool check_keywords(const char* data, uint32_t len) {
    /* Simple case-insensitive substring search */
    const char* keywords[] = {
        "social security",
        "ssn:",
        "credit card",
        "card number",
        "password:",
        "secret key",
        "private key",
        "api key",
        "bank account",
        NULL
    };
    
    /* Convert to lowercase for comparison (simple ASCII only) */
    /* Note: In real implementation, would need proper buffer */
    
    for (int k = 0; keywords[k] != NULL; k++) {
        const char* keyword = keywords[k];
        uint32_t klen = 0;
        while (keyword[klen]) klen++;
        
        if (klen > len) continue;
        
        for (uint32_t i = 0; i <= len - klen; i++) {
            bool match = true;
            for (uint32_t j = 0; j < klen && match; j++) {
                char c = data[i + j];
                char k = keyword[j];
                
                /* Simple lowercase conversion */
                if (c >= 'A' && c <= 'Z') c += 32;
                if (k >= 'A' && k <= 'Z') k += 32;
                
                if (c != k) match = false;
            }
            
            if (match) {
                return true;  /* Found keyword! */
            }
        }
    }
    
    return false;
}

/*
 * Main entry point - called by the TEE harness
 * 
 * @param ptr  Pointer to document data (in WASM linear memory)
 * @param len  Length of document
 * @return     1 if unsafe (PII detected), 0 if safe
 */
__attribute__((export_name("check_document")))
int32_t check_document(const char* ptr, uint32_t len) {
    /* Check various PII patterns */
    
    if (check_ssn(ptr, len)) {
        return 1;  /* SSN found - unsafe! */
    }
    
    if (check_credit_card(ptr, len)) {
        return 1;  /* Credit card found - unsafe! */
    }
    
    if (check_email(ptr, len)) {
        /* Emails alone might be okay - but flag for review */
        /* For this demo, we'll flag them as potentially unsafe */
        return 1;
    }
    
    if (check_keywords(ptr, len)) {
        return 1;  /* Sensitive keyword found - unsafe! */
    }
    
    return 0;  /* Safe! */
}