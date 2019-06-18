#include <stdarg.h>
#include <stdio.h>
#include "../tests/test_enclave/test_enclave_t.h"
#include "sgx_trts.h"


int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    if (ocall_print_string(buf) != SGX_SUCCESS) {
        abort(); // Should never happen, cannot print error log at this point
    }
    return 0; // We do not care about the return value
}


void* outside_malloc(size_t size) {
    void* buf = 0;
    if (ocall_malloc(&buf, size) != SGX_SUCCESS) {
        abort();
    }
    if (!sgx_is_outside_enclave(buf, size)) {
        abort(); // must never happen
    }
    return buf;
}

void outside_free(void* ptr) {
    if (!sgx_is_outside_enclave(ptr, sizeof(void*))) {
        abort();
    }
    if (ocall_free(ptr) != SGX_SUCCESS) {
        abort();
    }
}
