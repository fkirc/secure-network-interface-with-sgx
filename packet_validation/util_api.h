#pragma once

#include <stdlib.h> // size_t
#include "../common/logging.h"

// Besides the trusted socket api, this library also provides an auxiliary SGX api based on OCALL's
int printf(const char *fmt, ...);

void* outside_malloc(size_t size);
void outside_free(void* ptr);

int sanitize_outside_packet(const void* buf, size_t packet_len, size_t buf_len);


// The assert() from the sgx standard library is painful to use since it just causes an invalid instruction without printing any information.
// This macro is also called in security-critical abort conditions in case of invalid states.
// Therefore, for release mode, this macro should call abort() immediately without calling the printf OCALL.
#define ASSERT_DEBUG(X) do { if (!(X)) {\
    printf("Enclave assertion failed: '%s', file: '%s', function: '%s', line %d\n", #X, __FILE__, __FUNCTION__, __LINE__);\
    abort(); } } while (0);


