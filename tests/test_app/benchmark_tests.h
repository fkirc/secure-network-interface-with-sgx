#pragma once

#include <stdlib.h> // size_t
#include <assert.h>
#include "sgx_urts.h"


#define TEST_MODE_REGULAR_INTERFACE 1
#define TEST_MODE_REGULAR_INTERFACE_STR "REGULAR_INTERFACE"
#define TEST_MODE_TAP_INTERFACE 2
#define TEST_MODE_TAP_INTERFACE_STR "TAP_INTERFACE"
#define TEST_MODE_SGX_RAW 3
#define TEST_MODE_SGX_RAW_STR "SGX_RAW"
#define TEST_MODE_SGX_VALIDATED 4
#define TEST_MODE_SGX_VALIDATED_STR "SGX_VALIDATED"
#define TEST_MODE_MACSEC_RAW 5
#define TEST_MODE_MACSEC_RAW_STR "MACSEC_RAW"
#define TEST_MODE_SGX_SECURED 6
#define TEST_MODE_SGX_SECURED_STR "SGX_SECURED"

typedef struct test_mode {
    int mode; // Provides type safety against integers
} test_mode_t;

char* test_mode_to_str(test_mode_t m);

struct benchmark {
    const char* name;
    const size_t default_size;
    void(*fct)(const sgx_enclave_id_t, struct trusted_sock_addr, const size_t benchmark_size);
};


// This defines the number of repetitions for all the individual tests.
// Should be set to a "large" value for estimating an accurate variance.
// The default is 1 since this suffices for a simple functional test.
#define DEFAULT_NUMBER_OF_TEST_RUNS 1

// Static configuration
#define HTTP_PORT 5678
#define BULK_DATA_PORT 10000
#define SEND_CLOSE_PORT 10001

void run_benchmark_tests(sgx_enclave_id_t eid, struct trusted_sock_addr server, struct test_mode mode);

#define RUN_TEST_ECALL(X) ret_val = -1; assert(X == SGX_SUCCESS); assert(!ret_val)
