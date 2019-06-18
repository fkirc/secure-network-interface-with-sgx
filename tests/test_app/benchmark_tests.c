#include "sgx_urts.h"
#include <sys/time.h>
#include <stdarg.h>
#include "../../common/logging.h"
#include "test_enclave_u.h"

#include "benchmark_tests.h"

// For some insecure modes, we directly link against some enclave code files
int mocked_ecall_simple_http_client(struct trusted_sock_addr server, size_t num_requests);
int mocked_ecall_bulk_data_client(struct trusted_sock_addr server, size_t num_requests, size_t stream_size);

int test_snmp_client(struct trusted_sock_addr server, const size_t num_requests);


static test_mode_t current_mode = {0};

static int mocked_ecall_api() {
    if (current_mode.mode == TEST_MODE_REGULAR_INTERFACE ||
            current_mode.mode == TEST_MODE_TAP_INTERFACE ||
            current_mode.mode == TEST_MODE_SGX_RAW ||
            current_mode.mode == TEST_MODE_MACSEC_RAW) {
        return 1;
    } else if (current_mode.mode == TEST_MODE_SGX_VALIDATED ||
            current_mode.mode == TEST_MODE_SGX_SECURED) {
        return 0;
    } else {
        assert(0 && "Unsupported test mode\n");
    }
}


static long long get_time() {
    struct timeval timecheck = {0};
    gettimeofday(&timecheck, NULL);
    return (long long)timecheck.tv_sec * 1000 + (long long)timecheck.tv_usec / 1000;
}


char* test_mode_to_str(test_mode_t m) {
    if (m.mode == TEST_MODE_REGULAR_INTERFACE) {
        return TEST_MODE_REGULAR_INTERFACE_STR;
    } else if (m.mode == TEST_MODE_TAP_INTERFACE) {
        return TEST_MODE_TAP_INTERFACE_STR;
    } else if (m.mode == TEST_MODE_SGX_RAW) {
        return TEST_MODE_SGX_RAW_STR;
    } else if (m.mode == TEST_MODE_SGX_VALIDATED) {
        return TEST_MODE_SGX_VALIDATED_STR;
    } else if (m.mode == TEST_MODE_MACSEC_RAW) {
        return TEST_MODE_MACSEC_RAW_STR;
    } else if (m.mode == TEST_MODE_SGX_SECURED) {
        return TEST_MODE_SGX_SECURED_STR;
    }
    assert(0 && "Unknown test mode");
}



static void bulk_data_test(sgx_enclave_id_t eid, struct trusted_sock_addr server, int num_requests, int request_size) {

    if (mocked_ecall_api()) {
        assert(!mocked_ecall_bulk_data_client(server, num_requests, request_size));
    } else {
        int ret_val = -1;
        RUN_TEST_ECALL(ecall_bulk_data_client(eid, &ret_val, server, num_requests, request_size));
    }
}

static void run_bulk_data_benchmark(const sgx_enclave_id_t eid, struct trusted_sock_addr server, const size_t benchmark_size) {

    const size_t bulk_data_chunk_size = 50000;

    server.port = BULK_DATA_PORT;
    const size_t bulk_data_size = benchmark_size;
    const size_t num_large_bulk_data_requests = bulk_data_size / bulk_data_chunk_size;
    const size_t size_of_remaining_bulk_data_request = bulk_data_size % bulk_data_chunk_size;
    assert(num_large_bulk_data_requests || size_of_remaining_bulk_data_request);

    if (num_large_bulk_data_requests) {
        bulk_data_test(eid, server, num_large_bulk_data_requests, bulk_data_chunk_size);
    }
    if (size_of_remaining_bulk_data_request) {
        bulk_data_test(eid, server, 1, size_of_remaining_bulk_data_request);
    }
}


static void run_http_benchmark(const sgx_enclave_id_t eid, struct trusted_sock_addr server, const size_t benchmark_size) {
    server.port = HTTP_PORT;
    if (mocked_ecall_api()) {
        assert(!mocked_ecall_simple_http_client(server, benchmark_size));
    } else {
        int ret_val = -1;
        RUN_TEST_ECALL(ecall_simple_http_client(eid, &ret_val, server, benchmark_size));
    }
}

static void run_udp_round_trips_benchmark(const sgx_enclave_id_t eid, struct trusted_sock_addr server, const size_t benchmark_size) {
    (void)(eid);
    // SNMP is based on UDP, this suffices for measuring UDP round trip times with our simple implementation
    test_snmp_client(server, benchmark_size);
}


static const struct benchmark benchmark_http = {.name = "HTTP_REQUESTS", .default_size = 10, .fct = &run_http_benchmark};
static const struct benchmark benchmark_bulk_data = {.name = "BULK_DATA", .default_size = 60000, .fct = &run_bulk_data_benchmark};
static const struct benchmark benchmark_udp_round_trips = {.name = "UDP_ROUND_TRIPS", .default_size = 15, .fct = &run_udp_round_trips_benchmark};

static void run_individual_benchmark(sgx_enclave_id_t eid, struct trusted_sock_addr server, const struct benchmark* b, const size_t benchmark_size) {

    // Run the benchmark and measure its execution time
    long long t = get_time();
    b->fct(eid, server, benchmark_size);
    double time = ((double)(get_time() - t)) / 1000.L;

    // Print results as json for later parsing
    printf("REPORT-RESULT: {\"BENCHMARK\": \"%s\", \"SIZE\": %zd, \"SECONDS\": %f10, \"TEST_MODE\": \"%s\"}\n", b->name, benchmark_size, time, test_mode_to_str(current_mode));
}


static size_t get_individual_benchmark_size(const struct benchmark* b) {
    // Figure out the size of the individual benchmark based on environment variables
    char env[1000];
    snprintf(env, sizeof(env), "BENCHMARK_SIZE_%s", b->name);
    size_t benchmark_size = 0;
    const char* e = getenv(env);
    if (e) {
        benchmark_size = strtoll(e, 0, 10);
    }
    if (!benchmark_size) {
        benchmark_size = b->default_size;
    }
    return benchmark_size;
}


static void run_benchmark_sequence(sgx_enclave_id_t eid, struct trusted_sock_addr server, const struct benchmark* b, size_t number_of_test_runs) {

    // A "benchmark sequence" executes the same benchmark multiple times, which allows to estimate a variance later on
    size_t benchmark_size = get_individual_benchmark_size(b);

    printf("Start benchmark sequence %s with (%zd * %zd) runs\n", b->name, number_of_test_runs, benchmark_size);

    for (size_t cnt = 1; cnt <= number_of_test_runs; cnt++) {
        run_individual_benchmark(eid, server, b, benchmark_size);
    }
}


static size_t get_num_test_runs() {
    size_t num = 0;
    char* e = getenv("NUMBER_OF_TEST_RUNS");
    if (e) {
        num = strtoll(e, 0, 10);
    }
    if (!num) {
        num = DEFAULT_NUMBER_OF_TEST_RUNS;
    }
    return num;
}


void run_benchmark_tests(sgx_enclave_id_t eid, struct trusted_sock_addr server, test_mode_t mode) {

    printf("Start benchmark tests in mode %s\n", test_mode_to_str(mode));
    current_mode = mode;

    const size_t number_of_test_runs = get_num_test_runs();
    printf("Number of test runs: %zd\n", number_of_test_runs);

    /**************************************************************************/
    run_benchmark_sequence(eid, server, &benchmark_http, number_of_test_runs);
    run_benchmark_sequence(eid, server, &benchmark_bulk_data, number_of_test_runs);
    run_benchmark_sequence(eid, server, &benchmark_udp_round_trips, number_of_test_runs);
}
