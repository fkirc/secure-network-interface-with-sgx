
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <getopt.h>
#include <pthread.h>

#include "test_enclave_u.h"
#include "../../support_lib/sgx_utils_u.h"

#include "benchmark_tests.h"
#include "../../support_lib/interface_connector.h"
#include "../../common/utils.h"
#include "../../common/key_file_definitions.h"
#include "test_app.h"

#define NUM_HTTP_REQUESTS_PACKET_DROP 7
#define BULK_DATA_STREAM_SIZE_PACKET_DROP 5000

static void run_tests(sgx_enclave_id_t eid, struct trusted_sock_addr server, test_mode_t m) {

    /**************************************************************************/
    // Run stress tests with packet dropping enabled

    int ret_val = -1;
    /*DEBUG_LOG("\nStart stress tests with random packet dropping enabled\n");
    enable_random_packet_dropping(1);

    server.port = BULK_DATA_PORT;
    RUN_TEST_ECALL(ecall_bulk_data_client(eid, &ret_val, server, 1, BULK_DATA_STREAM_SIZE_PACKET_DROP));

    server.port = HTTP_PORT;
    RUN_TEST_ECALL(ecall_simple_http_client(eid, &ret_val, server, NUM_HTTP_REQUESTS_PACKET_DROP));

    enable_random_packet_dropping(0);*/

    if (m.mode == TEST_MODE_SGX_SECURED) {
        DEBUG_LOG(" Mode %s: Run additional tests\n", test_mode_to_str(m));
        server.port = SEND_CLOSE_PORT;
        RUN_TEST_ECALL(ecall_send_close(eid, &ret_val, server, 5));
    }

    /**************************************************************************/
    // Run the benchmark tests
    run_benchmark_tests(eid, server, m);

    /**************************************************************************/
    // Run DCP test
    test_pn_dcp(VIRTUAL_ENCLAVE_INTERFACE);
}


static char trusted_interface[ARG_BUF_LEN + 1] = {0};
static char ip_config[ARG_BUF_LEN + 1] = {0};
static char server_ip[ARG_BUF_LEN + 1] = {0};
static char test_mode_arg[ARG_BUF_LEN + 1] = {0};


void common_usage(const char* prog_name) {
    fprintf(stderr, "Usage for permanent mode: %s --%s <mode> --%s <iface> --%s <ip/subnet>\n", prog_name,
            PARAM_PERMANENT_MODE, PARAM_INTERFACE, PARAM_IP_CONFIG);
    fprintf(stderr, "Usage for running the tests: %s --%s <ip of remote test end> --%s <mode> --%s <iface> --%s <ip/subnet>\n", prog_name,
            PARAM_SERVER_IP, PARAM_TEST_MODE, PARAM_INTERFACE, PARAM_IP_CONFIG);
    exit(-1);
}

void test_app_launch(int argc, char** argv) {

    int permanent_mode = 0;

    int arg_cnt = 0;
    while (1) {
        static struct option options[] = {
                {PARAM_PERMANENT_MODE, required_argument, 0, 'p'},
                {PARAM_INTERFACE, required_argument, 0, 't'},
                {PARAM_IP_CONFIG,         required_argument, 0, 'i'},
                {PARAM_SERVER_IP,   required_argument, 0, 's'},
                {PARAM_TEST_MODE,   required_argument, 0, 'm'},
                {0,                   0,                 0, 0}};
        int option_index = 0;
        int c = getopt_long_only(argc, argv, "n:p:", options, &option_index);
        if (c < 0) {
            break;
        }
        arg_cnt++;
        switch (c) {
            case 'p':
                permanent_mode = 1;
                strncpy(test_mode_arg, optarg, ARG_BUF_LEN);
                break;
            case 'm':
                strncpy(test_mode_arg, optarg, ARG_BUF_LEN);
                break;
            case 't':
                strncpy(trusted_interface, optarg, ARG_BUF_LEN);
                break;
            case 'i':
                strncpy(ip_config, optarg, ARG_BUF_LEN);
                break;
            case 's':
                strncpy(server_ip, optarg, ARG_BUF_LEN);
                break;
            default:
                fprintf(stderr, "Unrecognized option\n");
                common_usage(argv[0]);
        }
    }

    if (arg_cnt != 3 && arg_cnt != 4) {
        fprintf(stderr, "Wrong number of arguments\n");
        common_usage(argv[0]);
    }

    // This mode runs the test and shuts down the trusted interface once the tests are completed.
    test_mode_t m = {0};
    if (!strcmp(test_mode_arg, TEST_MODE_SGX_SECURED_STR)) {
        m.mode = TEST_MODE_SGX_SECURED;
    } else if (!strcmp(test_mode_arg, TEST_MODE_SGX_VALIDATED_STR)) {
        m.mode = TEST_MODE_SGX_VALIDATED;
    } else if (!strcmp(test_mode_arg, TEST_MODE_SGX_RAW_STR)) {
        m.mode = TEST_MODE_SGX_RAW;
    } else if (!strcmp(test_mode_arg, TEST_MODE_TAP_INTERFACE_STR)) {
        m.mode = TEST_MODE_TAP_INTERFACE;
    } else if (!strcmp(test_mode_arg, TEST_MODE_REGULAR_INTERFACE_STR)) {
        m.mode = TEST_MODE_REGULAR_INTERFACE;
    } else if (!strcmp(test_mode_arg, TEST_MODE_MACSEC_RAW_STR)) {
        m.mode = TEST_MODE_MACSEC_RAW;
    } else {
        printf("Test mode %s not recognized\n", test_mode_arg);
        exit(-1);
    }

    struct trusted_sock_addr server = {0};
    if (!permanent_mode) { // The server ip is only required for the tests
        server.ip4_addr = ipv4_to_int(server_ip);
        if (!server.ip4_addr) {
            printf("Invalid server ip\n");
            exit(-1);
        }
    }

    /************** Check whether we are running on a regular interface *************/
    if (m.mode == TEST_MODE_REGULAR_INTERFACE) {
        if (permanent_mode) {
            printf("Error - The permanent mode does not make sense without a TAP interface\n");
            exit(-1);
        }
        run_tests(0, server, m);
        return;
    }


    /************** Configure the support lib to do the right thing depending on the mode *************/
    int sgx_used = 1;
    if (m.mode == TEST_MODE_TAP_INTERFACE) {
        sgx_used = 0;
    }

    if (!is_valid_ipv4_config(ip_config)) {
        printf("Invalid ip config %s\n", ip_config);
        exit(-1);
    }
    
    enable_sgx(sgx_used); // Tell the support lib to (not) use sgx
    enable_raw_macsec(m.mode == TEST_MODE_MACSEC_RAW);
    enable_raw_sgx(m.mode == TEST_MODE_SGX_RAW);

    sgx_enclave_id_t eid = 0;
    if (sgx_used && initialize_enclave(ENCLAVE_FILENAME, &eid)) {
        exit(-1);
    }

    if (m.mode == TEST_MODE_SGX_SECURED || m.mode == TEST_MODE_MACSEC_RAW) {
        DEBUG_LOG("Mode %s - Use MACSec, load MACSec keys\n", test_mode_to_str(m));
        load_macsec_keys(eid);
    } else {
        DEBUG_LOG("Mode %s - Skip the MACSec key loading, run without MACSec\n", test_mode_to_str(m));
    }

    if (launch_trusted_interface(trusted_interface, ip_config, eid)) {
        printf("Failed to launch the trusted interface\n");
        exit(-1);
    }
    
    
    /************** Either launch the permanent mode or run the tests *************/
    if (permanent_mode) {
        // This mode is intended for usage with external software, where the SGX-secured network interface needs to be permanently active,
        // rather than only executing tests and terminating afterwards.
        printf("Running trusted interface %s in permanent mode %s with ip config %s...\n", trusted_interface, test_mode_to_str(m), ip_config);
        pthread_exit(0); // Let the main thread die, the trusted interface is kept running by other threads
    }


    run_tests(eid, server, m);


    /************** Shutdown *************/
    if (shutdown_trusted_interface()) {
        printf("Graceful shutdown of interface failed\n");
        exit(-1);
    }

    if (sgx_used && destroy_enclave(eid)) {
        exit(-1);
    }

    printf("%s successfully completed.\n\n", argv[0]);
}
