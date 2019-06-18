
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "test_enclave_u.h"
#include "test_app.h"
#include "../../support_lib/sgx_utils_u.h"

void common_usage(const char* prog_name);

void usage(const char *prog_name) {
    fprintf(stderr, "Usage for key installation: %s --%s <16 byte hex string> --%s <16 byte hex string>\n",
            prog_name, PARAM_ENCLAVE_TX_KEY, PARAM_ENCLAVE_RX_KEY);
    common_usage(prog_name);
    exit(-1);
}

int main(int argc, char **argv) {

    if (argc < 2) {
        usage(argv[0]);
    }

    try_sgx_enable_or_die();

    char* first_param = argv[1] + 2; // skip the "--" characters
    if (!strncmp(first_param, PARAM_ENCLAVE_TX_KEY, sizeof(PARAM_ENCLAVE_TX_KEY))) {
        test_app_key_installation(argc, argv);
    } else {
        test_app_launch(argc, argv);
    }
    return 0;
}

