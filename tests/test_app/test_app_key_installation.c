#include <stdio.h>
#include <string.h>

#include <getopt.h>

#include "test_enclave_u.h"
#include "test_app.h"

#include "../../support_lib/sgx_utils_u.h"
#include "../../common/utils.h"
#include "../../support_lib/key_installation.h"

static char enclave_tx_key[MACSEC_KEY_SIZE] = {0};
static char enclave_rx_key[MACSEC_KEY_SIZE] = {0};


static int read_key(char* key_buf, const char* string, const char* param_name) {
    if (strlen(string) != MACSEC_KEY_SIZE * 2) {
        printf("%s: Invalid hex string length, must be %d bytes\n", param_name, MACSEC_KEY_SIZE);
        exit(-1);
    }
    if (hex_string_to_bytes(string, key_buf, MACSEC_KEY_SIZE)) {
        printf("%s: Invalid hex string\n", param_name);
        exit(-1);
    }
    return 0;
}


void test_app_key_installation(int argc, char** argv) {


    int arg_cnt = 0;
    while (1) {
        static struct option options[] = {
                {PARAM_ENCLAVE_TX_KEY,    required_argument, 0, 't'},
                {PARAM_ENCLAVE_RX_KEY,    required_argument, 0, 'r'},
                {0,                   0,                 0, 0}};
        int option_index = 0;
        int c = getopt_long_only(argc, argv, "n:p:", options, &option_index);
        if (c < 0) {
            break;
        }
        arg_cnt++;
        switch (c) {
            case 't':
                read_key(enclave_tx_key, optarg, PARAM_ENCLAVE_TX_KEY);
                break;
            case 'r':
                read_key(enclave_rx_key, optarg, PARAM_ENCLAVE_RX_KEY);
                break;
            default:
                usage(argv[0]);
        }
    }
    if (arg_cnt != 2) {
        usage(argv[0]);
    }

    sgx_enclave_id_t eid = 0;
    if (initialize_enclave(ENCLAVE_FILENAME, &eid)) {
        exit(-1);
    }

    printf("\nInstall keys to the enclave %s...\n", ENCLAVE_FILENAME);

    if (install_keys(eid, SEALED_KEYFILE, enclave_tx_key, enclave_rx_key)) {
        printf("Key installation failed\n");
        exit(-1);
    }

    printf("Key installation successful: Created sealed key file \"%s\"\n", SEALED_KEYFILE);

    if (destroy_enclave(eid)) {
        exit(-1);
    }
}
