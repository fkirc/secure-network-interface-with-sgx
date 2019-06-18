#include "sealed_key_file.h"
#include <string.h>
#include "macsec.h"
#include "sgx_trts.h"

static int unseal_macsec_keys(void* sealed_key_file) {

    if (!sgx_is_within_enclave(sealed_key_file, SEALED_KEY_FILE_SIZE)) {
        return -1;
    }

    if (sgx_get_encrypt_txt_len(sealed_key_file) != KEY_FILE_SIZE) {
        return ERROR_INVALID_KEY_FILE_SIZE;
    }

    uint8_t key_file[KEY_FILE_SIZE] = {0};
    uint32_t key_file_len = sizeof(key_file);
    sgx_status_t ret_state = sgx_unseal_data(sealed_key_file, 0, 0, key_file, &key_file_len);
    if (ret_state != SGX_SUCCESS) {
        return ERROR_UNSEALING_OPERATION_FAILED;
    }
    
    if (memcmp(key_file, key_file_header, sizeof(key_file_header))) {
        return ERROR_INVALID_KEY_FILE_HEADER;
    }

    const uint8_t* enclave_tx_key = key_file + sizeof(key_file_header);
    const uint8_t* enclave_rx_key = enclave_tx_key + MACSEC_KEY_SIZE;

    if (!memcmp(enclave_tx_key, enclave_rx_key, MACSEC_KEY_SIZE)) {
        return ERROR_KEYPAIR_NOT_DIFFERENT;
    }

    if (macsec_initialize(enclave_tx_key, enclave_rx_key)) {
        return -1;
    }

    return 0;
}


int ecall_load_macsec_keys(const void* sealed_key_file, uint32_t sealed_keyfile_len) {

    if (is_macsec_initialized()) {
        return -1; // double initializations not allowed
    }

    if (sealed_keyfile_len != SEALED_KEY_FILE_SIZE) {
        return ERROR_INVALID_SEALED_KEY_FILE_SIZE;
    }

    if (!sgx_is_outside_enclave(sealed_key_file, sealed_keyfile_len)) {
        return -1;
    }

    uint8_t local_sealed_key_file[SEALED_KEY_FILE_SIZE];
    memcpy(local_sealed_key_file, sealed_key_file, SEALED_KEY_FILE_SIZE);

    return unseal_macsec_keys(local_sealed_key_file);
}
