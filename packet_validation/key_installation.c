#include "util_api.h"
#include <sgx_key.h>
#include <string.h>
#include "sealed_key_file.h"
#include "sgx_trts.h"

int seal_keyfile(const void* p_keyfile, void* sealed_keyfile) {

    if (!sgx_is_within_enclave(p_keyfile, KEY_FILE_SIZE)) {
        return -1;
    }
    if (!sgx_is_within_enclave(sealed_keyfile, SEALED_KEY_FILE_SIZE)) {
        return -1;
    }

    if (memcmp(p_keyfile, key_file_header, sizeof(key_file_header))) {
        return ERROR_INVALID_KEY_FILE_HEADER;
    }

    // The default seal key derivation depends only on local cpu keys and on the MRSIGNER identity, but not on the enclave's measurement.
    // This allows seamless enclave updates if the same MRSIGNER identity is reused.

    if (sgx_calc_sealed_data_size(0, KEY_FILE_SIZE) != SEALED_KEY_FILE_SIZE) {
        return -1;
    }

    sgx_status_t ret_status = sgx_seal_data(0, NULL, KEY_FILE_SIZE, p_keyfile, SEALED_KEY_FILE_SIZE, (sgx_sealed_data_t*)sealed_keyfile);
    if (ret_status != SGX_SUCCESS) {
        return ERROR_SEALING_OPERATION_FAILED;
    }
    return 0;
}


int ecall_install_macsec_keys(const void* p_keyfile, const uint32_t p_keyfile_len, void* sealed_keyfile, const uint32_t sealed_keyfile_buf_len, uint32_t* sealed_keyfile_out_len) {

    if (p_keyfile_len != KEY_FILE_SIZE) {
        return ERROR_INVALID_KEY_FILE_SIZE;
    }
    if (sealed_keyfile_buf_len < SEALED_KEY_FILE_SIZE) {
        return -1;
    }

    if (!sgx_is_outside_enclave(p_keyfile, p_keyfile_len)) {
        return -1;
    }
    if (!sgx_is_outside_enclave(sealed_keyfile, sealed_keyfile_buf_len)) {
        return -1;
    }
    if (!sgx_is_outside_enclave(sealed_keyfile_out_len, sizeof(uint32_t))) {
        return -1;
    }

    uint8_t p_keyfile_local[KEY_FILE_SIZE];
    memcpy(p_keyfile_local, p_keyfile, KEY_FILE_SIZE);

    uint8_t sealed_keyfile_local[SEALED_KEY_FILE_SIZE] = {0};

    int err = seal_keyfile(p_keyfile_local, sealed_keyfile_local);
    if (err) {
        return err;
    }

    memcpy(sealed_keyfile, sealed_keyfile_local, SEALED_KEY_FILE_SIZE);
    *sealed_keyfile_out_len = SEALED_KEY_FILE_SIZE;

    return 0;
}
