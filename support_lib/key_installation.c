#include <stdio.h>
#include <string.h>
#include "key_installation.h"
#include "../tests/test_app/test_enclave_u.h"
#include <fcntl.h>
#include <unistd.h>


int install_keys(sgx_enclave_id_t eid, const char* sealed_key_file_path, const void* enclave_tx_key, const void* enclave_rx_key) {

    if (!memcmp(enclave_rx_key, enclave_tx_key, MACSEC_KEY_SIZE)) {
        printf("enclave_rx_key and enclave_tx_key must be different\n");
        return -1;
    }

    // Prepare the keys in the file format which is expected by the enclave
    char p_keyfile[KEY_FILE_SIZE] = {0};
    memcpy(p_keyfile, key_file_header, sizeof(key_file_header));
    char* tx_key = p_keyfile + sizeof(key_file_header);
    memcpy(tx_key, enclave_tx_key, MACSEC_KEY_SIZE);
    char* rx_key = tx_key + MACSEC_KEY_SIZE;
    memcpy(rx_key, enclave_rx_key, MACSEC_KEY_SIZE);

    // Let the enclave seal the keys
    char sealed_keyfile[10000] = {0};
    uint32_t sealed_keyfile_len = 0;
    int ret_val = -1;
    if (ecall_install_macsec_keys(eid, &ret_val, p_keyfile, sizeof(p_keyfile), sealed_keyfile, sizeof(sealed_keyfile), &sealed_keyfile_len) != SGX_SUCCESS) {
        printf("ecall for key installation failed. Enclave is not running?\n");
        return -1;
    }
    if (ret_val) {
        printf("The enclave rejected the keys\n");
        return -1;
    }

    int fd = open(sealed_key_file_path, O_CREAT | O_WRONLY);
    if (fd < 0) {
        perror("open()");
        printf("Failed to create file %s\n", sealed_key_file_path);
        return -1;
    }

    if (write(fd, sealed_keyfile, sealed_keyfile_len) != sealed_keyfile_len) {
        perror("write()");
        printf("Failed to write sealed key file\n");
        return -1;
    }

    if (close(fd)) {
        perror("close()");
        return -1;
    }

    return 0;
}
