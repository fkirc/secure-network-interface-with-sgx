#pragma once

#include "../common/key_file_definitions.h"
#include "sgx_urts.h"

int install_keys(sgx_enclave_id_t eid, const char* sealed_key_file_path, const void* enclave_tx_key, const void* enclave_rx_key);

