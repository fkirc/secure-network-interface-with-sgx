#pragma once

#include "sgx_urts.h"
#include "sgx_capable.h"

void print_sgx_error_message(sgx_status_t ret);

int try_sgx_enable(sgx_device_status_t *dev_state);

int try_sgx_enable_or_die();

int initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid);

int destroy_enclave(sgx_enclave_id_t eid);
