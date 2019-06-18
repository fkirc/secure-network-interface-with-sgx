#pragma once

#include <sgx_tseal.h>
#include "../common/key_file_definitions.h"

// A sealed file contains metadata in addition to the encrypted payload and the authentication tag, most importantly the parameters that were used for the seal key derivation
#define SEALED_KEY_FILE_SIZE (KEY_FILE_SIZE + sizeof(sgx_sealed_data_t))

