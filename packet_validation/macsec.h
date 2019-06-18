#pragma once

#include <inttypes.h>

int macsec_authenticate_packet(char* buf, size_t packet_len, size_t buf_len, uint32_t packet_number);

int macsec_verify_packet(char* buf, size_t packet_len);

int macsec_initialize(const uint8_t* tx_key, const uint8_t* rx_key);

char is_macsec_initialized(void);
