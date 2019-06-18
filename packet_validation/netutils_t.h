#pragma once

#include <inttypes.h>
#include <stdlib.h> /* for size_t */

#include "util_api.h"

uint32_t htonl(uint32_t hostlong);
uint16_t ntohs(uint16_t val);
uint32_t ntohl(uint32_t val);

void ehex_dump(const void *data, size_t size);

#define ETHER_TYPE_PROFINET 0x9288

int is_ether_type(const void* packet, uint16_t ether_type);

const char* inet_ntoa_t(uint32_t ipv4);
