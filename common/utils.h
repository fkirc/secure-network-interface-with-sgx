#pragma once

#include <inttypes.h>
#include <stdlib.h>
#include "logging.h"

int run_cmd(const char *__format, ...);

int read_n(int fd, void *buf, int n);

int write_n(int fd, const void *buf, int n);

int str_to_short(const char *str, uint16_t *res);

#define ARG_BUF_LEN 1000

int is_valid_ipv4_config(const char *str);

uint32_t ipv4_to_int(const char* ip);

void hex_dump(const void *data, size_t size);

int hex_string_to_bytes(const char* string, char* buf, size_t buf_len);
