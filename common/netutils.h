#pragma once

#include "utils.h"

int open_raw_socket(const char* iface);

int get_mac_address(const char* iface, const int raw_fd, char* mac);
