#pragma once

#include "unistd.h" // ssize_t
#include "util_api.h"

// These functions must be only called within the TEE where this library is statically linked!

int trusted_sock_create(int domain, int type, int protocol);

int trusted_sock_connect(int sock_fd, struct trusted_sock_addr addr, const void* send_buf, size_t send_buf_len, void* rec_buf, size_t rec_buf_len);

ssize_t trusted_sock_send(int sock_fd, size_t len, int flags);

ssize_t trusted_sock_recv(int sock_fd, size_t len, int flags);

int trusted_sock_close(int sock_fd);


#define CREATE_U32(a,b,c,d)    (((unsigned int)((a) & 0xff) << 24) | \
                               ((unsigned int)((b) & 0xff) << 16) | \
                               ((unsigned int)((c) & 0xff) << 8)  | \
                                (unsigned int)((d) & 0xff))

#define IP4_ADDR(a,b,c,d) CREATE_U32(a,b,c,d)
