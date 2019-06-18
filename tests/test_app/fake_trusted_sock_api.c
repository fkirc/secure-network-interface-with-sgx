#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../../packet_validation/edl_types.h"

// This implements a mock-version of the trusted sock api for performance comparison purposes

// Only one connection at a time
static const char* send_buf = 0;
static char* rec_buf = 0;

int trusted_sock_create(int domain, int type, int protocol) {
    (void) (domain);
    (void) (type);
    (void) (protocol);

    int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1) {
        perror("socket()");
        return -1;
    }
    return sock_fd;
}

int trusted_sock_connect(int sock_fd, struct trusted_sock_addr sock_addr, const void* send_buf_, size_t send_buf_len, void* rec_buf_, size_t rec_buf_len) {
    (void)(send_buf_len);
    (void)(rec_buf_len);

    struct sockaddr_in addr_in = {0};
    addr_in.sin_addr.s_addr = htonl(sock_addr.ip4_addr);
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(sock_addr.port);

    if (connect(sock_fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) < 0) {
        perror("connect()");
        return -1;
    }

    send_buf = send_buf_;
    rec_buf = rec_buf_;
    return 0;
}

ssize_t trusted_sock_send(int sock_fd, size_t len, int flags) {
    ssize_t bytes_sent = send(sock_fd, send_buf, len, flags);
    if (bytes_sent == -1) {
        perror("send()");
        return -1;
    }
    send_buf += len; // This is just a quick hack for compliance with this api
    return bytes_sent;
}

ssize_t trusted_sock_recv(int sock_fd, size_t len, int flags) {
    ssize_t bytes_received = recv(sock_fd, rec_buf, len, flags);
    if (bytes_received == -1) {
        perror("recv()");
        return -1;
    }
    rec_buf += len; // This is just a quick hack for compliance with this api
    return bytes_received;
}

int trusted_sock_close(int sock_fd) {
    if (close(sock_fd)) {
        perror("close()");
        return -1;
    }
    return 0;
}

