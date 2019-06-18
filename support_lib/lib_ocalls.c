#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../common/utils.h"
#include "../packet_validation/edl_types.h"

// These untrusted out-calls are wrapper functions that should be only called by the trusted lib (initiating the call within the TEE)


int ocall_sock_create(int domain, int type, int protocol_) {
    (void) (domain);
    (void) (type);
    (void) (protocol_);

    int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1) {
        perror("socket()");
        return -1;
    }

    // Set the SO_LINGER option to ensure that close() blocks until all data has been sent
    struct linger l = {0};
    l.l_onoff = 1;
    l.l_linger = 2; // timeout in seconds
    if (setsockopt(sock_fd, SOL_SOCKET, SO_LINGER, (const char *) &l, sizeof(l))) {
        perror("setsockopt(SO_LINGER)");
        exit(-1);
    }

    //DEBUG_LOG("Socket %d created\n", sock_fd);
    return sock_fd;
}


int ocall_sock_connect(int sock_fd, struct trusted_sock_addr sock_addr) {

    //printf("Socket %d: Try to connect to ip %ux at port %d\n", sock_fd, sock_addr.ip4_addr, sock_addr.port);
    struct sockaddr_in addr_in = {0};
    addr_in.sin_addr.s_addr = htonl(sock_addr.ip4_addr);
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(sock_addr.port);

    if (connect(sock_fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) < 0) {
        perror("connect()");
        return -1;
    }
    return 0;
}


ssize_t ocall_sock_send(int sock_fd, const void *buf, size_t len, int flags) {
    ssize_t bytes_sent = send(sock_fd, buf, len, flags);
    if (bytes_sent == -1) {
        perror("send()");
        return -1;
    }
    //DEBUG_LOG("Bytes sent on socket %d: %zd\n", sock_fd, bytes_sent);
    return bytes_sent;
}

#define MAX_RECV_LEN 10000000
static char dummy_buf[MAX_RECV_LEN];

ssize_t ocall_sock_recv(int sock_fd, void *buf, size_t len, int flags) {

    if (buf) {
        printf("should be null\n");
        exit(-1);
    }
    if (len > sizeof(dummy_buf)) {
        printf("len not supported\n");
        exit(-1);
    }

    ssize_t bytes_received = recv(sock_fd, dummy_buf, len, flags);
    if (bytes_received == -1) {
        perror("recv()");
        return -1;
    }
    //DEBUG_LOG("Bytes received on socket %d: %zd\n", sock_fd, bytes_received);
    return bytes_received;
}


int ocall_sock_shutdown(int sock_fd, int how) {
    //DEBUG_LOG("Shutdown socket %d\n", sock_fd);
    if (shutdown(sock_fd, how)) {
        perror("shutdown()");
        return -1;
    }
    return 0;
}


int ocall_sock_close(int sock_fd) {
    //DEBUG_LOG("Close socket %d\n", sock_fd);
    if (close(sock_fd)) {
        perror("close()");
        return -1;
    }
    return 0;
}


void ocall_print_string(const char *str) {
    printf("%s", str);
}


void* ocall_malloc(size_t size) {
    return malloc(size);
}

void ocall_free(void* ptr) {
    free(ptr);
}
