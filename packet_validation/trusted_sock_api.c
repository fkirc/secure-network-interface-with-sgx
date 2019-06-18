#include "sgx_trts.h"
#include "sgx_spinlock.h"
#include "../packet_validation/edl_types.h"
#include "trusted_sock_api.h"
#include "tcp_validation.h"

// This is the main lock for the intra-enclave api functions
static sgx_spinlock_t sock_api_lock = {0};

int trusted_sock_create(int domain, int type, int protocol) {
    (void)(domain);
    (void)(type);
    (void)(protocol);

    sgx_spin_lock(&sock_api_lock);

    int ret = -1;
    int sock_idx = tcp_sock_allocate();
    if (sock_idx < 0) {
        ret = -1;
    } else {
        ret = sock_idx + 1;
    }

    sgx_spin_unlock(&sock_api_lock);
    return ret;
}

int trusted_sock_connect(int sock_fd, struct trusted_sock_addr addr, const void* send_buf, size_t send_buf_len, void* rec_buf, size_t rec_buf_len) {
    if (!sgx_is_within_enclave(send_buf, send_buf_len)) {
        return -1;
    }
    if (!sgx_is_within_enclave(rec_buf, rec_buf_len)) {
        return -1;
    }
    sgx_spin_lock(&sock_api_lock);
    int ret = tcp_sock_connect(sock_fd - 1, addr, send_buf, send_buf_len, rec_buf, rec_buf_len);
    sgx_spin_unlock(&sock_api_lock);
    return ret;
}

ssize_t trusted_sock_send(int sock_fd, size_t len, int flags) {
    (void)(flags);
    sgx_spin_lock(&sock_api_lock);
    ssize_t ret = tcp_sock_send(sock_fd - 1, len);
    sgx_spin_unlock(&sock_api_lock);
    return ret;
}

ssize_t trusted_sock_recv(int sock_fd, size_t len, int flags) {
    (void)(flags);
    sgx_spin_lock(&sock_api_lock);
    ssize_t ret = tcp_sock_recv(sock_fd - 1, len);
    sgx_spin_unlock(&sock_api_lock);
    return ret;
}

int trusted_sock_close(int sock_fd) {
    sgx_spin_lock(&sock_api_lock);
    int ret = tcp_sock_free(sock_fd - 1);
    sgx_spin_unlock(&sock_api_lock);
    return ret;
}

