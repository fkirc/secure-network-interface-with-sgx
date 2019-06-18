#include "../test_enclave_t.h"
#include "../../../packet_validation/trusted_sock_api.h"
#include "../../../packet_validation/netutils_t.h"
#include "stdlib.h"
#include "test_utils.h"
#include "inttypes.h"
#include "string.h"

// send-close is a problematic case in the sense that it can fail undetected if not implemented properly

static const char MAGIC_CHUNK[] = "GET / HTTP/1.1\r\n\r\nNo response expected!";

// We do not want to send the terminating null byte
#define MSG_SIZE(X) (sizeof(X) - 1)

static void send_chunk(struct trusted_sock_addr server) {
    
    int sock_fd = trusted_sock_create(0, 0, 0);
    ASSERT_DEBUG(sock_fd != -1);

    char dummy;
    ASSERT_DEBUG(!trusted_sock_connect(sock_fd, server, MAGIC_CHUNK, MSG_SIZE(MAGIC_CHUNK), &dummy, 0));

    int n_sent = trusted_sock_write_n(sock_fd, MSG_SIZE(MAGIC_CHUNK));
    ASSERT_DEBUG(n_sent == MSG_SIZE(MAGIC_CHUNK));

    ASSERT_DEBUG(!trusted_sock_close(sock_fd));
}


int ecall_send_close(struct trusted_sock_addr server, size_t num_requests) {

    TEST_LOG("Send %zd chunks to server ip %s at port %d...\n", num_requests, inet_ntoa_t(server.ip4_addr), server.port);

    for (size_t req_nr = 1; req_nr <= num_requests; req_nr++) {
        send_chunk(server);
    }

    TEST_LOG("Sent %zd chunks successfully\n", num_requests);
    return 0;
}
