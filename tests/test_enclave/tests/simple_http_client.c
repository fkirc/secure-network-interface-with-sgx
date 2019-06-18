#include "../test_enclave_t.h"
#include "../../../packet_validation/trusted_sock_api.h"
#include "../../../packet_validation/netutils_t.h"
#include "stdlib.h"
#include "test_utils.h"
#include "inttypes.h"
#include "string.h"


static const char HTTP_REQUEST[] = "GET / HTTP/1.1\r\n\r\n";
static const char EXPECTED_RESPONSE[] = "HTTP/1.1 200 OK\r\n\r\n";

// We do not want to send the terminating null byte
#define MSG_SIZE(X) (sizeof(X) - 1)

static void do_request(struct trusted_sock_addr server) {

    int sock_fd;

    sock_fd = trusted_sock_create(0, 0, 0);
    ASSERT_DEBUG(sock_fd != -1);

    char response_buf[sizeof(EXPECTED_RESPONSE)];

    ASSERT_DEBUG(!trusted_sock_connect(sock_fd, server, HTTP_REQUEST, MSG_SIZE(HTTP_REQUEST), response_buf, sizeof(response_buf)));

    int n_sent = trusted_sock_write_n(sock_fd, MSG_SIZE(HTTP_REQUEST));
    ASSERT_DEBUG(n_sent == MSG_SIZE(HTTP_REQUEST));

    int n_rec = trusted_sock_read_n(sock_fd, MSG_SIZE(EXPECTED_RESPONSE));
    ASSERT_DEBUG(n_rec == MSG_SIZE(EXPECTED_RESPONSE));

    ASSERT_DEBUG(!memcmp(response_buf, EXPECTED_RESPONSE, MSG_SIZE(EXPECTED_RESPONSE)));

    ASSERT_DEBUG(!trusted_sock_close(sock_fd));
}

#ifdef MOCK_ECALL_API
int mocked_ecall_simple_http_client(struct trusted_sock_addr server, size_t num_requests) {
#else
int ecall_simple_http_client(struct trusted_sock_addr server, size_t num_requests) {
#endif

    //TEST_LOG("Send %zd http requests to server ip %s at port %d...\n", num_requests, inet_ntoa_t(server.ip4_addr), server.port);

    for (size_t req_nr = 1; req_nr <= num_requests; req_nr++) {
        do_request(server);
    }

    //TEST_LOG("Finished %zd http requests successfully\n", num_requests);
    return 0;
}
