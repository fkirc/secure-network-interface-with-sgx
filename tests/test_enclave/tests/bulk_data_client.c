#include "../test_enclave_t.h"
#include "../../../packet_validation/trusted_sock_api.h"
#include "../../../packet_validation/netutils_t.h"
#include "stdlib.h"
#include "test_utils.h"
#include "inttypes.h"
#include "string.h"

#define MAX_STREAM_SIZE 10000000

static uint8_t send_buf[MAX_STREAM_SIZE] = {0};
static uint8_t rec_buf[sizeof(size_t)] = {0};

static void do_stream_request(struct trusted_sock_addr server, const size_t stream_size) {

    *((size_t*)send_buf) = stream_size;
    for (size_t cnt = sizeof(size_t); cnt < stream_size + sizeof(size_t); cnt++) {
        send_buf[cnt] = (uint8_t)cnt;
    }

    int sock_fd = trusted_sock_create(0, 0, 0);
    ASSERT_DEBUG(sock_fd > 0);

    const size_t send_len = stream_size + sizeof(size_t);
    ASSERT_DEBUG(send_len <= sizeof(send_buf));
    ASSERT_DEBUG(!trusted_sock_connect(sock_fd, server, send_buf, send_len, rec_buf, sizeof(rec_buf)));

    ASSERT_DEBUG(sizeof(size_t) == trusted_sock_send(sock_fd, sizeof(size_t), 0));
    size_t to_send = stream_size;

    while (to_send) {
        ssize_t n_sent = trusted_sock_send(sock_fd, to_send, 0);
        ASSERT_DEBUG(n_sent > 0);
        to_send -= (size_t)n_sent;
    }
    ssize_t n_rec = trusted_sock_read_n(sock_fd, sizeof(size_t));
    ASSERT_DEBUG(n_rec == sizeof(size_t));
    ASSERT_DEBUG(*((size_t*)rec_buf) == stream_size);

    ASSERT_DEBUG(!trusted_sock_close(sock_fd));
}

#ifdef MOCK_ECALL_API
int mocked_ecall_bulk_data_client(struct trusted_sock_addr server, size_t num_requests, size_t stream_size) {
#else
int ecall_bulk_data_client(struct trusted_sock_addr server, size_t num_requests, size_t stream_size) {
#endif

    if (stream_size > MAX_STREAM_SIZE) {
        DEBUG_LOG("Stream size too large\n");
        return -1;
    }
    if (!stream_size || !num_requests) {
        DEBUG_LOG("Attempt to send zero data\n");
        return -1;
    }
    if (stream_size < num_requests) {
        DEBUG_LOG("Not bulky enough\n");
        return -1;
    }

    //TEST_LOG("Num requests: %zd Stream size: %zd Server ip %s Port %d\n", num_requests, stream_size, inet_ntoa_t(server.ip4_addr), server.port);

    for (size_t cnt = 0; cnt < num_requests; cnt++) {
        do_stream_request(server, stream_size);
    }

    //TEST_LOG("Finished successfully\n");
    return 0;
}
