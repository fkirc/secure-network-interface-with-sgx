#include "test_utils.h"
#include "stdlib.h"
#include "../../../packet_validation/edl_types.h"
#include "../../../packet_validation/trusted_sock_api.h"

#define MSG_WAITALL 0x100 // For these tests, we want to block until all data is there

int trusted_sock_read_n(const int fd, const int n) {

    int left = n;

    while (left > 0) {
        int n_read = (int) trusted_sock_recv(fd, (size_t) left, MSG_WAITALL);
        //printf("trusted_sock_recv read %d bytes\n", n_read);
        if (!n_read) {
            break;
        } else if (n_read < 0) {
            ASSERT_DEBUG(0);
        } else {
            left -= n_read;
        }
    }
    return n - left;
}

int trusted_sock_write_n(const int fd, const int n) {

    int left = n;

    while (left > 0) {
        int n_written = (int) trusted_sock_send(fd, (size_t) left, 0);
        if (!n_written) {
            break;
        } else if (n_written < 0) {
            ASSERT_DEBUG(0);
        } else {
            left -= n_written;
        }
    }
    return n - left;
}
