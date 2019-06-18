#include <net/ethernet.h>
#include "../../common/pn_definitions.h"
#include "../../common/netutils.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>

// In contrast to the tcp tests, this runs outside of the enclave (but inside the same test app for simplicity)


#define PACKET_BUF_SIZE 10000
#define DCP_XID 0x01010101

static char src_mac[6] = {0};
static char resp_buf[PACKET_BUF_SIZE] = {0};
static int raw_fd = -1;

static void send_dcp_ident_request() {

    char req_packet[sizeof(struct dcp_packet) + DCP_DATA_LENGTH_REQUEST] = {0};
    struct dcp_packet* req_hdr = (struct dcp_packet*)req_packet;
    char* req_block = req_packet + sizeof(struct dcp_packet);

    memcpy(req_hdr->ether.ether_dhost, pn_multicast, 6);
    memcpy(req_hdr->ether.ether_shost, src_mac, 6);
    req_hdr->ether.ether_type = ETHER_TYPE_PROFINET;
    req_hdr->frame_id = DCP_IDENTIFY_MULTICAST_REQUEST;
    req_hdr->service_id = DCP_SERVICE_ID_IDENTIFY;
    req_hdr->service_type = DCP_SERVICE_TYPE_REQUEST;
    req_hdr->xid = DCP_XID;
    req_hdr->response_delay = htons(10);
    req_hdr->dcp_data_length = htons(DCP_DATA_LENGTH_REQUEST);

    req_block[0] = 0xff;
    req_block[1] = 0xff;

    int n_sent = send(raw_fd, req_packet, sizeof(req_packet), 0);
    if (n_sent == -1) {
        perror("send()");
        exit(-1);
    } else if (n_sent != sizeof(req_packet)) {
        DEBUG_LOG("Sent bytes mismatch\n");
        exit(-1);
    }
}


static int proc_response_packet() {

    int n_read = recv(raw_fd, resp_buf, sizeof(resp_buf), 0);
    if (n_read == -1) {
        perror("recv()");
        exit(-1);
    }

    if (n_read < (int)sizeof(struct dcp_packet)) {
        return -1;
    }

    const struct dcp_packet* res_hdr = (struct dcp_packet*)resp_buf;
    if (res_hdr->ether.ether_type != ETHER_TYPE_PROFINET) {
        return -1;
    }
    if (res_hdr->frame_id != DCP_IDENTIFY_RESPONSE) {
        return -1;
    }
    if (res_hdr->service_id != DCP_SERVICE_ID_IDENTIFY) {
        return -1;
    }
    if (res_hdr->service_type != DCP_SERVICE_TYPE_RESPONSE) {
        return -1;
    }
    if (res_hdr->xid != DCP_XID) {
        return -1;
    }

    DEBUG_LOG("DCP response received\n");
    return 0;
}

static int poll_response_packet(int polltime) {

    struct pollfd fd = {0};
    fd.fd = raw_fd;
    fd.events = POLLIN;

    //DEBUG_LOG("Poll for DCP response with timeout %d\n", polltime);

    int ret = poll(&fd, 1, polltime);
    switch (ret) {
        case -1:
            perror("poll()");
            exit(-1);
        case 0:
            DEBUG_LOG("Timeout - did not receive the expected DCP response\n");
            exit(-1);
        default:
            return proc_response_packet();
    }
}

static int get_time() {
    struct timeval timecheck = {0};
    gettimeofday(&timecheck, NULL);
    return (int)timecheck.tv_sec * 1000 + (int)timecheck.tv_usec / 1000;
}

static void wait_for_dcp_response() {


    const int timeout = 1000; // timeout in milliseconds
    const int start_time = get_time();

    while (1) {
        int polltime = start_time - get_time() + timeout;
        if (polltime < 1) {
            polltime = 1;
        }
        if (!poll_response_packet(polltime)) {
            break;
        }
    }
}

int test_pn_dcp(const char* iface) {

    raw_fd = open_raw_socket(iface);
    if (raw_fd == -1) {
        DEBUG_LOG("Failed to open raw socket\n");
        exit(-1);
    }

    if (get_mac_address(iface, raw_fd, src_mac)) {
        DEBUG_LOG("Failed to retrieve MAC address\n");
        exit(-1);
    }

    send_dcp_ident_request();
    DEBUG_LOG("Sent DCP request on interface %s. Waiting for DCP responses...\n", iface);
    wait_for_dcp_response();


    if (close(raw_fd)) {
        perror("close(raw_fd)");
        exit(-1);
    }
    return 0;
}

