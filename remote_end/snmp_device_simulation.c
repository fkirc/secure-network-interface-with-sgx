#include <net/ethernet.h>
#include "../common/snmp_definitions.h"
#include "../common/netutils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include <getopt.h>
#include "assert.h"
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>

#define PACKET_BUF_SIZE 10000

static int sock_fd = -1;

/*static const uint8_t snmp_fake_bindings_s71200[] = "\x30\x62\x30\x60" \
"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x04\x54\x53\x69\x65\x6d" \
"\x65\x6e\x73\x2c\x20\x53\x49\x4d\x41\x54\x49\x43\x20\x53\x37\x2c" \
"\x20\x43\x50\x55\x2d\x31\x32\x30\x30\x2c\x20\x36\x45\x53\x37\x20" \
"\x32\x31\x34\x2d\x31\x48\x47\x34\x30\x2d\x30\x58\x42\x30\x2c\x20" \
"\x48\x57\x3a\x20\x35\x2c\x20\x46\x57\x3a\x20\x56\x2e\x34\x2e\x32" \
"\x2e\x33\x2c\x20\x53\x20\x43\x2d\x4a\x37\x53\x36\x34\x37\x32\x36";*/


static void send_response(struct sockaddr* client, const void* req, const void* bindings, const size_t bindings_len) {

    const struct snmp_hdr* req_hdr = req;

    size_t response_len = sizeof(struct snmp_hdr) + bindings_len;
    void* response = calloc(1, response_len);
    assert(response);
    struct snmp_hdr* hdr = response;
    hdr->snmp_id = SNMP_SNMP_ID;
    hdr->snmp_len = (uint8_t)(response_len - 2);
    hdr->version_id = SNMP_VERSION_ID;
    hdr->version_len = 1;
    hdr->version = 0;
    hdr->community_id = SNMP_COMMUNITY_ID;
    hdr->community_len = sizeof(hdr->community);
    memcpy(hdr->community, snmp_community_public, sizeof(hdr->community));
    hdr->body_id = SNMP_BODY_ID_GET_RESPONSE;
    hdr->body_len = (uint8_t)bindings_len + 12; // 12 bytes for request id, error status, error index
    hdr->request_id_id = SNMP_REQUEST_ID_ID;
    hdr->request_id_len = sizeof(hdr->request_id);
    hdr->request_id = req_hdr->request_id;
    hdr->error_status_id = SNMP_ERROR_STATUS_ID;
    hdr->error_status_len = 1;
    hdr->error_status = 0;
    hdr->error_index_id = SNMP_ERROR_INDEX_ID;
    hdr->error_index_len = 1;
    hdr->error_index = 0;
    memcpy((char*)response + sizeof(struct snmp_hdr), bindings, bindings_len);

    int n_written = sendto(sock_fd, response, response_len, 0, client, sizeof(struct sockaddr_in));
    if (n_written == -1) {
        perror("write(snmp)");
        exit(-1);
    }
    assert(n_written == (int)response_len);
    free(response);
}


static void proc_packet(struct sockaddr* client, const void* packet, const size_t len) {

    (void)(packet);
    assert(len >= sizeof(struct snmp_hdr));
    //DEBUG_LOG("Received a UDP packet of len %zd, send responses...\n", len);

    //send_response(client, packet, snmp_fake_bindings_s71200, sizeof(snmp_fake_bindings_s71200) - 1);
    send_response(client, packet, snmp_fake_bindings_scalance_x200, sizeof(snmp_fake_bindings_scalance_x200) - 1);

}


static void snmp_simulation() {

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)  {
        perror("socket(SOCK_DGRAM)");
        exit(-1);
    }

    int optval = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval, sizeof(int));

    struct sockaddr_in name = {0};
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    name.sin_port = htons(SNMP_PORT);

    if (bind(sock_fd, (struct sockaddr*) &name, sizeof(name))) {
        perror("bind()");
        DEBUG_LOG("Binding on UDP port %d failed. Probably the port is occupied by another process.\n", SNMP_PORT);
        exit(-1);
    }
    DEBUG_LOG("Listening on UDP port %d for incoming SNMP requests...\n", SNMP_PORT);

    size_t len = sizeof(struct sockaddr_in);
    char rec_buf[PACKET_BUF_SIZE] = {0};
    struct sockaddr_in client = {0};

    while (1) {
        int n_read = recvfrom(sock_fd, rec_buf, sizeof(rec_buf), 0, (struct sockaddr*)&client, (socklen_t*)&len);
        if (n_read < 0) {
            perror("read(sock_fd)");
            DEBUG_LOG("Reading from UDP socket failed\n");
            break;
        }
        proc_packet((struct sockaddr*)&client, rec_buf, n_read);
    }

    exit(-1);
}


int main() {

    if (geteuid()) {
        DEBUG_LOG("Operations not permitted - we need super user privileges\n");
        return -1;
    }

    snmp_simulation(); // This should never return
    return -1;
}
