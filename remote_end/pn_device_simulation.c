#include <net/ethernet.h>
#include "../common/pn_definitions.h"
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

#define PACKET_BUF_SIZE 10000

static const char dcp_fake_s7_1200[] = "\x02\x05\x00\x04\x00\x00" \
"\x02\x07\x02\x01\x00\x09\x00\x00\x53\x37\x2d\x31\x32\x30\x30\x00" \
"\x02\x02\x00\x10\x00\x00\x63\x70\x75\x78\x61\x31\x32\x31\x34\x63" \
"\x34\x34\x64\x35\x02\x03\x00\x06\x00\x00\x00\x2a\x01\x0d\x02\x04" \
"\x00\x04\x00\x00\x02\x00\x02\x07\x00\x04\x00\x00\x00\x64\x01\x02" \
"\x00\x0e\x00\x01\xc0\xa8\x00\x01\xff\xff\xff\x00\x00\x00\x00";

static const char dcp_fake_scalance_x200[] = "\x02\x05\x00\x04\x00\x00" \
"\x02\x07\x02\x01\x00\x10\x00\x00\x53\x43\x41\x4c\x41\x4e\x43\x45" \
"\x20\x58\x2d\x32\x30\x30\x02\x02\x00\x02\x00\x00\x02\x03\x00\x06" \
"\x00\x00\x00\x2a\x0a\x01\x02\x04\x00\x04\x00\x00\x01\x00\x02\x07" \
"\x00\x04\x00\x00\x00\x01\x01\x02\x00\x0e\x00\x01\xc0\xa8\x00\x6f" \
"\xff\xff\xff\x00\x00\x00\x00";


static char src_mac[6] = {0};
static int raw_fd = -1;

static void send_dcp_response(const struct dcp_packet* req_hdr, const char* dev_blocks, const size_t dev_blocks_len) {

    ssize_t response_len = sizeof(struct dcp_packet) + dev_blocks_len;
    char* response = calloc(1, response_len);
    assert(response);
    struct dcp_packet* res_hdr = (struct dcp_packet*)response;

    memcpy(res_hdr->ether.ether_dhost, req_hdr->ether.ether_shost, 6);
    memcpy(res_hdr->ether.ether_shost, src_mac, 6);
    res_hdr->ether.ether_type = ETHER_TYPE_PROFINET;
    res_hdr->frame_id = DCP_IDENTIFY_RESPONSE;
    res_hdr->service_id = DCP_SERVICE_ID_IDENTIFY;
    res_hdr->service_type = DCP_SERVICE_TYPE_RESPONSE;
    res_hdr->xid = req_hdr->xid;
    res_hdr->response_delay = 0; // Reserved
    res_hdr->dcp_data_length = htons(dev_blocks_len);

    memcpy(response + sizeof(struct dcp_packet), dev_blocks, dev_blocks_len);

    ssize_t n_sent = send(raw_fd, response, response_len, 0);
    if (n_sent == -1) {
        perror("send()");
        exit(-1);
    }
    assert(n_sent == response_len);
    free(response);
}

static void proc_packet(const void* packet, const size_t len) {

    if (len < sizeof(struct dcp_packet)) {
        return;
    }

    const struct dcp_packet* req_hdr = packet;
    if (req_hdr->ether.ether_type != ETHER_TYPE_PROFINET) {
        return;
    }

    if (req_hdr->frame_id != DCP_IDENTIFY_MULTICAST_REQUEST) {
        return;
    }
    if (req_hdr->service_id != DCP_SERVICE_ID_IDENTIFY) {
        return;
    }
    if (req_hdr->service_type != DCP_SERVICE_TYPE_REQUEST) {
        return;
    }

    DEBUG_LOG("Received DCP request, send DCP responses\n");
    send_dcp_response(req_hdr, dcp_fake_s7_1200, sizeof(dcp_fake_s7_1200));
    // This is a hack for having different source MACs
    // The inventory viewer app expects different MACs for all devices
    src_mac[0] += 0x1;
    send_dcp_response(req_hdr, dcp_fake_scalance_x200, sizeof(dcp_fake_scalance_x200));
    src_mac[0] -= 0x1;
}


static void pn_simulation(const char* iface) {

    raw_fd = open_raw_socket(iface);
    if (raw_fd == -1) {
        DEBUG_LOG("Failed to open raw socket\n");
        exit(-1);
    }

    if (get_mac_address(iface, raw_fd, src_mac)) {
        DEBUG_LOG("Failed to retrieve MAC address\n");
        exit(-1);
    }

    DEBUG_LOG("Simulating profinet devices on interface %s...\n", iface);

    char buf[PACKET_BUF_SIZE];
    memset(&buf, 0, sizeof(buf));

    while (1) {

        ssize_t n_read = recv(raw_fd, &buf, sizeof(buf), 0);
        if (n_read == -1) {
            perror("recv(raw_fd)");
            exit(-1);
        }
        proc_packet(buf, n_read);
    }
}



static void usage(const char *prog_name) {
    fprintf(stderr,
            "Usage: %s --interface <network interface>\n",
            prog_name);
    exit(-1);
}

static char interface[ARG_BUF_LEN + 1] = {0};

int main(int argc, char **argv) {

    if (geteuid()) {
        DEBUG_LOG("Operations not permitted - we need super user privileges for using raw sockets\n");
        return -1;
    }

    int arg_cnt = 0;
    while (1) {
        static struct option options[] = {
                {"interface", required_argument, 0, 'n'},
                {0,           0,                 0, 0}};
        int option_index = 0;
        int c = getopt_long(argc, argv, "n:p:", options, &option_index);
        if (c < 0) {
            break;
        }
        arg_cnt++;
        switch (c) {
            case 'n':
                strncpy(interface, optarg, ARG_BUF_LEN);
                break;
            default:
                usage(argv[0]);
        }
    }
    if (arg_cnt != 1) {
        usage(argv[0]);
    }

    pn_simulation(interface); // This should never return
    return -1;
}
