#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../../common/snmp_definitions.h"
//#include "../common/netutils.h"
#include "../../packet_validation/netutils_t.h"
#include "../../packet_validation/edl_types.h"
#include <assert.h>

#define RECBUF_SIZE 1024


static struct snmp_hdr request = {0};

static void prepare_request() {

    request.snmp_id = SNMP_SNMP_ID;
    request.snmp_len = (uint8_t)(sizeof(struct snmp_hdr) - 2);
    request.version_id = SNMP_VERSION_ID;
    request.version_len = 1;
    request.community_id = SNMP_COMMUNITY_ID;
    request.community_len = sizeof(request.community);
    memcpy(&request.community, snmp_community_public, sizeof(request.community));
    request.body_id = SNMP_BODY_ID_GET_REQUEST;
    const size_t bindings_len = 0;
    request.body_len = (uint8_t)bindings_len + 12;
    request.request_id_id = SNMP_REQUEST_ID_ID;
    request.request_id_len = sizeof(request.request_id);
    request.error_status_id = SNMP_ERROR_STATUS_ID;
    request.error_status_len = 1;
    request.error_index_id = SNMP_ERROR_INDEX_ID;
    request.error_index_len = 1;

}


static void do_snmp_request(struct trusted_sock_addr server) {

    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SNMP_PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_addr.s_addr = htonl(server.ip4_addr);

    int sock_fd;
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket(SOCK_DGRAM)");
        exit(-1);
    }

    int n_sent = sendto(sock_fd, (const char*)&request, sizeof(request), MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    if (n_sent < 0) {
        perror("sendto()");
        exit(-1);
    }
    assert(n_sent == sizeof(request));


    char recbuf[RECBUF_SIZE];

    socklen_t len = {0};
    int n_rec = recvfrom(sock_fd, (char *)recbuf, sizeof(recbuf), MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
    if (n_rec <= 0) {
        perror("recvfrom()");
        exit(-1);
    }

    const int expected_len = sizeof(snmp_fake_bindings_scalance_x200) + sizeof(struct snmp_hdr) - 1;
    assert(expected_len == n_rec);
    assert(!memcmp(recbuf + sizeof(struct snmp_hdr), snmp_fake_bindings_scalance_x200, sizeof(snmp_fake_bindings_scalance_x200) - 1));

    if (close(sock_fd)) {
        perror("close()");
        exit(-1);
    }
}


int test_snmp_client(struct trusted_sock_addr server, const size_t num_requests) {
    
    //DEBUG_LOG("Send %zd SNMP requests to server ip %s at UDP port %d...\n", num_requests, inet_ntoa_t(server.ip4_addr), SNMP_PORT);

    prepare_request();

    for (size_t cnt = 1; cnt <= num_requests; cnt++) {
        do_snmp_request(server);
    }

    return 0;
}
