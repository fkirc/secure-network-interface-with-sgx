#include "../common/snmp_definitions.h"
#include "edl_types.h"
#include "tcp_validation.h"
#include "netutils_t.h"

struct snmp_packet {
    struct ether_header ether;
    struct ip_header ip;
    struct udphdr udp;
    struct snmp_hdr snmp;
} __attribute__((packed));


int basic_udp_validation(const void* packet, const size_t packet_len) {
    if (packet_len < sizeof(struct udp_packet)) {
        return -1;
    }
    const struct udp_packet* udp = packet;
    if (ntohs(udp->udp.len) != (packet_len - sizeof(struct ipv4_packet))) {
        return -1;
    }
    return 0;
}


int validate_outgoing_udp_packet(const void* packet, const size_t packet_len) {

    if (basic_udp_validation(packet, packet_len)) {
        return -1;
    }
    // Currently, we only allow certain SNMP requests as outgoing UDP traffic
    if (packet_len < sizeof(struct snmp_packet)) {
        return -1;
    }
    const struct snmp_packet* snmp = packet;
    const struct snmp_hdr* hdr = &snmp->snmp;

    if (ntohs(snmp->udp.dest) != SNMP_PORT) {
        return -1; // No debug log, too common
    }

    if (hdr->snmp_id != SNMP_SNMP_ID) {
        DEBUG_LOG("Unexpected snmp_id\n");
        return -1;
    }
    if (hdr->snmp_len != (uint8_t)(packet_len - sizeof(struct udp_packet) - 2)) {
        DEBUG_LOG("Unexpected snmp_len\n");
        return -1;
    }
    if (hdr->version_id != SNMP_VERSION_ID) {
        DEBUG_LOG("Unexpected version_id\n");
        return -1;
    }
    if (hdr->version_len != 1) {
        DEBUG_LOG("Unexpected version_len\n");
        return -1;
    }
    if (hdr->version != 0) {
        DEBUG_LOG("Unexpected version\n");
        return -1;
    }
    if (hdr->community_id != SNMP_COMMUNITY_ID) {
        DEBUG_LOG("Unexpected community_id\n");
        return -1;
    }
    if (hdr->community_len != sizeof(hdr->community)) {
        DEBUG_LOG("Unexpected community_len\n");
        return -1;
    }
    if (memcmp(hdr->community, snmp_community_public, sizeof(hdr->community))) {
        DEBUG_LOG("Unexpected community\n");
        return -1;
    }
    // Only allow "GET_NEXT_REQUEST" or "GET_REQUEST" as outgoing snmp packet
    if (hdr->body_id != SNMP_BODY_ID_GET_NEXT_REQUEST && hdr->body_id != SNMP_BODY_ID_GET_REQUEST) {
        DEBUG_LOG("Unexpected body_id\n");
        return -1;
    }
    const size_t bindings_len = packet_len - sizeof(struct snmp_packet);
    if (hdr->body_len != (uint8_t)bindings_len + 12) { // 12 bytes for request id, error status, error index
        DEBUG_LOG("Unexpected body_len\n");
        return -1;
    }
    if (hdr->request_id_id != SNMP_REQUEST_ID_ID) {
        DEBUG_LOG("Unexpected request_id_id\n");
        return -1;
    }
    if (hdr->request_id_len != sizeof(hdr->request_id)) {
        DEBUG_LOG("Unexpected request_id_len\n");
        return -1;
    }
    if (hdr->error_status_id != SNMP_ERROR_STATUS_ID) {
        DEBUG_LOG("Unexpected error_status_id\n");
        return -1;
    }
    if (hdr->error_status_len != 1) {
        DEBUG_LOG("Unexpected error_status_len\n");
        return -1;
    }
    if (hdr->error_status != 0) {
        DEBUG_LOG("Unexpected error_status\n");
        return -1;
    }
    if (hdr->error_index_id != SNMP_ERROR_INDEX_ID) {
        DEBUG_LOG("Unexpected error_index_id\n");
        return -1;
    }
    if (hdr->error_index_len != 1) {
        DEBUG_LOG("Unexpected error_index_len\n");
        return -1;
    }
    if (hdr->error_index != 0) {
        DEBUG_LOG("Unexpected error_index\n");
        return -1;
    }
    return 0;
}