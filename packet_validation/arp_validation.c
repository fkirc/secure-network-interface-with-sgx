#include "edl_types.h"
#include "netutils_t.h"
#include "tcp_validation.h"

#define ARP_OPCODE_REQUEST 0x1
#define ARP_OPCODE_REPLY 0x2

int validate_outgoing_arp_packet(const void* packet, const size_t len) {

    if (len != sizeof(struct arp_packet))
        return -1;
    const struct arp_packet* arp = packet;

    if (arp->proto_type != ETHER_TYPE_IPV4)
        return -1;
    if (arp->hw_size != 6)
        return -1;
    if (arp->prot_size != 4)
        return -1;

    if (is_valid_host_ip(ntohl(arp->ip_sender))) { // Prevent ARP spoofing
        DEBUG_LOG("Unexpected sender IP of outgoing arp packet\n");
        return -1;
    }

    const uint16_t opcode = ntohs(arp->opcode);
    if (opcode == ARP_OPCODE_REQUEST) {
        return 0;
    } else if (opcode == ARP_OPCODE_REPLY) {
        return 0;
    } else {
        return -1; // Unexpected opcode
    }
}
