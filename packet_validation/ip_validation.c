#include "edl_types.h"
#include "tcp_validation.h"
#include "netutils_t.h"
#include "snmp_validation.h"
#include "trusted_sock_api.h"

#define HOST_IP IP4_ADDR(0,0,0,57)
#define HOST_SUBNET IP4_ADDR(0xFF,0xFF,0xFF,0)

int is_valid_host_ip(const uint32_t ip) {
    const uint32_t host_part = ip & (~HOST_SUBNET);
    if (host_part != HOST_IP) {
        return -1;
    }
    return 0;
}

static int basic_ip_validation(const void* packet, const size_t packet_len) {
    if (packet_len < sizeof(struct ipv4_packet))
        return -1;

    const struct ipv4_packet *p = packet;
    if (ntohs(p->ip.tlen) > (packet_len - sizeof(struct ether_header))) {
        DEBUG_LOG("ip tlen too large\n");
        return -1;
    }
    if (ntohs(p->ip.tlen) < (packet_len - sizeof(struct ether_header))) {
        DEBUG_LOG("ip tlen too small\n");
        return -1;
    }
    if ((p->ip.ver_ihl & 0xF0) != 0x40) {
        DEBUG_LOG("Unexpected IP version\n");
        return -1;
    }
    if ((p->ip.ver_ihl & 0x0F) != 5) {
        DEBUG_LOG("Unexpected IP header len\n");
        return -1;
    }
    if (p->ip.flags_fo != 0x40) { // Don't fragment
        DEBUG_LOG("Unexpected flags or fragment offset\n");
        return -1;
    }
    return 0;
}

int validate_outgoing_ipv4_packet(const void* packet, const size_t packet_len) {

    if (basic_ip_validation(packet, packet_len))
        return -1;

    const struct ipv4_packet *p = packet;
    if (is_valid_host_ip(ntohl(p->ip.saddr))) { // Prevent IP spoofing
        DEBUG_LOG("Unexpected source IP of outgoing packet, expecting a X.X.X.%d address\n", HOST_IP);
        return -1;
    }

    uint8_t proto = p->ip.proto;
    if (proto == IP_PROTO_TCP) {
        return validate_outgoing_tcp_packet(packet, packet_len);
    } else if (proto == IP_PROTO_UDP) {
        return validate_outgoing_udp_packet(packet, packet_len);
    }
    return -1; // this means that we also block ICMP
}

int consume_incoming_ipv4_packet(const void* packet, const size_t packet_len) {

    if (basic_ip_validation(packet, packet_len))
        return -1;

    const struct ipv4_packet* ip = packet;
    if (is_valid_host_ip(ntohl(ip->ip.daddr))) {
        //DEBUG_LOG("Unexpected destination IP for incoming packet\n");
        return -1;
    }

    uint8_t proto = ip->ip.proto;
    if (proto == IP_PROTO_TCP) {
        return read_incoming_tcp_packet(packet, packet_len);
    } else if (proto == IP_PROTO_UDP) {
        return basic_udp_validation(packet, packet_len);
    }
    return -1;
}
