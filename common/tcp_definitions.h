#pragma once

#include <inttypes.h>
#include <stdlib.h> // size_t
#include <unistd.h> // ssize_t

#define ETHER_TYPE_ARP 0x0608
#define ETHER_TYPE_IPV4 0x0008
#define IP_PROTO_TCP 0x06
#define IP_PROTO_UDP 0x11

// This ether_header is compatible with the Linux definition in <net/ethernet.h>
struct ether_header
{
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
} __attribute__((packed));


struct ip_header {
    uint8_t ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    uint8_t tos;            // Type of service
    uint16_t tlen;            // Total length
    uint16_t identification; // Identification
    uint16_t flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t ttl;            // Time to live
    uint8_t proto;            // Protocol
    uint16_t crc;            // Header checksum
    uint32_t saddr;        // Source address
    uint32_t daddr;        // Destination address
    //uint32_t op_pad;            // Option + Padding
} __attribute__((packed));


struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1 : 4,
            doff : 4,
            fin : 1,
            syn : 1,
            rst : 1,
            psh : 1,
            ack : 1,
            urg : 1,
            ece : 1,
            cwr : 1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct tcp_packet {
    struct ether_header ether;
    struct ip_header ip;
    struct tcp_header tcp;
} __attribute__((packed));


struct arp_packet {
    struct ether_header ether;
    uint16_t hw_type;           // hardware type
    uint16_t proto_type;        // protocol type
    uint8_t hw_size;            // hardware address len
    uint8_t prot_size;          // protocol address len
    uint16_t opcode;            // arp opcode
    uint8_t mac_sender[6];
    uint32_t ip_sender;
    uint8_t mac_target[6];
    uint32_t ip_target;
} __attribute__((packed));


struct ipv4_packet {
    struct ether_header ether;
    struct ip_header ip;
} __attribute__((packed));


struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

struct udp_packet {
    struct ether_header ether;
    struct ip_header ip;
    struct udphdr udp;
} __attribute__((packed));
