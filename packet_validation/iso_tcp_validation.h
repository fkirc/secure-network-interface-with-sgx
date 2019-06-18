#pragma once

#define TCP_PORT_ISO 102

int validate_iso_tcp_packet(const void* packet, const size_t len, const size_t tcp_payload_len);

struct tpkt_header {
    uint8_t version;
    uint8_t reserved;
    uint16_t tpkt_len;
    uint8_t iso_hdr_len;
    uint8_t pdu_type;
} __attribute__((packed));

struct iso_data {
    struct tpkt_header tpkt;
    uint8_t last_data_unit;
} __attribute__((packed));

