#pragma once

#include <inttypes.h>

// Profinet related definitions, used by enclave, test app, remote simulation

struct dcp_packet {
    struct ether_header ether;
    uint16_t frame_id;
    uint8_t service_id;
    uint8_t service_type;
    uint32_t xid;
    uint16_t response_delay;
    uint16_t dcp_data_length;
} __attribute__((packed));

#define ETHER_TYPE_PROFINET 0x9288
#define DCP_IDENTIFY_MULTICAST_REQUEST 0xfefe
#define DCP_IDENTIFY_RESPONSE 0xfffe
#define DCP_SERVICE_ID_IDENTIFY 5
#define DCP_SERVICE_TYPE_REQUEST 0
#define DCP_SERVICE_TYPE_RESPONSE 1

#define DCP_DATA_LENGTH_REQUEST 4

static const uint8_t pn_multicast[] = {0x01,0x0e,0xcf,0x00,0x00,0x00};
