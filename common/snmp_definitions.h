#pragma once

#include <inttypes.h>

// snmp related definitions

struct snmp_hdr {
    uint8_t snmp_id;
    uint8_t snmp_len;
    uint8_t version_id;
    uint8_t version_len;
    uint8_t version;
    uint8_t community_id;
    uint8_t community_len;
    uint8_t community[6];
    uint8_t body_id;
    uint8_t body_len;
    uint8_t request_id_id;
    uint8_t request_id_len;
    uint32_t request_id;
    uint8_t error_status_id;
    uint8_t error_status_len;
    uint8_t error_status;
    uint8_t error_index_id;
    uint8_t error_index_len;
    uint8_t error_index;
} __attribute__((packed));

#define SNMP_SNMP_ID 0x30
#define SNMP_VERSION_ID 0x02
#define SNMP_COMMUNITY_ID 0x04
#define SNMP_BODY_ID_GET_REQUEST 0xa0
#define SNMP_BODY_ID_GET_NEXT_REQUEST 0xa1
#define SNMP_BODY_ID_GET_RESPONSE 0xa2
#define SNMP_REQUEST_ID_ID 0x02
#define SNMP_ERROR_STATUS_ID 0x02
#define SNMP_ERROR_INDEX_ID 0x02

#define SNMP_PORT 161

static const uint8_t snmp_community_public[] = "\x70\x75\x62\x6c\x69\x63";

static const uint8_t snmp_fake_bindings_scalance_x200[] = "\x30\x0f\x30\x0d" \
"\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x06\x01\x00";
