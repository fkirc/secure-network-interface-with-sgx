#pragma once

#include <inttypes.h>
#include "iso_tcp_validation.h"

struct s7commp_hdr {
    struct iso_data iso;
    uint8_t prot_id;
    uint8_t prot_version;
    uint16_t data_len;
} __attribute__((packed));

struct s7commp_op_hdr {
    uint8_t opcode;
    uint16_t reserved;
    uint16_t function;
    uint16_t reserved2;
    uint16_t seq_num;
    uint32_t session_id;
    uint8_t transport_flags;
} __attribute__((packed));

struct s7commp_v1 {
    struct s7commp_hdr hdr;
    struct s7commp_op_hdr op_hdr;
} __attribute__((packed));

struct s7commp_v3 {
    struct s7commp_hdr hdr;
    uint8_t digest_len;
    uint8_t digest[32];
    struct s7commp_op_hdr op_hdr;
} __attribute__((packed));

#define S7COMMP_PROT_ID 0x72

#define S7COMMP_PROT_VERSION_1 0x01
#define S7COMMP_PROT_VERSION_2 0x02
#define S7COMMP_PROT_VERSION_3 0x03

#define S7COMMP_OPCODE_REQUEST 0x31

#define S7COMMP_FUNCTION_CREATEOBJECT 0xCA04
#define S7COMMP_FUNCTION_DELETEOBJECT 0xD404
#define S7COMMP_FUNCTION_SETMULTIVARIABLES 0x4205
#define S7COMMP_FUNCTION_SETVARIABLE 0xF204
#define S7COMMP_FUNCTION_SETVARSUBSTREAMED 0x7C05
#define S7COMMP_FUNCTION_GETVARSUBSTREAMED 0x8605
#define S7COMMP_FUNCTION_EXPLORE 0xBB04


// This holds all the state that we use for S7COMM+/OMS+ security validations
struct s7commp_shadow_state {
    char s7commp_session_created;
    uint16_t s7commp_seq_number;
    uint16_t last_s7commp_len; // Used for S7COMM+ fragmentation detection
    size_t last_iso_payload_len; // Used for S7COMM+ fragmentation detection
};

int validate_s7commp_pdu(struct s7commp_shadow_state* s7_state, const void* buf, const size_t len);

