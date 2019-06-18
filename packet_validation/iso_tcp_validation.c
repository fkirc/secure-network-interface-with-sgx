#include "netutils_t.h"
#include "iso_tcp_validation.h"
#include "s7commp_validation.h"
#include "../tests/test_enclave/test_enclave_t.h"
#include "tcp_validation.h"

// Only validate outgoing ISO-TCP packets



struct iso_shadow_state {
    // ISO specific fields
    char iso_connection_created;
    char expect_new_tsdu; // Indicates whether a new "Transport Service Data Unit" is expected, in our case an S7COMM+ PDU
    size_t tpkt_offset; // Marks the beginning of the next TPKT within a TCP packet payload

    // ------------------------------------------------------------------------
    // S7COMM+/OMS+ specific shadow state
    struct s7commp_shadow_state s7_state;
};


struct iso_connect_request {
    struct tpkt_header tpkt;
    uint16_t  dest_reference;
    uint16_t src_reference;
    uint8_t flags;
    uint8_t src_tsap_param_code;
    uint8_t src_tsap_param_len;
    uint16_t src_tsap;
    uint8_t dst_tsap_param_code;
    uint8_t dst_tsap_param_len;
    uint16_t dst_tsap;
    uint8_t tpdu_size_param_code;
    uint8_t tpdu_size_param_len;
    uint8_t tpdu_size;
} __attribute__((packed));



#define ISO_PDU_TYPE_DATA 0xF0
#define ISO_PDU_TYPE_CONNECT_REQUEST 0xE0



static int validate_iso_connect_request(const void* buf, const size_t len) {
    if (len != sizeof(struct iso_connect_request)) {
        DEBUG_LOG("Spurious packet detected, expecting an ISO Connect Request for a new source port\n");
        return -1;
    }

    const struct iso_connect_request* cr = buf;
    if (cr->tpkt.pdu_type != ISO_PDU_TYPE_CONNECT_REQUEST) {
        DEBUG_LOG("Unexpected pdu_type, expected ISO_PDU_TYPE_CONNECT_REQUEST\n");
        return -1;
    }
    if (cr->tpkt.iso_hdr_len != (sizeof(struct iso_connect_request) - sizeof(struct tpkt_header) + 1)) {
        DEBUG_LOG("iso_hdr_len must be 17 for ISO_PDU_TYPE_CONNECT_REQUEST\n");
        return -1;
    }
    if (cr->dest_reference) {
        DEBUG_LOG("Unexpected CR dest reference\n");
        return -1;
    }
    if (cr->flags) {
        DEBUG_LOG("Unexpected CR flags\n");
        return -1;
    }
    if (cr->src_tsap_param_code != 0xC1) {
        DEBUG_LOG("Unexpected CR src_tsap_param_code\n");
        return -1;
    }
    if (cr->src_tsap_param_len != 2) {
        DEBUG_LOG("Unexpected CR src_tsap_param_len\n");
        return -1;
    }
    if (cr->src_tsap != 0x06) {
        DEBUG_LOG("Unexpected CR src_tsap\n");
        return -1;
    }
    if (cr->dst_tsap_param_code != 0xC2) {
        DEBUG_LOG("Unexpected CR dst_tsap_param_code\n");
        return -1;
    }
    if (cr->dst_tsap_param_len != 2) {
        DEBUG_LOG("Unexpected CR dst_tsap_param_len\n");
        return -1;
    }
    if (cr->dst_tsap != 0x06) {
        DEBUG_LOG("Unexpected CR dst_tsap\n");
        return -1;
    }
    if (cr->tpdu_size_param_code != 0xC0) {
        DEBUG_LOG("Unexpected CR tpdu_size_param_code\n");
        return -1;
    }
    if (cr->tpdu_size_param_len != 1) {
        DEBUG_LOG("Unexpected CR tpdu_size_param_len\n");
        return -1;
    }
    if (cr->tpdu_size != 0x0A) {
        DEBUG_LOG("Unexpected CR tpdu_size\n");
        return -1;
    }
    return 0;
}



static int validate_iso_data(struct iso_shadow_state* iso_state, const void* buf, const size_t len) {
    
    if (len < sizeof(struct iso_data)) {
        DEBUG_LOG("Error: ISO data header spanning over packet boundary\n");
        return -1;
    }

    const struct iso_data* iso = buf;

    if (iso->tpkt.pdu_type != ISO_PDU_TYPE_DATA) {
        DEBUG_LOG("Unexpected pdu_type, expected ISO_PDU_TYPE_DATA\n");
        return -1;
    }
    if (iso->tpkt.iso_hdr_len != 2) {
        DEBUG_LOG("iso_hdr_len must be 2 for ISO_PDU_TYPE_DATA\n");
        return -1;
    }

    const int tpkt_payload_len = ntohs(iso->tpkt.tpkt_len) - iso->tpkt.iso_hdr_len - 5;
    if (tpkt_payload_len < 0) {
        DEBUG_LOG("Inconsistent tpkt payload len\n");
        return -1;
    }


    // -------------------------------------------------------
    // Check whether this TPKT marks the beginning of a new S7COMM+ PDU
    if (iso_state->expect_new_tsdu) {
        // -------------------------------------------------------
        // Do the S7COMM+/OMS+ validation
        if (validate_s7commp_pdu(&iso_state->s7_state, buf, len)) {
            return -1;
        }
    }

    // Update "last_iso_payload_len"
    if (iso_state->expect_new_tsdu) {
        iso_state->s7_state.last_iso_payload_len = 0;
    }
    iso_state->s7_state.last_iso_payload_len += (size_t)tpkt_payload_len;

    // Update "expect_new_tsdu"
    if (iso->last_data_unit == 0x80) {
        iso_state->expect_new_tsdu = 1;
    } else if (!iso->last_data_unit) {
        iso_state->expect_new_tsdu = 0;
    } else {
        DEBUG_LOG("Unexpected last_data_unit\n");
        return -1;
    }

    return 0;
}


static int validate_iso_tpkt(struct iso_shadow_state* iso_state, const void* buf, const size_t len) {

    if (len < sizeof(struct tpkt_header)) {
        DEBUG_LOG("Error: tpkt_header spanning over a packet boundary\n");
        return -1;
    }
    const struct tpkt_header* tpkt = buf;

    if (tpkt->version != 0x03) {
        DEBUG_LOG("tpkt version mismatch\n");
        return -1;
    }
    if (tpkt->reserved) {
        DEBUG_LOG("tpkt reserved mismatch\n");
        return -1;
    }
    if (ntohs(tpkt->tpkt_len) <= tpkt->iso_hdr_len) {
        DEBUG_LOG("iso header len inconsistency\n");
        return -1;
    }

    if (!iso_state->iso_connection_created) {
        if  (!validate_iso_connect_request(buf, len)) {
            iso_state->iso_connection_created = 1;
            return 0;
        } else {
            return -1;
        }
    } else {
        return validate_iso_data(iso_state, buf, len);
    }
}





// -----------------------------------------------------------------------------------------------------------
// Switch to the TCP stream layer and to the layer of individual TCP packets with the code below




#define MAX_TCP_STREAM_LEN 100000000 // Limitation to approximately 100 MB firmware updates

static int validate_new_tcp_stream(struct iso_shadow_state* iso_state, const char* stream, const size_t len) {
    while (iso_state->tpkt_offset < len) {
        const struct tpkt_header* tpkt = (const struct tpkt_header*)(stream + iso_state->tpkt_offset);
        if (validate_iso_tpkt(iso_state, tpkt, len - iso_state->tpkt_offset)) {
            return -1;
        }
        iso_state->tpkt_offset += ntohs(tpkt->tpkt_len);
    }

    iso_state->tpkt_offset -= len;
    return 0;
}


struct iso_tcp_stream {

    char initialized;

    // ------------------------------------------------------------------------
    // TCP specific fields, including the full stream of TCP payload data
    size_t eos; // End of tcp stream
    uint16_t src_port; // The destination port is always 102
    uint32_t initial_seq_number; // Allows to determine a TCP payload offset within tcp_stream
    char tcp_stream[MAX_TCP_STREAM_LEN];

    // ------------------------------------------------------------------------
    // ISO specific fields
    struct iso_shadow_state iso_state;
};


static void init_iso_tcp_stream(struct iso_tcp_stream* state, const struct tcp_packet* p) {

    state->initialized = 1;

    struct iso_shadow_state* iso_state = &state->iso_state;
    memset(iso_state, 0, sizeof(struct iso_shadow_state));
    iso_state->expect_new_tsdu = 1;

    state->eos = 0;
    state->src_port = ntohs(p->tcp.source);
    state->initial_seq_number = ntohl(p->tcp.seq);
    // Do not clear tcp_stream, avoiding unnecessary memory stress
}


static int check_tcp_retransmission(const struct iso_tcp_stream* stream_state, const char* stream, const size_t offset, const size_t len) {
    // This is probably a TCP retransmission
    if ((offset + len) > stream_state->eos) {
        DEBUG_LOG("Inconsistent retransmission len\n");
        return -1;
    }
    // Retransmissions must match previous TCP packets
    int match = memcmp(stream_state->tcp_stream + offset, stream, len);
    if (match) {
        DEBUG_LOG("Retransmission does not match\n");
        return -1;
    }
    return 0; // Accept retransmission
}


static int validate_tcp_stream(struct iso_tcp_stream* stream_state, const char* stream, const size_t offset, const size_t len) {

    if ((offset + len) <= offset) {
        DEBUG_LOG("Offset overflow\n");
        return -1;
    }
    if (offset + len >= MAX_TCP_STREAM_LEN) {
        DEBUG_LOG("Stream buffer overflow\n");
        return -1;
    }
    if (offset > stream_state->eos) {
        DEBUG_LOG("Sequence mismatch - offset: %zd eos: %zd\n", offset, stream_state->eos);
        return -1;
    }

    // -------------------------------------------------------
    // If this is supposed to be a TCP retransmission, then do a separate check
    if (offset < stream_state->eos) {
        return check_tcp_retransmission(stream_state, stream, offset, len);
    }


    // -------------------------------------------------------
    // Do the actual protocol validation with a temporary state
    struct iso_shadow_state tmp_iso_state = stream_state->iso_state;
    if (validate_new_tcp_stream(&tmp_iso_state, stream, len)) {
        return -1;
    }

    // -------------------------------------------------------
    // Apply the state updates only after a successful packet validation
    stream_state->iso_state = tmp_iso_state;
    memcpy(stream_state->tcp_stream + stream_state->eos, stream, len);
    stream_state->eos += len;
    return 0;
}



// We do not support multiple concurrent firmware updates
static struct iso_tcp_stream global_shadow_state = {0};


int validate_iso_tcp_packet(const void* packet, const size_t len, const size_t tcp_payload_len) {

    if (len < sizeof(struct tcp_packet)) {
        return -1;
    }
    if ((len - sizeof(struct tcp_packet)) != tcp_payload_len) {
        DEBUG_LOG("payload len inconsistency\n");
        return -1;
    }
    const struct tcp_packet* p = packet;
    const char* tcp_payload = (const char*)packet + sizeof(struct tcp_packet);

    if (ntohs(p->tcp.dest) != TCP_PORT_ISO) {
        DEBUG_LOG("TCP destination port must be 102 for ISO-TCP\n");
        return -1;
    }

    if (!tcp_payload_len) {
        return 0; // No further checks for TCP packets without payload
    }


    if (!global_shadow_state.initialized || global_shadow_state.src_port != ntohs(p->tcp.source)) {

        // Switch the shadow state only if this is a valid ISO Connect Request

        if (!validate_iso_connect_request(tcp_payload, tcp_payload_len)) {
            init_iso_tcp_stream(&global_shadow_state, p);
            DEBUG_LOG("\nISO Connect Request detected - reset current shadow state and prepare for a new S7COMM+ session at TCP source port %d\n", global_shadow_state.src_port);
        } else {
            DEBUG_LOG("Drop packet with spurious source port %d\n", ntohs(p->tcp.source));
            return -1;
        }
    }

    const uint32_t offset = ntohl(p->tcp.seq) - global_shadow_state.initial_seq_number;
    return validate_tcp_stream(&global_shadow_state, tcp_payload, offset, tcp_payload_len);
}

