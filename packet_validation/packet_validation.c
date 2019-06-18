#include "edl_types.h"
#include "netutils_t.h"
#include "tcp_validation.h"
#include "macsec.h"
#include "sgx_spinlock.h"
#include "../common/key_file_definitions.h"
#include "sgx_trts.h"


int sanitize_outside_packet(const void* buf, size_t packet_len, size_t buf_len) {
    if (packet_len < MIN_PACKET_LEN)
        return -1;
    if (buf_len < packet_len)
        return -1;
    if (MAX_PACK_SIZE < packet_len)
        return -1;
    if (MAX_PACK_SIZE < buf_len)
        return -1;
    if (!sgx_is_outside_enclave(buf, packet_len))
        return -1;
    if (!sgx_is_outside_enclave(buf, buf_len))
        return -1;
    return 0;
}

static int validate_outgoing_packet(const void* packet, const size_t packet_len) {

    if (!sgx_is_within_enclave(packet, packet_len))
        return -1;

    if (is_ether_type(packet, ETHER_TYPE_ARP)) {
        return validate_outgoing_arp_packet(packet, packet_len);
    } else if (is_ether_type(packet, ETHER_TYPE_IPV4)) {
        return validate_outgoing_ipv4_packet(packet, packet_len);
    } else if (is_ether_type(packet, ETHER_TYPE_PROFINET)) {
        return validate_outgoing_pn_packet(packet, packet_len);
    }
    return -1;
}


static int ecall_authenticate_outgoing_packet__(void* outside_buf, const size_t packet_len, const size_t buf_len, const uint32_t packet_number) {
    
    if (sanitize_outside_packet(outside_buf, packet_len, buf_len))
        return -1;

    char local_buf[MAX_PACK_SIZE];
    memcpy(local_buf, outside_buf, packet_len);

    if (validate_outgoing_packet(local_buf, packet_len))
        return -1; // Validation failure

    if (is_macsec_initialized()) {
        if (macsec_authenticate_packet(local_buf, packet_len, buf_len, packet_number))
            return -1;
    }
    // Checks succeeded, copy back to outside buffer
    memcpy(outside_buf, local_buf, packet_len + MACSEC_OVERHEAD);
    return 0;
}


static int consume_incoming_packet(const void* packet, const size_t packet_len) {

    if (!sgx_is_within_enclave(packet, packet_len))
        return -1;

    if (is_ether_type(packet, ETHER_TYPE_IPV4)) {
        return consume_incoming_ipv4_packet(packet, packet_len);
    } else if (is_ether_type(packet, ETHER_TYPE_ARP)) {
        return 0;
    } else if (is_ether_type(packet, ETHER_TYPE_PROFINET)) {
        return 0;
    }
    return -1;
}


static int ecall_verify_incoming_packet__(void* outside_buf, const size_t packet_len, const size_t buf_len) {

    if (sanitize_outside_packet(outside_buf, packet_len, buf_len))
        return -1;

    char local_buf[MAX_PACK_SIZE];
    memcpy(local_buf, outside_buf, packet_len);

    size_t  new_packet_len = 0;
    if (is_macsec_initialized()) {
        if (macsec_verify_packet(local_buf, packet_len))
            return -1; // Incoming packet not authenticated
        new_packet_len = packet_len - MACSEC_OVERHEAD;
    } else {
        new_packet_len = packet_len;
    }

    if (consume_incoming_packet(local_buf, new_packet_len))
        return -1;

    // Checks succeeded, copy back to outside buffer
    memcpy(outside_buf, local_buf, new_packet_len);
    return 0;
}


// These ecall's should never be called by multiple threads, but we lock them for security reasons

sgx_spinlock_t outgoing_packet_lock = {0};
sgx_spinlock_t incoming_packet_lock = {0};

int ecall_authenticate_outgoing_packet(void* buf, const size_t packet_len, const size_t buf_len, const uint32_t packet_number) {
    sgx_spin_lock(&outgoing_packet_lock);
    int ret = ecall_authenticate_outgoing_packet__(buf, packet_len, buf_len, packet_number);
    sgx_spin_unlock(&outgoing_packet_lock);
    return ret;
}

int ecall_verify_incoming_packet(void* buf, const size_t packet_len, const size_t buf_len) {
    sgx_spin_lock(&incoming_packet_lock);
    int ret = ecall_verify_incoming_packet__(buf, packet_len, buf_len);
    sgx_spin_unlock(&incoming_packet_lock);
    return ret;
}
