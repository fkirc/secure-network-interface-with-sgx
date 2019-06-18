#include "sgx_spinlock.h"
#include "../../../packet_validation/util_api.h"
#include "../../../packet_validation/macsec.h"
#include "../../../common/key_file_definitions.h"


static int ecall_macsec_raw_authenticate__(void* outside_buf, const size_t packet_len, const size_t buf_len, const uint32_t packet_number) {

    if (sanitize_outside_packet(outside_buf, packet_len, buf_len))
        return -1;

    ASSERT_DEBUG(is_macsec_initialized());

    char local_buf[MAX_PACK_SIZE];
    memcpy(local_buf, outside_buf, packet_len);

    if (macsec_authenticate_packet(local_buf, packet_len, buf_len, packet_number))
        return -1;

    memcpy(outside_buf, local_buf, packet_len + MACSEC_OVERHEAD);
    return 0;
}


static int ecall_macsec_raw_verify__(void* outside_buf, const size_t packet_len, const size_t buf_len) {

    if (sanitize_outside_packet(outside_buf, packet_len, buf_len))
        return -1;

    ASSERT_DEBUG(is_macsec_initialized());

    char local_buf[MAX_PACK_SIZE];
    memcpy(local_buf, outside_buf, packet_len);

    if (macsec_verify_packet(local_buf, packet_len))
            return -1; // Incoming packet not authenticated

    memcpy(outside_buf, local_buf, packet_len - MACSEC_OVERHEAD);
    return 0;
}


int ecall_raw_packet_copy(void* outside_buf, const size_t packet_len, const size_t buf_len) {

    // No locking since this is called for both outgoing and incoming packets (by two threads)

    if (sanitize_outside_packet(outside_buf, packet_len, buf_len))
        return -1;

    ASSERT_DEBUG(!is_macsec_initialized()); // Enforce consistency with the support lib config

    char local_buf[MAX_PACK_SIZE];
    memcpy(local_buf, outside_buf, packet_len);

    // Must fail since MACSec is not initialized for this mode
    ASSERT_DEBUG(macsec_verify_packet(local_buf, packet_len) != 0);

    memcpy(outside_buf, local_buf, packet_len);
    return 0;
}


static sgx_spinlock_t outgoing_macsec_lock = {0};
int ecall_macsec_raw_authenticate(void* buf, const size_t packet_len, const size_t buf_len, const uint32_t packet_number) {
    sgx_spin_lock(&outgoing_macsec_lock);
    int ret = ecall_macsec_raw_authenticate__(buf, packet_len, buf_len, packet_number);
    sgx_spin_unlock(&outgoing_macsec_lock);
    return ret;
}

static sgx_spinlock_t incoming_macsec_lock = {0};
int ecall_macsec_raw_verify(void* buf, const size_t packet_len, const size_t buf_len) {
    sgx_spin_lock(&incoming_macsec_lock);
    int ret = ecall_macsec_raw_verify__(buf, packet_len, buf_len);
    sgx_spin_unlock(&incoming_macsec_lock);
    return ret;
}
