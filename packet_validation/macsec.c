#include <sgx_tcrypto.h>
#include "macsec.h"
#include "netutils_t.h"
#include "../common/key_file_definitions.h"
#include "sgx_trts.h"
// Implements parts of IEEE Std 802.1AE-2006


#define SOURCE_MAC_OFFSET 6
#define MACSEC_PACKET_NUMBER_OFFSET (MAC_HEADER_LEN + 4) // offset of packet number within ethernet packets
#define MACSEC_SCI_OFFSET (MAC_HEADER_LEN + 8) // offset of optional explicit sci within ethernet packets

struct macsec_key {
    uint8_t bytes[16];
};

struct macaddress {
    uint8_t bytes[6];
} __attribute__((packed));

struct macsec_sci {
    struct macaddress mac; // Could be the mac of the secure channel sender, but we use a constant send-sci
    uint16_t port; // port = 00-01, has nothing to do with tcp ports
} __attribute__((packed));

struct macsec_rx_sa {
    uint32_t next_pn;
    struct macsec_key rx_key;
};

struct macsec_tx_sa {
    struct macsec_key tx_key;
};

struct macsec_rx_sc {
    //struct macsec_sci sci; // We do not care about rx sci's
    struct macsec_rx_sa rx_sas[1]; // Only one rx sa, we also do not support on-the-fly key switching
};

struct macsec_tx_sc {
    struct macsec_sci sci;
    struct macsec_tx_sa tx_sas[1]; // Only one tx sa, we also do not support on-the-fly key switching
};

struct macsec_secy {
    struct macsec_rx_sc rx_sc;
    struct macsec_tx_sc tx_sc;
};

struct macsec_sectag {
    uint8_t ether_type[2]; // = 0x88-0xe5
    uint8_t tci; // tag control identifier
    uint8_t short_length;
    uint32_t packet_number;
    struct macsec_sci sci;
} __attribute__((packed));

struct macsec_icv { // integrity check value
    uint8_t bytes[16];
} __attribute__((packed));


/*****************************************************************************/
static struct macsec_secy secy = {0}; // There is only one secure interface per enclave
static char macsec_initialized = 0; // initialization has to be done at each application launch, once keys are sealed
/*****************************************************************************/

int macsec_initialize(const uint8_t* tx_key, const uint8_t* rx_key) {

    ASSERT_DEBUG(MACSEC_OVERHEAD == (sizeof(struct macsec_sectag) + sizeof(struct macsec_icv)));

    if (macsec_initialized) {
        return -1; // double initialization not allowed
    }

    struct macsec_sci* tx_sci = &secy.tx_sc.sci;
    struct macsec_tx_sa* tx_sa = &secy.tx_sc.tx_sas[0];
    struct macsec_rx_sa* rx_sa = &secy.rx_sc.rx_sas[0];

    // Initialize the keys
    memcpy(tx_sa->tx_key.bytes, tx_key, MACSEC_KEY_SIZE);
    memcpy(rx_sa->rx_key.bytes, rx_key, MACSEC_KEY_SIZE);

    // We use a constant send-sci
    memset(tx_sci->mac.bytes, 0x11, 6);
    tx_sci->port = 0x100; // port 00-01, little endian assignment

    macsec_initialized = 1;
    return 0;
}

char is_macsec_initialized(void) {
    return macsec_initialized;
}

// tag control identifier flags for MACSec
#define TCI_VERSION 0x80
#define TCI_END_STATION 0x40
#define TCI_EXPLICIT_SCI 0x20
#define TCI_SINGLE_COPY_BROADCAST 0x10
#define TCI_ENCRYPTION 0x08
#define TCI_CHANGED_TEXT 0x04
#define TCI_ASSOCIATION_NUMBER 0x03 // there are up to 4 "secure associations" for each secure channel

static void insert_sectag(char* buf, const size_t packet_len, struct macsec_tx_sc* tx_sc, uint32_t packet_number) {

    struct macsec_sectag* sectag = (struct macsec_sectag*)(buf + MAC_HEADER_LEN);
    sectag->ether_type[0] = 0x88;
    sectag->ether_type[1] = 0xe5;

    uint8_t tci = 0; // secure association zero
    tci |= TCI_EXPLICIT_SCI; // send explicit sci, all other (optional) flags disabled
    sectag->tci = tci;
    sectag->sci = tx_sc->sci;

    sectag->packet_number = htonl(packet_number);
    //sectag->packet_number = 0xFFFFFFFF; // This would also work against the Linux MACSec replay protection, since it always triggers an integer overflow

    // Everything except of dest mac and source mac is considered as "user data" for macsec
    size_t user_data_len = packet_len - MAC_HEADER_LEN;
    if (user_data_len < 48) { // 9.7 Short Length encoding
        sectag->short_length = (uint8_t)user_data_len;
    } else {
        sectag->short_length = 0;
    }
}


static int insert_icv(char* buf, const size_t packet_len, struct macsec_tx_sc* tx_sc) {

    // the initialization vector is constructed as: ( sci || packet_number )
    uint8_t iv[12] = {0};
    memcpy(iv, (uint8_t*)&tx_sc->sci, 8);
    memcpy(&iv[8], &buf[MACSEC_PACKET_NUMBER_OFFSET], 4);

    struct macsec_tx_sa* tx_sa = &tx_sc->tx_sas[0];

    const uint32_t secured_data_len = (uint32_t)(packet_len + sizeof(struct macsec_sectag));
    sgx_status_t ret_status = sgx_rijndael128GCM_encrypt(
            (const sgx_aes_gcm_128bit_key_t*)tx_sa->tx_key.bytes,
            0, 0, 0, iv, sizeof(iv),
            (uint8_t*)buf,
            secured_data_len,
            (sgx_aes_gcm_128bit_tag_t*)(buf + secured_data_len));
    if (ret_status != SGX_SUCCESS) {
        return -1;
    }
    return 0;
}


static int check_icv_aes_gcm_128(char* secured_data, size_t secured_data_len, struct macsec_rx_sa* rx_sa) {

    uint8_t iv[12] = {0};
    memcpy(iv, &secured_data[MACSEC_SCI_OFFSET], 8);
    memcpy(iv + 8, &secured_data[MACSEC_PACKET_NUMBER_OFFSET], 4);

    sgx_status_t ret_status = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)rx_sa->rx_key.bytes,
            0, 0, 0, iv, sizeof(iv),
            (uint8_t*)secured_data,
            (uint32_t)secured_data_len,
            (sgx_aes_gcm_128bit_tag_t*)(secured_data + secured_data_len));
    if (ret_status != SGX_SUCCESS) {
        return -1;
    }
    return 0;
}


static int check_icv(char* packet, size_t packet_len, struct macsec_rx_sa* rx_sa) {

    // Regular icv check
    size_t icv_offset = packet_len - sizeof(struct macsec_icv);
    if (!check_icv_aes_gcm_128(packet, icv_offset, rx_sa)) {
        return 0; // Regular icv check success
    }

    // This is a bad workaround since some configurations append unwanted null-bytes to incoming macsec packets
    if (packet_len < (MIN_MACSEC_LEN + 1)) {
        return -1;
    }
    return check_icv_aes_gcm_128(packet, icv_offset - 1, rx_sa); // Second try - workaround icv check

}

int macsec_authenticate_packet(char* buf, const size_t packet_len, const size_t buf_len, uint32_t packet_number) {

    if (!is_macsec_initialized()) {
        return -1;
    }
    ASSERT_DEBUG(sgx_is_within_enclave(buf, packet_len));
    ASSERT_DEBUG(sgx_is_within_enclave(buf, buf_len));

    if (buf_len < packet_len) {
        return -1;
    }
    if (buf_len < (packet_len + MACSEC_OVERHEAD)) {
        return -1;
    }

    // Move the ethernet payload including the ether type backwards to make space for the macsec sectag
    for (size_t i = (packet_len - 1); i >= MAC_HEADER_LEN; i--) {
        buf[i + sizeof(struct macsec_sectag)] = buf[i];
    }

    struct macsec_tx_sc* tx_sc = &secy.tx_sc;

    insert_sectag(buf, packet_len, tx_sc, packet_number);

    if (insert_icv(buf, packet_len, tx_sc)) {
        return -1;
    }

    return 0;
}


int macsec_verify_packet(char* buf, const size_t packet_len) {

    if (!is_macsec_initialized()) {
        return -1;
    }
    ASSERT_DEBUG(sgx_is_within_enclave(buf, packet_len));

    if (packet_len < (MIN_MACSEC_LEN)) {
        return -1;
    }

    struct macsec_rx_sa* rx_sa = &secy.rx_sc.rx_sas[0];

    const struct macsec_sectag* sectag = (struct macsec_sectag*)(buf + MAC_HEADER_LEN);
    if (sectag->ether_type[0] != 0x88 || sectag->ether_type[1] != 0xe5) {
        return -1;
    }

    if (check_icv(buf, packet_len, rx_sa)) {
        return -1; // MACSec packet verification failed
    }

    const uint32_t pn = ntohl(sectag->packet_number);
    if (pn < rx_sa->next_pn) {
        DEBUG_LOG("Incoming packet number is too small\n");
        return -1;
    }
    rx_sa->next_pn = pn + 1; // Packet accepted

    // Move the ethernet payload forward, overwriting the macsec sectag
    size_t icv_offset = packet_len - sizeof(struct macsec_icv);
    for (size_t i = MAC_HEADER_LEN; i < icv_offset; i++) {
        buf[i] = buf[i + sizeof(struct macsec_sectag)];
    }

    return 0;
}
