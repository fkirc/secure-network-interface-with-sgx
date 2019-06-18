#pragma once

// Definition of our macsec key pair file format used for installing and sealing macsec key pairs

// The macsec key pair file format is specified as follows: key_file_header || ENCLAVE_TX_KEY || ENCLAVE_RX_KEY
// The size of a macsec key pair file must be (sizeof(key_file_header) + 16 + 16)

static const char key_file_header[] = "macsec_keypair_2*128bit"; // the terminating null byte is also included in the key file
#define KEY_FILE_SIZE (2 * MACSEC_KEY_SIZE + sizeof(key_file_header))

#define ERROR_INVALID_KEY_FILE_SIZE (-2)
#define ERROR_INVALID_KEY_FILE_HEADER (-3)
#define ERROR_SEALING_OPERATION_FAILED (-3)
#define ERROR_UNSEALING_OPERATION_FAILED (-4)
#define ERROR_INVALID_SEALED_KEY_FILE_SIZE (-5)
#define ERROR_KEYPAIR_NOT_DIFFERENT (-6)

#define MACSEC_OVERHEAD 32 // overhead per packet: 16 bytes sectag + 16 bytes icv, may need to be changed for new cipher suites
#define MACSEC_KEY_SIZE 16

#define MAX_PACK_SIZE 10000 // should not be too large, since this is used as local buffer on the stack

#define MAC_HEADER_LEN 12 // dest mac || source mac
#define MIN_PACKET_LEN (MAC_HEADER_LEN + 2) // dest mac || source mac || ether type
#define MIN_MACSEC_LEN (MIN_PACKET_LEN + MACSEC_OVERHEAD)

#define ETHER_TYPE_MACSEC 0xE588
