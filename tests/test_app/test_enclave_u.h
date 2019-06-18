#ifndef TEST_ENCLAVE_U_H__
#define TEST_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct trusted_sock_addr {
	unsigned int ip4_addr;
	unsigned short int port;
} trusted_sock_addr;

#ifndef OCALL_SOCK_CREATE_DEFINED__
#define OCALL_SOCK_CREATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sock_create, (int domain, int type, int protocol));
#endif
#ifndef OCALL_SOCK_CONNECT_DEFINED__
#define OCALL_SOCK_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sock_connect, (int sockfd, struct trusted_sock_addr sock_addr));
#endif
#ifndef OCALL_SOCK_SEND_DEFINED__
#define OCALL_SOCK_SEND_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sock_send, (int sockfd, const void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SOCK_RECV_DEFINED__
#define OCALL_SOCK_RECV_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sock_recv, (int sockfd, void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SOCK_SHUTDOWN_DEFINED__
#define OCALL_SOCK_SHUTDOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sock_shutdown, (int sockfd, int how));
#endif
#ifndef OCALL_SOCK_CLOSE_DEFINED__
#define OCALL_SOCK_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sock_close, (int sockfd));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_MALLOC_DEFINED__
#define OCALL_MALLOC_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_malloc, (size_t size));
#endif
#ifndef OCALL_FREE_DEFINED__
#define OCALL_FREE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (void* ptr));
#endif

sgx_status_t ecall_simple_http_client(sgx_enclave_id_t eid, int* retval, struct trusted_sock_addr server, size_t num_requests);
sgx_status_t ecall_send_close(sgx_enclave_id_t eid, int* retval, struct trusted_sock_addr server, size_t num_requests);
sgx_status_t ecall_bulk_data_client(sgx_enclave_id_t eid, int* retval, struct trusted_sock_addr server, size_t num_requests, size_t stream_size);
sgx_status_t ecall_macsec_raw_authenticate(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len, uint32_t packet_number);
sgx_status_t ecall_macsec_raw_verify(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len);
sgx_status_t ecall_raw_packet_copy(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len);
sgx_status_t ecall_authenticate_outgoing_packet(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len, uint32_t packet_number);
sgx_status_t ecall_verify_incoming_packet(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len);
sgx_status_t ecall_install_macsec_keys(sgx_enclave_id_t eid, int* retval, const void* p_keyfile, uint32_t p_keyfile_len, void* sealed_keyfile, uint32_t sealed_keyfile_buf_len, uint32_t* sealed_keyfile_len_out);
sgx_status_t ecall_load_macsec_keys(sgx_enclave_id_t eid, int* retval, const void* sealed_keyfile, uint32_t sealed_keyfile_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
