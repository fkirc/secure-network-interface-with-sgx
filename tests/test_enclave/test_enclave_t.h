#ifndef TEST_ENCLAVE_T_H__
#define TEST_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct trusted_sock_addr {
	unsigned int ip4_addr;
	unsigned short int port;
} trusted_sock_addr;

int ecall_simple_http_client(struct trusted_sock_addr server, size_t num_requests);
int ecall_send_close(struct trusted_sock_addr server, size_t num_requests);
int ecall_bulk_data_client(struct trusted_sock_addr server, size_t num_requests, size_t stream_size);
int ecall_macsec_raw_authenticate(void* buf, size_t packet_len, size_t buf_len, uint32_t packet_number);
int ecall_macsec_raw_verify(void* buf, size_t packet_len, size_t buf_len);
int ecall_raw_packet_copy(void* buf, size_t packet_len, size_t buf_len);
int ecall_authenticate_outgoing_packet(void* buf, size_t packet_len, size_t buf_len, uint32_t packet_number);
int ecall_verify_incoming_packet(void* buf, size_t packet_len, size_t buf_len);
int ecall_install_macsec_keys(const void* p_keyfile, uint32_t p_keyfile_len, void* sealed_keyfile, uint32_t sealed_keyfile_buf_len, uint32_t* sealed_keyfile_len_out);
int ecall_load_macsec_keys(const void* sealed_keyfile, uint32_t sealed_keyfile_len);

sgx_status_t SGX_CDECL ocall_sock_create(int* retval, int domain, int type, int protocol);
sgx_status_t SGX_CDECL ocall_sock_connect(int* retval, int sockfd, struct trusted_sock_addr sock_addr);
sgx_status_t SGX_CDECL ocall_sock_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_sock_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_sock_shutdown(int* retval, int sockfd, int how);
sgx_status_t SGX_CDECL ocall_sock_close(int* retval, int sockfd);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_malloc(void** retval, size_t size);
sgx_status_t SGX_CDECL ocall_free(void* ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
