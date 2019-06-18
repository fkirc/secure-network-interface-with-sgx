#include "test_enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_simple_http_client_t {
	int ms_retval;
	struct trusted_sock_addr ms_server;
	size_t ms_num_requests;
} ms_ecall_simple_http_client_t;

typedef struct ms_ecall_send_close_t {
	int ms_retval;
	struct trusted_sock_addr ms_server;
	size_t ms_num_requests;
} ms_ecall_send_close_t;

typedef struct ms_ecall_bulk_data_client_t {
	int ms_retval;
	struct trusted_sock_addr ms_server;
	size_t ms_num_requests;
	size_t ms_stream_size;
} ms_ecall_bulk_data_client_t;

typedef struct ms_ecall_macsec_raw_authenticate_t {
	int ms_retval;
	void* ms_buf;
	size_t ms_packet_len;
	size_t ms_buf_len;
	uint32_t ms_packet_number;
} ms_ecall_macsec_raw_authenticate_t;

typedef struct ms_ecall_macsec_raw_verify_t {
	int ms_retval;
	void* ms_buf;
	size_t ms_packet_len;
	size_t ms_buf_len;
} ms_ecall_macsec_raw_verify_t;

typedef struct ms_ecall_raw_packet_copy_t {
	int ms_retval;
	void* ms_buf;
	size_t ms_packet_len;
	size_t ms_buf_len;
} ms_ecall_raw_packet_copy_t;

typedef struct ms_ecall_authenticate_outgoing_packet_t {
	int ms_retval;
	void* ms_buf;
	size_t ms_packet_len;
	size_t ms_buf_len;
	uint32_t ms_packet_number;
} ms_ecall_authenticate_outgoing_packet_t;

typedef struct ms_ecall_verify_incoming_packet_t {
	int ms_retval;
	void* ms_buf;
	size_t ms_packet_len;
	size_t ms_buf_len;
} ms_ecall_verify_incoming_packet_t;

typedef struct ms_ecall_install_macsec_keys_t {
	int ms_retval;
	const void* ms_p_keyfile;
	uint32_t ms_p_keyfile_len;
	void* ms_sealed_keyfile;
	uint32_t ms_sealed_keyfile_buf_len;
	uint32_t* ms_sealed_keyfile_len_out;
} ms_ecall_install_macsec_keys_t;

typedef struct ms_ecall_load_macsec_keys_t {
	int ms_retval;
	const void* ms_sealed_keyfile;
	uint32_t ms_sealed_keyfile_len;
} ms_ecall_load_macsec_keys_t;

typedef struct ms_ocall_sock_create_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_ocall_sock_create_t;

typedef struct ms_ocall_sock_connect_t {
	int ms_retval;
	int ms_sockfd;
	struct trusted_sock_addr ms_sock_addr;
} ms_ocall_sock_connect_t;

typedef struct ms_ocall_sock_send_t {
	size_t ms_retval;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_sock_send_t;

typedef struct ms_ocall_sock_recv_t {
	size_t ms_retval;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_sock_recv_t;

typedef struct ms_ocall_sock_shutdown_t {
	int ms_retval;
	int ms_sockfd;
	int ms_how;
} ms_ocall_sock_shutdown_t;

typedef struct ms_ocall_sock_close_t {
	int ms_retval;
	int ms_sockfd;
} ms_ocall_sock_close_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_malloc_t {
	void* ms_retval;
	size_t ms_size;
} ms_ocall_malloc_t;

typedef struct ms_ocall_free_t {
	void* ms_ptr;
} ms_ocall_free_t;

static sgx_status_t SGX_CDECL test_enclave_ocall_sock_create(void* pms)
{
	ms_ocall_sock_create_t* ms = SGX_CAST(ms_ocall_sock_create_t*, pms);
	ms->ms_retval = ocall_sock_create(ms->ms_domain, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_sock_connect(void* pms)
{
	ms_ocall_sock_connect_t* ms = SGX_CAST(ms_ocall_sock_connect_t*, pms);
	ms->ms_retval = ocall_sock_connect(ms->ms_sockfd, ms->ms_sock_addr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_sock_send(void* pms)
{
	ms_ocall_sock_send_t* ms = SGX_CAST(ms_ocall_sock_send_t*, pms);
	ms->ms_retval = ocall_sock_send(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_sock_recv(void* pms)
{
	ms_ocall_sock_recv_t* ms = SGX_CAST(ms_ocall_sock_recv_t*, pms);
	ms->ms_retval = ocall_sock_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_sock_shutdown(void* pms)
{
	ms_ocall_sock_shutdown_t* ms = SGX_CAST(ms_ocall_sock_shutdown_t*, pms);
	ms->ms_retval = ocall_sock_shutdown(ms->ms_sockfd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_sock_close(void* pms)
{
	ms_ocall_sock_close_t* ms = SGX_CAST(ms_ocall_sock_close_t*, pms);
	ms->ms_retval = ocall_sock_close(ms->ms_sockfd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_malloc(void* pms)
{
	ms_ocall_malloc_t* ms = SGX_CAST(ms_ocall_malloc_t*, pms);
	ms->ms_retval = ocall_malloc(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL test_enclave_ocall_free(void* pms)
{
	ms_ocall_free_t* ms = SGX_CAST(ms_ocall_free_t*, pms);
	ocall_free(ms->ms_ptr);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[9];
} ocall_table_test_enclave = {
	9,
	{
		(void*)test_enclave_ocall_sock_create,
		(void*)test_enclave_ocall_sock_connect,
		(void*)test_enclave_ocall_sock_send,
		(void*)test_enclave_ocall_sock_recv,
		(void*)test_enclave_ocall_sock_shutdown,
		(void*)test_enclave_ocall_sock_close,
		(void*)test_enclave_ocall_print_string,
		(void*)test_enclave_ocall_malloc,
		(void*)test_enclave_ocall_free,
	}
};
sgx_status_t ecall_simple_http_client(sgx_enclave_id_t eid, int* retval, struct trusted_sock_addr server, size_t num_requests)
{
	sgx_status_t status;
	ms_ecall_simple_http_client_t ms;
	ms.ms_server = server;
	ms.ms_num_requests = num_requests;
	status = sgx_ecall(eid, 0, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_send_close(sgx_enclave_id_t eid, int* retval, struct trusted_sock_addr server, size_t num_requests)
{
	sgx_status_t status;
	ms_ecall_send_close_t ms;
	ms.ms_server = server;
	ms.ms_num_requests = num_requests;
	status = sgx_ecall(eid, 1, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bulk_data_client(sgx_enclave_id_t eid, int* retval, struct trusted_sock_addr server, size_t num_requests, size_t stream_size)
{
	sgx_status_t status;
	ms_ecall_bulk_data_client_t ms;
	ms.ms_server = server;
	ms.ms_num_requests = num_requests;
	ms.ms_stream_size = stream_size;
	status = sgx_ecall(eid, 2, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_macsec_raw_authenticate(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len, uint32_t packet_number)
{
	sgx_status_t status;
	ms_ecall_macsec_raw_authenticate_t ms;
	ms.ms_buf = buf;
	ms.ms_packet_len = packet_len;
	ms.ms_buf_len = buf_len;
	ms.ms_packet_number = packet_number;
	status = sgx_ecall(eid, 3, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_macsec_raw_verify(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len)
{
	sgx_status_t status;
	ms_ecall_macsec_raw_verify_t ms;
	ms.ms_buf = buf;
	ms.ms_packet_len = packet_len;
	ms.ms_buf_len = buf_len;
	status = sgx_ecall(eid, 4, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_raw_packet_copy(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len)
{
	sgx_status_t status;
	ms_ecall_raw_packet_copy_t ms;
	ms.ms_buf = buf;
	ms.ms_packet_len = packet_len;
	ms.ms_buf_len = buf_len;
	status = sgx_ecall(eid, 5, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_authenticate_outgoing_packet(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len, uint32_t packet_number)
{
	sgx_status_t status;
	ms_ecall_authenticate_outgoing_packet_t ms;
	ms.ms_buf = buf;
	ms.ms_packet_len = packet_len;
	ms.ms_buf_len = buf_len;
	ms.ms_packet_number = packet_number;
	status = sgx_ecall(eid, 6, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_verify_incoming_packet(sgx_enclave_id_t eid, int* retval, void* buf, size_t packet_len, size_t buf_len)
{
	sgx_status_t status;
	ms_ecall_verify_incoming_packet_t ms;
	ms.ms_buf = buf;
	ms.ms_packet_len = packet_len;
	ms.ms_buf_len = buf_len;
	status = sgx_ecall(eid, 7, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_install_macsec_keys(sgx_enclave_id_t eid, int* retval, const void* p_keyfile, uint32_t p_keyfile_len, void* sealed_keyfile, uint32_t sealed_keyfile_buf_len, uint32_t* sealed_keyfile_len_out)
{
	sgx_status_t status;
	ms_ecall_install_macsec_keys_t ms;
	ms.ms_p_keyfile = p_keyfile;
	ms.ms_p_keyfile_len = p_keyfile_len;
	ms.ms_sealed_keyfile = sealed_keyfile;
	ms.ms_sealed_keyfile_buf_len = sealed_keyfile_buf_len;
	ms.ms_sealed_keyfile_len_out = sealed_keyfile_len_out;
	status = sgx_ecall(eid, 8, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_load_macsec_keys(sgx_enclave_id_t eid, int* retval, const void* sealed_keyfile, uint32_t sealed_keyfile_len)
{
	sgx_status_t status;
	ms_ecall_load_macsec_keys_t ms;
	ms.ms_sealed_keyfile = sealed_keyfile;
	ms.ms_sealed_keyfile_len = sealed_keyfile_len;
	status = sgx_ecall(eid, 9, &ocall_table_test_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

