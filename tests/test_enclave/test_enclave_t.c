#include "test_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_simple_http_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_simple_http_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_simple_http_client_t* ms = SGX_CAST(ms_ecall_simple_http_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_simple_http_client(ms->ms_server, ms->ms_num_requests);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_send_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_send_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_send_close_t* ms = SGX_CAST(ms_ecall_send_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_send_close(ms->ms_server, ms->ms_num_requests);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bulk_data_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bulk_data_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bulk_data_client_t* ms = SGX_CAST(ms_ecall_bulk_data_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_bulk_data_client(ms->ms_server, ms->ms_num_requests, ms->ms_stream_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_macsec_raw_authenticate(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_macsec_raw_authenticate_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_macsec_raw_authenticate_t* ms = SGX_CAST(ms_ecall_macsec_raw_authenticate_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_buf = ms->ms_buf;



	ms->ms_retval = ecall_macsec_raw_authenticate(_tmp_buf, ms->ms_packet_len, ms->ms_buf_len, ms->ms_packet_number);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_macsec_raw_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_macsec_raw_verify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_macsec_raw_verify_t* ms = SGX_CAST(ms_ecall_macsec_raw_verify_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_buf = ms->ms_buf;



	ms->ms_retval = ecall_macsec_raw_verify(_tmp_buf, ms->ms_packet_len, ms->ms_buf_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_raw_packet_copy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_raw_packet_copy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_raw_packet_copy_t* ms = SGX_CAST(ms_ecall_raw_packet_copy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_buf = ms->ms_buf;



	ms->ms_retval = ecall_raw_packet_copy(_tmp_buf, ms->ms_packet_len, ms->ms_buf_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_authenticate_outgoing_packet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_authenticate_outgoing_packet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_authenticate_outgoing_packet_t* ms = SGX_CAST(ms_ecall_authenticate_outgoing_packet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_buf = ms->ms_buf;



	ms->ms_retval = ecall_authenticate_outgoing_packet(_tmp_buf, ms->ms_packet_len, ms->ms_buf_len, ms->ms_packet_number);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_incoming_packet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_incoming_packet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_incoming_packet_t* ms = SGX_CAST(ms_ecall_verify_incoming_packet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_buf = ms->ms_buf;



	ms->ms_retval = ecall_verify_incoming_packet(_tmp_buf, ms->ms_packet_len, ms->ms_buf_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_install_macsec_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_install_macsec_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_install_macsec_keys_t* ms = SGX_CAST(ms_ecall_install_macsec_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const void* _tmp_p_keyfile = ms->ms_p_keyfile;
	void* _tmp_sealed_keyfile = ms->ms_sealed_keyfile;
	uint32_t* _tmp_sealed_keyfile_len_out = ms->ms_sealed_keyfile_len_out;



	ms->ms_retval = ecall_install_macsec_keys((const void*)_tmp_p_keyfile, ms->ms_p_keyfile_len, _tmp_sealed_keyfile, ms->ms_sealed_keyfile_buf_len, _tmp_sealed_keyfile_len_out);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_macsec_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_macsec_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_macsec_keys_t* ms = SGX_CAST(ms_ecall_load_macsec_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const void* _tmp_sealed_keyfile = ms->ms_sealed_keyfile;



	ms->ms_retval = ecall_load_macsec_keys((const void*)_tmp_sealed_keyfile, ms->ms_sealed_keyfile_len);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_ecall_simple_http_client, 0},
		{(void*)(uintptr_t)sgx_ecall_send_close, 0},
		{(void*)(uintptr_t)sgx_ecall_bulk_data_client, 0},
		{(void*)(uintptr_t)sgx_ecall_macsec_raw_authenticate, 0},
		{(void*)(uintptr_t)sgx_ecall_macsec_raw_verify, 0},
		{(void*)(uintptr_t)sgx_ecall_raw_packet_copy, 0},
		{(void*)(uintptr_t)sgx_ecall_authenticate_outgoing_packet, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_incoming_packet, 0},
		{(void*)(uintptr_t)sgx_ecall_install_macsec_keys, 0},
		{(void*)(uintptr_t)sgx_ecall_load_macsec_keys, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][10];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_sock_create(int* retval, int domain, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sock_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sock_create_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sock_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sock_create_t));
	ocalloc_size -= sizeof(ms_ocall_sock_create_t);

	ms->ms_domain = domain;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sock_connect(int* retval, int sockfd, struct trusted_sock_addr sock_addr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sock_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sock_connect_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sock_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sock_connect_t));
	ocalloc_size -= sizeof(ms_ocall_sock_connect_t);

	ms->ms_sockfd = sockfd;
	ms->ms_sock_addr = sock_addr;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sock_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sock_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sock_send_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sock_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sock_send_t));
	ocalloc_size -= sizeof(ms_ocall_sock_send_t);

	ms->ms_sockfd = sockfd;
	ms->ms_buf = buf;
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sock_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sock_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sock_recv_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sock_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sock_recv_t));
	ocalloc_size -= sizeof(ms_ocall_sock_recv_t);

	ms->ms_sockfd = sockfd;
	ms->ms_buf = buf;
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sock_shutdown(int* retval, int sockfd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sock_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sock_shutdown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sock_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sock_shutdown_t));
	ocalloc_size -= sizeof(ms_ocall_sock_shutdown_t);

	ms->ms_sockfd = sockfd;
	ms->ms_how = how;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sock_close(int* retval, int sockfd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sock_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sock_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sock_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sock_close_t));
	ocalloc_size -= sizeof(ms_ocall_sock_close_t);

	ms->ms_sockfd = sockfd;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	ocalloc_size += (str != NULL) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_malloc(void** retval, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_malloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_malloc_t));
	ocalloc_size -= sizeof(ms_ocall_malloc_t);

	ms->ms_size = size;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_free(void* ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_free_t));
	ocalloc_size -= sizeof(ms_ocall_free_t);

	ms->ms_ptr = ptr;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

