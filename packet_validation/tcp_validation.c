#include "netutils_t.h"
#include "sgx_spinlock.h"
#include "../tests/test_enclave/test_enclave_t.h"
#include "tcp_validation.h"
#include "iso_tcp_validation.h"

#define MAX_NR_SOCKETS 8


struct tcp_sock {
    char volatile used;
    char volatile syn_init;
    char volatile syn_ack_init;
    int volatile sys_fd;
    uint32_t volatile initial_seq_out;
    uint32_t volatile initial_seq_in;
    size_t n_sent_syscall;
    size_t n_rec_internal;
    size_t n_rec_syscall;
    const uint8_t* volatile send_buf;
    uint8_t* volatile outside_send_buf;
    uint8_t* volatile rec_buf;
    size_t volatile send_buf_len;
    size_t volatile rec_buf_len;
    struct trusted_sock_addr dst_addr;
    uint16_t volatile src_port;
};


// This lock prevents sock structs from being freed while there is an incoming packet processed
extern sgx_spinlock_t outgoing_packet_lock;

// This lock prevents sock structs from being freed while there is an outgoing packet processed
extern sgx_spinlock_t incoming_packet_lock;

static struct tcp_sock socks[MAX_NR_SOCKETS] = {0};
static int next_sock_idx = 0;


static int find_free_sock(void) {

    // Try to allocate a free socket
    int sock_idx = next_sock_idx;
    for (int cnt = 0; cnt < MAX_NR_SOCKETS; cnt++) {
        if (!socks[sock_idx].used)
            goto SUCCESS;
        sock_idx = (sock_idx + 1) % MAX_NR_SOCKETS;
    }

    return -1;
    
    SUCCESS:
    next_sock_idx = (sock_idx + 1) % MAX_NR_SOCKETS;
    return sock_idx;
}


int tcp_sock_allocate(void) {

    const int sock_idx = find_free_sock();
    struct tcp_sock* sock = &socks[sock_idx];
    int sys_fd = -1;
    sgx_status_t ret_state = 0;

    if (sock_idx < 0)
        return -1; // no more socks available

    ret_state = ocall_sock_create(&sys_fd, 0, 0, 0);
    if (ret_state != SGX_SUCCESS)
        return -1;
    if (sys_fd < 0)
        return -1;

    sock->used = 1;
    sock->sys_fd = sys_fd;
    return sock_idx;
}


static struct tcp_sock* get_used_sock(int sock_idx) {
    if (sock_idx < 0)
        return 0;
    if (sock_idx >= MAX_NR_SOCKETS)
        return 0;
    struct tcp_sock* sock = &socks[sock_idx];
    if (!sock->used)
        return 0;
    return sock;
}


int tcp_sock_free(int sock_idx) {

    struct tcp_sock* sock = get_used_sock(sock_idx);
    if (!sock)
        return -1;
    ASSERT_DEBUG(sock->used);

    // Close the socket before removing the shadow state, allowing remaining data in the kernel queue to be sent
    // With the socket option SO_LINER, close must block until all data has been sent
    int ret_val = 0;
    sgx_status_t ret_state = ocall_sock_close(&ret_val, sock->sys_fd);
    if (ret_state != SGX_SUCCESS)
        ret_val = -1;
    else if (ret_val)
        ret_val = -1;

    void* outside_send_buf = sock->outside_send_buf;
    sgx_spin_lock(&incoming_packet_lock);
    sgx_spin_lock(&outgoing_packet_lock);
    memset(sock, 0, sizeof(struct tcp_sock)); // free the sock once there are no pending validation ecall's
    sgx_spin_unlock(&outgoing_packet_lock);
    sgx_spin_unlock(&incoming_packet_lock);
    outside_free(outside_send_buf);
    return ret_val;
}


int tcp_sock_connect(int sock_idx, struct trusted_sock_addr addr, const void* send_buf, size_t send_buf_len, void* rec_buf, size_t rec_buf_len) {

    struct tcp_sock* sock = get_used_sock(sock_idx);
    if (!sock)
        return -1;

    if (sock->send_buf || sock->rec_buf)
        return -1; // already connected

    sock->dst_addr = addr;
    sock->send_buf = send_buf;
    sock->send_buf_len = send_buf_len;
    sock->rec_buf = rec_buf;
    sock->rec_buf_len = rec_buf_len;
    
    int ret_val = -1;
    sgx_status_t ret_state = ocall_sock_connect(&ret_val, sock->sys_fd, sock->dst_addr);
    if (ret_state != SGX_SUCCESS)
        goto FAIL;
    if (ret_val)
        goto FAIL;

    sock->outside_send_buf = outside_malloc(send_buf_len);
    if (!sock->outside_send_buf)
        goto FAIL;

    return 0;

    FAIL:
    tcp_sock_free(sock_idx);
    return -1;
}



ssize_t tcp_sock_send(int sock_idx, size_t len) {

    volatile struct tcp_sock *sock = get_used_sock(sock_idx);
    if (!sock)
        return -1;

    if (!sock->send_buf)
        return -1; // socket is not yet connected

    if (len > (sock->send_buf_len - sock->n_sent_syscall))
        return -1; // not enough send data left

    // Copy data to the send buffer outside of the enclave
    memcpy(sock->outside_send_buf + sock->n_sent_syscall, sock->send_buf + sock->n_sent_syscall, len);

    ssize_t n_sent = -1;
    sgx_status_t ret_state = ocall_sock_send((size_t*)&n_sent, sock->sys_fd, sock->outside_send_buf + sock->n_sent_syscall, len, 0);
    if (ret_state != SGX_SUCCESS)
        return -1;
    else if (n_sent < 0)
        return -1;
    ASSERT_DEBUG((size_t)n_sent <= len);
    sock->n_sent_syscall += (size_t)n_sent;
    return n_sent;
}


ssize_t tcp_sock_recv(int sock_idx, size_t len) {

    volatile struct tcp_sock *sock = get_used_sock(sock_idx);
    if (!sock)
        return -1;

    if (!sock->rec_buf)
        return -1; // socket is not yet connected

    if (len > (sock->rec_buf_len - sock->n_rec_syscall))
        return -1; // not enough receive buffer space left

    ssize_t n_rec = -1;
    // We do not pass an outside read buffer
    sgx_status_t ret_state = ocall_sock_recv((size_t*)&n_rec, sock->sys_fd, 0, len, 0);
    if (ret_state != SGX_SUCCESS)
        return  -1;
    else if (n_rec < 0)
        return  -1;
    ASSERT_DEBUG((size_t)n_rec <= len);

    sock->n_rec_syscall += (size_t)n_rec;
    ASSERT_DEBUG(sock->n_rec_syscall <= sock->n_rec_internal); // This security check prevents us from reading uninitialized memory

    return n_rec;
}


static int tcp_basic_validation(const void* packet, const size_t len) {

    // ether type is already checked outside
    if (len < sizeof(struct tcp_packet))
        return -1;

    const struct tcp_packet* p = packet;
    if (p->tcp.urg) {
        DEBUG_LOG("URGENT not accepted\n");
        return -1;
    }
    if (p->tcp.res1) {
        DEBUG_LOG("Unexpected reserved\n");
        return -1;
    }
    return 0;
}


static struct tcp_sock* find_shadow_state(uint16_t local_port, uint16_t  remote_port, uint32_t remote_ip) {

    // Try to find a shadow state where the source port has been already initialized
    for (int cnt = 0; cnt < MAX_NR_SOCKETS; cnt++) {
        struct tcp_sock* sock = &socks[cnt];
        if (!sock->used)
            continue;
        if (sock->syn_init && sock->dst_addr.ip4_addr == remote_ip && sock->dst_addr.port == remote_port && sock->src_port == local_port)
            return sock;
    }

    // Try to find a partially initialized shadow state where only dst port and dst ip match
    for (int cnt = 0; cnt < MAX_NR_SOCKETS; cnt++) {
        struct tcp_sock* sock = &socks[cnt];
        if (!sock->used)
            continue;
        if (!sock->syn_init && sock->dst_addr.ip4_addr == remote_ip && sock->dst_addr.port == remote_port)
            return sock;
    }
    return NULL;
}


static size_t get_payload_len(const void* packet, const size_t len) {

    const struct tcp_packet* p = packet;
    const size_t tcp_hdr_len = p->tcp.doff * 4U;
    ASSERT_DEBUG(tcp_hdr_len >= sizeof(struct tcp_header));

    const size_t payload_offset = sizeof(struct ether_header) + sizeof(struct ip_header) + tcp_hdr_len;
    ASSERT_DEBUG((payload_offset + len) > len);
    ASSERT_DEBUG((payload_offset + len) > payload_offset);
    ASSERT_DEBUG(payload_offset <= len);

    const size_t payload_len = len - payload_offset;
    ASSERT_DEBUG(payload_offset + payload_len <= len);
    return payload_len;
}


#define TCP_OP_NOP 0x1
#define TCP_OP_NOP_LEN 1

#define TCP_OP_WINDOWSCALE 0x3
#define TCP_OP_WINDOWSCALE_LEN 3

#define TCP_OP_TIMESTAMP 0x8
#define TCP_OP_TIMESTAMP_LEN 10

#define TCP_OP_MAXSEGMENTSIZE 0x2
#define TCP_OP_MAXSEGMENTSIZE_LEN 4

#define TCP_OP_SACKPERMITTED 0x4
#define TCP_OP_SACKPERMITTED_LEN 2

#define TCP_OP_SACK 0x5
#define TCP_OP_SACK_LEN_MIN 10

static int validate_individual_tcp_option(const char* buf, const size_t len) {
    if (buf[0] == TCP_OP_NOP)
        return TCP_OP_NOP_LEN;
    if (len < 2) {
        DEBUG_LOG("No space left for a new TCP option\n");
        return -1;
    }
    const char op = buf[0];
    const uint8_t op_len = (uint8_t)buf[1];
    if (op == TCP_OP_TIMESTAMP && op_len == TCP_OP_TIMESTAMP_LEN) {
        return op_len;
    } else if (op == TCP_OP_WINDOWSCALE && op_len == TCP_OP_WINDOWSCALE_LEN) {
        return op_len;
    } else if (op == TCP_OP_MAXSEGMENTSIZE && op_len == TCP_OP_MAXSEGMENTSIZE_LEN) {
        return op_len;
    } else if (op == TCP_OP_SACKPERMITTED && op_len == TCP_OP_SACKPERMITTED_LEN) {
        return op_len;
    } else if (op == TCP_OP_SACK && op_len >= TCP_OP_SACK_LEN_MIN) {
        return op_len;
    } else {
        DEBUG_LOG("Malformed or unexpected TCP option %x\n", op);
        return -1;
    }
}

static int validate_tcp_options(const void* packet, const size_t len) {
    // We perform the option validation only for outgoing TCP packets, in order to retain compatibility with unknown incoming TCP options
    
    const char* tcp_ops = (const char*)packet + sizeof(struct tcp_packet) ;
    const size_t tcp_ops_len = len - sizeof(struct tcp_packet) - get_payload_len(packet, len);
    ASSERT_DEBUG(tcp_ops_len % 4 == 0);

    size_t idx = 0;
    while (idx < tcp_ops_len) {
        int op_len = validate_individual_tcp_option(tcp_ops + idx, tcp_ops_len - idx);
        if (op_len <= 0)
            return -1;
        idx += (size_t)op_len;
    }
    if (idx == tcp_ops_len) {
        return 0;
    } else {
        DEBUG_LOG("Inconsistent TCP option len\n");
        return -1;
    }
}


static int shadow_state_fully_initialized(struct tcp_sock* sock) {
    if (!sock)
        return 0;
    if (!sock->syn_init || !sock->syn_ack_init)
        return 0;
    return 1;
}


static int validate_syn_packet(const struct tcp_packet* p, const struct tcp_sock* sock, size_t payload_len) {
    ASSERT_DEBUG(!payload_len);
    ASSERT_DEBUG(!p->tcp.fin);
    ASSERT_DEBUG(!p->tcp.rst);
    ASSERT_DEBUG(!p->tcp.psh);
    if (!sock) {
        DEBUG_LOG("Reject SYN packet to port %d since no valid shadow state was found\n", ntohs(p->tcp.dest));
        return -1;
    }
    return 0;
}

static int validate_outgoing_syn_packet(const struct tcp_packet* p, struct tcp_sock* sock, size_t payload_len) {

    // SYN is the most security-critical TCP flag for the "outgoing traffic validation"
    if (validate_syn_packet(p, sock, payload_len))
        return -1;
    ASSERT_DEBUG(!p->tcp.ack); // Must be SYN, but not SYN-ACK

    const uint32_t initial_seq = ntohl(p->tcp.seq) + 1;
    if (!sock->syn_init) {
        // Synchronize the outgoing shadow state
        sock->syn_init = 1;
        sock->initial_seq_out = initial_seq;
        sock->src_port = ntohs(p->tcp.source);
    } else if (sock->initial_seq_out != initial_seq) { // Retransmission of a SYN packet
        DEBUG_LOG("Outgoing SYN packet with spurious sequence number for already existing connection\n");
        return -1;
    }
    return 0;
}


static int consume_incoming_syn_packet(const struct tcp_packet* p, struct tcp_sock* sock, size_t payload_len) {

    if (validate_syn_packet(p, sock, payload_len))
        return -1;
    ASSERT_DEBUG(p->tcp.ack); // Must be SYN-ACK
    ASSERT_DEBUG(sock->syn_init); // Outgoing SYN must have been sent previously

    const uint32_t initial_seq = ntohl(p->tcp.seq) + 1;
    if (!sock->syn_ack_init) {
        // This check ensures that the TEE and the remote end agree on the same sequence numbers
        if (ntohl(p->tcp.ack_seq) != sock->initial_seq_out) {
            DEBUG_LOG("ACK of incoming SYN packet does not match the shadow state\n");
            return -1;
        }
        // Synchronize the incoming shadow state
        sock->syn_ack_init = 1;
        sock->initial_seq_in = initial_seq;
    } else if (sock->initial_seq_in != initial_seq) { // Retransmission of a SYN-ACK packet
        DEBUG_LOG("Incoming SYN packet with spurious sequence number for already existing connection\n");
        return -1;
    }
    return 0;
}


int read_incoming_tcp_packet(const void* packet, const size_t len) {

    // The incoming packet validation is less critical than the outgoing packet validation,
    // since incoming packets are already verified by the incoming macsec signature
    if (tcp_basic_validation(packet, len))
        return -1;

    const size_t payload_len = get_payload_len(packet, len);
    const size_t payload_offset = len - payload_len;
    const struct tcp_packet* p = packet;

    if (ntohs(p->tcp.source) == TCP_PORT_ISO)
        return 0; // Special case for S7COMM+, has nothing to do with this trusted socket api
    if (ntohs(p->tcp.source) == TCP_PORT_HTTP)
        return 0;

    struct tcp_sock* sock = find_shadow_state(ntohs(p->tcp.dest), ntohs(p->tcp.source), ntohl(p->ip.saddr));

    if (p->tcp.syn)
        return consume_incoming_syn_packet(p, sock, payload_len);

    if (!payload_len)
        return 0; // accept incoming Non-SYN packets without payload data

    /***************************************************************************/
    // Incoming packet with payload data
    if (!shadow_state_fully_initialized(sock))
        return -1; // we need a full shadow state for packets with payload data

    const uint32_t seq_in = ntohl(p->tcp.seq);
    size_t rec_pos = seq_in - sock->initial_seq_in;
    // This check degrades the performance if used in combination with SACK
    // We cannot run representative performance benchmarks if both SACK and this check are enabled
    //if (rec_pos != sock->n_rec_internal) { // We accept incoming TCP packets only in the correct order
    //    DEBUG_LOG("Unexpected sequence number of incoming tcp packet\n");
    //    return -1;
    //}

    ASSERT_DEBUG(sock->rec_buf);
    ASSERT_DEBUG(rec_pos + payload_len <= sock->rec_buf_len);

    const char* payload = (const char*)packet + payload_offset;
    memcpy(sock->rec_buf + rec_pos, payload, payload_len); // Copy the payload into the target buffer
    sock->n_rec_internal += payload_len; // Update internal state
    return 0;
}


int validate_outgoing_tcp_packet(const void* packet, const size_t len) {

    if (tcp_basic_validation(packet, len))
        return -1;

    const size_t payload_len = get_payload_len(packet, len);
    const size_t payload_offset = len - payload_len;
    const struct tcp_packet* p = packet;

    if (validate_tcp_options(packet, len))
        return -1; // Validate tcp options only for outgoing packets

    if (ntohs(p->tcp.dest) == TCP_PORT_ISO)
        return validate_iso_tcp_packet(packet, len, payload_len); // Special case for S7COMM+, has nothing to do with this trusted socket api
    if (ntohs(p->tcp.dest) == TCP_PORT_HTTP)
        return 0;

    struct tcp_sock* sock = find_shadow_state(ntohs(p->tcp.source), ntohs(p->tcp.dest), ntohl(p->ip.daddr));

    if (p->tcp.syn)
        return validate_outgoing_syn_packet(p, sock, payload_len);

    if (!payload_len)
        return 0; // Accept outgoing Non-SYN packets without payload data

    /***************************************************************************/
    // Outgoing packet with payload data
    if (!shadow_state_fully_initialized(sock))
        return -1; // we need a full shadow state for packets with payload data

    const uint32_t seq_out = ntohl(p->tcp.seq);
    size_t send_pos = seq_out - sock->initial_seq_out;

    ASSERT_DEBUG(sock->send_buf);
    ASSERT_DEBUG(send_pos + payload_len <= sock->send_buf_len);

    const char* payload = (const char*)packet + payload_offset;
    ASSERT_DEBUG(!memcmp(sock->send_buf + send_pos, payload, payload_len)); // Ensure that the outgoing payload is correct
    return 0; // validation succeeded
}
