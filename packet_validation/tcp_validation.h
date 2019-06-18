#pragma once

#include "../common/tcp_definitions.h"

int tcp_sock_allocate(void);

int tcp_sock_free(int sock_idx);

int tcp_sock_connect(int sock_idx, struct trusted_sock_addr addr, const void* send_buf, size_t send_buf_len, void* rec_buf, size_t rec_buf_len);

ssize_t tcp_sock_send(int sock_idx, size_t len);

ssize_t tcp_sock_recv(int sock_idx, size_t len);

int validate_outgoing_tcp_packet(const void* buf, size_t len);

int read_incoming_tcp_packet(const void* packet, const size_t len);

// These functions are implemented elsewhere, could be refactored with more header files
int validate_outgoing_arp_packet(const void* packet, const size_t len);
int validate_outgoing_pn_packet(const void* packet, const size_t len);
int is_valid_host_ip(const uint32_t ip);
int validate_outgoing_ipv4_packet(const void* packet, const size_t packet_len);
int consume_incoming_ipv4_packet(const void* packet, const size_t packet_len);

#define TCP_PORT_HTTP 80
