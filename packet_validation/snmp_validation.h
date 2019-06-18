#pragma once

int validate_outgoing_udp_packet(const void* packet, const size_t packet_len);

int basic_udp_validation(const void* packet, const size_t packet_len);
