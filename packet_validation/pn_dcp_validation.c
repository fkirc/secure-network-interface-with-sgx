#include "edl_types.h"
#include "tcp_validation.h"
#include "../common/pn_definitions.h"
#include "netutils_t.h"

int validate_outgoing_pn_packet(const void* packet, const size_t packet_len) {

    if (packet_len < sizeof(struct dcp_packet)) {
        return -1;
    }
    // Currently, we only allow "DCP Identify Requests" as outgoing pn packets
    const struct dcp_packet* dcp_hdr = packet;
    if (dcp_hdr->frame_id != DCP_IDENTIFY_MULTICAST_REQUEST) {
        DEBUG_LOG("Outgoing PROFINET packets must be DCP_IDENTIFY_MULTICAST_REQUEST\n");
        return -1;
    }
    if (dcp_hdr->service_id != DCP_SERVICE_ID_IDENTIFY) {
        DEBUG_LOG("Outgoing PROFINET packets must be DCP_SERVICE_ID_IDENTIFY\n");
        return -1;
    }
    if (dcp_hdr->service_type != DCP_SERVICE_TYPE_REQUEST) {
        DEBUG_LOG("Outgoing PROFINET packets must be DCP_SERVICE_TYPE_REQUEST\n");
        return -1;
    }
    if (memcmp(dcp_hdr->ether.ether_dhost, pn_multicast, 6)) {
        DEBUG_LOG("Unexpected destination MAC\n");
        return -1;
    }
    return 0;
}
