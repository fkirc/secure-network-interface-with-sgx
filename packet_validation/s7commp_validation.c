#include "netutils_t.h"
#include "omsp_validation.h"




static int validate_s7commp_op_hdr(const struct s7commp_shadow_state* s7_state, const struct s7commp_op_hdr* op_hdr) {
    if (op_hdr->opcode != S7COMMP_OPCODE_REQUEST) {
        DEBUG_LOG("Error: Forbidden S7COMM+ opcode %x\n", op_hdr->opcode);
        return -1;
    }
    if (op_hdr->reserved) {
        DEBUG_LOG("Unexpected S7COMM+ reserved\n");
        return -1;
    }
    const uint16_t seq_num = ntohs(op_hdr->seq_num);
    const uint16_t expected_seq_num = s7_state->s7commp_seq_number;
    if (s7_state->s7commp_session_created && seq_num != expected_seq_num) {
        DEBUG_LOG("Expected S7COMM+ sequence number: %d Actual S7COMM+ sequence number: %d\n", expected_seq_num, seq_num);
        return -1;
    }
    if (op_hdr->reserved2) {
        DEBUG_LOG("Unexpected S7COMM+ reserved2\n");
        return -1;
    }
    return 0;
}



static int validate_s7commp_v1(struct s7commp_shadow_state* s7_state, const void* buf, const size_t len) {
    if (len < sizeof(struct s7commp_v1)) {
        DEBUG_LOG("Error: S7COMM+ V1 header spanning over packet boundary\n");
        return -1;
    }
    const struct s7commp_v1* s7 = buf;
    if (validate_s7commp_op_hdr(s7_state, &s7->op_hdr)) {
        DEBUG_LOG("V1 op hdr validation failed\n");
        return -1;
    }
    int ret = -1;
    const uint16_t function = s7->op_hdr.function;
    if (!s7_state->s7commp_session_created) {
        if (function != S7COMMP_FUNCTION_CREATEOBJECT) {
            DEBUG_LOG("Expected CREATEOBJECT since no S7COMM+ session exists yet\n");
            return -1;
        } else {
            ret = validate_omsp_create_session(s7_state, buf, len);
        }
    } else if (function == S7COMMP_FUNCTION_SETMULTIVARIABLES) {
        ret = validate_omsp_setmultivariables(buf, len);
    } else {
        DEBUG_LOG("Unexpected function for S7COMM+ V1\n");
        return -1;
    }


    // -------------------------------------------------------
    // State update
    if (!ret) {
        s7_state->s7commp_seq_number++;
    }
    return ret;
}



static int validate_s7commp_v3(struct s7commp_shadow_state* s7_state, const void* buf, const size_t len) {
    if (len < sizeof(struct s7commp_v3)) {
        DEBUG_LOG("Error: S7COMM+ V3 header spanning over packet boundary\n");
        return -1;
    }

    const struct s7commp_v3* s7 = buf;
    const struct s7commp_hdr* hdr = &s7->hdr;

    // The digest must be included in both inner fragments and regular S7COMM+ V3 PDUs
    if (s7->digest_len != 32) {
        DEBUG_LOG("Unexpected digest len\n");
        return -1;
    }

    // Check whether this is an "inner fragment"
    char is_inner_fragment = 0;
    const size_t s7_data_len_diff = s7_state->last_iso_payload_len - s7_state->last_s7commp_len;
    if (s7_data_len_diff == 4) {
        // This means that the last S7COMM+ PDU did not have a "trailer"
        is_inner_fragment = 1;
    }
    s7_state->last_s7commp_len = ntohs(hdr->data_len);

    // Most S7COMM+ V3 checks should be only performed if this is not an inner fragment
    if (is_inner_fragment) {
        return 0;
    }

    // Perform the more detailed checks for the beginning of fragment sequences
    const struct s7commp_op_hdr* op_hdr = &s7->op_hdr;
    if (validate_s7commp_op_hdr(s7_state, op_hdr)) {
        DEBUG_LOG("V3 op hdr validation failed\n");
        return -1;
    }
    int ret = -1;
    const uint16_t function = s7->op_hdr.function;
    if (function == S7COMMP_FUNCTION_GETVARSUBSTREAMED) {
        ret = validate_omsp_getvarsubstreamed(buf, len);
    } else if (function == S7COMMP_FUNCTION_SETVARIABLE) {
        ret = validate_omsp_setvariable(buf, len);
    } else if (function == S7COMMP_FUNCTION_SETVARSUBSTREAMED) {
        ret = validate_omsp_setvarsubstreamed(buf, len);
    } else if (function == S7COMMP_FUNCTION_EXPLORE) {
        ret = validate_omsp_explore(buf, len);
    } else if (function == S7COMMP_FUNCTION_DELETEOBJECT) {
        ret = validate_omsp_deleteobject(buf, len);
    } else {
        DEBUG_LOG("Unexpected function %x for S7COMM+ V3\n", function);
        return -1;
    }


    // -------------------------------------------------------
    // State update
    if (!ret) {
        s7_state->s7commp_seq_number++;
    }
    return ret;
}



int validate_s7commp_pdu(struct s7commp_shadow_state* s7_state, const void* buf, const size_t len) {
    if (len < sizeof(struct s7commp_hdr)) {
        DEBUG_LOG("Error: ISO/S7COMM+ header spanning over packet boundary\n");
        return -1;
    }
    const struct s7commp_hdr* s7 = buf;
    if (s7->prot_id != S7COMMP_PROT_ID) {
        DEBUG_LOG("Error: Expected a 0x72 S7COMM+ header\n");
        return -1;
    }

    if (!s7_state->s7commp_session_created) {
        if (s7->prot_version != S7COMMP_PROT_VERSION_1) {
            DEBUG_LOG("Error: Expected S7COMM+ V1 for initial session establishment\n");
            return -1;
        }
    }

    if (s7->prot_version == S7COMMP_PROT_VERSION_1 ||
        s7->prot_version == S7COMMP_PROT_VERSION_2) {
        return validate_s7commp_v1(s7_state, buf, len);
    } else if (s7->prot_version == S7COMMP_PROT_VERSION_3) {
        return validate_s7commp_v3(s7_state, buf, len);
    } else {
        DEBUG_LOG("Unexpected S7COMM+ prot version\n");
        return -1;
    }
}

