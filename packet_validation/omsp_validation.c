#include "netutils_t.h"
#include "omsp_validation.h"

struct omsp_create_session {
    struct s7commp_v1 s7_v1;
    uint32_t object_id;
    uint8_t datatype_flags;
    uint8_t datatype;
    uint8_t value;
    uint32_t unknown_value;
} __attribute__((packed));


struct omsp_setmultivariables {
    struct s7commp_v1 s7_v1;
    uint32_t object_id;
    uint8_t item_count;
    uint8_t item_address_count;
    uint16_t session_key_id;
    uint16_t server_session_version_id;
} __attribute__((packed));

struct omsp_generic {
    struct s7commp_v3 s7_v3;
    uint32_t object_id;
} __attribute__((packed));


#define OMS_DATA_TYPE_INT 0x04

#define OMS_OBJECT_ID_SERVERSESSIONCONTAINER 0x1D010000
#define OMS_OBJECT_ID_CPUPROXY 0x31000000
#define OMS_OBJECT_ID_CPUEXECUNIT 0x34000000


int validate_omsp_setmultivariables(const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_setmultivariables)) {
        DEBUG_LOG("Error: omsp_setmultivariables too short\n");
        return -1;
    }
    const struct omsp_setmultivariables* s7 = buf;
    if (s7->object_id != OMS_OBJECT_ID_CPUEXECUNIT && s7->object_id != 0x32000000 && s7->object_id != OMS_OBJECT_ID_CPUPROXY && s7->object_id != 0xb5030000 && s7->object_id != 0xb3030000 && s7->object_id != 0x9b030000) {
        DEBUG_LOG("omsp_setmultivariables: unexpected object_id 0x%x\n", s7->object_id);
        return -1;
    }
    if (s7->item_count != 2) {
        DEBUG_LOG("omsp_setmultivariables: unexpected item_count\n");
        return -1;
    }
    if (s7->item_address_count != 2) {
        DEBUG_LOG("omsp_setmultivariables: unexpected item_address_count\n");
        return -1;
    }
    if (s7->session_key_id != 0x268E) {
        DEBUG_LOG("omsp_setmultivariables: unexpected item_address_count\n");
        return -1;
    }
    if (s7->server_session_version_id != 0x3282) {
        DEBUG_LOG("omsp_setmultivariables: unexpected item_address_count\n");
        return -1;
    }
    return 0;
}


struct omsp_getvarsubstreamed {
    struct s7commp_v3 s7_v3;
    uint32_t id_number;
    uint8_t datatype_flags;
    uint8_t datatype;
    uint8_t array_size;
    uint32_t address_array;
} __attribute__((packed));


int validate_omsp_getvarsubstreamed(const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_getvarsubstreamed)) {
        DEBUG_LOG("Error: omsp_getvarsubstreamed too short\n");
        return -1;
    }
    const struct omsp_getvarsubstreamed* s7 = buf;
    if (s7->id_number != OMS_OBJECT_ID_CPUEXECUNIT && s7->id_number != 0x32000000 && s7->id_number != OMS_OBJECT_ID_CPUPROXY) {
        DEBUG_LOG("omsp_getvarsubstreamed: unexpected id_number 0x%x\n", s7->id_number);
        return -1;
    }
    if (s7->datatype != OMS_DATA_TYPE_INT) {
        DEBUG_LOG("omsp_getvarsubstreamed: unexpected datatype\n");
        return -1;
    }
    return 0;
}


int validate_omsp_setvariable(const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_generic)) {
        DEBUG_LOG("Error: omsp_setvariable too short\n");
        return -1;
    }
    const struct omsp_generic* s7 = buf;
    if (s7->object_id != OMS_OBJECT_ID_CPUPROXY && s7->object_id != 0xb5030000 && s7->object_id != 0xb3030000 && s7->object_id != 0xa1030000 && s7->object_id != OMS_OBJECT_ID_CPUEXECUNIT && s7->object_id != 0xe3030000 && s7->object_id != 0x9b030000) {
        DEBUG_LOG("omsp_setvariable: unexpected object_id 0x%x\n", s7->object_id);
        return -1;
    }
    return 0;
}

int validate_omsp_setvarsubstreamed(const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_generic)) {
        DEBUG_LOG("Error: setvarsubstreamed too short\n");
        return -1;
    }
    const struct omsp_generic* s7 = buf;
    if (s7->object_id != 0x9b030000) {
        DEBUG_LOG("omsp_setvarsubstreamed: unexpected object_id 0x%x\n", s7->object_id);
        return -1;
    }
    return 0;
}

int validate_omsp_explore(const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_generic)) {
        DEBUG_LOG("Error: omsp_explore too short\n");
        return -1;
    }
    const struct omsp_generic* s7 = buf;
    if (s7->object_id != 0x10270000 && s7->object_id != 0x1000000) {
        DEBUG_LOG("omsp_explore: unexpected object_id 0x%x\n", s7->object_id);
        return -1;
    }
    return 0;
}

int validate_omsp_deleteobject(const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_generic)) {
        DEBUG_LOG("Error: omsp_deleteobject too short\n");
        return -1;
    }
    const struct omsp_generic* s7 = buf;
    if (s7->object_id != 0xb5030000 && s7->object_id != 0x9b030000 && s7->object_id != 0xb3030000) {
        DEBUG_LOG("omsp_deleteobject: unexpected object_id 0x%x\n", s7->object_id);
        return -1;
    }
    return 0;
}



int validate_omsp_create_session(struct s7commp_shadow_state* s7_state, const void* buf, const size_t len) {
    if (len < sizeof(struct omsp_create_session)) {
        DEBUG_LOG("Error: S7COMM+ Create Session too short\n");
        return -1;
    }
    const struct omsp_create_session* s7_cr = buf;
    const struct s7commp_v1* s7 = &s7_cr->s7_v1;
    if (s7->op_hdr.function != S7COMMP_FUNCTION_CREATEOBJECT) {
        DEBUG_LOG("Session establishment is expected to use S7COMMP_FUNCTION_CREATEOBJECT\n");
        return -1;
    }
    if (s7_cr->object_id != OMS_OBJECT_ID_SERVERSESSIONCONTAINER) {
        DEBUG_LOG("Unexpected object id for session object\n");
        return -1;
    }
    if (s7_cr->datatype_flags) {
        DEBUG_LOG("Unexpected data type flags for session object\n");
        return -1;
    }
    if (s7_cr->datatype != OMS_DATA_TYPE_INT) {
        DEBUG_LOG("Unexpected data type for session object\n");
        return -1;
    }
    if (s7_cr->value) {
        DEBUG_LOG("Unexpected value for session object\n");
        return -1;
    }

    // -------------------------------------------------------
    // State update
    s7_state->s7commp_seq_number = ntohs(s7_cr->s7_v1.op_hdr.seq_num);
    s7_state->s7commp_session_created = 1;
    DEBUG_LOG("S7COMM+ Session created, from now on expecting S7COMM+ functions\n");
    return 0;
}
