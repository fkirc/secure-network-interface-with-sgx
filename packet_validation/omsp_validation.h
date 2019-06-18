#pragma once

#include "s7commp_validation.h"

int validate_omsp_create_session(struct s7commp_shadow_state* s7_state, const void* buf, const size_t len);

int validate_omsp_getvarsubstreamed(const void* buf, const size_t len);

int validate_omsp_setvariable(const void* buf, const size_t len);

int validate_omsp_setmultivariables(const void* buf, const size_t len);

int validate_omsp_setvarsubstreamed(const void* buf, const size_t len);

int validate_omsp_explore(const void* buf, const size_t len);

int validate_omsp_deleteobject(const void* buf, const size_t len);
