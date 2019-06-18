#pragma once

int load_macsec_keys(sgx_enclave_id_t eid);

int launch_trusted_interface(const char *trusted_iface, const char *ip_config, const sgx_enclave_id_t eid);

int shutdown_trusted_interface(void);


// Debugging features
void enable_random_packet_dropping(int enable);
void enable_sgx(int enable);
void enable_raw_macsec(int enable);
void enable_raw_sgx(int enable);

extern const char *VIRTUAL_ENCLAVE_INTERFACE;
