#pragma once

#include "benchmark_tests.h"

void usage(const char* prog_name);

#define ENCLAVE_FILENAME "test_enclave/test_enclave.signed.so"

#define SEALED_KEYFILE "test_enclave/test_enclave.signed.sealed_macsec_keypair"


static const char PARAM_PERMANENT_MODE[] = "permanent_mode";
static const char PARAM_INTERFACE[] = "interface";
static const char PARAM_IP_CONFIG[] = "ip_config";
static const char PARAM_SERVER_IP[] = "server_ip";
static const char PARAM_TEST_MODE[] = "test_mode";

static const char PARAM_ENCLAVE_TX_KEY[] = "enclave_tx_key";
static const char PARAM_ENCLAVE_RX_KEY[] = "enclave_rx_key";


void test_app_launch(int argc, char** argv);
void test_app_key_installation(int argc, char** argv);

int test_pn_dcp(const char* iface);

