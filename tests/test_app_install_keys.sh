#!/usr/bin/env bash
set -e # abort if anything fails

# -------------------------------------------------------------------------
# Install the preshared macsec keys

source environment_test_app.sh

ENCLAVE_TX_KEY=22222222222222222222222222222222
ENCLAVE_RX_KEY=11111111111111111111111111111111

if [ ${SGX_MODE} == "SIM" ]; then
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs/:$SGX_SDK/lib64/
else
    # In HW mode, /usr/lib/ must be searched first since sgxsdk/lib64 contains dummy libs
    export LD_LIBRARY_PATH=/usr/lib/:$SGX_SDK/lib64/
fi

set -x # print commands
./test_app.bin  --enclave_tx_key ${ENCLAVE_TX_KEY} --enclave_rx_key ${ENCLAVE_RX_KEY}
