#!/usr/bin/env bash

# Sets the environment variables that are required by test_app.bin

if [[ $EUID -ne 0 ]]; then
   echo "$0 must run as root" 1>&2
   exit -1
fi

if [[ -z "${SGX_MODE}" ]]; then
    echo "SGX_MODE must be set to SIM or HW"
    exit -1
fi

if [[ -z "${SGX_SDK}" ]]; then
    SGX_SDK=~/sgxsdk
    #echo "SGX_SDK is not set - Assume that the SGX SDK is installed in ${SGX_SDK}"
fi

if [ ${SGX_MODE} == "SIM" ]; then
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs/:$SGX_SDK/lib64/
else
    # In HW mode, /usr/lib/ must be searched first since sgxsdk/lib64 contains dummy libs
    export LD_LIBRARY_PATH=/usr/lib/:$SGX_SDK/lib64/
fi

export MACSEC_SEALED_KEY_FILE="test_enclave/test_enclave.signed.sealed_macsec_keypair"
