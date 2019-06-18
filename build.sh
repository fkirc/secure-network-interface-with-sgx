#!/usr/bin/env bash
set -e # abort if anything fails
set -x # print commands

if [[ $EUID -eq 0 ]]; then
   echo "We do not recommend to build as root" 1>&2
   exit -1
fi

if [ -z "$SGX_MODE" ]; then
    echo "SGX_MODE must be set to SIM or HW"
    exit -1
fi

# Build the remote end stuff
REMOTE_DIR=remote_end
( cd ${REMOTE_DIR} && cmake . && make )

# Build the test app, test enclave and the libraries
TEST_APP_DIR=tests
( cd ${TEST_APP_DIR} && cmake . && make )
