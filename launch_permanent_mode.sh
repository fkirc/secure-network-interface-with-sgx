#!/usr/bin/env bash
set -e # abort if anything fails
set -x # print commands

# Launches the trusted network interface in "permanent mode"

INTERFACE=veth_local
IP_CONFIG=40.40.40.57/24

export SGX_MODE=SIM
./build.sh

# Flush ip from physical interface, since we want to go via the virtual "tap_enclave" interface
sudo ip addr flush dev ${INTERFACE}

sudo pkill -f test_app.bin || true # kill it if already running
( cd tests && sudo -E ./test_app_install_keys.sh )
( cd tests && sudo -E ./test_app.sh  --permanent_mode TAP_INTERFACE --interface ${INTERFACE} --ip_config ${IP_CONFIG} )

