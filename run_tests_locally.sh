#!/usr/bin/env bash
set -e # abort if anything fails
set -x # print commands

usage() {
    echo "Usage : $0 SIM | HW "
    exit 1
}

[[ $# -eq 1 ]] || {
    usage
}
[[ "$1" == "SIM" ]] || [[ "$1" == "HW" ]] ||  {
    usage
}

export SGX_MODE=$1

./build.sh

# -------------------------------------------------------------------------
# Create and configure a simulated remote end using network namespaces

LOCAL_INTERFACE=veth_local
REMOTE_INTERFACE=veth_remote
REMOTE_IP_CONFIG=20.21.22.30/24
UNSECURED_REMOTE_IP_CONFIG=40.40.40.30/24

# Create a new network namespace for remote simulation if it does not exist
sudo ip netns add testns || true
# Create a new veth pair if it does not exist
sudo ip link add ${LOCAL_INTERFACE} type veth peer name ${REMOTE_INTERFACE} || true
# Move the peer interface to the remote network namespace, it it is not already there
sudo ip link set ${REMOTE_INTERFACE} netns testns || true
# Make sure that the none of the interfaces has an initial ip configuration
sudo ip addr flush dev ${LOCAL_INTERFACE}
sudo ip netns exec testns ip addr flush dev ${REMOTE_INTERFACE}
# Up the interfaces
sudo ip link set dev ${LOCAL_INTERFACE} up
sudo ip netns exec testns ip link set dev ${REMOTE_INTERFACE} up

sudo ip link del dev macsec_remote || true # we may need to remove this from a previous test configuration

# -------------------------------------------------------------------------
# Configure and run the simulated remote end in the network namespace

#sudo ip netns exec testns ./remote_end/configure_linux_macsec.sh ${REMOTE_INTERFACE} ${REMOTE_IP_CONFIG}

sudo ip netns exec testns ip addr add ${UNSECURED_REMOTE_IP_CONFIG} dev ${REMOTE_INTERFACE}

( cd remote_end && sudo ip netns exec testns ./remote_end.sh ${REMOTE_INTERFACE} )
sleep 0.2

# -------------------------------------------------------------------------
# Run the test app via the eval script

python3 performance_eval_client.py local

echo "TEST SUCCESS"
