#!/usr/bin/env bash
set -x # print commands

usage() {
    echo "Usage : $0 <network interface> <ip config>"
    exit 1
}

[[ $# -eq 2 ]] || {
    usage
}
INTERFACE=$1
IP_CONFIG=$2

if [[ $EUID -ne 0 ]]; then
   echo "$0 must run as root" 1>&2
   exit -1
fi

ip macsec show
if [ $? -ne 0 ]; then
    echo "MACSec is not supported, switch to the fallback mode"
    set -e # abort if anything fails
    ip addr add ${IP_CONFIG} dev ${INTERFACE}
    exit 0
fi

set -e # abort if anything fails

# -------------------------------------------------------------------------
# Configure the remote end macsec by using the Linux kernel implementation of macsec
# The Linux kernel implementation uses a virtual macsec interface that is bound to a physical interface

VIRTUAL_MACSEC_INTERFACE=macsec_remote

ENCLAVE_TX_KEY=22222222222222222222222222222222
ENCLAVE_RX_KEY=11111111111111111111111111111111

# validate strict: without this option there is no security at all
# protect on: protects against nonce reuse (by shutting down the interface when a packet number overflow occurs)
MACSEC_OPTIONS="cipher gcm-aes-128 icvlen 16 encrypt off send_sci on end_station off scb off protect on validate strict replay on window 0"
echo "MACSec options for remote simulation: ${MACSEC_OPTIONS}"


ALLOW_MACSEC_REUSE="false" # set to false to always enforce the usage of a new interface

if [[ ${ALLOW_MACSEC_REUSE} == "false" ]]; then
    ip link del dev ${VIRTUAL_MACSEC_INTERFACE} || true # delete if existing to refresh the config
fi

# Create the virtual macsec interface
ip link add link ${INTERFACE} ${VIRTUAL_MACSEC_INTERFACE} type macsec ${MACSEC_OPTIONS} || eval ${ALLOW_MACSEC_REUSE}

# Configure an rx secure association
ENCLAVE_SEND_SCI='1111111111110001' # this sci is a constant that is hardcoded within the enclave
ip macsec add ${VIRTUAL_MACSEC_INTERFACE} rx sci ${ENCLAVE_SEND_SCI} || eval ${ALLOW_MACSEC_REUSE}
ip macsec add ${VIRTUAL_MACSEC_INTERFACE} rx sci ${ENCLAVE_SEND_SCI} sa 0 pn 1 on key 01 ${ENCLAVE_TX_KEY} || eval ${ALLOW_MACSEC_REUSE}

# Configure a tx secure association
ip macsec add ${VIRTUAL_MACSEC_INTERFACE} tx sa 0 pn 1 on key 01 ${ENCLAVE_RX_KEY} || eval ${ALLOW_MACSEC_REUSE}

# Up the virtual macsec interface
ip link set dev ${VIRTUAL_MACSEC_INTERFACE} up

# We may need to remove the ip configuration from the interface, only the virtual macsec interface should get an ip
#ip addr flush dev ${INTERFACE}

# Configure an ip address for the virtual macsec interface
ip addr flush dev ${VIRTUAL_MACSEC_INTERFACE}
ip addr add ${IP_CONFIG} dev ${VIRTUAL_MACSEC_INTERFACE}

# Show the macsec configuration for visual inspection
ip macsec show
