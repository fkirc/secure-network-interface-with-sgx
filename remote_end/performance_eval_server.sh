#!/usr/bin/env bash
set -e # abort if anything fails
set -x # print commands

cmake .
make

# adapt for your machine
INTERFACE=enp0s25
IP_CONFIG=60.60.60.30/24
UNSECURED_INTERFACE=enp0s25
UNSECURED_IP_CONFIG=70.70.70.30/24

sudo ip addr flush dev ${INTERFACE}
sudo ip addr flush dev ${UNSECURED_INTERFACE}

#sudo -E ./configure_linux_macsec.sh ${INTERFACE} ${IP_CONFIG}
sudo -E ./remote_end.sh

sudo ip addr add ${UNSECURED_IP_CONFIG} dev ${UNSECURED_INTERFACE}

echo "Remote end configured, check the log to see whether it was successful"

