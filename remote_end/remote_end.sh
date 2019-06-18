#!/usr/bin/env bash
set -e # abort if anything fails
set -x # print commands

usage() {
    echo "Usage : $0 <interface>"
    exit 1
}

[[ $# -eq 1 ]] || {
    usage
}
INTERFACE=$1

# -------------------------------------------------------------------------
# Run the remote end test programs

HTTP_PORT=5678
BULK_DATA_PORT=10000
SEND_CLOSE_PORT=10001
SNMP_PORT=161

# Kill stuff that already listens on these ports
fuser -k ${HTTP_PORT}/tcp || true
fuser -k ${BULK_DATA_PORT}/tcp || true
fuser -k ${SEND_CLOSE_PORT}/tcp || true
fuser -k ${SNMP_PORT}/tcp || true
pkill -f pn_device_simulation.bin || true
sleep 0.2

./simple_http_server.bin --port ${HTTP_PORT} &
./bulk_data_server.bin --port ${BULK_DATA_PORT} &
./send_close_receiver.bin --port ${SEND_CLOSE_PORT} &
./snmp_device_simulation.bin &
./pn_device_simulation.bin --interface ${INTERFACE} &

