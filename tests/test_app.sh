#!/usr/bin/env bash
set -e # abort if anything fails

# -------------------------------------------------------------------------
# This is a wrapper around test_app.bin that does some environmental glue

source environment_test_app.sh

pkill -f test_app.bin || true # kill it if already running
set -x

# Get unbuffer: sudo apt install expect
#unbuffer ./test_app.bin "$@"
./test_app.bin "$@"
