import subprocess
import os
import time
import sys

def usage():
    print('Usage: ' + sys.argv[0] + ' <local | remote>')
    exit(-1)


if len(sys.argv) != 2:
    usage()

mode = sys.argv[1]
local_mode = None
if mode == 'local':
    local_mode = True
elif mode == 'remote':
    local_mode = False
else:
    usage()

def sh(cmd):
    # {PIPESTATUS} captures the success status of the pipe, it is only available in bash
    print('Python sh: ' + cmd)
    ret = subprocess.run(cmd, shell=True, env=os.environ, executable='/bin/bash')
    if ret.returncode != 0:
        exit(ret.returncode)


def set_env(key, value):
    print('Set environment variable ' + key + '=' + value)
    os.environ[key] = value


if local_mode:
    print('Run tests in local mode')
    quick_test = True
    INTERFACE='veth_local'
    IP_CONFIG='20.21.22.57/24'
    UNSECURED_IP_CONFIG='40.40.40.57/24'
    REMOTE_IP='20.21.22.30'
    UNSECURED_REMOTE_IP='40.40.40.30'
else:
    # adapt for your machine
    print('Run tests in remote mode')
    quick_test = False
    os.environ['SGX_MODE'] = 'HW'
    INTERFACE='eno2'
    IP_CONFIG='60.60.60.57/24'
    UNSECURED_IP_CONFIG='70.70.70.57/24'
    REMOTE_IP='60.60.60.30'
    UNSECURED_REMOTE_IP='70.70.70.30'

if not local_mode:
    sh('./build.sh')


set_env(key='NUMBER_OF_TEST_RUNS', value=str(1)) # Only one run for functional tests


# The higher these benchmark sizes, the higher the accuracy of the individual measurements
#set_env(key='BENCHMARK_SIZE_HTTP_REQUESTS', value=str(7500))
#set_env(key='BENCHMARK_SIZE_BULK_DATA', value=str(50 * 1000000)) # In Bytes
#set_env(key='BENCHMARK_SIZE_UDP_ROUND_TRIPS', value=str(15000))

os.chdir('tests/')

# Install keys
sh('sudo -E ./test_app_install_keys.sh')

# Run tests for all the different test modes
sh('sudo ip addr flush dev ' + INTERFACE)

NO_MACSEC_CMD = 'sudo -E ./test_app.sh --interface ' + INTERFACE + ' --ip_config ' + UNSECURED_IP_CONFIG + ' --server_ip ' + UNSECURED_REMOTE_IP
MACSEC_CMD = 'sudo -E ./test_app.sh --interface ' + INTERFACE + ' --ip_config ' + IP_CONFIG + ' --server_ip ' + REMOTE_IP

# REGULAR_INTERFACE
#sh('sudo ip addr flush dev tap_enclave || true')
#sh('sudo ip addr add ' + UNSECURED_IP_CONFIG + ' dev ' + INTERFACE)
#sh(NO_MACSEC_CMD + ' --test_mode REGULAR_INTERFACE')

# TAP_INTERFACE
#sh(NO_MACSEC_CMD + ' --test_mode TAP_INTERFACE')

# SGX_VALIDATED
sh(NO_MACSEC_CMD + ' --test_mode SGX_VALIDATED')

# SGX_SECURED
#sh(MACSEC_CMD + ' --test_mode SGX_SECURED')

print('SUCCESS: Client tests completed')
