#include "sgx_utils_u.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

// SGX_DEBUGGING_MODE must be set to 0 for production mode and 1 for debugging mode
#define SGX_DEBUGGING_MODE 1

typedef struct _sgx_dev_state_list_t {
    sgx_device_status_t err;
    const char *msg;
} sgx_dev_state_list_t;

static sgx_dev_state_list_t sgx_dev_state_list[] = {
        {SGX_ENABLED,                  "SGX is enabled",},
        {SGX_DISABLED_REBOOT_REQUIRED, "A reboot is required to finish enabling SGX",},
        {SGX_DISABLED_LEGACY_OS,       "SGX is disabled and a Software Control Interface is not available to enable it",},
        {SGX_DISABLED,                 "SGX is not enabled on this platform. More details are unavailable.",},
        {SGX_DISABLED_SCI_AVAILABLE,   "SGX is disabled, but a Software Control Interface is available to enable it",},
        {SGX_DISABLED_MANUAL_ENABLE,   "SGX is disabled, but can be enabled manually in the BIOS setup",},
        {SGX_DISABLED_HYPERV_ENABLED,  "Detected an unsupported version of Windows* 10 with Hyper-V enabled",},
        {SGX_DISABLED_UNSUPPORTED_CPU, "SGX is not supported by this CPU",},
};

static void print_sgx_dev_state(sgx_device_status_t dev_state) {
    size_t idx = 0;
    size_t ttl = sizeof(sgx_dev_state_list) / sizeof(sgx_dev_state_list[0]);

    for (idx = 0; idx < ttl; idx++) {
        if (dev_state == sgx_dev_state_list[idx].err) {
            printf("SGX Device State: %s\n", sgx_dev_state_list[idx].msg);
            break;
        }
    }
    if (idx == ttl) {
        printf("SGX device state code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n",
               dev_state);
    }
}


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
        {SGX_ERROR_UNEXPECTED,          "Unexpected error occurred.",                              NULL},
        {SGX_ERROR_INVALID_PARAMETER,   "Invalid parameter.",                                      NULL},
        {SGX_ERROR_OUT_OF_MEMORY,       "Out of memory.",                                          NULL},
        {SGX_ERROR_ENCLAVE_LOST,        "Power transition occurred.",                              "Please refer to the sample \"PowerTransition\" for details."},
        {SGX_ERROR_INVALID_ENCLAVE,     "Invalid enclave image.",                                  NULL},
        {SGX_ERROR_INVALID_ENCLAVE_ID,  "Invalid enclave identification.",                         NULL},
        {SGX_ERROR_INVALID_SIGNATURE,   "Invalid enclave signature.",                              NULL},
        {SGX_ERROR_OUT_OF_EPC,          "Out of EPC memory.",                                      NULL},
        {SGX_ERROR_NO_DEVICE,           "Invalid SGX device.",                                     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
        {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.",                                  NULL},
        {SGX_ERROR_INVALID_METADATA,    "Invalid enclave metadata.",                               NULL},
        {SGX_ERROR_DEVICE_BUSY,         "SGX device was busy.",                                    NULL},
        {SGX_ERROR_INVALID_VERSION,     "Enclave version was invalid.",                            NULL},
        {SGX_ERROR_INVALID_ATTRIBUTE,   "Enclave was not authorized.",                             NULL},
        {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Failed to find or open the enclave file.",                NULL},
        {SGX_ERROR_NO_PRIVILEGE,        "Insufficient privileges.",                                NULL},
        {SGX_SUCCESS,                   "SGX success.",                                            NULL},
};

void print_sgx_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof(sgx_errlist) / sizeof(sgx_errlist[0]);

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n",
           ret);
}


int try_sgx_enable(sgx_device_status_t *dev_state) {

    if (geteuid()) {
        printf("We need super user privileges for checking the SGX status and for running the app\n");
        return -1;
    }

    sgx_status_t ret_state = sgx_cap_get_status(dev_state);
    if (ret_state != SGX_SUCCESS) {
        printf("sgx_cap_get_status() failed\n");
        print_sgx_error_message(ret_state);
        return -1;
    }
    if (*dev_state == SGX_ENABLED) {
        return 0;
    }

    print_sgx_dev_state(*dev_state);
    printf("Try to enable SGX with sgx_cap_enable_device()\n");
    ret_state = sgx_cap_enable_device(dev_state);
    if (ret_state != SGX_SUCCESS) {
        printf("sgx_cap_enable_device() failed\n");
        print_sgx_error_message(ret_state);
        return -1;
    }

    print_sgx_dev_state(*dev_state);
    if (*dev_state == SGX_ENABLED) {
        printf("SGX has been successfully enabled by sgx_cap_enable_device()\n");
        return 0;
    }
    printf("sgx_cap_enable_device() did not manage to enable SGX\n");
    return -1;
}

static int print_current_working_dir() {
    char cwd[1000];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("Current working dir: %s\n", cwd);
        return 0;
    } else {
        perror("getcwd()");
        return 1;
    }
}


static int check_enclave_exists(const char* enclave_path) {
    if (access(enclave_path, F_OK) == -1) {
        printf("Error: Cannot find the enclave file '%s'\n", enclave_path);
        print_current_working_dir();
        return -1;
    }
    return 0;
}


int initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid) {

    if (check_enclave_exists(enclave_path)) {
        return -1;
    }

    sgx_launch_token_t token = {0};
    int updated = 0;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(enclave_path, SGX_DEBUGGING_MODE, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_sgx_error_message(ret);
        printf("Failed to launch the enclave \"%s\"\n", enclave_path);
        return -1;
    }

    return 0;
}


int destroy_enclave(sgx_enclave_id_t eid) {
    if (sgx_destroy_enclave(eid) != SGX_SUCCESS) {
        printf("Failed to destroy enclave with eid %zd\n", eid);
        return -1;
    }
    return 0;
}


int try_sgx_enable_or_die() {
    // Try to enable SGX if it is not already enabled
    sgx_device_status_t dev_state = {0};
    if (try_sgx_enable(&dev_state)) {
        if (dev_state == SGX_DISABLED_UNSUPPORTED_CPU) {
            // fallback to simulation mode on actually unsupported CPUs
            printf("Assume that we are running in simulation mode (this test will fail later on if not)\n");
        } else {
            // something else is mis-configured, abort test
            exit(-1);
        }
    }
    return 0;
}

