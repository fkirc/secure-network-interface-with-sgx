cmake_minimum_required(VERSION 3.0)


set(CMAKE_C_CPPCHECK "cppcheck")
set(CMAKE_VERBOSE_MAKEFILE ON)


if(DEFINED ENV{SGX_SDK})
    message(STATUS "SGX_SDK is set to $ENV{SGX_SDK}")
else()
    set(ENV{SGX_SDK} $ENV{HOME}/sgxsdk)
    message(STATUS "SGX_SDK was not set - Assume that the SGX SDK is installed in $ENV{SGX_SDK}")
endif()


if($ENV{SGX_MODE} STREQUAL SIM)
    set(SGX_LIBS "-lsgx_urts_sim -lsgx_uae_service_sim")
else()
    set(SGX_LIBS "-lsgx_urts -lsgx_uae_service")
endif()


############################# Build the test enclave ##########################################

# The enclave's build options are highly security-critical, therefore we use a manually written Makefile for the enclave
# Everything else is built using cmake
add_custom_target(test_enclave ALL
        COMMAND make SHELL='sh -x' # use SHELL='sh -x' for printing the compiler and linker commands
        WORKING_DIRECTORY test_enclave)


############################# Build the test app ##########################################

# Generate untrusted edge routines with the sgx_edger8r tool
add_custom_command(
        OUTPUT test_app/test_enclave_u.c
        DEPENDS test_enclave/test_enclave.edl ../packet_validation/packet_validation.edl ../packet_validation/edl_types.h
        COMMAND $ENV{SGX_SDK}/bin/x64/sgx_edger8r --untrusted ../test_enclave/test_enclave.edl --search-path ../Enclave --search-path $ENV{SGX_SDK}/include
        WORKING_DIRECTORY test_app
)

AUX_SOURCE_DIRECTORY(test_app TEST_APP_C_FILES)
AUX_SOURCE_DIRECTORY(../support_lib SUPPORT_LIB_C_FILES)

add_executable(test_app.bin
        test_app/test_enclave_u.c
        ${TEST_APP_C_FILES}
        ${SUPPORT_LIB_C_FILES}
        ../common/utils.c ../common/netutils.c
        test_enclave/tests/simple_http_client.c test_enclave/tests/bulk_data_client.c test_enclave/tests/test_utils.c
        ../packet_validation/netutils_t.c)

add_dependencies(test_app.bin test_enclave) # Build the test enclave before building the test app

target_compile_options(test_app.bin PUBLIC -I$ENV{SGX_SDK}/include -IApp
        -std=gnu11 -Wall -Wextra -Werror -fPIC -Wbuiltin-macro-redefined
        -pthread -fno-omit-frame-pointer -fsanitize=address)

target_compile_definitions(test_app.bin PRIVATE MOCK_ECALL_API=1)

target_link_libraries(test_app.bin
        -L$ENV{SGX_SDK}/lib64 ${SGX_LIBS} -lsgx_capable
        -lpthread -fno-omit-frame-pointer -fsanitize=address)
