cmake_minimum_required(VERSION 3.0)


add_compile_options(-std=gnu11 -Wall -Wextra -Werror -fno-omit-frame-pointer -fsanitize=address -pthread)

link_libraries(-fno-omit-frame-pointer -fsanitize=address -pthread)

set(CMAKE_C_CPPCHECK "cppcheck")

set(COMMON_C_FILES ../common/utils.c ../common/netutils.c)

project(remote_end_simulation C)

add_executable(simple_http_server.bin simple_http_server.c ${COMMON_C_FILES})

add_executable(send_close_receiver.bin send_close_receiver.c ${COMMON_C_FILES})

add_executable(bulk_data_server.bin bulk_data_server.c ${COMMON_C_FILES})

add_executable(pn_device_simulation.bin pn_device_simulation.c ${COMMON_C_FILES})

add_executable(snmp_device_simulation.bin snmp_device_simulation.c)
