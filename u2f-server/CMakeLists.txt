cmake_minimum_required(VERSION 3.5.1)
project(u2f_server C)

set(CMAKE_C_STANDARD 99)

find_library(microhttpd REQUIRED)
find_library(u2f-server REQUIRED)

add_executable(u2f_server 2fserver-main.c 2fserver-http.c 2fserver-http.h 2fserver-model.c 2fserver-model.h 2fserver-support.c 2fserver-support.h openvpn-plugin.h u2fdbt.c u2fdbt.h sha1.c sha1.h ../comm-2fserver.c ../comm-2fserver.h)
target_link_libraries(u2f_server microhttpd u2f-server)
