cmake_minimum_required(VERSION 3.5.1)
project(u2f_server C)

set(CMAKE_C_STANDARD 99)

add_library(u2f_server SHARED comm-2fserver.c comm-2fserver.h plugin-u2f-server.c support.c support.h)
