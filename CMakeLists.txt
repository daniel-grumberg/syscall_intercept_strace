cmake_minimum_required(VERSION 3.12)
project(syscall_intercept_strace)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

find_package(SyscallIntercept REQUIRED)
include_directories(${SYSCALL_INTERCEPT_INCLUDE_DIRS})

add_library(syscall_intercept_strace SHARED
  strace.c)

target_link_libraries(syscall_intercept_strace "${SYSCALL_INTERCEPT_LIBRARIES}")
