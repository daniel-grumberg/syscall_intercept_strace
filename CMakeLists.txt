cmake_minimum_required(VERSION 3.12)
project(syscall_intercept_strace)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

find_package(SyscallIntercept REQUIRED)
include_directories(${SYSCALL_INTERCEPT_INCLUDE_DIRS})

add_library(syscall_intercept_strace SHARED
  strace_impl.c)

target_link_libraries(syscall_intercept_strace "${SYSCALL_INTERCEPT_LIBRARIES}")

file(GENERATE
  OUTPUT include/config.h
  CONTENT
  "#ifndef CONFIG_H
#define CONFIG_H
#define STRACE_PRELOAD_LIB \"$<TARGET_FILE:syscall_intercept_strace>\"
#endif
")

include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")

add_executable(si_strace
  strace.cpp)
