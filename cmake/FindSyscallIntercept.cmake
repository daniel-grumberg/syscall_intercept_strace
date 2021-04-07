# Tries to find an install of the syscall_intercept and header files
#
# Once done this will define
#  SYSCALL_INTERCEPT_FOUND - BOOL: System has syscall_intercept installed
#  SYSCALL_INTERCEPT_INCLUDE_DIRS - LIST:The syscall_intercept include directories
#  SYSCALL_INTERCEPT_LIBRARIES - LIST:The libraries needed to use syscall_intercept
include(FindPackageHandleStandardArgs)

set(SYSCALL_INTERCEPT_DIR
  CACHE
  PATH
  "Path to built syscall_intercept checkout")

# Try to find libexpr
find_library(SYSCALL_INTERCEPT_LIBRARIES
  NAMES libsyscall_intercept.so
  PATHS "${SYSCALL_INTERCEPT_DIR}"
  PATH_SUFFIXES "build"
  DOC "syscall_intercept libraries")

if (SYSCALL_INTERCEPT_LIBRARIES)
  message(STATUS "Found syscall_intercept libraries: \"${SYSCALL_INTERCEPT_LIBRARIES}\"")
else()
  message(STATUS "Could not find syscall_intercept libraries")
endif()

# Try to find headers
find_path(SYSCALL_INTERCEPT_INCLUDE_DIRS
  NAMES libsyscall_intercept_hook_point.h
  PATHS "${SYSCALL_INTERCEPT_DIR}"
  PATH_SUFFIXES "include"
  DOC "syscall_intercept library header")

if (SYSCALL_INTERCEPT_INCLUDE_DIRS)
  message(STATUS "Found syscall_intercept library include path: \"${SYSCALL_INTERCEPT_INCLUDE_DIRS}\"")
else()
  message(STATUS "Could not find syscall_intercept include path")
endif()

find_package_handle_standard_args(SYSCALL_INTERCEPT DEFAULT_MSG SYSCALL_INTERCEPT_INCLUDE_DIRS SYSCALL_INTERCEPT_LIBRARIES)
