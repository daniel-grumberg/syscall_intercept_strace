/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 *
 *  Adaptations made for use with syscall_intercept.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __USE_GNU
#include <fcntl.h>
#include <sys/mman.h>
#undef __USE_GNU

#include "libsyscall_intercept_hook_point.h"

#include "sysent.h"

// Global state - not the nicest, but this is a tiny application
int log_fd;

static char buffer[0x20000];
static size_t buffer_offset;

static bool exchange_buffer_offset(size_t *expected, size_t new) {
  return __atomic_compare_exchange_n(&buffer_offset, expected, new, false,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

#define DUMP_TRESHOLD (sizeof(buffer) - 0x1000)

static void memcpy(char *dst, const char *start, ssize_t len) {
  while (len--)
    *dst++ = *start++;
}

static void append_buffer(const char *data, ssize_t len) {
  static long writers;
  size_t offset = buffer_offset;

  while (true) {
    while (offset >= DUMP_TRESHOLD) {
      syscall_no_intercept(SYS_sched_yield);
      offset = buffer_offset;
    }

    __atomic_fetch_add(&writers, 1, __ATOMIC_SEQ_CST);

    if (exchange_buffer_offset(&offset, offset + len)) {
      memcpy(buffer + offset, data, len);
      break;
    }

    __atomic_fetch_sub(&writers, 1, __ATOMIC_SEQ_CST);
  }

  if (offset + len > DUMP_TRESHOLD) {
    while (__atomic_load_n(&writers, __ATOMIC_SEQ_CST) != 0)
      syscall_no_intercept(SYS_sched_yield);

    syscall_no_intercept(SYS_write, log_fd, buffer, buffer_offset);
    __atomic_store_n(&buffer_offset, 0, __ATOMIC_SEQ_CST);
  }
}
static char *print_cstr(char *dst, const char *str) {
  while (*str != '\0')
    *dst++ = *str++;

  return dst;
}

static const char xdigit[16] = "0123456789ABCDEF";

static char *print_hex_impl(char *dst, unsigned long n) {
  *dst++ = '0';
  *dst++ = 'X';

  static const char num_xdigits[] = {
      16, 16, 16, 16, 15, 15, 15, 15, 14, 14, 14, 14, 13, 13, 13, 13, 12,
      12, 12, 12, 11, 11, 11, 11, 10, 10, 10, 10, 9,  9,  9,  9,  8,  8,
      8,  8,  7,  7,  7,  7,  6,  6,  6,  6,  5,  5,  5,  5,  4,  4,  4,
      4,  3,  3,  3,  3,  2,  2,  2,  2,  1,  1,  1,  1,  1};

  char *end = dst + num_xdigits[__builtin_clzl(n)];
  char *curr = end;
  do {
    *curr-- = xdigit[n & 0xf];
    n >>= 4;
  } while (curr >= dst);

  return end + 1;
}

static char *print_hex(char *dst, long n) {
  if (n < 0) {
    *dst++ = '-';
    return print_hex_impl(dst, -n);
  }
  return print_hex_impl(dst, n);
}

static char *print_octal_impl(char *dst, long n) {
  *dst++ = '0';

  static const char num_odigits[] = {
      22, 21, 21, 21, 20, 20, 20, 19, 19, 19, 18, 18, 18, 17, 17, 17, 16,
      16, 16, 15, 15, 15, 14, 14, 14, 13, 13, 13, 12, 12, 12, 11, 11, 11,
      10, 10, 10, 9,  9,  9,  8,  8,  8,  7,  7,  7,  6,  6,  6,  5,  5,
      5,  4,  4,  4,  3,  3,  3,  2,  2,  2,  1,  1,  1,  1};

  dst++;
  char *end = dst + num_odigits[__builtin_clzl(n)];
  char *curr = end;
  do {
    *curr-- = xdigit[n & 07];
    n >>= 3;
  } while (curr >= dst);

  return end + 1;
}

static char *print_octal(char *dst, long n) {
  if (n < 0) {
    *dst++ = '-';
    return print_octal_impl(dst, -n);
  }
  return print_octal_impl(dst, n);
}

static char *print_dec_impl(char *dst, unsigned long n) {
  char digits[0x40];

  digits[sizeof(digits) - 1] = '\0';
  char *c = digits + sizeof(digits) - 1;

  do {
    *--c = xdigit[n % 10];
    n /= 10;
  } while (n > 0);

  while (*c != '\0')
    *dst++ = *c++;

  return dst;
}

static char *print_signed_dec(char *dst, long n) {
  unsigned long nu;
  if (n < 0) {
    *dst++ = '-';
    return print_dec_impl(dst, -n);
  }

  return print_dec_impl(dst, n);
}

static char *print_fd(char *dst, long n) { return print_signed_dec(dst, n); }

// We don't want to use ctype since it accesses TLS,
// which messes with %fs and causes segfault
static bool isprint(char ch) { return ((ch >= ' ') && (ch <= '~')); }

#define CSTR_MAX_LEN 0x100

static char *print_cstr_escaped(char *dst, const char *str, long max_len) {
  size_t len = 0;
  if (max_len == 0 || max_len >= CSTR_MAX_LEN)
    max_len = CSTR_MAX_LEN;
  *dst++ = '"';
  while (*str != '\0' && len < max_len) {
    if (*str == '\n') {
      *dst++ = '\\';
      *dst++ = 'n';
    } else if (*str == '\\') {
      *dst++ = '\\';
      *dst++ = '\\';
    } else if (*str == '\t') {
      *dst++ = '\\';
      *dst++ = 't';
    } else if (*str == '\"') {
      *dst++ = '\\';
      *dst++ = '"';
    } else if (isprint((unsigned char)*str)) {
      *dst++ = *str;
    } else {
      *dst++ = '\\';
      *dst++ = 'x';
      *dst++ = xdigit[((unsigned char)*str) / 0x10];
      *dst++ = xdigit[((unsigned char)*str) % 0x10];
    }

    ++len;
    ++str;
  }

  if (*str != '\0')
    dst = print_cstr(dst, "...");

  *dst++ = '"';

  return dst;
}

static const struct_sysent sysent[] = {
#include "syscallent.h"
};

#define RAW_ARG raw
#define OUT_ARG output
#define ARG_PATTERN2(s) "--" #s "="
#define ARG_PATTERN(s) ARG_PATTERN2(s)
#define ARG_PATTERN_NO_PARAM2(s) "--" #s
#define ARG_PATTERN_NO_PARAM(s) ARG_PATTERN_NO_PARAM2(s)

static char *print_prot(char *dst, long flags) {
  char *dst_next = dst;
  if (!flags) {
    dst_next = print_cstr(dst_next, "PROT_NONE|");
  } else {
    if (flags & PROT_EXEC)
      dst_next = print_cstr(dst_next, "PROT_EXEC|");

    if (flags & PROT_READ)
      dst_next = print_cstr(dst_next, "PROT_READ|");

    if (flags & PROT_WRITE) {
      dst_next = print_cstr(dst_next, "PROT_WRITE|");
    }
  }

  flags &= ~(PROT_EXEC | PROT_READ | PROT_WRITE);
  if (flags)
    dst_next = print_hex(dst_next, flags);
  else if (dst_next != dst)
    dst_next--; // All flags were parsed and we wrote some text, let's get
                // rid of the extra "|" at then end
  return dst_next;
}

static char *print_mmap_flags(char *dst, long flags) {
  if (flags & MAP_SHARED)
    dst = print_cstr(dst, "MAP_SHARED");
  else
    dst = print_cstr(dst, "MAP_PRIVATE");

#ifdef __x86_64__
  if (flags & MAP_32BIT)
    dst = print_cstr(dst, "|MAP_32_BIT");
#endif // __x86_64__

  if (flags & MAP_ANONYMOUS)
    dst = print_cstr(dst, "|MAP_ANONYMOUS");

  if (flags & MAP_DENYWRITE)
    dst = print_cstr(dst, "|MAP_DENYWRITE");

  if (flags & MAP_EXECUTABLE)
    dst = print_cstr(dst, "|MAP_EXECUTABLE");

  if (flags & MAP_FILE)
    dst = print_cstr(dst, "|MAP_FILE");

  if (flags & MAP_FIXED)
    dst = print_cstr(dst, "|MAP_FIXED");

  if (flags & MAP_GROWSDOWN)
    dst = print_cstr(dst, "|MAP_GROWSDOWN");

  if (flags & MAP_HUGETLB)
    dst = print_cstr(dst, "|MAP_HUGETLB");

  if (flags & MAP_LOCKED)
    dst = print_cstr(dst, "|MAP_LOCKED");

  if (flags & MAP_NONBLOCK)
    dst = print_cstr(dst, "|MAP_NONBLOCK");

  if (flags & MAP_NORESERVE)
    dst = print_cstr(dst, "|MAP_NORESERVE");

  if (flags & MAP_POPULATE)
    dst = print_cstr(dst, "|MAP_POPULATE");

  if (flags & MAP_STACK)
    dst = print_cstr(dst, "|MAP_STACK");

  flags &= ~(MAP_SHARED | MAP_PRIVATE |
#ifdef __x86_64__
             MAP_32BIT |
#endif // __x86_64__
             MAP_ANONYMOUS | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_FILE |
             MAP_FIXED | MAP_GROWSDOWN | MAP_HUGETLB | MAP_LOCKED |
             MAP_NONBLOCK | MAP_NORESERVE | MAP_POPULATE | MAP_STACK);

  if (flags) {
    *dst++ = '|';
    dst = print_hex(dst, flags);
  }

  return dst;
}

static char *print_open_flags(char *dst, long flags, bool *creates) {
  *creates = false;

  if (flags & O_RDWR)
    dst = print_cstr(dst, "O_RDWR");

  else if (flags & O_WRONLY)
    dst = print_cstr(dst, "O_WRONLY");

  else
    dst = print_cstr(dst, "O_RDONLY");

  // Creation and file status flags
  if (flags & O_APPEND)
    dst = print_cstr(dst, "|O_APPEND");

  if (flags & O_ASYNC)
    dst = print_cstr(dst, "|O_ASYNC");

  if (flags & O_CLOEXEC)
    dst = print_cstr(dst, "|O_CLOEXEC");

  if (flags & O_CREAT) {
    dst = print_cstr(dst, "|O_CREAT");
    *creates = true;
  }

  if (flags & O_DIRECT)
    dst = print_cstr(dst, "|O_DIRECT");

  if (flags & O_DIRECTORY)
    dst = print_cstr(dst, "|O_DIRECTORY");

  if (flags & O_DSYNC)
    dst = print_cstr(dst, "|O_DSYNC");

  if (flags & O_EXCL)
    dst = print_cstr(dst, "|O_EXCL");

  if (flags & O_NOATIME)
    dst = print_cstr(dst, "|O_NOATIME");

  if (flags & O_NOCTTY)
    dst = print_cstr(dst, "|O_NOCTTY");

  if (flags & O_NOFOLLOW)
    dst = print_cstr(dst, "|O_NOFOLLOW");

  if (flags & O_NONBLOCK)
    dst = print_cstr(dst, "|O_NONBLOCK");

  if (flags & O_PATH)
    dst = print_cstr(dst, "|O_PATH");

  if (flags & O_SYNC)
    dst = print_cstr(dst, "|O_SYNC");

  if (flags & O_TMPFILE) {
    dst = print_cstr(dst, "|O_TMPFILE");
    *creates = true;
  }

  if (flags & O_TRUNC)
    dst = print_cstr(dst, "|O_TRUNC");

  flags &= ~(O_RDWR | O_WRONLY | O_RDONLY | O_APPEND | O_ASYNC | O_CLOEXEC |
             O_CREAT | O_DIRECT | O_DIRECTORY | O_DSYNC | O_EXCL | O_NOATIME |
             O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_PATH | O_SYNC | O_TMPFILE |
             O_TRUNC);

  if (flags) {
    *dst++ = '|';
    dst = print_hex(dst, flags);
  }

  return dst;
}

static char *pre_decode_args(char *dst, long sc, const long args[]) {
  bool creates = false;

  switch (sc) {
  case SYS_mprotect:
    dst = print_hex(dst, args[0]);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[1]);
    dst = print_cstr(dst, ", ");
    dst = print_prot(dst, args[2]);
    break;

#ifdef __x86_64__
      case SYS_access:
        dst = print_cstr_escaped(dst, (char *)args[0], 0);
        dst = print_cstr(dst, ", ");
        dst = print_hex(dst, args[1]);
        break;
#endif // __x86_64__

      case SYS_mmap:
        for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
          if (!argno) {
            dst = print_hex(dst, args[argno]);
          } else {
            dst = print_cstr(dst, ", ");
            if (argno == 2)
              dst = print_prot(dst, args[2]);
            else if (argno == 3)
              dst = print_mmap_flags(dst, args[3]);
            else if (argno == 4)
              dst = print_fd(dst, args[4]);
            else
              dst = print_hex(dst, args[argno]);
          }
        }
        break;

#ifdef __x86_64__
      case SYS_open:
        dst = print_cstr_escaped(dst, (char *)args[0], 0);
        dst = print_cstr(dst, ", ");
        creates = false;
        dst = print_open_flags(dst, args[1], &creates);
        if (creates)
          dst = print_octal(dst, args[2]);
        break;
#endif // __x86_64__

      case SYS_openat:
        dst = print_cstr_escaped(dst, (char *)args[1], 0);
        dst = print_cstr(dst, ", ");
        creates = false;
        dst = print_open_flags(dst, args[2], &creates);
        if (creates)
          dst = print_octal(dst, args[3]);
        break;

      case SYS_write:
        for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
          if (!argno) {
            dst = print_fd(dst, args[argno]);
          } else {
            dst = print_cstr(dst, ", ");
            if (argno == 1)
              dst =
                  print_cstr_escaped(dst, (char *)args[argno], args[argno + 1]);
            else
              dst = print_hex(dst, args[argno]);
          }
        }
        break;

      case SYS_read:
        dst = print_fd(dst, args[0]);
        break;

      default:
        for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
          if (!argno) {
            dst = print_hex(dst, args[argno]);
          } else {
            dst = print_cstr(dst, ", ");
            dst = print_hex(dst, args[argno]);
          }
        }
        break;
      }
      return dst;
}

static char *post_decode_args(char *dst, long sc, const long args[], long rtn) {
  (void)rtn;  // unused
  switch (sc) {
  case SYS_read:
    for (int argno = 1; argno < sysent[sc].nargs; ++argno) {
      dst = print_cstr(dst, ", ");
      if (argno == 1)
        dst = print_cstr_escaped(dst, (char *)args[argno], args[argno + 1]);
      else
        dst = print_hex(dst, args[argno]);
    }
    break;

  default:
    break;
  }
  return dst;
}

int handle_syscall_hook(long sc_no, long arg1, long arg2, long arg3, long arg4,
                        long arg5, long arg6, long *result) {
  long local_args[] = {arg1, arg2, arg3, arg4, arg5, arg6};
  char local_buffer[0x300];
  char *dst = local_buffer;
  static bool outfd_close = false;

  dst = print_cstr(dst, sysent[sc_no].sys_name);
  *dst++ = '(';

  // Special-case the exit syscalls
  if ((sc_no == SYS_exit) || (sc_no == SYS_exit_group)) {
    dst = print_signed_dec(dst, arg1);
    dst = print_cstr(dst, ") = ?\n");
    append_buffer(local_buffer, dst - local_buffer);

    if (buffer_offset > 0)
      syscall_no_intercept(SYS_write, log_fd, buffer, buffer_offset);
    if (outfd_close)
      (void)syscall_no_intercept(SYS_close, log_fd);

    *result = syscall_no_intercept(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  } else {
    dst = pre_decode_args(dst, sc_no, local_args);

    // If the sandboxed app is closing our output FD
    if ((sc_no == SYS_close) && ((int)arg1 == log_fd)) {
      // A bit hacky - what if there was an error? We can't see in the future
      // though, so...
      *result = 0;
      outfd_close = true;
    } else
      *result = syscall_no_intercept(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);

    dst = post_decode_args(dst, sc_no, local_args, *result);

      dst = print_cstr(dst, ") = ");
      dst = print_signed_dec(dst, *result);
    if (*result < 0)
      dst = print_cstr(dst, "(error)");
    *dst++ = '\n';
      append_buffer(local_buffer, dst - local_buffer);
  }
  return 0;
}

static __attribute__((constructor)) void init(void) {
  const char *path = getenv("SYSCALL_LOG_PATH");

  if (!path)
    log_fd = STDERR_FILENO;
  else
    log_fd =
        syscall_no_intercept(SYS_open, path, O_CREAT | O_RDWR, (mode_t)0700);
  if (log_fd < 0)
    syscall_no_intercept(SYS_exit_group, 4);

  intercept_hook_point = handle_syscall_hook;
}
