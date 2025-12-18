// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include <gadget/common.h>

// This is a workaround to make the IDE happy.
// The __TARGET_ARCH_* macros are defined at build time.
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#if defined(__x86_64__)
#define __TARGET_ARCH_x86
#elif defined(__aarch64__)
#define __TARGET_ARCH_arm64
#endif
#endif

#ifndef EPERM
#define EPERM 1
#endif

#ifndef CAP_SYS_MODULE
#define CAP_SYS_MODULE 16
#endif

#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN 21
#endif

#define CLONE_NEWNS 0x00020000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWPID 0x20000000
#define CLONE_NEWNET 0x40000000

#if defined(__TARGET_ARCH_x86)
#define SYSCALL_UNSHARE 272
#define SYSCALL_SETNS 308
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_UNSHARE 97
#define SYSCALL_SETNS 268
#endif

struct cap_info {
  unsigned long flags;
  int syscall;
};

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process process;
  int cap;
  unsigned long flags;
  int syscall;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, struct cap_info);
} catch_at_cap SEC(".maps");