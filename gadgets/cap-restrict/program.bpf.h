// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include <gadget/common.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef CAP_SYS_MODULE
#define CAP_SYS_MODULE 16
#endif

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process process;
  int cap;
};
