// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include <gadget/common.h>
#include <micromize/event_types.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef AF_KEY
#define AF_KEY 15
#endif

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

#define SOCKADDR_ALG_TYPE_OFFSET 2
#define SOCKADDR_ALG_TYPE_LEN 14
#define SOCKADDR_ALG_TYPE_END (SOCKADDR_ALG_TYPE_OFFSET + SOCKADDR_ALG_TYPE_LEN)

#define SOCKADDR_ALG_NAME_OFFSET 24
#define SOCKADDR_ALG_NAME_LEN 64
#define SOCKADDR_ALG_MIN_LEN (SOCKADDR_ALG_NAME_OFFSET + SOCKADDR_ALG_NAME_LEN)

#define EVENT_ALG_TYPE_LEN (SOCKADDR_ALG_TYPE_LEN + 1)

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process process;
  __u32 event_type;
  __u32 family;
  char alg_type[EVENT_ALG_TYPE_LEN];
  char alg_name[SOCKADDR_ALG_NAME_LEN];
};
