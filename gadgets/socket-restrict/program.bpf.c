// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

const volatile int enforce = 1;
GADGET_PARAM(enforce);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(socket_restrict, events, event);

// Block AF_ALG socket creation — main choke point.
SEC("lsm/socket_create")
int BPF_PROG(micromize_socket_create, int family, int type, int protocol,
             int kern) {
  if (kern)
    return 0;

  if (gadget_should_discard_data_current())
    return 0;

  if (family != AF_ALG)
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event) {
    if (enforce)
      return -EPERM;
    return 0;
  }

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->event_type = EVENT_TYPE_SOCKET_AF_ALG_CREATE;
  event->family = AF_ALG;
  event->alg_type[0] = '\0';
  event->alg_name[0] = '\0';

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

// Defense-in-depth: block AF_ALG bind if a socket FD exists from before
// policy load. Preserves alg_type/alg_name for visibility.
SEC("lsm/socket_bind")
int BPF_PROG(micromize_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen) {
  (void)sock;

  if (gadget_should_discard_data_current())
    return 0;

  if (!address || addrlen < SOCKADDR_ALG_TYPE_END)
    return 0;

  __u16 family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), address);
  if (family != AF_ALG)
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event) {
    if (enforce)
      return -EPERM;
    return 0;
  }

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->event_type = EVENT_TYPE_SOCKET_AF_ALG_BIND;
  event->family = family;

  bpf_probe_read_kernel(event->alg_type, SOCKADDR_ALG_TYPE_LEN,
                        (const char *)address + SOCKADDR_ALG_TYPE_OFFSET);
  event->alg_type[SOCKADDR_ALG_TYPE_LEN] = '\0';

  if (addrlen >= SOCKADDR_ALG_MIN_LEN) {
    bpf_probe_read_kernel(event->alg_name, SOCKADDR_ALG_NAME_LEN,
                          (const char *)address + SOCKADDR_ALG_NAME_OFFSET);
    event->alg_name[SOCKADDR_ALG_NAME_LEN - 1] = '\0';
  } else {
    event->alg_name[0] = '\0';
  }

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
