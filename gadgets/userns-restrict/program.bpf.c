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

GADGET_TRACER(userns_restrict, events, event);

SEC("lsm/userns_create")
int BPF_PROG(micromize_userns_create, const struct cred *cred, int ret) {
  // Preserve a deny decision from a previously-run LSM program in the chain.
  if (ret)
    return ret;

  if (gadget_should_discard_data_current())
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
  event->event_type = EVENT_TYPE_USERNS_CREATE_DENIED;

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
