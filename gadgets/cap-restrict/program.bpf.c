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

GADGET_TRACER(cap_restrict, events, event);

static __always_inline int check_unshare_flags(unsigned long flags) {
  unsigned long ns_flags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS |
                           CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |
                           CLONE_NEWNET;
  return (flags & ns_flags);
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int ig_unshare_enter(struct syscall_trace_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;

  unsigned long flags = ctx->args[0];
  if (!check_unshare_flags(flags))
    return 0;

  u64 pid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&catch_at_cap, &pid, &flags, BPF_ANY);

  return 0;
}

SEC("lsm/capable")
int BPF_PROG(micromize_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts) {
  if (gadget_should_discard_data_current())
    return 0;

  if (cap != CAP_SYS_MODULE && cap != CAP_SYS_ADMIN)
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  if (cap == CAP_SYS_ADMIN) {
    u64 pid = bpf_get_current_pid_tgid();
    unsigned long *flags;

    flags = bpf_map_lookup_elem(&catch_at_cap, &pid);
    bpf_map_delete_elem(&catch_at_cap, &pid);

    if (!flags) {
      gadget_discard_buf(event);
      return 0;
    }

    event->flags = *flags;
  }

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->cap = cap;

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
