// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

// NOTE: This gadget is currently observe-only. There is no kernel LSM hook
// at io_uring_setup time, and the underlying functions are not marked
// ALLOW_ERROR_INJECTION, so kprobe+bpf_override_return is not viable
// either. Operators wanting hard blocking should layer a Docker / runtime
// seccomp profile denying io_uring_{setup,enter,register} (Docker default
// since moby/moby#46762). See README for details. Enforcement will be
// re-evaluated when a clean mechanism becomes available.
const volatile int enforce = 1;
GADGET_PARAM(enforce);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(iouring_restrict, events, event);

static __always_inline void emit_event(void *ctx, __u32 event_type) {
  if (gadget_should_discard_data_current())
    return;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return;

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->event_type = event_type;

  gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int micromize_iouring_setup(struct syscall_trace_enter *ctx) {
  emit_event(ctx, EVENT_TYPE_IOURING_SETUP);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int micromize_iouring_enter(struct syscall_trace_enter *ctx) {
  emit_event(ctx, EVENT_TYPE_IOURING_ENTER);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int micromize_iouring_register(struct syscall_trace_enter *ctx) {
  emit_event(ctx, EVENT_TYPE_IOURING_REGISTER);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
