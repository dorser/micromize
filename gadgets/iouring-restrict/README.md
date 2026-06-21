# iouring-restrict

Surface `io_uring` usage from monitored containers.

This gadget attaches to the `io_uring_setup`, `io_uring_enter`, and
`io_uring_register` syscall entry tracepoints and emits an event whenever a
container process invokes one of them. `io_uring` is a dense source of Linux
local privilege escalations:

- CVE-2022-1116 — integer overflow in `io_sqe_buffer_register`
- CVE-2023-2598 — fixed-buffer registration OOB write
- CVE-2024-0582 — `IORING_REGISTER_PBUF_RING` use-after-free
- CVE-2023-2236 — `io_install_fixed_file` use-after-free
- CVE-2023-21400 — kernel memory corruption via improper locking

## Observe-only (today)

> **This gadget detects io_uring usage but does not block it.**

Unlike the other micromize gadgets, `iouring-restrict` cannot enforce. There
is no kernel LSM hook at `io_uring_setup` time (the `lsm/uring_*` hooks added
in Linux 6.0 fire only *after* the ring exists, which is too late for
setup-time bugs). The relevant kernel functions (`io_uring_create`,
`__do_sys_io_uring_setup`) are not marked `ALLOW_ERROR_INJECTION`, so a
`kprobe` + `bpf_override_return` approach is not viable either. The `enforce`
parameter is wired for parity with the other gadgets and for future
enablement, but it does not currently cause the syscall to be denied.

## Recommended complementary control

For actual blocking today, layer a runtime seccomp profile that denies the
io_uring syscalls. The Docker default seccomp profile has blocked
`io_uring_setup` / `io_uring_enter` / `io_uring_register` since
[moby/moby#46762](https://github.com/moby/moby/pull/46762) (Oct 2023), and
Kubernetes pods with `seccompProfile.type: RuntimeDefault` inherit that
block. This gadget is therefore most useful as:

1. detection in pods that opt out of seccomp, and
2. a placeholder for the day a kernel hook (or a micromize-internal
   seccomp operator) makes enforcement possible.

## Hooks

| Hook | Purpose |
|---|---|
| `tracepoint/syscalls/sys_enter_io_uring_setup` | Emit an event on io_uring instance creation |
| `tracepoint/syscalls/sys_enter_io_uring_enter` | Emit an event on io_uring submission/completion |
| `tracepoint/syscalls/sys_enter_io_uring_register` | Emit an event on io_uring resource registration |

## Getting Started

```bash
sudo ig run ghcr.io/micromize-dev/micromize/gadgets/iouring-restrict:latest
```
