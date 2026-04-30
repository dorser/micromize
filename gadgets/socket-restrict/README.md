# socket-restrict

Restrict dangerous socket primitives in containers.

This gadget blocks all `AF_ALG` (kernel crypto userspace API) socket usage
inside containers. `AF_ALG` is rarely needed in containerized production
workloads — most TLS, SSH, and dm-crypt use cases never touch it — and
blocking it eliminates a class of kernel attack surface from the container
boundary.

The initial motivation is CVE-2026-31431 (Copy Fail), a Linux kernel local
privilege escalation in `algif_aead` that can be triggered via `AF_ALG`
sockets. This gadget blocks the entire killchain at socket creation time,
before any vulnerable kernel path is reached.

## Hooks

| Hook | Purpose |
|---|---|
| `lsm/socket_create` | Block `AF_ALG` socket creation (main choke point) |
| `lsm/socket_bind` | Defense-in-depth: block `AF_ALG` bind if a socket FD exists from before policy load. Preserves `alg_type`/`alg_name` for visibility. |

## Getting Started

```bash
sudo ig run ghcr.io/micromize-dev/micromize/gadgets/socket-restrict:latest
```
