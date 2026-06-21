# userns-restrict

Restrict user namespace creation from containers.

This gadget blocks `unshare(CLONE_NEWUSER)` / `clone(CLONE_NEWUSER)` from
monitored containers via the `lsm/userns_create` LSM hook. Creating a new
user namespace is the precondition for a large class of Linux local
privilege escalation chains: an unprivileged process gains `CAP_SYS_ADMIN` /
`CAP_NET_ADMIN` inside the new namespace and uses it to reach otherwise
unreachable kernel subsystems.

## Why it matters

Unprivileged user-namespace creation is the first link in the killchain for:

- The `nf_tables` LPE family (CVE-2022-32250, CVE-2023-32233, CVE-2024-1086,
  CVE-2024-26925, CVE-2024-26581, CVE-2024-26809) — reached through
  `AF_NETLINK / NETLINK_NETFILTER` after gaining `CAP_NET_ADMIN`.
- OverlayFS capability-bypass escalations (CVE-2021-3493, CVE-2023-0386,
  CVE-2023-2640).
- net/sched qdisc/filter UAFs (CVE-2022-2588, CVE-2023-4623).

Blocking user-namespace creation removes the precondition for all of them at
once, rather than chasing each subsystem bug individually.

The existing `cap-restrict` gadget catches namespace creation that goes
through a `CAP_SYS_ADMIN` capability check, but on distributions that set
`kernel.unprivileged_userns_clone=1` (Ubuntu, Debian) the
`capable(CAP_SYS_ADMIN)` check is never reached for unprivileged user
namespaces. `userns-restrict` hooks `lsm/userns_create` directly, which fires
unconditionally, closing that gap.

## Kernel requirement

`lsm/userns_create` was added in **Linux 6.1** (commit `a014d4917a0b`). On
kernels **5.18–6.0**, disable this gadget with
`--disable-gadgets=userns-restrict`. A kprobe + `bpf_override_return`
fallback for older kernels is deferred to a future iteration.

## Compatibility

Rootless container builders genuinely need user namespaces — for example
Buildah, Podman rootless, and BuildKit. Exempt namespaces that run those
workloads via the `micromize.dev/exempt` namespace label so this gadget does
not block legitimate use.

## Hooks

| Hook | Purpose |
|---|---|
| `lsm/userns_create` | Block creation of a new user namespace from a container process |

## Getting Started

```bash
sudo ig run ghcr.io/micromize-dev/micromize/gadgets/userns-restrict:latest
```
