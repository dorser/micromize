<h1>
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/images/logo/logo-horizontal.svg">
    <img src="docs/images/logo/logo-horizontal.svg" alt="Micromize Logo" width="80%">
  </picture>
</h1>

Kernel-enforced boundary hardening for cloud-native containers.

Micromize uses [BPF-LSM](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/) to enforce what well-behaved cloud-native containers should look like. Micromize is built on [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget).

![Demo](docs/images/demo.gif)

## The Problem

Containers rely on namespaces, cgroups, seccomp, and LSMs but they still expose kernel attack surface. Misconfigured or overly privileged workloads lead to container escape primitives, host mutation from containers, runtime drift from the image, and undefined kernel behavior.

Tools may detect this. Few eliminate it.

## Philosophy

Micromize doesn't care what happens inside the container. Instead, it enforces the boundaries. We don't scan for cryptominers because with Micromize, unauthorized binaries can't execute in the first place. You can't effectively protect against every poorly written application, but you can guarantee that nothing runs unless it was part of the original image.

Micromize assumes containers are immutable, disposable, non-host-mutating, and explicit about privilege.

If your workload violates those assumptions, Micromize blocks it or forces an explicit posture decision.

## What Micromize Does

Today, Micromize attaches eBPF programs to LSM hooks and enforces:

- **Strict container boundaries** — blocks filesystem escapes and host access
- **Capability restriction** — prevents privilege escalation via `unshare`/`clone`/`setns`
- **Ptrace blocking** — eliminates ptrace-based debugging/injection attacks
- **Execution integrity** — SBOM + runtime hash validation via `bpf_ima_file_hash`

Policies are loaded before container start and enforced at execution time. No runtime replacement. No learning mode. Kernel-native enforcement.

## Quickstart

### Docker

```bash
docker run -it \
  --name micromize \
  --pid=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  -v /bin:/host/bin \
  -v /proc:/host/proc \
  -v /run:/host/run \
  -v /usr:/host/usr \
  ghcr.io/micromize-dev/micromize:latest
```

### Kubernetes (Helm)

```bash
helm install micromize ./charts/micromize \
  --namespace micromize \
  --create-namespace
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--enforce` | `true` | Enforce restrictions (block) vs audit mode |
| `--verbose` / `-v` | `false` | Debug logging |
| `--filter-namespaces` | `""` | Comma-separated K8s namespaces to monitor (`!` prefix to exclude) |

## Requirements

- Linux kernel 5.18+
- BPF LSM enabled (`CONFIG_BPF_LSM=y`, boot with `lsm=...,bpf`)
- IMA enabled (`CONFIG_IMA=y`) — required for execution integrity via `bpf_ima_file_hash`

## Development

Requires [`ig`](https://inspektor-gadget.io/docs/latest/quick-start#linux) CLI v0.49+ for building gadgets.

```bash
# Build everything (gadgets + binary). Requires sudo.
make build-all

# Run tests
make test
```

## Status

Micromize is under active development. Contributions are welcome.

