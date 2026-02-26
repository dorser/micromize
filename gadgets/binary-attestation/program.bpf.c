// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filesystem.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

const volatile int enforce = 1;
GADGET_PARAM(enforce);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(binary_attestation, events, event);

// Inner map template: filepath -> sha256
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ALLOWED_FILE_HASHES);
  __type(key, struct filepath_key);
  __type(value, struct sha256_hash);
} inner_map SEC(".maps");

// Outer map: mntns_id -> inner map (filepath -> sha256)
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_RUNNING_CONTAINERS);
  __type(key, __u64);
  __array(
      values, struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ALLOWED_FILE_HASHES);
        __type(key, struct filepath_key);
        __type(value, struct sha256_hash);
      });
} expected_hashes SEC(".maps");

static __always_inline int
attest_file(void *ctx, struct file *file, __u32 unattested_event_type,
            __u32 mismatch_event_type) {
  gadget_mntns_id mntns_id = gadget_get_current_mntns_id();

  // Look up the inner map for this mount namespace
  void *inner = bpf_map_lookup_elem(&expected_hashes, &mntns_id);
  if (!inner)
    return 0;

  // Get the file path
  struct filepath_key fkey = {};
  struct path f_path = BPF_CORE_READ(file, f_path);
  char *path_str = get_path_str(&f_path);
  if (!path_str)
    return 0;

  bpf_probe_read_kernel_str(fkey.path, sizeof(fkey.path), path_str);

  // Look up the expected hash for this file path
  struct sha256_hash *expected = bpf_map_lookup_elem(inner, &fkey);
  if (!expected) {
    bpf_printk("binary-attestation: Unattested file %s in mntns_id=%llu\n",
               fkey.path, mntns_id);

    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
      return enforce ? -EPERM : 0;

    gadget_process_populate(&event->process);
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    event->event_type = unattested_event_type;
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              path_str);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    if (enforce)
      return -EPERM;

    return 0;
  }

  bpf_printk(
      "binary-attestation: Found expected hash for file %s in mntns_id=%llu\n",
      fkey.path, mntns_id);

  // Calculate the IMA hash of the file
  struct sha256_hash computed = {};
  long ret = bpf_ima_file_hash(file, computed.hash, SHA256_HASH_SIZE);
  bpf_printk("binary-attestation: bpf_ima_file_hash returned %ld for %s\n", ret,
             fkey.path);
  if (ret != HASH_ALGO_SHA256) {
    // IMA did not return a SHA256 hash (e.g., disabled or misconfigured).
    // Logging so operators can detect that attestation was skipped.
    bpf_printk("binary-attestation: IMA hash algorithm (%ld) is not SHA256; "
               "skipping attestation for %s in mntns_id=%llu\n",
               ret, fkey.path, mntns_id);
    return 0;
  }

  bpf_printk("binary-attestation: Computed hash for file %s in mntns_id=%llu\n",
             fkey.path, mntns_id);

  // Compare computed hash with the expected hash
  int i;
  for (i = 0; i < SHA256_HASH_SIZE; i++) {
    if (computed.hash[i] != expected->hash[i]) {
      bpf_printk(
          "binary-attestation: Hash mismatch for %s in mntns_id=%llu\n",
          fkey.path, mntns_id);

      struct event *event;
      event = gadget_reserve_buf(&events, sizeof(*event));
      if (!event)
        return enforce ? -EPERM : 0;

      gadget_process_populate(&event->process);
      event->timestamp_raw = bpf_ktime_get_boot_ns();
      event->event_type = mismatch_event_type;
      bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                                path_str);

      gadget_submit_buf(ctx, &events, event, sizeof(*event));

      if (enforce)
        return -EPERM;

      return 0;
    }
  }

  return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(micromize_bprm_check_security, struct linux_binprm *bprm) {
  if (gadget_should_discard_data_current())
    return 0;

  return attest_file(ctx, bprm->file, EVENT_TYPE_UNATTESTED_BINARY,
                     EVENT_TYPE_HASH_MISMATCH);
}

SEC("lsm.s/mmap_file")
int BPF_PROG(micromize_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
  if (!file)
    return 0;

  if (!(prot & PROT_EXEC))
    return 0;

  if (gadget_should_discard_data_current())
    return 0;

  return attest_file(ctx, file, EVENT_TYPE_UNATTESTED_SHARED_OBJECT,
                     EVENT_TYPE_SHARED_OBJECT_HASH_MISMATCH);
}

char LICENSE[] SEC("license") = "GPL";
