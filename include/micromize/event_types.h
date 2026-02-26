// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) micromize-Authors */

#ifndef __MICROMIZE_EVENT_TYPES_H
#define __MICROMIZE_EVENT_TYPES_H

enum micromize_event_type {
  EVENT_TYPE_UNKNOWN = 0,

  // fs-restrict
  EVENT_TYPE_FS_PROCFS_ACCESS = 1,
  EVENT_TYPE_FS_EXEC_OUTSIDE_ROOTFS = 2,

  // cap-restrict
  EVENT_TYPE_CAP_NAMESPACE_CREATION = 3,
  EVENT_TYPE_CAP_MODULE_LOAD = 4,

  // ptrace-restrict
  EVENT_TYPE_PTRACE_ACCESS = 5,
  EVENT_TYPE_PTRACE_TRACEME = 6,

  // binary-attestation
  EVENT_TYPE_UNATTESTED_BINARY = 7,
  EVENT_TYPE_HASH_MISMATCH = 8,
};

#endif /* __MICROMIZE_EVENT_TYPES_H */
