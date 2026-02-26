// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include <gadget/common.h>
#include <gadget/filesystem.h>
#include <micromize/event_types.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

#define MAX_RUNNING_CONTAINERS 1024
#define MAX_ALLOWED_FILE_HASHES 512
#define SHA256_HASH_SIZE 32
#define HASH_ALGO_SHA256 4
#define MAX_FILEPATH_LEN 64

struct filepath_key {
  char path[MAX_FILEPATH_LEN];
};

struct sha256_hash {
  __u8 hash[SHA256_HASH_SIZE];
};

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process process;
  __u32 event_type;
  char filename[MAX_FILEPATH_LEN];
};
