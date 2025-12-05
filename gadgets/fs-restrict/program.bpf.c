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

GADGET_TRACER(fs_restrict, events, event);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u8);
} container_state SEC(".maps");

enum {
  CONTAINER_STATE_INIT = 0,
  CONTAINER_STATE_RUNNING = 1,
};

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[level].ns);
  return BPF_CORE_READ(ns, ns.inum);
}

static __always_inline pid_t get_task_ns_pid(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(micromize_sched_process_fork, struct task_struct *parent,
             struct task_struct *child) {
  u32 parent_ns_id = get_task_pid_ns_id(parent);
  u32 child_ns_id = get_task_pid_ns_id(child);

  if (parent_ns_id != child_ns_id) {
    u8 state = CONTAINER_STATE_INIT;
    bpf_map_update_elem(&container_state, &child_ns_id, &state, BPF_ANY);
  }
  return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(micromize_sched_process_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm) {
  u32 pid_ns_id = get_task_pid_ns_id(p);
  pid_t pid = get_task_ns_pid(p);

  if (pid == 1) {
    u8 state = CONTAINER_STATE_RUNNING;
    bpf_map_update_elem(&container_state, &pid_ns_id, &state, BPF_ANY);
  }
  return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(micromize_sched_process_exit, struct task_struct *p) {
  u32 pid_ns_id = get_task_pid_ns_id(p);
  pid_t pid = get_task_ns_pid(p);

  if (pid == 1) {
    bpf_map_delete_elem(&container_state, &pid_ns_id);
  }
  return 0;
}

static __always_inline bool
is_file_in_container_rootfs(struct task_struct *task, struct file *file) {
  struct vfsmount *file_mnt, *root_mnt;

  // Get the mount of the file being executed
  file_mnt = BPF_CORE_READ(file, f_path.mnt);

  // Get the root mount of the current process (container root)
  root_mnt = BPF_CORE_READ(task, fs, root.mnt);

  return file_mnt == root_mnt;
}

static __always_inline bool is_container_procfs(struct task_struct *task,
                                                struct super_block *sb) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  struct pid_namespace *task_ns = BPF_CORE_READ(pid, numbers[level].ns);

  void *proc_info = (void *)BPF_CORE_READ(sb, s_fs_info);
  struct pid_namespace *proc_ns = NULL;
  bpf_probe_read_kernel(&proc_ns, sizeof(proc_ns), proc_info);

  return task_ns == proc_ns;
}

SEC("lsm/file_open")
int BPF_PROG(micromize_file_open, struct file *file) {
  if (gadget_should_discard_data_current())
    return 0;

  struct task_struct *task = bpf_get_current_task_btf();

  u32 pid_ns_id = get_task_pid_ns_id(task);
  u8 *state = bpf_map_lookup_elem(&container_state, &pid_ns_id);
  if (state && *state == CONTAINER_STATE_INIT)
    return 0;

  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct super_block *sb = BPF_CORE_READ(inode, i_sb);
  unsigned long magic = BPF_CORE_READ(sb, s_magic);

  if (magic == PROC_SUPER_MAGIC) {
    if ((is_container_procfs(task, sb) && file->f_mode & FMODE_WRITE) ||
        !is_container_procfs(task, sb)) {
      struct event *event;
      event = gadget_reserve_buf(&events, sizeof(*event));
      if (!event)
        return 0;

      gadget_process_populate(&event->process);
      event->timestamp_raw = bpf_ktime_get_boot_ns();

      struct path f_path = BPF_CORE_READ(file, f_path);
      char *path_str = get_path_str(&f_path);
      if (path_str) {
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                                  path_str);
      } else {
        event->filename[0] = '\0';
      }

      gadget_submit_buf(ctx, &events, event, sizeof(*event));

      if (enforce)
        return -EPERM;
    }
  }

  return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(micromize_bprm_creds_for_exec, struct linux_binprm *bprm) {
  struct task_struct *task;
  struct file *file;

  if (gadget_should_discard_data_current())
    return 0;

  task = bpf_get_current_task_btf();
  file = bprm->file;

  if (!is_file_in_container_rootfs(task, file)) {
    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
      return 0;

    gadget_process_populate(&event->process);
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    struct path f_path = BPF_CORE_READ(file, f_path);
    char *path_str = get_path_str(&f_path);
    if (path_str)
      bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                                path_str);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    if (enforce)
      return -EPERM;
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
