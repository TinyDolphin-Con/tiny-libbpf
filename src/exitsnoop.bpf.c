/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// 依赖头文件
#include "exitsnoop.h"

// ===== 定义全局变量 =====
// 是否应用控制组(cgroup)过滤
const volatile bool filter_cg = false;
// 目标进程 PID(默认值 0,跟踪所有进程)
const volatile pid_t target_pid = 0;
// 是否仅跟踪退出失败的进程
const volatile bool trace_failed_only = false;
// 是否只跟踪主线程(pid == tid)
const volatile bool trace_by_process = true;

// 哈希映射(cgroup_map), 用于过滤 cgroup
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cgroup_map SEC(".maps");

// perf_event 性能事件数组,用于将事件发送到用户空间
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/**
 * @brief 跟踪 sched_process_exit 事件(进程退出).
 *
 * 主要实现逻辑:
 *  1. 获取进程信息;
 *  2. 执行过滤条件:cgroup && PID && 线程 && 退出码
 *  3. 收集进程退出信息并输出到 events 中,共用户态程序处理
 *
 * @param ctx 包含关于系统调用的上下文信息
 */
// SEC("tracepoint/sched/sched_process_exit")
// 此处使用 tp_btf:基于BTF 类型的 tracepoint
SEC("tp_btf/sched_process_exit")
int sched_process_exit(void* ctx) {
  // 1. 获取进程信息: 进程 ID, 线程 ID
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  int exit_code;
  struct task_struct* task;
  struct event event = {};

  // 2. cgroup 过滤
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  // 3. PID 过滤
  if (target_pid && target_pid != pid) {
    return 0;
  }

  // 4. 线程过滤
  if (trace_by_process && pid != tid) {
    return 0;
  }

  // 5. 退出码过滤
  task = (struct task_struct*)bpf_get_current_task();
  exit_code = BPF_CORE_READ(task, exit_code);
  if (trace_failed_only && exit_code == 0) {
    return 0;
  }

  // 6. 收集进程退出信息
  event.start_time = BPF_CORE_READ(task, start_time);
  event.exit_time = bpf_ktime_get_ns();
  event.pid = pid;
  event.tid = tid;
  event.ppid = BPF_CORE_READ(task, real_parent, tgid);
  event.sig = exit_code & 0xff;
  event.exit_code = exit_code >> 8;
  bpf_get_current_comm(event.comm, sizeof(event.comm));
  // 7. 输出事件数据:输出到 events 映射中,用户空间通过 perf 事件读取这些数据
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
