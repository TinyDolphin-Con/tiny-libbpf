/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

// 提供内核定义
#include <vmlinux.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 依赖头文件
#include "runqlen.h"

// 表示是否针对每个 CPU 进行监控
const volatile bool targ_per_cpu = false;
// 表示是否指定主机过滤
const volatile bool targ_host = false;

// 数组,存储每个 CPU 的运行队列长度的直方图
struct hist hists[MAX_CPU_NR] = {};

// 被 SEC("perf_event") 标记,表示该函数会被用作 perf 事件的处理程序
SEC("perf_event")
int do_sample(struct bpf_perf_event_data* ctx) {
  struct task_struct* task;
  struct hist* hist;
  u64 slot, cpu = 0;

  // 获取当前任务信息
  task = (void*)bpf_get_current_task();
  // 读取任务队列长度
  if (targ_host) {
    slot = BPF_CORE_READ(task, se.cfs_rq, rq, nr_running);
  } else {
    slot = BPF_CORE_READ(task, se.cfs_rq, nr_running);
  }

  // 调整运行队列的长度
  // 含义:将运行队列长度调整为仅包括处于等待状态的任务数量
  if (slot > 0) {
    slot--;
  }

  // 若针对每个 CPU,则获取 CPU ID
  if (targ_per_cpu) {
    cpu = bpf_get_smp_processor_id();
    if (cpu >= MAX_CPU_NR) {
      return 0;
    }
  }

  // 获取当前 CPU 的直方图并更新
  hist = &hists[cpu];
  if (slot >= MAX_SLOTS) {
    slot = MAX_SLOTS - 1;
  }
  if (targ_per_cpu) {
    hist->slots[slot]++;
  } else {
    // 若不是针对每个 CPU 分别统计,则需要原子操作,确保线程安全
    __sync_fetch_and_add(&hist->slots[slot], 1);
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
