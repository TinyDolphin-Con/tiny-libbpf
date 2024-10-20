/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

// 提供内核定义
#include <vmlinux.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 依赖头文件
#include "bits.bpf.h"
#include "core_fixes.bpf.h"
#include "cpudist.h"

// 定义 BPF 映射中可以存储的最大条目数
#define MAX_ENTRIES 10240
// 表示任务的状态,表示进程处于运行状态
#define TASK_RUNNING 0

// 是否应用控制组(cgroup)过滤
const volatile bool filter_cg = false;
// 结果中以进程为单位进行统计
const volatile bool targ_per_process = false;
// 结果中以线程为单位进行统计
const volatile bool targ_per_thread = false;
// 是否专注于 off-cpu 时间
const volatile bool targ_offcpu = false;
// 时间以毫秒为单位进行统计
const volatile bool targ_ms = false;
// 目标线程组 ID, 默认 0 ,表示不对特定线程组进行过滤
const volatile pid_t targ_tgid = -1;

// 定义一个哈希映射(cgroup_map), 用于过滤 cgroup
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cgroup_map SEC(".maps");

// 定义一个哈希映射(starts), 用于存储每个进程 ID 的函数执行开始时间
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, u64);
} start SEC(".maps");

// 声明一个 hist 类型的静态变量,表示直方图的初始值
static struct hist initial_hist;

// 定义一个哈希映射(hists),存储直方图数据
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct hist);
} hists SEC(".maps");

/**
 * @brief 记录任务的开始执行时间
 *
 * @param tgid 线程组 ID
 * @param pid 进程 ID
 * @param ts 开始执行时间
 */
static __always_inline void store_start(u32 tgid, u32 pid, u64 ts) {
  // 检查当前进程是否与目标进程匹配
  if (targ_tgid != -1 && targ_tgid != tgid) {
    return;
  }
  bpf_map_update_elem(&start, &pid, &ts, 0);
}

/**
 * @brief 更新任务的执行时间分布
 *
 * @param task 指向任务的指针
 * @param tgid 线程组 ID
 * @param pid 进程 ID
 * @param ts 开始执行时间
 */
static __always_inline void update_hist(struct task_struct* task, u32 tgid,
                                        u32 pid, u64 ts) {
  u64 delta, *tsp, slot;
  struct hist* histp;
  u32 id;

  // 检查当前进程是否与目标进程匹配
  if (targ_tgid != -1 && targ_tgid != tgid) {
    return;
  }

  // 从 start 映射中获取该任务的开始时间戳
  tsp = bpf_map_lookup_elem(&start, &pid);
  if (!tsp || ts < *tsp) {
    return;
  }

  // 根据配置的统计维度(按进程或线程)确定直方图键ID
  if (targ_per_process) {
    id = tgid;
  } else if (targ_per_thread) {
    id = pid;
  } else {
    id = -1;
  }
  // hists 直方图中,找到对应条目
  histp = bpf_map_lookup_elem(&hists, &id);
  if (!histp) {
    // 若没有,初始化一个新的直方图
    bpf_map_update_elem(&hists, &id, &initial_hist, 0);
    // 找出新创建的直方图
    histp = bpf_map_lookup_elem(&hists, &id);
    if (!histp) {
      return;
    }
    // 将进程名存储到直方图数据中
    BPF_CORE_READ_STR_INTO(&histp->comm, task, comm);
  }
  // 计算出时间差并映射到直方图的某个槽位中
  delta = ts - *tsp;
  if (targ_ms) {
    delta /= 1000000;
  } else {
    delta /= 1000;
  }
  slot = log2l(delta);
  if (slot >= MAX_SLOTS) {
    slot = MAX_SLOTS - 1;
  }
  // 原子操作,增加相应的计数
  __sync_fetch_and_add(&histp->slots[slot], 1);
}

/**
 * @brief 处理任务切换事件
 *
 * 在任务切换时,捕获当前和前一个任务的信息,并相应地更新直方图或记录任务开始执行时间
 *
 * 主要实现逻辑:
 *
 * @param prev 指向上一个任务的指针(正在被切换)
 * @param next 指向下一个任务的指针(将要被调度)
 */
static int handle_switch(struct task_struct* prev, struct task_struct* next) {
  u32 prev_tgid, prev_pid;
  u32 next_tgid, next_pid;
  u64 ts;

  // 检查当前任务是否在指定的 cgroup 下
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  prev_tgid = BPF_CORE_READ(prev, tgid);
  prev_pid = BPF_CORE_READ(prev, pid);
  next_tgid = BPF_CORE_READ(next, tgid);
  next_pid = BPF_CORE_READ(next, pid);

  ts = bpf_ktime_get_ns();

  if (targ_offcpu) {
    // 记录任务的 off-cpu(即任务被切换出去的事件)
    store_start(prev_tgid, prev_pid, ts);
    update_hist(next, next_tgid, next_pid, ts);
  } else {
    // 记录任务的 on-cpu (即任务开始运行的时间)
    if (get_task_state(prev) == TASK_RUNNING) {
      update_hist(prev, prev_tgid, prev_pid, ts);
    }
    store_start(next_tgid, next_pid, ts);
  }
  return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct* prev,
             struct task_struct* next) {
  return handle_switch(prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_tp, bool preempt, struct task_struct* prev,
             struct task_struct* next) {
  return handle_switch(prev, next);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
