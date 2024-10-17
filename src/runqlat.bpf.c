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
#include "maps.bpf.h"
#include "runqlat.h"

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
// 结果中以 PID 命令空间为单位进行统计
const volatile bool targ_per_pidns = false;
// 时间以毫秒为单位进行统计
const volatile bool targ_ms = false;
// 目标线程组 ID, 默认 0 ,表示不对特定线程组进行过滤
const volatile pid_t targ_tgid = 0;

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
static struct hist zero;

// 定义一个哈希映射(hists),存储直方图数据
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct hist);
} hists SEC(".maps");

/**
 * @brief 记录任务的开始等待时间
 *
 * @param tgid 线程组 ID
 * @param pid 进程 ID
 */
static int trace_enqueue(u32 tgid, u32 pid) {
  u64 ts;

  if (!pid) {
    return 0;
  }
  if (targ_tgid && targ_tgid != tgid) {
    return 0;
  }

  // 获取当前时间戳,并记录到 start 哈希映射中
  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
  return 0;
}

/**
 * @brief 获取任务的 PID 命名空间
 *
 * @param task 指向任务的 PID 命名空间
 */
static unsigned int pid_namespace(struct task_struct* task) {
  struct pid* pid;
  unsigned int level;
  struct upid upid;
  unsigned int inum;

  /*  get the pid namespace by following task_active_pid_ns(),
   *  pid->numbers[pid->level].ns
   */
  // 通过访问任务结构中的 thread_pid 字段获取当前 PID
  pid = BPF_CORE_READ(task, thread_pid);
  level = BPF_CORE_READ(pid, level);
  // 读取 level 比国内获取对应的 upid
  bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
  // 返回 inum 表示该任务所在的 PID 命名空间
  inum = BPF_CORE_READ(upid.ns, ns.inum);

  return inum;
}

/**
 * @brief 处理任务切换事件
 *
 * 主要实现逻辑:
 *  1. 记录上一个任务的等待的开始时间(若上一个任务仍然为运行状态);
 *  2. 读取下一个任务,并计算出时间差(即延迟时间);
 *  3. 设置 hkey,并将下一个任务的 comm 存储到 histp 中;
 *  4. 计算出延迟时间对应的槽位,并更新到直方图槽中;
 *  5. 清理资源
 *
 * @param preempt 布尔值, 表示此次上下文切换是否为抢占式切换
 * @param prev 指向上一个任务的指针(正在被切换)
 * @param next 指向下一个任务的指针(将要被调度)
 */
static int handle_switch(bool preempt, struct task_struct* prev,
                         struct task_struct* next) {
  // histp 存储延迟分布
  struct hist* histp;
  // tsp 指向保存任务开始运行时间戳的内核映射
  // slot 延迟值所在的 hist 槽位
  u64 *tsp, slot;
  // pid 被调度任务的 PID(即下一个任务 PID)
  // hkey 用于查找 histp 的哈希键,通常是进程 TGID 或其他标识
  u32 pid, hkey;
  // delta 记录上下文切换时的调度延迟
  s64 delta;

  // 检查当前任务是否在指定的 cgroup 下
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  // 1. 若前一个任务处于运行状态,则表明它是因为时间片耗尽被调度出去的
  // , 因此需要调用 trace_enqueue 重新记录其等待的开始时间
  // N.B. BPF_CORE_READ 用于读取 task_struct 结构中字段的安全方法
  if (get_task_state(prev) == TASK_RUNNING) {
    trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));
  }

  // 2. 读取下一个任务,并计算出时间差
  // 读取下一个即将被调度的任务 PID
  pid = BPF_CORE_READ(next, pid);
  // 从 start 哈希映射中查找该 PID 的时间戳
  tsp = bpf_map_lookup_elem(&start, &pid);
  if (!tsp) {
    return 0;
  }
  // 并计算时间差 delta
  delta = bpf_ktime_get_ns() - *tsp;
  // 如果是负值,直接进入清理阶段
  if (delta < 0) {
    goto cleanup;
  }

  // 3. 设置 hkey, 并将下一个任务的 comm 存储到 histp 中
  // 根据不同的统计方式设置统计的 key, 用于区分不同任务的调度延迟统计
  if (targ_per_process) {
    hkey = BPF_CORE_READ(next, tgid);
  } else if (targ_per_thread) {
    hkey = pid;
  } else if (targ_per_pidns) {
    hkey = pid_namespace(next);
  } else {
    hkey = -1;
  }
  // 从 hists 哈希映射查找或初始化 histp
  histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
  if (!histp) {
    goto cleanup;
  }
  // 如果 histp 中 comm 字节为空,则表示第一次切换到该任务
  // ,因此需要读取下一个任务的命令名并存储到 histp 中
  if (!histp->comm[0]) {
    bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm), next->comm);
  }

  // 4. 计算出延迟时间对应槽位,更新到直方图槽中
  // 将 delta 转换成合适的单位(毫秒|微秒)
  if (targ_ms) {
    delta /= 1000000U;
  } else {
    delta /= 1000U;
  }

  // 计算 delta 的对数值 slot
  slot = log2l(delta);
  if (slot >= MAX_SLOTS) {
    slot = MAX_SLOTS - 1;
  }
  // 并更新相应的直方图槽
  __sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
  // 5. 清理阶段
  bpf_map_delete_elem(&start, &pid);
  return 0;
}

// BPF 程序入口: tp_btf 基于 BTF 元数据进行追踪(更推荐)
// sched_wakeup 在任务被唤醒时触发,调用 trace_enqueue 记录任务开始时间
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct* p) {
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  return trace_enqueue(p->tgid, p->pid);
}

// sched_wakeup_new 当新任务被唤醒时触发,同样调用 trace_enqueue 记录任务开始时间
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct* p) {
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  return trace_enqueue(p->tgid, p->pid);
}

// sched_switch 处理任务切换事件,调用 handle_switch 函数
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct* prev,
             struct task_struct* next) {
  return handle_switch(preempt, prev, next);
}

// BPF 程序入口: raw_tp 基于原始 tracepoint 进行追踪(兼容不支持 BTF 的情况)
SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct* p) {
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct* p) {
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct* prev,
             struct task_struct* next) {
  return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
