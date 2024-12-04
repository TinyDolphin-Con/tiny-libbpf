/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

// 提供内核定义
#include <vmlinux.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 依赖头文件
#include "core_fixes.bpf.h"
#include "offcputime.h"

// 标记位,用于标识内核线程
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */
// 限制哈希表额度最大容量
#define MAX_ENTRIES 10240

// 控制是否仅记录内核线程
const volatile bool kernel_threads_only = false;
// 控制是否仅记录用户线程
const volatile bool user_threads_only = false;
// 设置线程阻塞时间的上限(过滤不符合时间条件的记录)
const volatile __u64 max_block_ns = -1;
// 设置线程阻塞时间的下限
const volatile __u64 min_block_ns = 1;
// 控制是否按照线程组 TGID 进行过滤
const volatile bool filter_by_tgid = false;
// 控制是否按照线程 PID 进行过滤
const volatile bool filter_by_pid = false;
// 执行线程状态过滤条件(如:只记录特定状态的线程)
const volatile long state = -1;

// 结构体定义:存储线程的阻塞开始时间和关键标识信息
struct internal_key {
  u64 start_ts;
  struct key_t key;  // 包含 pid 和 tgid 等线程信息
};

// eBPF Map 定义
// 用于保存阻塞的开始时间
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct internal_key);
  __uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

// 用于保存用户态和内核态的栈追踪信息,帮助分析阻塞发生的调用栈
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

// 用于存储每个线程的累计阻塞时间
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct key_t);
  __type(value, struct val_t);
  __uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

// 用于存储用户指定的线程组 TGID,以供后续过滤使用
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u8);
  __uint(max_entries, MAX_PID_NR);
} tgids SEC(".maps");

// 用于存储用户指定的线程 PID,以供后续过滤使用
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u8);
  __uint(max_entries, MAX_TID_NR);
} pids SEC(".maps");

/**
 * @brief 用于检查线程是否满足记录条件
 *
 * 条件包括:
 *   - 是否在指定的 TGID 或 PID 列表中;
 *   - 是否符合用户态或内核态线程过滤条件;
 *   - 是否符合线程状态 state 的要求
 *
 * @param t 指向当前任务的指针
 */
static bool allow_record(struct task_struct* t) {
  u32 tgid = BPF_CORE_READ(t, tgid);
  u32 pid = BPF_CORE_READ(t, pid);

  if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid)) {
    return false;
  }
  if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid)) {
    return false;
  }
  if (user_threads_only && (BPF_CORE_READ(t, flags) & PF_KTHREAD)) {
    return false;
  } else if (kernel_threads_only && !(BPF_CORE_READ(t, flags) & PF_KTHREAD)) {
    return false;
  }
  if (state != -1 && get_task_state(t) != state) {
    return false;
  }
  return true;
}

static int handle_sched_switch(void* ctx, bool preempt,
                               struct task_struct* prev,
                               struct task_struct* next) {
  // 分别用于获取 start 哈希表中记录的阻塞开始时间,以及保存新的阻塞开始时间
  struct internal_key *i_keyp, i_key;
  struct val_t *valp, val;
  s64 delta;  // 存储计算出的阻塞时间
  u32 pid;

  // 当 prev 线程被切换出去时,检查是否符合记录条件
  if (allow_record(prev)) {
    pid = BPF_CORE_READ(prev, pid);
    /* To distinguish idle threads of different cores */
    if (!pid) {
      pid = bpf_get_smp_processor_id();
    }

    // 记录当前线程 PID|TGID|当前时间(阻塞的开始时间)
    i_key.key.pid = pid;
    i_key.key.tgid = BPF_CORE_READ(prev, tgid);
    i_key.start_ts = bpf_ktime_get_ns();

    // 保存当前的用户栈和内核栈追踪信息
    if (BPF_CORE_READ(prev, flags) & PF_KTHREAD) {
      i_key.key.user_stack_id = -1;
    } else {
      i_key.key.user_stack_id =
          bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    }
    i_key.key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
    // 将阻塞的开始时间保存到 start 哈希表中
    bpf_map_update_elem(&start, &pid, &i_key, 0);
    // 从 prev 结构体中读取线程名称,并将其保存到 val.comm 中,以便后续分析
    bpf_probe_read_kernel_str(&val.comm, sizeof(prev->comm),
                              BPF_CORE_READ(prev, comm));
    // 初始化累计阻塞时间为 0
    val.delta = 0;
    // 将新的线程阻塞信息存入 info 表
    // BPF_NOEXIST 确保info 表中若已有该键,则不进行更新
    bpf_map_update_elem(&info, &i_key.key, &val, BPF_NOEXIST);
  }

  // 获取next 的线程 PID,尝试从 start 中查找该线程的阻塞开始时间记录
  pid = BPF_CORE_READ(next, pid);
  i_keyp = bpf_map_lookup_elem(&start, &pid);
  if (!i_keyp) {
    return 0;
  }
  // 计算阻塞时间 delta
  delta = (s64)(bpf_ktime_get_ns() - i_keyp->start_ts);
  // 若 < 0, 说明时间记录有误,跳过
  if (delta < 0) {
    goto cleanup;
  }
  // 转换为微妙级单位
  delta /= 1000U;
  // 范围过滤
  if (delta < min_block_ns || delta > max_block_ns) {
    goto cleanup;
  }
  // info 中查找
  valp = bpf_map_lookup_elem(&info, &i_keyp->key);
  if (!valp) {
    goto cleanup;
  }
  // 将当前阻塞时间 delta 累加到 valp->delta 中,以确保多线程访问的同步性
  __sync_fetch_and_add(&valp->delta, delta);

cleanup:
  bpf_map_delete_elem(&start, &pid);
  return 0;
}

// sched_switch 处理任务切换事件,调用 handle_switch 函数
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct* prev,
             struct task_struct* next) {
  return handle_sched_switch(ctx, preempt, prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct* prev,
             struct task_struct* next) {
  return handle_sched_switch(ctx, preempt, prev, next);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
