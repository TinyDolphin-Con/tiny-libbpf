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
#include "oncputime.h"

// 标记位,用于标识内核线程
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */
// 限制哈希表额度最大容量
#define MAX_ENTRIES 10240
// 表示任务的状态,表示进程处于运行状态
#define TASK_RUNNING 0

// 是否应用控制组(cgroup)过滤
const volatile bool filter_cg = false;
// 控制是否按照线程组 TGID 进行过滤
const volatile bool filter_by_tgid = false;
// 控制是否按照线程 PID 进行过滤
const volatile bool filter_by_pid = false;
// 执行线程状态过滤条件(如:只记录特定状态的线程)
const volatile long state = -1;

// 结构体定义:存储线程的相关数据和关键标识信息
struct internal_key {
  u64 utime;
  u64 stime;
  u32 cswch;
  u32 nvcswch;
  struct key_t key;  // 包含 pid 和 tgid 等线程信息
};

// eBPF Map 定义
// 用于保存线程的上一次执行信息
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct internal_key);
  __uint(max_entries, MAX_ENTRIES);
} task_info SEC(".maps");

// 定义一个哈希映射(cgroup_map), 用于过滤 cgroup
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cgroup_map SEC(".maps");

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

// 用于存储各线程 CPU 相关的统计信息
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct key_t);
  __type(value, struct val_t);
  __uint(max_entries, MAX_ENTRIES);
} cpu_info SEC(".maps");

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
static __always_inline bool allow_record(struct task_struct* t) {
  u32 tgid = BPF_CORE_READ(t, tgid);
  u32 pid = BPF_CORE_READ(t, pid);

  // 检查当前任务是否在指定的 cgroup 下
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return false;
  }
  if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid)) {
    return false;
  }
  if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid)) {
    return false;
  }
  if (state != -1 && get_task_state(t) != state) {
    return false;
  }
  return true;
}

/**
 * @brief 跟踪当前任务的执行情况
 *
 * @param ctx 包含关于系统调用的上下文信息
 */
static int handle_do_sample(struct bpf_perf_event_data* ctx) {
  struct task_struct* task;
  struct internal_key *i_keyp, i_key;
  struct key_t key;
  struct val_t *valp, val;
  u64 utime, stime;
  u32 cswch, nvcswch;
  s64 utimedelta, stimedelta;
  u32 cswchdelta, nvcswchdelta;
  u32 pid, tgid;

  // 获取当前任务的 task_struct 指针
  task = (void*)bpf_get_current_task();

  if (!allow_record(task)) {
    return 0;
  }

  // 获取当前任务的 pid tgid utime stime cswch nvcswch
  pid = BPF_CORE_READ(task, pid);
  tgid = BPF_CORE_READ(task, tgid);
  utime = BPF_CORE_READ(task, utime);
  stime = BPF_CORE_READ(task, stime);
  cswch = BPF_CORE_READ(task, nvcsw);
  nvcswch = BPF_CORE_READ(task, nivcsw);

  // key_t
  key.tgid = tgid;
  key.pid = filter_by_pid ? pid : tgid;

  valp = bpf_map_lookup_elem(&cpu_info, &key);
  if (!valp) {
    // init task_info
    i_key.key = key;
    i_key.utime = utime;
    i_key.stime = stime;
    i_key.cswch = cswch;
    i_key.nvcswch = nvcswch;
    bpf_map_update_elem(&task_info, &pid, &i_key, BPF_ANY);

    // 从 next 结构体中读取线程名称,并将其保存到 val.comm 中,以便后续分析
    __builtin_memset(&val, 0, sizeof(val));
    bpf_probe_read_kernel_str(&val.comm, sizeof(task->comm),
                              BPF_CORE_READ(task, comm));
    // 将新的线程执行信息存入 cpu_info 表
    // BPF_NOEXIST 确保cpu_info 表中若已有该键,则不进行更新
    bpf_map_update_elem(&cpu_info, &key, &val, BPF_NOEXIST);
    return 0;
  }

  // 查询当前线程的上一次统计数据
  i_keyp = bpf_map_lookup_elem(&task_info, &pid);
  if (!i_keyp) {
    return 0;
  }

  // 计算指标增量
  utimedelta = (s64)(utime - i_keyp->utime);
  stimedelta = (s64)(stime - i_keyp->stime);
  cswchdelta = cswch - i_keyp->cswch;
  nvcswchdelta = nvcswch - i_keyp->nvcswch;
  // 若 < 0, 说明时间记录有误,跳过
  if (utimedelta < 0 || stimedelta < 0 || cswchdelta < 0 || nvcswchdelta < 0) {
    return 0;
  }
  // 转换为微妙级单位
  utimedelta /= 1000U;
  stimedelta /= 1000U;

  // 累加统计数据
  __sync_fetch_and_add(&valp->utimedelta, utimedelta);
  __sync_fetch_and_add(&valp->stimedelta, stimedelta);
  __sync_fetch_and_add(&valp->cswchdelta, cswchdelta);
  __sync_fetch_and_add(&valp->nvcswchdelta, nvcswchdelta);

  // 更新任务信息
  i_keyp->key = key;
  i_keyp->utime = utime;
  i_keyp->stime = stime;
  i_keyp->cswch = cswch;
  i_keyp->nvcswch = nvcswch;

  return 0;
}

// 被 SEC("perf_event") 标记,表示该函数会被用作 perf 事件的处理程序
SEC("perf_event")
int do_sample(struct bpf_perf_event_data* ctx) { return handle_do_sample(ctx); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
