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
#include "funclatency.h"

// 是否应用控制组(cgroup)过滤
const volatile bool filter_cg = false;
// 目标进程ID(或线程组ID)
const volatile pid_t targ_tgid = 0;
// 确定延迟测量的时间单位(如:微妙或毫秒)
const volatile int units = 0;

// 定义一个哈希映射(cgroup_map), 用于过滤 cgroup
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);  // cgroup 数组
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);  // 只能存储一个条目
} cgroup_map SEC(".maps");

// 定义一个哈希映射(starts), 用于存储每个进程 ID 的函数执行开始时间
/* key: pid.  value: start time */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);  // 哈希映射
  __uint(max_entries, MAX_PIDS);
  __type(key, u32);
  __type(value, u64);
} starts SEC(".maps");

// hits 用于存储直方图数据,记录函数延迟
__u32 hist[MAX_SLOTS] = {};

/**
 * @brief 跟踪 fentry/dummy_fentry && kprobe/dummy_kprobe 事件.
 *
 * 在函数进入时捕获当前时间戳,并将其存储在以进程 ID 为键的 starts 映射中
 *
 * 主要实现逻辑:
 *  1. 获取进程信息;
 *  2. 执行过滤条件:cgroup && 进程 ID
 *  3. 将 <进程 PID, 当前时间> 存入 starts 中
 */
static void entry(void) {
  // 1. 获取当前进程和线程 ID
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;
  u64 nsec;

  // 2. cgroup 过滤:检查当前任务是否在指定的 cgroup 中
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return;
  }

  // 3. 进程 ID(或进程组ID)过滤
  if (targ_tgid && targ_tgid != tgid) {
    return;
  }
  // 4. 获取当前时间,并将 PID 和对应的开始时间存入 starts 中
  nsec = bpf_ktime_get_ns();
  // 其中 BPF_ANY: 标识如果这个位置已经有元素,则可以覆盖它
  bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

SEC("fentry/dummy_fentry")
int BPF_PROG(dummy_fentry) {
  entry();
  return 0;
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe) {
  entry();
  return 0;
}

/**
 * @brief 跟踪 fexit/dummy_fexit && kretprobe/dummy_kretprobe 事件.
 *
 * 通过将存储的开始时间与当前时间相减来计算延迟.
 *  然后将结果分类到直方图槽中,并增加该槽的计数以记录该延迟范围的发生次数
 *
 * 主要实现逻辑:
 *  1. 获取进程信息;
 *  2. 执行过滤条件:cgroup && 进程 ID
 *  3. 计算函数延迟,进行单位转换并将其归类到直方图的对应槽中
 */
static void exit(void) {
  u64* start;
  u64 nsec = bpf_ktime_get_ns();
  // 1. 获取当前进程和线程 ID
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 slot, delta;

  // 2. cgroup 过滤:检查当前任务是否在指定的 cgroup 中
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return;
  }

  // 3. 从 starts 映射中查找与当前 PID 对应的开始时间
  start = bpf_map_lookup_elem(&starts, &pid);
  if (!start) {
    return;
  }

  // 4. 计算函数的执行时间:进入函数到退出函数的时间差
  delta = nsec - *start;

  // 5. 根据 units 的值,将延迟从纳秒转换为微秒或毫秒
  switch (units) {
    case USEC:
      delta /= 1000;
      break;
    case MSEC:
      delta /= 1000000;
      break;
  }

  // 6. 计算延迟的二进制对数,并将其归类到直方图的某个槽中(slot)
  // 目的:为了更好地处理不同数据量级的延迟
  slot = log2l(delta);
  if (slot >= MAX_SLOTS) {
    slot = MAX_SLOTS - 1;
  }
  // 7. 将对应槽的计数器加 1 ,表示延迟落入了这个范围
  __sync_fetch_and_add(&hist[slot], 1);
}

SEC("fexit/dummy_fexit")
int BPF_PROG(dummy_fexit) {
  exit();
  return 0;
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe) {
  exit();
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
