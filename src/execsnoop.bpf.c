/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

// 提供内核定义
#include <vmlinux.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// 依赖头文件
#include "execsnoop.h"

// ===== 定义全局变量 =====
// 是否应用控制组(cgroup)过滤
const volatile bool filter_cg = false;
// 是否忽略某些操作失败的情况
const volatile bool ignore_failed = true;
// 目标用户 ID(默认值: INVALID_UID 表示为指定特定用户)
const volatile uid_t targ_uid = INVALID_UID;
// 控制最大参数数量
const volatile int max_args = DEFAULT_MAXARGS;

// 定义一个空的事件结构体变量,初始化为空
static const struct event empty_event = {};

// 哈希映射(cgroup_map), 用于过滤 cgroup
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);  // cgroup 数组
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);  // 只能存储一个条目
} cgroup_map SEC(".maps");

// 哈希映射:用于存储进程执行事件
struct {
  __uint(type, BPF_MAP_TYPE_HASH);  // 哈希映射
  __type(key, pid_t);
  __type(value, struct event);
  __uint(max_entries, 10240);
} execs SEC(".maps");

// perf_event 性能事件数组,用于将事件发送到用户空间
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);  // 性能事件数组
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 有效用户 ID 检查函数
static __always_inline bool valid_uid(uid_t uid) { return uid != INVALID_UID; }

/**
 * @brief 跟踪 sys_enter_execve 事件.
 *
 * 主要实现逻辑:
 *  1. 执行过滤条件:cgroup 过滤 && 用户 ID 过滤
 *  2. 更新映射: 进程执行信息 execs
 *  3. 读取各种参数:大小以及数量
 *
 * @param ctx 包含关于系统调用的上下文信息
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx) {
  u64 id;
  pid_t pid, tgid;
  int ret;
  struct event* event;
  struct task_struct* task;
  const char** args = (const char**)(ctx->args[1]);
  const char* argp;

  // 1. cgroup 过滤:检查当前任务是否在指定的 cgroup 中
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  // 2. 用户 ID 验证:检查当前用户 ID 是否为目标ID(若指定了目标ID)
  // 获取当前进程的用户 ID
  uid_t uid = (u32)bpf_get_current_uid_gid();
  int i;
  if (valid_uid(targ_uid) && targ_uid != uid) {
    return 0;
  }

  // 3. 获取当前进程 ID 并更新 execs 映射
  id = bpf_get_current_pid_tgid();
  pid = (pid_t)id;
  tgid = id >> 32;
  // 将空事件插入 execs 映射中
  // N.B. 尽量减少对映射的直接操作和复杂性,所以先插入一个空事件
  if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST)) {
    return 0;
  }

  // 4.事件结构体更新
  // 从 execs 映射中找到对应的事件
  event = bpf_map_lookup_elem(&execs, &pid);
  if (!event) {
    return 0;
  }

  // 更新事件结构体的字段,包括:进程 ID,用户 ID,父进程 ID,参数计数和参数大小
  event->pid = tgid;
  event->uid = uid;
  task = (struct task_struct*)bpf_get_current_task();
  event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
  event->args_count = 0;
  event->args_size = 0;

  // 5. 读取用户参数,并更新 args_size, args_count
  ret =
      bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
  if (ret < 0) {
    return 0;
  }
  if (ret <= ARGSIZE) {
    event->args_size += ret;
  } else {
    /* write an empty string */
    event->args[0] = '\0';
    event->args_size++;
  }

  event->args_count++;

  // 6. 读取其他参数. 优化循环,逐个读取后续参数.如果任何读取失败,则返回 0
#pragma unroll
  for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
    ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
    if (ret < 0) {
      return 0;
    }

    // 检查参数大小是否超出限制
    if (event->args_size > LAST_ARG) {
      return 0;
    }

    ret =
        bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
    if (ret < 0) {
      return 0;
    }

    event->args_count++;
    event->args_size += ret;
  }
  /* try to read one more argument to check if there is one */
  // 7. 检查更多参数,以确定是否有更多的参数
  ret = bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
  if (ret < 0) {
    return 0;
  }

  /* pointer to max_args+1 isn't null, asume we have more arguments */
  // 读取成功则增加 args_count
  event->args_count++;
  return 0;
}

/**
 * @brief 跟踪 sys_exit_execve 事件.
 *
 * 主要实现逻辑:
 *  1. 执行过滤条件: cgroup 过滤 && 用户 ID 过滤
 *  2. 更新映射: 进程执行信息 execs 的返回值
 *  3. 清理操作: 清理映射中当前进程信息,避免内存泄露
 *
 * @param ctx 包含关于系统调用的上下文信息
 */
SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx) {
  u64 id;
  pid_t pid;
  int ret;
  struct event* event;

  // 1. cgroup 过滤:检查当前任务是否在指定的 cgroup 中
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
    return 0;
  }

  // 2. 用户 ID 验证:检查当前用户 ID 是否为目标ID(若指定了目标ID)
  // 获取当前进程的用户 ID
  uid_t uid = (u32)bpf_get_current_uid_gid();
  if (valid_uid(targ_uid) && targ_uid != uid) {
    return 0;
  }

  // 3. 获取当前进程 ID
  id = bpf_get_current_pid_tgid();
  pid = (pid_t)id;
  // 从 execs 映射中找到对应的事件
  event = bpf_map_lookup_elem(&execs, &pid);
  if (!event) {
    return 0;
  }
  // 获取系统调用的返回值
  ret = ctx->ret;
  // 如果启用了忽略失败的选择且返回值小于 0,则直接跳到清理部分,不记录该事件
  if (ignore_failed && ret < 0) {
    goto cleanup;
  }

  // 4. 更新 execs 映射(更新返回值)
  event->retval = ret;
  // 获取当前进程的命令名,并存储在事件结构中
  bpf_get_current_comm(&event->comm, sizeof(event->comm));
  // 计算事件的大小
  size_t len = EVENT_SIZE(event);
  // 如果大小合法,则将事件信息输出到 events 映射中,以便用户态进行处理
  if (len <= sizeof(*event)) {
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len);
  }
cleanup:
  // 5. 清理操作:从映射中删除与当前 PID 相关的事件信息
  //  → 确保映射中的数据保持最新状态,避免内存泄露
  bpf_map_delete_elem(&execs, &pid);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
