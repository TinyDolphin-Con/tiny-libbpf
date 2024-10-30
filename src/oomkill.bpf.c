/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

// 提供内核定义
#include <vmlinux.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 依赖头文件
#include "compat.bpf.h"
#include "oomkill.h"

/**
 * @brief 跟踪 fentry/oom_kill_process 事件.
 *
 * SEC 将此函数附加到 oom_kill_process 内核函数上
 * BPF_PROG 声明一个 fentry 探针,用于在特定的内核函数调用时捕获信息
 *
 * 主要实现逻辑:
 *  1. 分配和检查缓冲区
 *  2. 获取相关数据并进行赋值操作
 *  3. 提交数据到用户空间
 *
 * @param oom_control 结构体的指针,包含当前触发 OOM 事件的相关信息
 * @param message 用于描述事件的消息字符串
 */
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control* oc, const char* message) {
  struct data_t* data;

  // 1. 分配和检查缓冲区
  // 调用 reserve_buf 函数分配数据缓冲区,以存储当前 oom_kill_process 事件的数据
  data = reserve_buf(sizeof(*data));
  if (!data) {
    return 0;
  }

  // 2. 赋值操作
  // 获取当前进程的 PID 并赋值
  data->fpid = bpf_get_current_pid_tgid() >> 32;
  // 从 oc 中读取目标进程的 TGID (即被杀死进程的 PID)
  data->tpid = BPF_CORE_READ(oc, chosen, tgid);
  // 从 oc 中读取页面总数,表示系统中已用的页面数
  data->pages = BPF_CORE_READ(oc, totalpages);
  // 获取当前进程(发起 OOM 杀进程的进程)的名称,并存储到 fcomm
  bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm));
  // 读取被杀死进程的名称并存储到 tcomm 中
  // 这里使用 bpf_probe_read_kernel 以安全地读取内核空间的数据
  bpf_probe_read_kernel(&data->tcomm, sizeof(data->tcomm),
                        BPF_CORE_READ(oc, chosen, comm));

  // 3. 提交数据
  // 将数据提交到用户空间,以便后续分析
  submit_buf(ctx, data, sizeof(*data));
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
