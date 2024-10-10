/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

// 单个参数字符串的最大字节数
#define ARGSIZE 128
// 进程名的最大字节数,典型值 16(Linux 系统中进程名称的长度)
#define TASK_COMM_LEN 16
// 最多可以捕获的命令行参数数量(execve 调用的参数数量)
#define TOTAL_MAX_ARGS 60
// 默认情况下,BPF 程序会跟踪的参数数量限制为 20 个
#define DEFAULT_MAXARGS 20
// 计算总的参数数组大小
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
// 无效的用户 ID,通常用于初始化或判断用户 ID 的有效性
#define INVALID_UID ((uid_t) - 1)
// 计算 struct event 结构体中 args 字段的偏移量,
// 表示事件结构体的基础大小,不包含 args 字段.
// 这种偏移量计算方式通常用于获取结构体字段的位置
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
// 计算整个事件的大小,
// 包括 struct event 的基础大小和 args_size 字段表示的参数大小
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
// 计算可以存储的最后一个参数的起始位置
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
  pid_t pid;                     // 当前进程 ID
  pid_t ppid;                    // 当前进程的父进程 ID
  uid_t uid;                     // 当前系统调用的用户 ID
  int retval;                    // 系统调用的返回值
  int args_count;                // 存储捕获的参数个数
  unsigned int args_size;        // 存储捕获的所有参数总大小
  char comm[TASK_COMM_LEN];      // 存储进程的命令名称
  char args[FULL_MAX_ARGS_ARR];  // 存储所有命令行参数
};

#endif /* __EXECSNOOP_H */
