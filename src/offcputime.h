/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __OFFCPUTIME_H
#define __OFFCPUTIME_H

// 定义任务(进程)的命令名的最大长度
#define TASK_COMM_LEN 16
// 定义最多可以指定的 PID 数量
#define MAX_PID_NR 30
// 定义最多可以指定的 TID 数量
#define MAX_TID_NR 30

// 存储线程信息
struct key_t {
  __u32 pid;
  __u32 tgid;
  int user_stack_id;
  int kern_stack_id;
};

// 存储阻塞时间信息
struct val_t {
  __u64 delta;  // 用来累计阻塞时间
  char comm[TASK_COMM_LEN];
};

#endif /* __OFFCPUTIME_H */
