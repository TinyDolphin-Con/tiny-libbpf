/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __ONCPUTIME_H
#define __ONCPUTIME_H

// 定义最大的 CPU 数量
#define MAX_CPU_NR 128
// 定义任务(进程)的命令名的最大长度
#define TASK_COMM_LEN 16
// 定义最多可以指定的 PID 数量
#define MAX_PID_NR 60
// 定义最多可以指定的 TID 数量
#define MAX_TID_NR 60

// 存储线程关键标识信息
struct key_t {
  __u32 pid;
  __u32 tgid;
};

// 存储CPU统计信息
struct val_t {
  __u64 utimedelta;    // 用来累计 sys 时间
  __u64 stimedelta;    // 用来累计 usr 时间
  __u64 waitdelta;     // 用来累计 wait 时间
  __u32 cswchdelta;    // 统计自愿上下文换入的次数
  __u32 nvcswchdelta;  // 统计非自愿上下文换入的次数
  char comm[TASK_COMM_LEN];
};

#endif /* __ONCPUTIME_H */
