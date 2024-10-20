/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __CPUDIST_H
#define __CPUDIST_H

// 定义任务(进程)的命令名的最大长度
#define TASK_COMM_LEN 16
// 定义直方图中的最大槽位数量(每个槽位对应特定范围的时间)
#define MAX_SLOTS 36

// 用于存储任务的统计信息
struct hist {
  __u32 slots[MAX_SLOTS];
  char comm[TASK_COMM_LEN];
};

#endif  // __CPUDIST_H
