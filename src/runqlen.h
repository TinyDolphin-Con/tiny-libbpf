/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __RUNQLEN_H
#define __RUNQLEN_H

// 定义最大的 CPU 数量
#define MAX_CPU_NR 128
// 定义直方图最大支持 32 个槽位
#define MAX_SLOTS 32

// 存储每个 CPU 的运行队列长度统计数据
struct hist {
  __u32 slots[MAX_SLOTS];
};

#endif /* __RUNQLEN_H */
