/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

// 定义系统中允许跟踪的最大进程数
#define MAX_PIDS 102400
// 定义 BPF 程序中分配 slots 的最大数量
#define MAX_SLOTS 25

enum units {
  NSEC,  // 纳秒
  USEC,  // 微秒
  MSEC,  // 毫秒
};

#endif /* __BOOTSTRAP_H */
