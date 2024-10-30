/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __OOMKILL_H
#define __OOMKILL_H

// 定义任务(进程)的命令名的最大长度
#define TASK_COMM_LEN 16

struct data_t {
  __u32 fpid;                 // 发起杀进程操作的进程 ID(父进程 ID)
  __u32 tpid;                 // 被杀死进程的进程 ID(目标进程 ID)
  __u64 pages;                // OOM 杀死进程前系统中总的页面数
  char fcomm[TASK_COMM_LEN];  // 发起杀进程操作的进程名(父进程名称)
  char tcomm[TASK_COMM_LEN];  // 被杀死进程的进程名(目标进程名称)
};

#endif /* __OOMKILL_H */
