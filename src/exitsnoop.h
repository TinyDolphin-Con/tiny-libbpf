/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __EXITSNOOP_H
#define __EXITSNOOP_H

// 进程名的最大字节数,典型值 16(Linux 系统中进程名称的长度)
#define TASK_COMM_LEN 16

struct event {
  __u64 start_time;  // 进程的启动时间戳
  __u64 exit_time;   // 进程的退出时间戳
  __u32 pid;         // 当前进程的进程 ID（PID）
  __u32 tid;         // 当前线程的线程 ID（TID）
  __u32 ppid;        // 当前进程的父进程 ID（PPID）
  __u32 sig;         // 导致进程退出的信号
                     // 识别是否是因信号终止，如SIGKILL/SIGTERM
  int exit_code;     // 进程的退出代码
                     // 0 - 正常退出, 非0 - 遇到错误/异常
  char comm[TASK_COMM_LEN];  // 存储进程的命令名称
};

#endif /* __EXITSNOOP_H */
