/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __MEMLEAK_H
#define __MEMLEAK_H

// 定义了最大内存分配条目的数量
#define ALLOCS_MAX_ENTRIES 1000000
// 定义了合并后的内存分配条目的最大数量
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

// 用于存储单个内存分配的详细信息
struct alloc_info {
  __u64 size;          // 内存分配的字节大小
  __u64 timestamp_ns;  // 分配事件发生的时间戳
  int stack_id;        // 调用栈 ID
};

// 用于合并多个内存分配的信息，以便高效存储和处理
union combined_alloc_info {
  struct {
    __u64 total_size : 40;        // 所有合并分配的总大小
    __u64 number_of_allocs : 24;  // 合并后的内存分配次数
  };
  __u64 bits;  // 作为联合体的一个整体视图，允许一次性访问所有位
};

#endif /* __MEMLEAK_H */
