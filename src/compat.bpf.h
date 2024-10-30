// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 TinyDolphin */

#ifndef __COMPAT_BPF_H
#define __COMPAT_BPF_H

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

// 定义事件的最大大小 10240 字节
#define MAX_EVENT_SIZE 10240
// 定义环形缓冲区的总大小 256 KB
#define RINGBUF_SIZE (1024 * 256)

// 定义 PERCPU_ARRAY 映射,用于在不支持 BPF 环形缓冲区的情况下存储事件数据
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, MAX_EVENT_SIZE);
} heap SEC(".maps");

// 定义 BPF_MAP_TYPE_RINGBUF 映射,用于高效存储和传输事件数据
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// 预留一块缓冲区,用于存储单个事件
static __always_inline void* reserve_buf(__u64 size) {
  static const int zero = 0;

  // 判断当前环境是否支持BPF_MAP_TYPE_RINGBUF
  if (bpf_core_type_exists(struct bpf_ringbuf)) {
    // 若支持,则从 events 环形缓冲区中分配 size 字节的空间
    return bpf_ringbuf_reserve(&events, size, 0);
  }

  // 若不支持,则获取 head 数组中的第一个元素的地址,作为事件缓冲区
  return bpf_map_lookup_elem(&heap, &zero);
}

// 提交已填充的事件数据,使其可被用户空间消费
static __always_inline long submit_buf(void* ctx, void* buf, __u64 size) {
  // 若支持 BPF_MAP_TYPE_RINGBUF
  if (bpf_core_type_exists(struct bpf_ringbuf)) {
    bpf_ringbuf_submit(buf, 0);
    return 0;
  }

  // 若不支持,则使用 bpf_perf_event_output 将事件数据 buf 输出到 events 映射中
  return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, size);
}

#endif /* __COMPAT_BPF_H */
