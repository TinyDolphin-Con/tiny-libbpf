/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include "compat.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#include "trace_helpers.h"

// 定义用于性能缓冲区的页面数量
#define PERF_BUFFER_PAGES 64

// 事件的缓冲区结构体
struct bpf_buffer {
  struct bpf_map* events;   // 指向一个 bpf_map, 用于存储事件
  void* inner;              // 指向内部缓冲区的指针
  bpf_buffer_sample_fn fn;  // 回调函数指针,用于处理样本数据
  void* ctx;  // 上下文指针,传递给回调函数的附加数据
  int type;   // 缓冲区类型:性能事件数组|环形缓冲区
};

/**
 * @brief 回调函数
 *
 * 用于处理从性能缓冲区接收到的样本数据
 *
 * @param ctx 包含关于系统调用的上下文信息
 * @param cpu 产生样本的 CPU 核心 ID
 * @param data 样本数据的指针
 * @param size 样本数据的大小
 */
static void perfbuf_sample_fn(void* ctx, int cpu, void* data, __u32 size) {
  struct bpf_buffer* buffer = ctx;
  bpf_buffer_sample_fn fn;

  // 检查是否设置了样本回调函数 fn
  fn = buffer->fn;
  if (!fn) {
    return;
  }

  // 如果设置了,则调用它并传递相关数据
  (void)fn(buffer->ctx, data, size);
}

/**
 * @brief 创建新的 bpf_buffer 实例
 *
 * @param events 指向事件映射的指针
 * @param heap 指向堆的映射,可用于动态内存分配
 */
struct bpf_buffer* bpf_buffer__new(struct bpf_map* events,
                                   struct bpf_map* heap) {
  struct bpf_buffer* buffer;
  bool use_ringbuf;
  int type;

  // 检查是否使用环形缓冲区,并设置相应的 BPF 映射类型
  use_ringbuf = probe_ringbuf();
  if (use_ringbuf) {
    bpf_map__set_autocreate(heap, false);
    type = BPF_MAP_TYPE_RINGBUF;
  } else {
    bpf_map__set_type(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    bpf_map__set_key_size(events, sizeof(int));
    bpf_map__set_value_size(events, sizeof(int));
    type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
  }

  // 动态分配内存用于 bpf_buffer 实例
  buffer = calloc(1, sizeof(*buffer));
  if (!buffer) {
    errno = ENOMEM;
    return NULL;
  }

  // 初始化 events 和 type 字段
  buffer->events = events;
  buffer->type = type;

  return buffer;
}

/**
 * @brief 打开并初始化 bpf_buffer 实例以准备数据接收
 *
 * @param buffer 指向 bpf_buffer 实例的指针
 * @param sample_cb 样本回调函数
 * @param lost_cb 丢失样本回调函数
 * @param ctx 包含关于系统调用的上下文信息
 */
int bpf_buffer__open(struct bpf_buffer* buffer, bpf_buffer_sample_fn sample_cb,
                     bpf_buffer_lost_fn lost_cb, void* ctx) {
  int fd, type;
  void* inner;

  // 获取 events 的文件描述符
  fd = bpf_map__fd(buffer->events);
  type = buffer->type;

  // 根据缓冲区类型,调用相应的函数来创建性能缓冲区或环形缓冲区
  switch (type) {
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
      buffer->fn = sample_cb;
      buffer->ctx = ctx;
      inner = perf_buffer__new(fd, PERF_BUFFER_PAGES, perfbuf_sample_fn,
                               lost_cb, buffer, NULL);
      break;
    case BPF_MAP_TYPE_RINGBUF:
      inner = ring_buffer__new(fd, sample_cb, ctx, NULL);
      break;
    default:
      return 0;
  }

  if (!inner) {
    return -errno;
  }

  // 如果成功,设置 buffer->inner 指向新创建的内部缓冲区
  buffer->inner = inner;
  return 0;
}

/**
 * @brief 轮询 bpf_buffer 中的事件
 *
 * @param buffer 指向 bpf_buffer 实例的指针
 * @param timeout_ms 超时时间,单位为毫秒
 */
int bpf_buffer__poll(struct bpf_buffer* buffer, int timeout_ms) {
  // 根据缓冲区类型,调用相应的轮询函数,并返回轮询结果
  switch (buffer->type) {
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
      return perf_buffer__poll(buffer->inner, timeout_ms);
    case BPF_MAP_TYPE_RINGBUF:
      return ring_buffer__poll(buffer->inner, timeout_ms);
    default:
      return -EINVAL;
  }
}

/**
 * @brief 释放 bpf_buffer 实例及其内部资源
 *
 * @param buffer 指向 bpf_buffer 实例的指针
 */
void bpf_buffer__free(struct bpf_buffer* buffer) {
  if (!buffer) {
    return;
  }

  // 根据缓冲区类型调用相应的释放函数,释放 inner 的资源
  switch (buffer->type) {
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
      perf_buffer__free(buffer->inner);
      break;
    case BPF_MAP_TYPE_RINGBUF:
      ring_buffer__free(buffer->inner);
      break;
  }
  // 释放 buffer 内存
  free(buffer);
}
