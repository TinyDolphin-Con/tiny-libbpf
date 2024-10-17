// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 TinyDolphin */

#ifndef __COMPAT_H
#define __COMPAT_H

#include <limits.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <sys/types.h>

// 定义轮询的超时时间为 100 毫秒
#define POLL_TIMEOUT_MS 100

// 前向声明
struct bpf_buffer;
struct bpf_map;

// 定义一个函数指针类型,用于处理样本数据的回调函数
typedef int (*bpf_buffer_sample_fn)(void* ctx, void* data, size_t size);
// 定义另一个函数指针类型,用于处理丢失的样本数据的回调函数
typedef void (*bpf_buffer_lost_fn)(void* ctx, int cpu, __u64 cnt);

/**
 * @brief 创建新的 bpf_buffer 实例
 *
 * @param events 指向事件映射的指针
 * @param heap 指向堆的映射,可用于动态内存分配
 */
struct bpf_buffer* bpf_buffer__new(struct bpf_map* events,
                                   struct bpf_map* heap);

/**
 * @brief 打开并初始化 bpf_buffer 实例以准备数据接收
 *
 * @param buffer 指向 bpf_buffer 实例的指针
 * @param sample_cb 样本回调函数
 * @param lost_cb 丢失样本回调函数
 * @param ctx 包含关于系统调用的上下文信息
 */
int bpf_buffer__open(struct bpf_buffer* buffer, bpf_buffer_sample_fn sample_cb,
                     bpf_buffer_lost_fn lost_cb, void* ctx);

/**
 * @brief 轮询 bpf_buffer 中的事件
 *
 * @param buffer 指向 bpf_buffer 实例的指针
 * @param timeout_ms 超时时间,单位为毫秒
 */
int bpf_buffer__poll(struct bpf_buffer*, int timeout_ms);

/**
 * @brief 释放 bpf_buffer 实例及其内部资源
 *
 * @param buffer 指向 bpf_buffer 实例的指针
 */
void bpf_buffer__free(struct bpf_buffer*);

/* taken from libbpf */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/**
 * @brief 用于安全地重新分配内存,处理可能的溢出情况
 *
 * @param ptr 当前指针,指向要重新分配的内存块
 * @param nmemb 要分配的元素数量
 * @param size 每个元素的大小
 */
static inline void* libbpf_reallocarray(void* ptr, size_t nmemb, size_t size) {
  size_t total;

#if __has_builtin(__builtin_mul_overflow)
  if (__builtin_mul_overflow(nmemb, size, &total)) {
    return NULL;
  }
#else
  if (size == 0 || nmemb > ULONG_MAX / size) {
    return NULL;
  }
  total = nmemb * size;
#endif
  return realloc(ptr, total);
}

#endif /* __COMPAT_H */
