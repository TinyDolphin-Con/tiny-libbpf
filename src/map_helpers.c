/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include "map_helpers.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

// 全局变量,表示是否使用批量操作模式
static bool batch_map_ops = true; /* hope for the best */

/**
 * @brief 获取 BPF 映射中键值对的函数(逐个迭代)
 *
 * @param map_fd bpf 映射的文件描述符
 * @param keys 指向键的指针
 * @param key_size 键的大小
 * @param values 指向值的指针
 * @param value_size 值的大小
 * @param count 用于传递希望读取的键值对数量
 * @param invalid_key 无效键,用于初始化迭代操作
 */
static int dump_hash_iter(int map_fd, void* keys, __u32 key_size, void* values,
                          __u32 value_size, __u32* count, void* invalid_key) {
  // 存储当前键和下一个键
  __u8 key[key_size], next_key[key_size];
  // 计数器,记录读取的键值对数量
  __u32 n = 0;
  int i, err;

  /* First get keys */
  // invalid_key 通常是一个不存在的键,表示映射中最初的开始位置
  __builtin_memcpy(key, invalid_key, key_size);
  while (n < *count) {
    // 获取下一个键
    err = bpf_map_get_next_key(map_fd, key, next_key);
    if (err && errno != ENOENT) {
      return -1;
    } else if (err) {
      break;
    }
    __builtin_memcpy(key, next_key, key_size);
    __builtin_memcpy(keys + key_size * n, next_key, key_size);
    n++;
  }

  /* Now read values */
  // 循环读取对应的值
  for (i = 0; i < n; i++) {
    err = bpf_map_lookup_elem(map_fd, keys + key_size * i,
                              values + value_size * i);
    if (err) {
      return -1;
    }
  }

  *count = n;
  return 0;
}

/**
 * @brief 获取 BPF 映射中键值对的函数(批量操作方式)
 *
 * @param map_fd bpf 映射的文件描述符
 * @param keys 指向键的指针
 * @param key_size 键的大小
 * @param values 指向值的指针
 * @param value_size 值的大小
 * @param count 用于传递希望读取的键值对数量
 */
static int dump_hash_batch(int map_fd, void* keys, __u32 key_size, void* values,
                           __u32 value_size, __u32* count) {
  void *in = NULL, *out;
  __u32 n, n_read = 0;
  int err = 0;

  while (n_read < *count && !err) {
    n = *count - n_read;
    // 批量读取
    err = bpf_map_lookup_batch(map_fd, &in, &out, keys + n_read * key_size,
                               values + n_read * value_size, &n, NULL);
    if (err && errno != ENOENT) {
      return -1;
    }
    n_read += n;
    in = out;
  }

  *count = n_read;
  return 0;
}

/**
 * @brief 负责从 BPF 映射中提取键值对
 *
 * @param map_fd bpf 映射的文件描述符
 * @param keys 指向键的指针
 * @param key_size 键的大小
 * @param values 指向值的指针
 * @param value_size 值的大小
 * @param count 用于传递希望读取的键值对数量
 * @param invalid_key 无效键,用于初始化迭代操作
 */
int dump_hash(int map_fd, void* keys, __u32 key_size, void* values,
              __u32 value_size, __u32* count, void* invalid_key) {
  int err;

  // 参数验证
  if (!keys || !values || !count || !key_size || !value_size) {
    errno = EINVAL;
    return -1;
  }

  // 批量操作
  if (batch_map_ops) {
    err = dump_hash_batch(map_fd, keys, key_size, values, value_size, count);
    if (err && errno == EINVAL) {
      /* assume that batch operations are not
       * supported and try non-batch mode */
      batch_map_ops = false;
    } else {
      return err;
    }
  }

  if (!invalid_key) {
    errno = EINVAL;
    return -1;
  }

  // 使用迭代模式逐个获取键值对
  return dump_hash_iter(map_fd, keys, key_size, values, value_size, count,
                        invalid_key);
}
