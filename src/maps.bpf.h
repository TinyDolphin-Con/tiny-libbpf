/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <asm-generic/errno.h>
#include <bpf/bpf_helpers.h>

/**
 * @brief 从指定的 BPF 映射中查找键对应的值,
 *
 * 若不存在,则尝试用初始值 init 插入该键值对
 *
 * @param map 指向 BPF 映射的指针,用于存储键值对
 * @param key 指向映射中的键的指针
 * @param init 指向初始化值的指针
 */
static __always_inline void* bpf_map_lookup_or_try_init(void* map,
                                                        const void* key,
                                                        const void* init) {
  // 用于存储 bpf_map_lookup_elem 返回的键对应的值
  void* val;
  // 用于存储 BPF 操作（如插入键值对）的返回值。
  int err;

  // 从 BPF 映射中查找指定键 key 对应的值
  val = bpf_map_lookup_elem(map, key);
  if (val) {
    return val;
  }

  // 将键值对 <key, init> 插入映射中
  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  if (err && err != -EEXIST) {
    return 0;
  }

  // 再次尝试查找键对应的值并返回
  return bpf_map_lookup_elem(map, key);
}

#endif /* __MAPS_BPF_H */
