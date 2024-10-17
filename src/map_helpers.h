/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __MAP_HELPERS_H
#define __MAP_HELPERS_H

#include <bpf/bpf.h>

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
              __u32 value_size, __u32* count, void* invalid_key);

#endif /* __MAP_HELPERS_H */
