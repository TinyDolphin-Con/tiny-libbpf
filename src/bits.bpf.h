/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __BITS_BPF_H
#define __BITS_BPF_H

// 将变量 x 作为 volatile 类型进行读取
#define READ_ONCE(x) (*(volatile typeof(x)*)&(x))
// 将变量 x 作为 volatile 类型进行写入
#define WRITE_ONCE(x, val) ((*(volatile typeof(x)*)&(x)) = val)

/**
 * @brief 计算一个数值以 2 为底的对数(32 位无符号整数)
 */
static __always_inline u64 log2(u32 v) {
  u32 shift, r;

  r = (v > 0xFFFF) << 4;
  v >>= r;
  shift = (v > 0xFF) << 3;
  v >>= shift;
  r |= shift;
  shift = (v > 0xF) << 2;
  v >>= shift;
  r |= shift;
  shift = (v > 0x3) << 1;
  v >>= shift;
  r |= shift;
  r |= (v >> 1);

  return r;
}

/**
 * @brief 计算一个数值以 2 为底的对数(64 位无符号整数)
 */
static __always_inline u64 log2l(u64 v) {
  u32 hi = v >> 32;

  if (hi) {
    return log2(hi) + 32;
  } else {
    return log2(v);
  }
}

#endif /* __BITS_BPF_H */
