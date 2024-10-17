/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#ifndef __BTF_HELPERS_H
#define __BTF_HELPERS_H

#include <bpf/libbpf.h>

// BTF 文件确保函数
int ensure_core_btf(struct bpf_object_open_opts* opts);
// 用于删除临时生成的 BTF 文件并释放内存
void cleanup_core_btf(struct bpf_object_open_opts* opts);

#endif /* __BTF_HELPERS_H */
