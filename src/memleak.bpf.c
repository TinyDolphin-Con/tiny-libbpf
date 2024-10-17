/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

// 提供内核定义
#include <vmlinux.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 依赖头文件
#include "core_fixes.bpf.h"
#include "maps.bpf.h"
#include "memleak.h"

// 跟踪分配的最小内存大小
const volatile size_t min_size = 0;
// 跟踪分配的最大内存大小
const volatile size_t max_size = -1;
// 定义内存分页的大小(通常是 4KB)
const volatile size_t page_size = 4096;
// 采样率, 1 - 表示每个分配都会被跟踪
const volatile __u64 sample_rate = 1;
// 是否每次内存分配或释放时都记录日志
const volatile bool trace_all = false;
// 表示获取栈追踪时的标志
const volatile __u64 stack_flags = 0;
// 是否需要处理未正确释放的内存分配
const volatile bool wa_missing_free = false;

// 线程 ID 为键,记录分配的内存大小
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 10240);
} sizes SEC(".maps");

// 地址为键,记录内存分配的详细信息:大小|时间戳|调用堆栈等
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64); /* address */
  __type(value, struct alloc_info);
  __uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

// 堆栈 ID 为键,记录每个堆栈的总分配内存大小和次数,
// 便于统计某些调用路径的内存分配情况
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64); /* stack id */
  __type(value, union combined_alloc_info);
  __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

// 存储 posix_memalign 调用的内存指针,便于后续查找
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 10240);
} memptrs SEC(".maps");

// 记录内核或用户态调用栈的追踪信息
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __type(key, u32);
} stack_traces SEC(".maps");

// 全局静态变量,用于表示内存分配的统计信息(比如:内存分配总大小和分配次数)
static union combined_alloc_info initial_cinfo;

/**
 * @brief 更新内存分配统计信息
 *
 * 通过 bpf map 查找当前调用栈 ID 对应的内存分配信息
 * , 然后增加相应的内存分配大小和分配次数
 *
 * 主要逻辑:
 *  1. 查找或初始化 map 中的记录
 *  2. 原子增加分配大小和次数
 *
 * @param stack_id 分配内存时的调用栈 ID,用来区分不同的调用路径
 * @param sz 本次内存分配的大小
 */
static void update_statistics_add(u64 stack_id, u64 sz) {
  union combined_alloc_info* existing_cinfo;

  // 1, 从 combined_allocs 中查找或初始化当前调用栈的内存分配信息
  existing_cinfo =
      bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
  if (!existing_cinfo) {
    return;
  }

  // 保存本次增加的内存大小和分配次数
  const union combined_alloc_info incremental_cinfo = {.total_size = sz,
                                                       .number_of_allocs = 1};

  // 2. 原子操作:增加本次分配的内存大小和分配次数
  __sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

/**
 * @brief 更新内存释放统计信息
 *
 * 通过 bpf map 查找当前调用栈 ID 对应的内存释放信息
 * , 然后减少相应的内存释放大小和释放次数
 *
 * 主要逻辑:
 *  1. 查找或初始化 map 中的记录
 *  2. 原子减少释放大小和次数
 *
 * @param stack_id 释放内存时的调用栈 ID,用来区分不同的调用路径
 * @param sz 本次内存释放的大小
 */
static void update_statistics_del(u64 stack_id, u64 sz) {
  union combined_alloc_info* existing_cinfo;

  // 1, 从 combined_allocs 中查找当前调用栈的内存释放信息
  existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
  if (!existing_cinfo) {
    bpf_printk("failed to lookup combined allocs\n");

    return;
  }

  // 保存本次减少的内存大小和释放次数
  const union combined_alloc_info decremental_cinfo = {.total_size = sz,
                                                       .number_of_allocs = 1};

  // 2. 原子操作:减少本次释放的内存大小和释放次数
  __sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

/**
 * @brief 在内存分配函数调用时,被调用
 *
 * 用于记录内存分配请求的大小
 *
 *
 * 主要逻辑:
 *  1. 过滤无效分配请求
 *  2. 记录线程分配请求
 *  3. 打印调试信息
 *
 * @param size 要分配的内存大小
 */
static int gen_alloc_enter(size_t size) {
  // 根据内存大小进行过滤
  if (size < min_size || size > max_size) {
    return 0;
  }

  // 采样频率控制
  if (sample_rate > 1) {
    if (bpf_ktime_get_ns() % sample_rate != 0) {
      return 0;
    }
  }

  // 获取当前线程 ID
  const u32 tid = bpf_get_current_pid_tgid();
  // 将该线程分配内存大小保存到 sizes BPF map 中,以便继续追踪
  bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

  // 打印日志
  if (trace_all) {
    bpf_printk("alloc entered, size = %lu\n", size);
  }

  return 0;
}

/**
 * @brief 在内存分配函数返回时,被调用
 *
 * 用于记录分配完成后的信息(如:分配地址,时间戳,调用栈) 并更新统计
 *
 *
 * 主要逻辑:
 *  1. 获取线程分配的大小
 *  2. 清空并准备分配信息
 *  3. 记录分配的内存地址和调用栈
 *  4. 更新分配统计信息
 *  5. 打印调试信息
 *
 * @param ctx 上下文指针,用于获取调用栈
 * @param address 分配函数的返回值,即分配的内存地址
 */
static int gen_alloc_exit2(void* ctx, u64 address) {
  // 获取当前线程 ID
  const u32 tid = bpf_get_current_pid_tgid();
  struct alloc_info info;

  // 使用线程 ID 查找 sizes map, 即获取该线程刚才分配的大小
  const u64* size = bpf_map_lookup_elem(&sizes, &tid);
  if (!size) {
    return 0;  // missed alloc entry
  }

  // 清空并填充 alloc_info 结构体，记录分配大小,时间戳和调用栈 ID
  __builtin_memset(&info, 0, sizeof(info));
  info.size = *size;
  bpf_map_delete_elem(&sizes, &tid);

  if (address != 0) {
    info.timestamp_ns = bpf_ktime_get_ns();

    info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

    // 更新映射和分配统计数据
    bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
    update_statistics_add(info.stack_id, info.size);
  }

  // 打印调试信息
  if (trace_all) {
    bpf_printk("alloc exited, size = %lu, result = %lx\n", info.size, address);
  }

  return 0;
}

/**
 * @brief 封转函数,调用 gen_alloc_exit2
 *
 * @param ctx 上下文指针,用于获取调用栈
 */
static int gen_alloc_exit(struct pt_regs* ctx) {
  // PT_REGS_RC(ctx) 获取分配函数的返回值（分配的内存地址）
  return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

/**
 * @brief 在内存释放函数调用时,被调用
 *
 * 用于删除对应的内存分配记录,并更新统计信息
 *
 *
 * 主要逻辑:
 *  1. 查找分配记录
 *  2. 删除分配记录
 *  3. 更新释放统计信息
 *  4. 打印调试信息
 *
 * @param address 要释放的内存地址
 */
static int gen_free_enter(const void* address) {
  const u64 addr = (u64)address;

  // 从 allocs map 中查找对应的 alloc_info 信息
  const struct alloc_info* info = bpf_map_lookup_elem(&allocs, &addr);
  if (!info) {
    return 0;
  }

  // 删除 allocs map 中该内存地址的记录
  bpf_map_delete_elem(&allocs, &addr);
  // 减少统计信息
  update_statistics_del(info->stack_id, info->size);

  // 打印调试信息
  if (trace_all) {
    bpf_printk("free entered, address = %lx, size = %lu\n", address,
               info->size);
  }

  return 0;
}

// 以下通过使用 uprobe 和 uretprobe 来跟踪 C/C++ 中的内存分配和释放函数
//  如:malloc | calloc | free | realloc 等,
//  以及通过 tracepoint 机制来监视内核级别的内存管理活动
SEC("uprobe")
int BPF_UPROBE(malloc_enter, size_t size) { return gen_alloc_enter(size); }

SEC("uretprobe")
int BPF_URETPROBE(malloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(free_enter, void* address) { return gen_free_enter(address); }

SEC("uprobe")
int BPF_UPROBE(calloc_enter, size_t nmemb, size_t size) {
  return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_URETPROBE(calloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(realloc_enter, void* ptr, size_t size) {
  gen_free_enter(ptr);

  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(realloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(mmap_enter, void* address, size_t size) {
  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(mmap_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(munmap_enter, void* address) { return gen_free_enter(address); }

SEC("uprobe")
int BPF_UPROBE(posix_memalign_enter, void** memptr, size_t alignment,
               size_t size) {
  const u64 memptr64 = (u64)(size_t)memptr;
  const u32 tid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(posix_memalign_exit) {
  u64* memptr64;
  void* addr;
  const u32 tid = bpf_get_current_pid_tgid();

  memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
  if (!memptr64) {
    return 0;
  }

  bpf_map_delete_elem(&memptrs, &tid);

  if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64)) {
    return 0;
  }

  const u64 addr64 = (u64)(size_t)addr;

  return gen_alloc_exit2(ctx, addr64);
}
SEC("uprobe")
int BPF_UPROBE(aligned_alloc_enter, size_t alignment, size_t size) {
  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(aligned_alloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(valloc_enter, size_t size) { return gen_alloc_enter(size); }

SEC("uretprobe")
int BPF_URETPROBE(valloc_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(memalign_enter, size_t alignment, size_t size) {
  return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(memalign_exit) { return gen_alloc_exit(ctx); }

SEC("uprobe")
int BPF_UPROBE(pvalloc_enter, size_t size) { return gen_alloc_enter(size); }

SEC("uretprobe")
int BPF_URETPROBE(pvalloc_exit) { return gen_alloc_exit(ctx); }

SEC("tracepoint/kmem/kmalloc")
int memleak__kmalloc(void* ctx) {
  const void* ptr;
  size_t bytes_alloc;

  if (has_kmem_alloc()) {
    struct trace_event_raw_kmem_alloc___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
    bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
  } else {
    struct trace_event_raw_kmalloc___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
    bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
  }

  if (wa_missing_free) {
    gen_free_enter(ptr);
  }

  gen_alloc_enter(bytes_alloc);

  return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(void* ctx) {
  const void* ptr;
  size_t bytes_alloc;

  if (has_kmem_alloc_node()) {
    struct trace_event_raw_kmem_alloc_node___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
    bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

    if (wa_missing_free) {
      gen_free_enter(ptr);
    }

    gen_alloc_enter(bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)ptr);
  } else {
    /* tracepoint is disabled if not exist, avoid compile warning */
    return 0;
  }
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(void* ctx) {
  const void* ptr;

  if (has_kfree()) {
    struct trace_event_raw_kfree___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
  } else {
    struct trace_event_raw_kmem_free___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
  }

  return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void* ctx) {
  const void* ptr;
  size_t bytes_alloc;

  if (has_kmem_alloc()) {
    struct trace_event_raw_kmem_alloc___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
    bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
  } else {
    struct trace_event_raw_kmem_cache_alloc___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
    bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
  }

  if (wa_missing_free) {
    gen_free_enter(ptr);
  }

  gen_alloc_enter(bytes_alloc);

  return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void* ctx) {
  const void* ptr;
  size_t bytes_alloc;

  if (has_kmem_alloc_node()) {
    struct trace_event_raw_kmem_alloc_node___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
    bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

    if (wa_missing_free) {
      gen_free_enter(ptr);
    }

    gen_alloc_enter(bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)ptr);
  } else {
    /* tracepoint is disabled if not exist, avoid compile warning */
    return 0;
  }
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void* ctx) {
  const void* ptr;

  if (has_kmem_cache_free()) {
    struct trace_event_raw_kmem_cache_free___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
  } else {
    struct trace_event_raw_kmem_free___x* args = ctx;
    ptr = BPF_CORE_READ(args, ptr);
  }

  return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc* ctx) {
  gen_alloc_enter(page_size << ctx->order);

  return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free* ctx) {
  return gen_free_enter((void*)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int memleak__percpu_alloc_percpu(
    struct trace_event_raw_percpu_alloc_percpu* ctx) {
  gen_alloc_enter(ctx->bytes_alloc);

  return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int memleak__percpu_free_percpu(
    struct trace_event_raw_percpu_free_percpu* ctx) {
  return gen_free_enter(ctx->ptr);
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
