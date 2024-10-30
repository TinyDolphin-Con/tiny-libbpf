/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "btf_helpers.h"
#include "compat.h"
#include "oomkill.h"
#include "oomkill.skel.h"
#include "trace_helpers.h"

// ========= 结构体声明 =========
struct env {
  bool verbose;  // 控制调试信息的详细程度
} env = {};

// ========= 宏定义声明 =========
#define warn(...) fprintf(stderr, __VA_ARGS__)

// ========= 静态函数声明 =========
/**
 * @brief 信号处理函数
 *
 * @param signo 收到的信号值
 */
static void sig_handler(int signo);

/**
 * @brief 解析命令行参数
 *
 * @param key 当前解析到的命令行选项
 * @param arg 选项的参数
 * @param state 保存当前的解析状态和一些上下文信息
 */
static error_t argp_parse_arg(int key, char* arg, struct argp_state* state);

/**
 * @brief libbpf 的日志打印函数,根据日志等级打印消息
 *
 * @param level libbpf 日志的级别(例如 LIBBPF_DEBUG 表示调试信息)
 * @param format 日志信息的格式字符串(类似 printf)
 * @param args 可变参数列表,包含格式化字符串的实际值
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args);

/**
 * @brief 事件处理函数,捕获 OOM 事件,并将事件信息格式化输出
 *
 * @param ctx 上下文信息
 * @param data 指向事件数据的指针,包含 OOM 事件的相关信息
 * @param len 事件数据的长度,用于数据完整性验证
 */
static int handle_event(void* ctx, void* data, size_t len);

/**
 * @brief 用于处理丢失的事件
 *
 * 当内核环形缓冲区中的事件未及时处理并丢弃时调用
 * 打印丢失事件的数量以及对应的 CPU 编号,提醒用户有部分事件未处理
 *
 * @param ctx 上下文信息
 * @param cpu 事件发生丢失的 CPU 编号
 * @param lost_cnt 丢失的事件数量
 */
static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt);

// ========= 全局常量|变量定义 =========
// 程序版本和文档说明
const char* argp_program_version = "oomkill 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Trace OOM kills.\n"
    "\n"
    "USAGE: oomkill [-h]\n"
    "\n"
    "EXAMPLES:\n"
    "    oomkill               # trace OOM kills\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

// 定义标志位,用于检测程序退出信号(SIGINT)
static volatile sig_atomic_t exiting;

// 定义信号处理结构体 sigaction,并将 sig_handler 设置为处理信号的回调函数
static struct sigaction sig_action = {.sa_handler = sig_handler};

// ========= 函数实现 =========

/**
 * @brief 主函数
 *
 * 主要实现逻辑:
 *  1. 主函数入口:定义变量 && 解析命令行参数
 *  2. 设置调试输出:处理调试信息 && 确保内核 BTF 数据可用
 *  3. 打开 BPF 对象并初始化事件缓冲区
 *  4. 加载并附加 BPF 程序: 加载 BPF 程序并附加到内核钩子上,开始监控相应事件
 *  5. 设置信号处理和事件回调
 *  6. 事件主循环:从 perf buffer 中获取 BPF 程序捕获的事件数据并进行处理
 *  7. 清理资源
 */
int main(int argc, char** argv) {
  // LIBBPF_OPTS 用来创建一个结构体 open_opts,
  // 这个结构体会配置 BPF 对象加载时的选项
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  static const struct argp argp = {
      .options = opts,
      .parser = argp_parse_arg,
      .doc = argp_program_doc,
  };
  struct bpf_buffer* buf = NULL;
  struct oomkill_bpf* obj = NULL;
  int err;

  // 1. 解析命令行参数
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err) {
    return err;
  }

  // 2. 信号处理设置
  // 设置 SIGINT 信号的处理函数(SIGINT :通常用于捕获 Ctrl-C 中断信号)
  // 目的:优雅地停止程序,确保清理资源
  if (sigaction(SIGINT, &sig_action, NULL)) {
    perror("failed to set up signal handling");
    err = -errno;

    goto cleanup;
  }

  // 3. 设置调试输出
  // 设置一个调试输出函数(libbpf_print_fn),用来处理 libbpf 内部的调试信息
  // 如果用户没有开启 verbose 模式,则不会输出调试信息
  libbpf_set_print(libbpf_print_fn);

  // 4. 确保调试输出: 确保内核的 BTF 数据可用,CO-RE 依赖 BTF 来解析内核类型
  err = ensure_core_btf(&open_opts);
  if (err) {
    warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
    return 1;
  }

  // 5. 打开 BPF 对象
  obj = oomkill_bpf__open_opts(&open_opts);
  if (!obj) {
    warn("failed to load and open BPF object\n");
    return 1;
  }

  // 6. 事件缓冲区初始化
  // 初始化BPF缓冲区，用于接收BPF程序的事件数据
  buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
  if (!buf) {
    err = -errno;
    warn("failed to create ring/perf buffer: %d\n", err);
    goto cleanup;
  }

  // 7. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = oomkill_bpf__load(obj);
  if (err) {
    warn("failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  // 8. 附加程序
  // 将 BPF 程序附加到相应的内核钩子上,开始监控 sched_process_exit 事件
  err = oomkill_bpf__attach(obj);
  if (err) {
    warn("failed to attach BPF programs\n");
    goto cleanup;
  }

  // 9. 设置事件回调
  // handle_event:回调函数,当内核的 BPF 程序生成一个事件时,通过这个函数处理数据
  // handle_lost_events:当缓冲区数据丢失时,会调用这个回调函数处理丢失事件
  err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
  if (err) {
    warn("failed to open ring/perf buffer: %d\n", err);
    goto cleanup;
  }

  // 10. 设置信号处理(TODO:使用 sigaction 方式)
  if (signal(SIGINT, sig_handler) == SIG_ERR) {
    warn("can't set signal handler: %d\n", err);
    err = 1;
    goto cleanup;
  }

  printf("Tracing OOM kills... Ctrl-C to stop.\n");

  // 11. 事件循环
  // 从 perf buffer 中获取 BPF 程序捕获的事件数据,
  // 捕获到事件时, 会调用回调函数 handle_event
  while (!exiting) {
    err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
    if (err < 0 && err != -EINTR) {
      warn("error polling ring/perf buffer: %d\n", err);
      goto cleanup;
    }
    /* reset err to return 0 if exiting */
    err = 0;
  }

cleanup:
  // 12. 清理资源
  bpf_buffer__free(buf);
  oomkill_bpf__destroy(obj);
  cleanup_core_btf(&open_opts);

  return err != 0;
}

void sig_handler(int signo) { exiting = 1; }

error_t argp_parse_arg(int key, char* arg, struct argp_state* state) {
  switch (key) {
    case 'v':
      env.verbose = true;
      break;
    case 'h':
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                    va_list args) {
  if (level == LIBBPF_DEBUG && !env.verbose) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

int handle_event(void* ctx, void* data, size_t len) {
  FILE* f;
  char buf[256];
  int n = 0;
  struct tm* tm;
  char ts[32];
  time_t t;
  struct data_t* e = data;

  // 指向文件 /proc/loadavg 的文件指针(用于获取系统当前的平均负载)
  f = fopen("/proc/loadavg", "r");
  if (f) {
    // 读取文件内容,并存储到 buf 中
    memset(buf, 0, sizeof(buf));
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
  }
  // 获取当前时间戳
  time(&t);
  // 并转换为本地时间结构体
  tm = localtime(&t);
  // 格式化之后存储到 ts 中,用于显示事件发生的时间
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (n) {
    printf(
        "%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld "
        "pages, loadavg: %s",
        ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages, buf);
  } else {
    printf(
        "%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld "
        "pages\n",
        ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages);
  }

  return 0;
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
  warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}
