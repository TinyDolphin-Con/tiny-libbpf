/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "btf_helpers.h"
#include "execsnoop.h"
#include "execsnoop.skel.h"
#include "trace_helpers.h"

// 用于性能缓冲区的页面数量
#define PERF_BUFFER_PAGES 64
// 在用户空间轮询性能缓冲区的超时时间,单位为毫秒
#define PERF_POLL_TIMEOUT_MS 100
// 用于跟踪最大参数数量的键值
#define MAX_ARGS_KEY 259

// 标志程序是否需要退出
// sig_atomic_t 表示该变量是一个可以安全地在信号处理程序中访问的类型,
// 它确保在信号处理期间对变量的访问不会被中断
// 这个变量通常在捕获到退出信号时被设置为 1,从而通知主循环退出
static volatile sig_atomic_t exiting = 0;

static struct env {
  bool time;         // 是否打印时间信息
  bool timestamp;    // 是否打印带有时间戳的事件
  bool fails;        // 是否捕获失败的系统调用事件
  uid_t uid;         // 跟踪特定用户的 UID
  bool quote;        // 是否对参数加引号进行输出
  const char* name;  // 程序名称过滤器,只跟踪特定名称的进程
  const char* line;  // 行号过滤器
  bool print_uid;    // 是否打印 UID
  bool verbose;      // 是否启用详细输出模式
  int max_args;      // 要捕获的最大参数数量
  char* cgroupspath;  // cgroup 路径过滤器,只跟踪特定 cgroup 内的进程
  bool cg;            // 是否启用 cgroup 过滤
} env = {.max_args = DEFAULT_MAXARGS, .uid = INVALID_UID};

static struct timespec start_time;

// 程序版本和文档说明
const char* argp_program_version = "execsnoop 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Trace exec syscalls\n"
    "\n"
    "USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] "
    "[-U] [-c CG]\n"
    "                 [--max-args MAX_ARGS]\n"
    "\n"
    "EXAMPLES:\n"
    "   ./execsnoop           # trace all exec() syscalls\n"
    "   ./execsnoop -x        # include failed exec()s\n"
    "   ./execsnoop -T        # include time (HH:MM:SS)\n"
    "   ./execsnoop -U        # include UID\n"
    "   ./execsnoop -u 1000   # only trace UID 1000\n"
    "   ./execsnoop -t        # include timestamps\n"
    "   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
    "   ./execsnoop -n main   # only print command lines containing \"main\"\n"
    "   ./execsnoop -l tpkg   # only print command where arguments contains "
    "\"tpkg\""
    "   ./execsnoop -c CG     # Trace process under cgroupsPath CG\n";

// 命令行选项定义
static const struct argp_option opts[] = {
    {"time", 'T', NULL, 0, "include time column on output (HH:MM:SS)", 0},
    {"timestamp", 't', NULL, 0, "include timestamp on output", 0},
    {"fails", 'x', NULL, 0, "include failed exec()s", 0},
    {"uid", 'u', "UID", 0, "trace this UID only", 0},
    {"quote", 'q', NULL, 0, "Add quotemarks (\") around arguments", 0},
    {"name", 'n', "NAME", 0, "only print commands matching this name, any arg",
     0},
    {"line", 'l', "LINE", 0, "only print commands where arg contains this line",
     0},
    {"print-uid", 'U', NULL, 0, "print UID column", 0},
    {"max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
     "maximum number of arguments parsed and displayed, defaults to 20", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path",
     0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

/**
 * @brief 解析命令行参数
 *
 * @param key 当前解析到的命令行选项
 * @param arg 选项的参数
 * @param state 保存当前的解析状态和一些上下文信息
 */
static error_t parse_arg(int key, char* arg, struct argp_state* state) {
  long int uid, max_args;

  switch (key) {
    case 'h':
      // 输出标准的帮助文档并停止程序
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
      break;
    case 'T':
      env.time = true;
      break;
    case 't':
      env.timestamp = true;
      break;
    case 'x':
      env.fails = true;
      break;
    case 'c':
      env.cgroupspath = arg;
      env.cg = true;
      break;
    case 'u':
      errno = 0;
      uid = strtol(arg, NULL, 10);
      if (errno || uid < 0 || uid >= INVALID_UID) {
        fprintf(stderr, "Invalid UID %s\n", arg);
        argp_usage(state);  // 输出帮助信息
      }
      env.uid = uid;
      break;
    case 'q':
      env.quote = true;
      break;
    case 'n':
      env.name = arg;
      break;
    case 'l':
      env.line = arg;
      break;
    case 'U':
      env.print_uid = true;
      break;
    case 'v':
      env.verbose = true;
      break;
    case MAX_ARGS_KEY:
      errno = 0;
      max_args = strtol(arg, NULL, 10);
      if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
        fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
                arg, TOTAL_MAX_ARGS);
        argp_usage(state);
      }
      env.max_args = max_args;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/**
 * @brief libbpf 的日志打印函数,根据日志等级打印消息
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  if (level == LIBBPF_DEBUG && !env.verbose) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

/**
 * @brief 信号处理函数
 *
 * 收到中断信号(SIGINT, 通常是 Ctrl-C) 时,将 exiting 标志设置为 1,
 * 以便能够检测到并优雅地退出
 */
static void sig_int(int signo) { exiting = 1; }

/**
 * @brief 计算程序运行的时间差,并打印从程序启动到当前事件发生的时间
 */
static void time_since_start() {
  long nsec, sec;
  static struct timespec cur_time;
  double time_diff;

  // 获取当前事件点(CLOCK_MONOTONIC,即从系统启动到现在的时间)
  clock_gettime(CLOCK_MONOTONIC, &cur_time);

  // 通过减去全局变量 start_time 来计算时间差,并将结果以秒为单位输出
  nsec = cur_time.tv_nsec - start_time.tv_nsec;
  sec = cur_time.tv_sec - start_time.tv_sec;
  if (nsec < 0) {
    nsec += NSEC_PER_SEC;
    sec--;
  }
  time_diff = sec + (double)nsec / NSEC_PER_SEC;
  printf("%-8.3f", time_diff);
}

/**
 * @brief 用于处理特定字符的转义输出
 */
static void inline quoted_symbol(char c) {
  switch (c) {
    case '"':
      putchar('\\');
      putchar('"');
      break;
    case '\t':
      putchar('\\');
      putchar('t');
      break;
    case '\n':
      putchar('\\');
      putchar('n');
      break;
    default:
      putchar(c);
      break;
  }
}

/**
 * @brief 打印捕获到的事件的参数(args)
 */
static void print_args(const struct event* e, bool quote) {
  int i, args_counter = 0;

  if (env.quote) {
    putchar('"');
  }

  for (i = 0; i < e->args_size && args_counter < e->args_count; i++) {
    char c = e->args[i];

    if (env.quote) {
      if (c == '\0') {
        args_counter++;
        putchar('"');
        putchar(' ');
        if (args_counter < e->args_count) {
          putchar('"');
        }
      } else {
        quoted_symbol(c);
      }
    } else {
      if (c == '\0') {
        args_counter++;
        putchar(' ');
      } else {
        putchar(c);
      }
    }
  }
  if (e->args_count == env.max_args + 1) {
    fputs(" ...", stdout);
  }
}

/**
 * @brief 事件处理函数,接收事件数据并格式化输出
 */
static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
  const struct event* e = data;
  time_t t;
  struct tm* tm;
  char ts[32];

  /* TODO: use pcre lib */
  if (env.name && strstr(e->comm, env.name) == NULL) {
    return;
  }

  /* TODO: use pcre lib */
  if (env.line && strstr(e->comm, env.line) == NULL) {
    return;
  }

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (env.time) {
    printf("%-8s ", ts);
  }
  if (env.timestamp) {
    time_since_start();
  }

  if (env.print_uid) {
    printf("%-6d", e->uid);
  }

  printf("%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval);
  print_args(e, env.quote);
  putchar('\n');
}

/**
 * @brief 用于处理丢失的事件
 *
 * 当内核环形缓冲区中的事件未及时处理并丢弃时调用
 * 打印丢失事件的数量以及对应的 CPU 编号,提醒用户有部分事件未处理
 */
static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
  fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

/**
 * @brief 主函数
 *
 * 主要实现逻辑:
 *  1. 主函数入口:定义变量 && 解析命令行参数
 *  2. 设置调试输出:处理调试信息 && 确保内核 BTF 数据可用
 *  3. 打开 BPF 对象并初始化全局数据
 *  4. 加载并附加 BPF 程序: 加载 BPF 程序并附加到内核钩子上,开始监控相应事件
 *  5. 设置信号处理和事件回调
 *  6. 事件主循环:从 perf buffer 中获取 BPF 程序捕获的事件数据并进行处理
 *  7. 清理资源
 */
int main(int argc, char** argv) {
  // LIBBPF_OPTS 用来创建一个结构体 open_opts,
  // 这个结构体会配置 BPF 对象加载时的选项
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  // argp 用于解析命令行参数,处理用户输入的选项
  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };
  struct perf_buffer* pb = NULL;
  struct execsnoop_bpf* obj;
  int err;
  int idx, cg_map_fd;
  int cgfd = -1;

  // 1. 解析命令行参数
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err) {
    return err;
  }

  // 2. 设置调试输出
  // 设置一个调试输出函数(libbpf_print_fn),用来处理 libbpf 内部的调试信息
  // 如果用户没有开启 verbose 模式,则不会输出调试信息
  libbpf_set_print(libbpf_print_fn);

  // 3. 确保调试输出: 确保内核的 BTF 数据可用,CO-RE 依赖 BTF 来解析内核类型
  err = ensure_core_btf(&open_opts);
  if (err) {
    fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n",
            strerror(-err));
    return 1;
  }

  // 4. 打开 BPF 对象
  obj = execsnoop_bpf__open_opts(&open_opts);
  if (!obj) {
    fprintf(stderr, "failed to open BPF object\n");
    return 1;
  }

  /* initialize global data (filtering options) */
  // 5. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  obj->rodata->ignore_failed = !env.fails;
  obj->rodata->targ_uid = env.uid;
  obj->rodata->max_args = env.max_args;
  obj->rodata->filter_cg = env.cg;

  // 6. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = execsnoop_bpf__load(obj);
  if (err) {
    fprintf(stderr, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  /* update cgroup path fd to map */
  // 7. 判断是否启用 cgroup 的过滤功能
  if (env.cg) {
    idx = 0;
    // bpf_map__fd :获取 BPF map 的文件描述符
    // (BPF map 用于在内核空间和用户空间共享数据)
    // maps.cgroup_map 存储和管理特定 cgroup 的信息
    cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
    // 打开 env.cgroupspath 并以只读模式打开 cgroup
    cgfd = open(env.cgroupspath, O_RDONLY);
    if (cgfd < 0) {
      fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
      goto cleanup;
    }
    // bpf_map_update_elem :用于将元素插入到 BPF map 中
    // BPF_ANY: 标识如果这个位置已经有元素,则可以覆盖它
    if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
      fprintf(stderr, "Failed adding target cgroup to map");
      goto cleanup;
    }
  }

  // 8. 设置时间戳并附加程序
  // 程序记录当前时间,
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  // 并将 BPF 程序附加到相应的内核钩子上,开始监控 exec 事件
  err = execsnoop_bpf__attach(obj);
  if (err) {
    fprintf(stderr, "failed to attach BPF programs\n");
    goto cleanup;
  }
  /* print headers */
  if (env.time) {
    printf("%-9s", "TIME");
  }
  if (env.timestamp) {
    printf("%-8s ", "TIME(s)");
  }
  if (env.print_uid) {
    printf("%-6s ", "UID");
  }

  printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS");

  /* setup event callbacks */
  // 9. 设置事件回调
  // 初始化perf buffer(性能缓冲区),用于从内核向用户空间传递事件数据
  // PERF_BUFFER_PAGES:用于事件缓冲区的页数
  // handle_event:回调函数,当内核的 BPF 程序生成一个事件时,通过这个函数处理数据
  // handle_lost_events:当缓冲区数据丢失时,会调用这个回调函数处理丢失事件
  pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                        handle_event, handle_lost_events, NULL, NULL);
  if (!pb) {
    err = -errno;
    fprintf(stderr, "failed to open perf buffer: %d\n", err);
    goto cleanup;
  }

  // 10. 设置信号处理
  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    err = 1;
    goto cleanup;
  }

  /* main: poll */
  // 11. 事件循环
  // 从 perf buffer 中获取 BPF 程序捕获的事件数据,
  // 捕获到事件时, 会调用回调函数 handle_event
  while (!exiting) {
    err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
    if (err < 0 && err != -EINTR) {
      fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
      goto cleanup;
    }
    /* reset err to return 0 if exiting */
    err = 0;
  }

  // 12. 清理资源
cleanup:
  perf_buffer__free(pb);
  execsnoop_bpf__destroy(obj);
  cleanup_core_btf(&open_opts);
  if (cgfd > 0) {
    close(cgfd);
  }

  return err != 0;
}
