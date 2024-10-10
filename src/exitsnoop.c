/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "btf_helpers.h"
#include "exitsnoop.h"
#include "exitsnoop.skel.h"
#include "trace_helpers.h"

// 用于性能缓冲区的页面数量
#define PERF_BUFFER_PAGES 16
// 在用户空间轮询性能缓冲区的超时时间,单位为毫秒
#define PERF_POLL_TIMEOUT_MS 100

#define warn(...) fprintf(stderr, __VA_ARGS__)

// 标志程序是否需要退出
// sig_atomic_t 表示该变量是一个可以安全地在信号处理程序中访问的类型,
// 它确保在信号处理期间对变量的访问不会被中断
// 这个变量通常在捕获到退出信号时被设置为 1,从而通知主循环退出
static volatile sig_atomic_t exiting = 0;

static struct env {
  bool emit_timestamp;     // 是否打印时间戳信息
  pid_t target_pid;        // 指定要跟踪的进程 PID
  bool trace_failed_only;  // 是否仅跟踪退出失败的进程
  bool trace_by_process;   // 是否只跟踪主线程
  bool verbose;            // 是否启用详细输出模式
  char* cgroupspath;       // 指定要跟踪的 cgroup 路径
  bool cg;                 // 是否启用 cgroup 跟踪
} env = {
    .emit_timestamp = false,     // -t -timestamp
    .target_pid = 0,             // -p --pid
    .trace_failed_only = false,  // -x --failed
    .trace_by_process = true,    // -T --threaded
    .verbose = false,            // -v --verbose
};

// 程序版本和文档说明
const char* argp_program_version = "exitsnoop 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Trace process termination.\n"
    "\n"
    "USAGE: exitsnoop [-h] [-t] [-x] [-p PID] [-T] [-c CG]\n"
    "\n"
    "EXAMPLES:\n"
    "    exitsnoop             # trace process exit events\n"
    "    exitsnoop -t          # include timestamps\n"
    "    exitsnoop -x          # trace error exits only\n"
    "    exitsnoop -p 1216     # only trace PID 1216\n"
    "    exitsnoop -T          # trace by thread\n"
    "    exitsnoop -c CG       # Trace process under cgroupsPath CG\n";

// 命令行选项定义
static const struct argp_option opts[] = {
    {"timestamp", 't', NULL, 0, "Include timestamp on output", 0},
    {"failed", 'x', NULL, 0, "Trace error exits only.", 0},
    {"pid", 'p', "PID", 0, "Process ID to trace", 0},
    {"threaded", 'T', NULL, 0, "Trace by thread.", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path",
     0},
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
  long pid;

  switch (key) {
    case 'p':
      errno = 0;
      pid = strtol(arg, NULL, 10);
      if (errno || pid <= 0) {
        warn("Invalid PID: %s\n", arg);
        argp_usage(state);
      }
      env.target_pid = pid;
      break;
    case 't':
      env.emit_timestamp = true;
      break;
    case 'x':
      env.trace_failed_only = true;
      break;
    case 'T':
      env.trace_by_process = false;
      break;
    case 'v':
      env.verbose = true;
      break;
    case 'c':
      env.cgroupspath = arg;
      env.cg = true;
      break;
    case 'h':
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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
 * @brief 事件处理函数,接收事件数据并格式化输出
 */
static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
  const struct event* e = data;
  time_t t;
  struct tm* tm;
  char ts[32];
  double age;
  int sig, coredump;

  if (!e || data_sz < sizeof(*e)) {
    printf("Error: packet too small\n");
    return;
  }

  if (env.emit_timestamp) {
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("%8s ", ts);
  }

  age = (e->exit_time - e->start_time) / 1e9;
  printf("%-16s %-7d %-7d %-7d %-7.2f ", e->comm, e->pid, e->ppid, e->tid, age);

  if (!e->sig) {
    if (!e->exit_code) {
      printf("0\n");
    } else {
      printf("code %d\n", e->exit_code);
    }
  } else {
    sig = e->sig & 0x7f;
    coredump = e->sig & 0x80;
    if (sig) {
      printf("signal %d (%s)", sig, strsignal(sig));
    }
    if (coredump) {
      printf(", core dumped");
    }
    printf("\n");
  }
}

/**
 * @brief 用于处理丢失的事件
 *
 * 当内核环形缓冲区中的事件未及时处理并丢弃时调用
 * 打印丢失事件的数量以及对应的 CPU 编号,提醒用户有部分事件未处理
 */
static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
  warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
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
  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };
  struct perf_buffer* pb = NULL;
  struct exitsnoop_bpf* obj;
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
  obj = exitsnoop_bpf__open_opts(&open_opts);
  if (!obj) {
    warn("failed to open BPF object\n");
    return 1;
  }

  /* initialize global data (filtering options) */
  // 5. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  obj->rodata->target_pid = env.target_pid;
  obj->rodata->trace_failed_only = env.trace_failed_only;
  obj->rodata->trace_by_process = env.trace_by_process;
  obj->rodata->filter_cg = env.cg;

  // 6. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = exitsnoop_bpf__load(obj);
  if (err) {
    warn("failed to load BPF object: %d\n", err);
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

  // 8. 附加程序
  // 将 BPF 程序附加到相应的内核钩子上,开始监控 sched_process_exit 事件
  err = exitsnoop_bpf__attach(obj);
  if (err) {
    warn("failed to attach BPF programs: %d\n", err);
    goto cleanup;
  }

  // 9. 设置事件回调
  // 初始化perf buffer(性能缓冲区),用于从内核向用户空间传递事件数据
  // PERF_BUFFER_PAGES:用于事件缓冲区的页数
  // handle_event:回调函数,当内核的 BPF 程序生成一个事件时,通过这个函数处理数据
  // handle_lost_events:当缓冲区数据丢失时,会调用这个回调函数处理丢失事件
  pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                        handle_event, handle_lost_events, NULL, NULL);
  if (!pb) {
    err = -errno;
    warn("failed to open perf buffer: %d\n", err);
    goto cleanup;
  }

  // 10. 设置信号处理(TODO:使用 sigaction 方式)
  if (signal(SIGINT, sig_int) == SIG_ERR) {
    warn("can't set signal handler: %s\n", strerror(errno));
    err = 1;
    goto cleanup;
  }

  if (env.emit_timestamp) {
    printf("%-8s ", "TIME(s)");
  }
  printf("%-16s %-7s %-7s %-7s %-7s %-s\n", "PCOMM", "PID", "PPID", "TID",
         "AGE(s)", "EXIT_CODE");

  // 11. 事件循环
  // 从 perf buffer 中获取 BPF 程序捕获的事件数据,
  // 捕获到事件时, 会调用回调函数 handle_event
  while (!exiting) {
    err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
    if (err < 0 && err != -EINTR) {
      warn("error polling perf buffer: %s\n", strerror(-err));
      goto cleanup;
    }
    /* reset err to return 0 if exiting */
    err = 0;
  }

  // 12. 清理资源
cleanup:
  perf_buffer__free(pb);
  exitsnoop_bpf__destroy(obj);
  cleanup_core_btf(&open_opts);
  if (cgfd > 0) {
    close(cgfd);
  }

  return err != 0;
}
