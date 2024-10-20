/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "cpudist.h"
#include "cpudist.skel.h"
#include "trace_helpers.h"

// ========= 结构体声明 =========
static struct env {
  time_t interval;      // 采样的时间间隔
  time_t nr_intervals;  // 运行的总间隔数, -1 表示无限次采样
  pid_t pid;            // 目标进程的 PID, -1 表示跟踪所有进程
  bool offcpu;          // 是否专注于 off-cpu
  bool timestamp;       // 是否显示时间戳
  bool per_process;     // 是否按进程监控事件
  bool per_thread;      // 是否按线程监控事件
  bool milliseconds;    // 表示时间记录的单位是否为毫秒
  bool verbose;         // 控制调试信息的详细程度
  char* cgroupspath;  // cgroup 路径，指定 BPF 程序作用于哪个 cgroup
  bool cg;  // 标识是否过滤特定 cgroup，控制是否仅在指定的 cgroup 中执行
} env = {
    .interval = 99999999,
    .pid = -1,
    .nr_intervals = 99999999,
};

// ========= 宏定义声明 =========

// ========= 静态函数声明 =========
/**
 * @brief 信号处理函数
 *
 * @param signo 收到的信号值
 */
static void sig_handler(int signo);

/**
 * @brief 解析长整数型参数
 *
 * @param key 当前解析到的命令行选项
 * @param arg 选项的参数
 * @param state 保存当前的解析状态和一些上下文信息
 */
static long argp_parse_long(int key, const char* arg, struct argp_state* state);

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
 * @brief 以可读的方式打印直方图数据,并清理 hists 数据
 *
 * @param hists 存储直方图数据的 map
 */
static int print_log2_hists(struct bpf_map* hists);

// ========= 变量定义 =========
// 程序版本和文档说明
const char* argp_program_version = "cpudist 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Summarize on-CPU time per task as a histogram.\n"
    "\n"
    "USAGE: cpudist [-h] [-O] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] "
    "[interval] [count] [-c CG]\n"
    "\n"
    "EXAMPLES:\n"
    "    cpudist         # summarize on-CPU time as a histogram\n"
    "    cpudist -O      # summarize off-CPU time as a histogram\n"
    "    cpudist -c CG   # Trace process under cgroupsPath CG\n"
    "    cpudist 1 10    # print 1 second summaries, 10 nr_intervalstimes\n"
    "    cpudist -mT 1   # 1s summaries, milliseconds, and timestamps\n"
    "    cpudist -P      # show each PID separately\n"
    "    cpudist -p 185  # trace PID 185 only\n";

#define OPT_PIDNSS 1 /* --pidnss */

static const struct argp_option opts[] = {
    {"offcpu", 'O', NULL, 0, "Measure off-CPU time", 0},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output", 0},
    {"milliseconds", 'm', NULL, 0, "Millisecond histogram", 0},
    {"pidnss", OPT_PIDNSS, NULL, 0, "Print a histogram per PID namespace", 0},
    {"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path",
     0},
    {"pids", 'P', NULL, 0, "Print a histogram per process ID", 0},
    {"tids", 'L', NULL, 0, "Print a histogram per thread ID", 0},
    {"pid", 'p', "PID", 0, "Trace this PID only", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

// 定义两个标志位,用于检测程序退出信号(SIGINT)和子进程退出信号(SIGCHLD)
static volatile sig_atomic_t exiting;

// 定义信号处理结构体 sigaction,并将 sig_handler 设置为处理信号的回调函数
static struct sigaction sig_action = {.sa_handler = sig_handler};

// ========= 函数实现 =========

/**
 * @brief 主函数
 *
 * 主要实现逻辑:
 *  1. 主函数入口:定义变量 && 解析命令行参数 && 注册信号处理函数
 *  2. 设置调试输出:处理调试信息
 *  3. 打开 BPF 对象并初始化全局数据
 *  4. 选择所需要的 BPF 跟踪点进行加载,并完成附加程序操作
 *  5. 主循环:数据收集并打印
 *  6. 清理资源
 */
int main(int argc, char** argv) {
  static const struct argp argp = {
      .options = opts,
      .parser = argp_parse_arg,
      .doc = argp_program_doc,
  };
  int ret = 0;
  struct cpudist_bpf* obj = NULL;
  struct tm* tm;
  char ts[32];
  time_t t;
  int idx, cg_map_fd;
  int cgfd = -1;

  // 1. 命令行参数解析
  ret = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (ret) {
    fprintf(stderr, "failed to parse args\n");

    goto cleanup;
  }

  // 2. 信号处理设置
  // 设置 SIGINT 信号的处理函数(SIGINT :通常用于捕获 Ctrl-C 中断信号)
  // 目的:优雅地停止程序,确保清理资源
  if (sigaction(SIGINT, &sig_action, NULL)) {
    perror("failed to set up signal handling");
    ret = -errno;

    goto cleanup;
  }

  // 3. 设置调试输出
  // 设置一个调试输出函数(libbpf_print_fn),用来处理 libbpf 内部的调试信息
  // 如果用户没有开启 verbose 模式,则不会输出调试信息
  libbpf_set_print(libbpf_print_fn);

  // 4. 打开 BPF 对象
  obj = cpudist_bpf__open();
  if (!obj) {
    fprintf(stderr, "failed to open BPF object\n");
    ret = 1;

    goto cleanup;
  }

  // 5. 选择需要加载的 BPF 程序
  // probe_tp_btf() 检测是否支持特定的 sched_wakeup 跟踪点
  if (probe_tp_btf("sched_switch")) {
    bpf_program__set_autoload(obj->progs.sched_switch_tp, false);
  } else {
    bpf_program__set_autoload(obj->progs.sched_switch_btf, false);
  }

  // 6. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  // 用于在 BPF 程序中进行条件过滤,这些设置取决于用户在命令行提供的选项
  obj->rodata->filter_cg = env.cg;
  obj->rodata->targ_per_process = env.per_process;
  obj->rodata->targ_per_thread = env.per_thread;
  obj->rodata->targ_ms = env.milliseconds;
  obj->rodata->targ_offcpu = env.offcpu;
  obj->rodata->targ_tgid = env.pid;

  // 7. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  ret = cpudist_bpf__load(obj);
  if (ret) {
    fprintf(stderr, "failed to load BPF object: %d\n", ret);
    goto cleanup;
  }

  // 8. 判断是否启用 cgroup 的过滤功能
  if (env.cg) {
    idx = 0;
    cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
    cgfd = open(env.cgroupspath, O_RDONLY);
    if (cgfd < 0) {
      fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
      goto cleanup;
    }
    if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
      fprintf(stderr, "Failed adding target cgroup to map");
      goto cleanup;
    }
  }

  // 9. 附加程序操作
  // 将 BPF 程序附加到相应的内核钩子上,开始监控相关事件
  ret = cpudist_bpf__attach(obj);
  if (ret) {
    fprintf(stderr, "failed to attach BPF programs\n");
    goto cleanup;
  }

  printf("Tracing %s-CPU time... Hit Ctrl-C to end.\n",
         env.offcpu ? "off" : "on");

  // 10. 主循环:数据收集并打印
  while (!exiting && env.nr_intervals--) {
    // 休眠一段时间后,打印统计结果
    sleep(env.interval);
    printf("\n");

    if (env.timestamp) {
      time(&t);
      tm = localtime(&t);
      strftime(ts, sizeof(ts), "%H:%M:%S", tm);
      printf("%-8s\n", ts);
    }

    // 打印直方图数据
    ret = print_log2_hists(obj->maps.hists);
    if (ret) {
      break;
    }
  }

cleanup:
  // 11. 清理资源
  cpudist_bpf__destroy(obj);
  if (cgfd > 0) {
    close(cgfd);
  }

  return ret != 0;
}

long argp_parse_long(int key, const char* arg, struct argp_state* state) {
  errno = 0;
  const long temp = strtol(arg, NULL, 10);
  if (errno || temp <= 0) {
    fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
    argp_usage(state);
  }

  return temp;
}

error_t argp_parse_arg(int key, char* arg, struct argp_state* state) {
  static int pos_args = 0;

  switch (key) {
    case 'h':
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
      break;
    case 'v':
      env.verbose = true;
      break;
    case 'm':
      env.milliseconds = true;
      break;
    case 'c':
      env.cgroupspath = arg;
      env.cg = true;
      break;
    case 'p':
      env.pid = atoi(arg);
      break;
    case 'O':
      env.offcpu = true;
      break;
    case 'P':
      env.per_process = true;
      break;
    case 'L':
      env.per_thread = true;
      break;
    case 'T':
      env.timestamp = true;
      break;
    case ARGP_KEY_ARG:
      pos_args++;

      if (pos_args == 1) {
        env.interval = argp_parse_long(key, arg, state);
      } else if (pos_args == 2) {
        env.nr_intervals = argp_parse_long(key, arg, state);
      } else {
        fprintf(stderr, "unrecognized positional argument: %s\n", arg);
        argp_usage(state);
      }
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

void sig_handler(int sig) { exiting = 1; }

int print_log2_hists(struct bpf_map* hists) {
  // 选择时间单位
  const char* units = env.milliseconds ? "msecs" : "usecs";
  // 从 hists 中获取文件描述符 fd
  int err, fd = bpf_map__fd(hists);
  // lookup_key 存储获取的第一个键, next_key 存储下一个键
  __u32 lookup_key = -2, next_key;
  // 存储从 map 中读取的直方图数据
  struct hist hist;

  // 1. 遍历 hists 直方图并输出数据
  while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    err = bpf_map_lookup_elem(fd, &next_key, &hist);
    if (err < 0) {
      fprintf(stderr, "failed to lookup hist: %d\n", err);
      return -1;
    }
    if (env.per_process) {
      printf("\npid = %d %s\n", next_key, hist.comm);
    } else if (env.per_thread) {
      printf("\ntid = %d %s\n", next_key, hist.comm);
    }
    // include from trace_helpers.h
    // 输出格式化的直方图数据
    print_log2_hist(hist.slots, MAX_SLOTS, units);
    lookup_key = next_key;
  }

  // 2. 清理 hists 中的元素
  lookup_key = -2;
  while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    err = bpf_map_delete_elem(fd, &next_key);
    if (err < 0) {
      fprintf(stderr, "failed to cleanup hist : %d\n", err);
      return -1;
    }
    lookup_key = next_key;
  }
  return 0;
}
