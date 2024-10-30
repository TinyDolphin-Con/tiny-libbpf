/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 提供 eBPF 程序的辅助函数
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "btf_helpers.h"
#include "runqlen.h"
#include "runqlen.skel.h"
#include "trace_helpers.h"

// ========= 结构体声明 =========
struct env {
  bool per_cpu;         // 是否按每个 CPU 监控事件
  bool runqocc;         // 是否显示运行队列占用率
  bool timestamp;       // 是否显示时间戳
  bool host;            // 是否指定主机过滤
  time_t interval;      // 采样的时间间隔
  time_t nr_intervals;  // 运行的总间隔数, -1 表示无限次采样
  int freq;             // 采样频率
  bool verbose;         // 控制调试信息的详细程度
} env = {
    .interval = 99999999,
    .nr_intervals = 99999999,
    .freq = 99,
};

// ========= 宏定义声明 =========
#define max(x, y)                  \
  ({                               \
    typeof(x) _max1 = (x);         \
    typeof(y) _max2 = (y);         \
    (void)(&_max1 == &_max2);      \
    _max1 > _max2 ? _max1 : _max2; \
  })

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

 * @brief 设置和附加 perf_event,并与每个 CPU 的 BPF 程序关联
 *
 * @param freq 采集的频率(每秒钟的采样次数)
 * @param prog 指向 BPF 程序的指针
 * @param links 存储 BPF 程序与 perf_event 之间的链接
 */
static int open_and_attach_perf_event(int freq, struct bpf_program* prog,
                                      struct bpf_link* links[]);

/**

 * @brief 计算并打印每个 CPU 的运行队列占用率(runqocc)
 *
 * @param bss 指向 BPF 程序的 BSS 段的指针(BSS 段:BPF 全局数据存储区域)
 */
static void print_runq_occupancy(struct runqlen_bpf__bss* bss);

/**

 * @brief 以线性方式打印运行队列长度的直方图
 *
 * @param bss 指向 BPF 程序的 BSS 段的指针(BSS 段:BPF 全局数据存储区域)
 */
static void print_linear_hists(struct runqlen_bpf__bss* bss);

// ========= 全局常量|变量定义 =========
// 程序版本和文档说明
const char* argp_program_version = "runqlen 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Summarize scheduler run queue length as a histogram.\n"
    "\n"
    "USAGE: runqlen [--help] [-C] [-O] [-T] [-f FREQUENCY] [interval] [count]\n"
    "\n"
    "EXAMPLES:\n"
    "    runqlen         # summarize run queue length as a histogram\n"
    "    runqlen 1 10    # print 1 second summaries, 10 times\n"
    "    runqlen -T 1    # 1s summaries and timestamps\n"
    "    runqlen -O      # report run queue occupancy\n"
    "    runqlen -C      # show each CPU separately\n"
    "    runqlen -H      # show nr_running from host's rq instead of cfs_rq\n"
    "    runqlen -f 199  # sample at 199HZ\n";

static const struct argp_option opts[] = {
    {"cpus", 'C', NULL, 0, "Print output for each CPU separately", 0},
    {"frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency", 0},
    {"runqocc", 'O', NULL, 0, "Report run queue occupancy", 0},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {"host", 'H', NULL, 0, "Report nr_running from host's rq", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

// 定义标志位,用于检测程序退出信号(SIGINT)
static volatile sig_atomic_t exiting;

// 定义信号处理结构体 sigaction,并将 sig_handler 设置为处理信号的回调函数
static struct sigaction sig_action = {.sa_handler = sig_handler};

// 存储系统中可用的 CPU 数量
static int nr_cpus;

// 初始化的 hist 结构体,用于重置计数
static struct hist zero;

// ========= 函数实现 =========

/**
 * @brief 主函数
 *
 * 主要实现逻辑:
 *  1. 主函数入口:定义变量 && 解析命令行参数 && 注册信号处理函数 && 设置调试输出
 *  2. CPU 核心数据检查
 *  3. 打开 BPF 对象并初始化全局数据
 *  4. 加载 BPF程序并附加 perf event
 *  5. 主循环:数据收集并打印
 *  6. 清理资源
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
  // 存储附加到每个 CPU 的 BPF 链接
  struct bpf_link* links[MAX_CPU_NR] = {};
  struct runqlen_bpf* obj = NULL;
  struct tm* tm;
  char ts[32];
  int err, i;
  time_t t;

  // 1. 命令行参数解析
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

  // 4. CPU 核心数据检查
  // 通过 libbpf_num_possible_cpus 获取 CPU 核心数量,并确保不超过 MAX_CPU_NR
  nr_cpus = libbpf_num_possible_cpus();
  if (nr_cpus < 0) {
    printf("failed to get # of possible cpus: '%s'!\n", strerror(-nr_cpus));
    return 1;
  }
  if (nr_cpus > MAX_CPU_NR) {
    fprintf(stderr,
            "the number of cpu cores is too big, please "
            "increase MAX_CPU_NR's value and recompile");
    return 1;
  }

  // 5. 确保内核的 BTF 数据可用,CO-RE 依赖 BTF 来解析内核类型
  err = ensure_core_btf(&open_opts);
  if (err) {
    fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n",
            strerror(-err));
    return 1;
  }

  // 6. 打开 BPF 对象
  obj = runqlen_bpf__open_opts(&open_opts);
  if (!obj) {
    fprintf(stderr, "failed to open BPF object\n");
    return 1;
  }

  // 7. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  obj->rodata->targ_per_cpu = env.per_cpu;
  obj->rodata->targ_host = env.host;

  // 8. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = runqlen_bpf__load(obj);
  if (err) {
    fprintf(stderr, "failed to load BPF object: %d\n", err);

    goto cleanup;
  }

  // 是否支持 BSS (即 BPF 全局数据存储区域)
  if (!obj->bss) {
    fprintf(stderr,
            "Memory-mapping BPF maps is supported starting from Linux 5.7, "
            "please upgrade.\n");

    goto cleanup;
  }

  // 9. 附加 perf event: 将 perf_event 附加到每个 CPU 上
  err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links);
  if (err) {
    goto cleanup;
  }

  printf("Sampling run queue length... Hit Ctrl-C to end.\n");

  // 10. 主循环:数据采集和输出
  // 按照设定的时间间隔采样数据并输出运行队列长度或占用率
  while (!exiting && env.nr_intervals) {
    sleep(env.interval);
    printf("\n");

    if (env.timestamp) {
      time(&t);
      tm = localtime(&t);
      strftime(ts, sizeof(ts), "%H:%M:%S", tm);
      printf("%-8s\n", ts);
    }

    if (env.runqocc) {
      // 打印运行队列占用率
      print_runq_occupancy(obj->bss);
    } else {
      // 打印运行队列长度的直方图
      print_linear_hists(obj->bss);
    }
  }

cleanup:
  // 11. 清理资源
  for (i = 0; i < nr_cpus; i++) {
    bpf_link__destroy(links[i]);
  }
  runqlen_bpf__destroy(obj);
  cleanup_core_btf(&open_opts);

  return err != 0;
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
    case 'C':
      env.per_cpu = true;
      break;
    case 'O':
      env.runqocc = true;
      break;
    case 'T':
      env.timestamp = true;
      break;
    case 'H':
      env.host = true;
      break;
    case 'f':
      env.freq = argp_parse_long(key, arg, state);
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

int open_and_attach_perf_event(int freq, struct bpf_program* prog,
                               struct bpf_link* links[]) {
  struct perf_event_attr attr = {
      .type = PERF_TYPE_SOFTWARE,
      .freq = 1,
      .sample_period = freq,
      .config = PERF_COUNT_SW_CPU_CLOCK,
  };
  int i, fd;

  for (i = 0; i < nr_cpus; i++) {
    // 打开每个 CPU 的 perf_event
    fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
    if (fd < 0) {
      // 忽略离线的 CPU
      if (errno == ENODEV) {
        continue;
      }
      fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
      return -1;
    }
    // 将打开的 perf_event 附加到 BPF 程序上
    links[i] = bpf_program__attach_perf_event(prog, fd);
    if (!links[i]) {
      fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
      close(fd);
      return -1;
    }
  }

  return 0;
}

void print_runq_occupancy(struct runqlen_bpf__bss* bss) {
  struct hist hist;
  int slot, i = 0;
  float runqocc;

  do {
    __u64 samples, idle = 0, queued = 0;

    // 获取直方图数据
    hist = bss->hists[i];
    // 并将其归零
    bss->hists[i] = zero;

    // 将直方图数据分成两部分:空闲时间(idel) 和排队时间(queued),并计算样本总数
    for (slot = 0; slot < MAX_SLOTS; slot++) {
      __u64 val = hist.slots[slot];

      if (slot == 0) {
        // slot 0 表示 CPU 空间时间
        idle += val;
      } else {
        // slot 非 0 表示 CPU 排队时间
        queued += val;
      }
    }
    // 计算运行队列占用率
    samples = idle + queued;
    runqocc = queued * 1.0 / max(1ULL, samples);
    // 按每个 CPU 或整体输出结果,具体取决于 env.per_cpu 的值
    if (env.per_cpu) {
      printf("runqocc, CPU %-3d %6.2f%%\n", i, 100 * runqocc);
    } else {
      printf("runqocc: %0.2f%%\n", 100 * runqocc);
    }
    // 如果启动 per-cpu 模式,则继续遍历下一个 CPU
  } while (env.per_cpu && ++i < nr_cpus);
}

void print_linear_hists(struct runqlen_bpf__bss* bss) {
  struct hist hist;
  int i = 0;

  do {
    // 读取直方图数据
    hist = bss->hists[i];
    // 并将其归零
    bss->hists[i] = zero;
    // 按每个 CPU 输出
    if (env.per_cpu) {
      printf("cpu = %d\n", i);
    }
    // 打印直方图内容
    print_linear_hist(hist.slots, MAX_SLOTS, 0, 1, "runqlen");
  } while (env.per_cpu && ++i < nr_cpus);
}
