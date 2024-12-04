/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// 提供 eBPF 程序的辅助函数
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "btf_helpers.h"
#include "oncputime.h"
#include "oncputime.skel.h"
#include "trace_helpers.h"

// ========= 结构体声明 =========
static struct env {
  pid_t pids[MAX_PID_NR];  // 保存需要分析的进程 ID 列表
  pid_t tids[MAX_TID_NR];  // 保存需要分析的线程 ID 列表
  long state;              // 状态过滤器
  time_t interval;         // 采样的时间间隔
  time_t nr_intervals;     // 运行的总间隔数, -1 表示无限次采样
  int freq;                // 采样频率
  char* cgroupspath;  // cgroup 路径，指定 BPF 程序作用于哪个 cgroup
  bool cg;  // 标识是否过滤特定 cgroup，控制是否仅在指定的 cgroup 中执行
  bool verbose;  // 控制调试信息的详细程度
} env = {
    .state = -1,
    .interval = 99999999,
    .nr_intervals = 99999999,
    .freq = 99,
};

// ========= 宏定义声明 =========
// 用于筛选特定的线程状态
#define OPT_STATE 3 /* --state */

// ========= 静态函数声明 =========
/**
 * @brief 信号处理函数
 *
 * @param signo 收到的信号值
 */
static void sig_handler(int signo);

/**
 * @brief 解析长整数型参数 long
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
 * @brief 打印头部信息,列出所有指定的 PID 和 TID
 * 返回 true 或 false 表示是否有 PID 或 TID 被指定
 */
static bool print_header_threads();

/**
 * @brief 打印各线程的 on-cpu 时间
 *
 * @param obj oncputime_bpf 结构体对象,包含了通过 BPF maps 获取的数据
 */
static int print_data(struct oncputime_bpf* obj);

// ========= 全局常量|变量定义 =========
// 程序版本和文档说明
const char* argp_program_version = "oncputime 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Summarize on-CPU time.\n"
    "\n"
    "USAGE: oncputime [--help] [-p PID] [--state] [-c CG] "
    "[interval] [nr_intervals]\n"
    "EXAMPLES:\n"
    "    oncputime             # summarize on-CPU time until Ctrl-C\n"
    "    oncputime 1 10        # print 1 second summaries, 10 times\n"
    "    oncputime -p 185,175,165 # only trace threads for PID 185,175,165\n"
    "    oncputime -t 188,120,134 # only trace threads 188,120,134\n"
    "    oncputime -c CG       # Trace process under cgroupsPath CG\n"
    "    oncputime -f 199      # sample at 199HZ\n";

static const struct argp_option opts[] = {
    {"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path",
     0},
    {"pid", 'p', "PID", 0, "Trace these PIDs only, comma-separated list", 0},
    {"frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency", 0},
    {"tid", 't', "TID", 0, "Trace these TIDs only, comma-separated list", 0},
    {"state", OPT_STATE, "STATE", 0,
     "filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE) see "
     "include/linux/sched.h",
     0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

// 定义标志位,用于检测程序退出信号(SIGINT)
static volatile sig_atomic_t exiting;

// 定义信号处理结构体 sigaction,并将 sig_handler 设置为处理信号的回调函数
static struct sigaction sig_action = {.sa_handler = sig_handler};

// 存储系统中可用的 CPU 数量
static int nr_cpus;

// ========= 函数实现 =========
/**
 * @brief 主函数
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
  struct bpf_link* links[MAX_CPU_NR] = {};
  struct oncputime_bpf* obj = NULL;
  int pids_fd, tids_fd;
  int idx, cg_map_fd;
  int cgfd = -1;
  int err = 0, i;
  __u8 val = 0;

  // 命令行参数解析
  if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
    fprintf(stderr, "failed to parse args\n");

    goto cleanup;
  }

  // 信号处理设置
  // 设置 SIGINT 信号的处理函数(SIGINT :通常用于捕获 Ctrl-C 中断信号)
  // 目的:优雅地停止程序,确保清理资源
  if (sigaction(SIGINT, &sig_action, NULL)) {
    perror("failed to set up signal handling");
    err = -errno;
    goto cleanup;
  }

  // 设置调试输出
  // 设置一个调试输出函数(libbpf_print_fn),用来处理 libbpf 内部的调试信息
  // 如果用户没有开启 verbose 模式,则不会输出调试信息
  libbpf_set_print(libbpf_print_fn);

  // CPU 核心数据检查
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

  // 打开 BPF 对象
  obj = oncputime_bpf__open();
  if (!obj) {
    fprintf(stderr, "failed to open BPF object\n");
    err = 1;
    goto cleanup;
  }

  // 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  // 用于在 BPF 程序中进行条件过滤,这些设置取决于用户在命令行提供的选项
  obj->rodata->state = env.state;
  obj->rodata->filter_cg = env.cg;

  // 跟踪的 PID/TID 设置
  // 将用户定义的过滤条件(仅追踪用户线程或仅追踪内核线程)
  // 写入 BPF 对象的只读数据段,传递到内核 BPF 程序
  if (env.pids[0]) {
    obj->rodata->filter_by_tgid = true;
  }
  if (env.tids[0]) {
    obj->rodata->filter_by_pid = true;
  }

  // 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = oncputime_bpf__load(obj);
  if (err) {
    fprintf(stderr, "failed to load BPF programs\n");
    goto cleanup;
  }

  // 判断是否启用 cgroup 的过滤功能
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

  // 过滤 PID 和 TID
  // 如果设定了 pids 和 tids,则将其写入 BPF 映射以用于过滤
  if (env.pids[0]) {
    /* User pids_fd points to the pids map in the BPF program */
    pids_fd = bpf_map__fd(obj->maps.tgids);
    for (size_t i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
      if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
        fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
        goto cleanup;
      }
    }
  }
  if (env.tids[0]) {
    /* User tids_fd points to the tgids map in the BPF program */
    tids_fd = bpf_map__fd(obj->maps.pids);
    for (size_t i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
      if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
        fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
        goto cleanup;
      }
    }
  }

  // 附加 perf event: 将 perf_event 附加到每个 CPU 上
  err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links);
  if (err) {
    goto cleanup;
  }

  // 附加程序操作
  // 将 BPF 程序附加到相应的内核钩子上,开始监控相关事件
  err = oncputime_bpf__attach(obj);
  if (err) {
    fprintf(stderr, "failed to attach BPF programs\n");
    goto cleanup;
  }

  // 输出捕获的栈信息和 on-cpu 时间
  printf("Tracing on-CPU time (us) of");

  // 打印线程信息
  if (!print_header_threads()) {
    printf(" all threads");
  }

  // 打印追踪持续时间
  if (env.nr_intervals < 99999999) {
    printf(" for %ld second, %ld times.\n", env.interval, env.nr_intervals);
  } else {
    printf("... Hit Ctrl-C to end.\n");
  }

  // 主循环:数据收集并打印
  while (!exiting && env.nr_intervals) {
    env.nr_intervals--;

    // 休眠一段时间后,打印统计结果
    sleep(env.interval);
    printf("\n");

    if (env.interval < 99999999) {
      printf("%-8s %-16s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME(s)",
             "PCOMM", "TGID", "TID", "cswch", "nvcswch", "usr%", "sys%",
             "CPU%");
    } else {
      printf("%-8s %-16s %-8s %-8s %-8s %-8s %-12s\n", "TIME(s)", "PCOMM",
             "TGID", "TID", "cswch", "nvcswch", "CPU(µs)");
    }

    // 打印数据
    err = print_data(obj);
    if (err) {
      break;
    }
  }

cleanup:
  for (i = 0; i < nr_cpus; i++) {
    bpf_link__destroy(links[i]);
  }
  oncputime_bpf__destroy(obj);

  if (cgfd > 0) {
    close(cgfd);
  }

  return err != 0;
}

void sig_handler(int sig) { exiting = 1; }

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
  int ret;

  switch (key) {
    case 'h':
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
      break;
    case 'v':
      env.verbose = true;
      break;
    case 'c':
      env.cgroupspath = arg;
      env.cg = true;
      break;
    case 'f':
      env.freq = argp_parse_long(key, arg, state);
      break;
    case 'p':
      ret = split_convert(strdup(arg), ",", env.pids, sizeof(env.pids),
                          sizeof(pid_t), str_to_int);
      if (ret) {
        if (ret == -ENOBUFS) {
          fprintf(stderr,
                  "the number of pid is too big, please "
                  "increase MAX_PID_NR's value and recompile\n");
        } else {
          fprintf(stderr, "invalid PID: %s\n", arg);
        }

        argp_usage(state);
      }
      break;
    case 't':
      ret = split_convert(strdup(arg), ",", env.tids, sizeof(env.tids),
                          sizeof(pid_t), str_to_int);
      if (ret) {
        if (ret == -ENOBUFS) {
          fprintf(stderr,
                  "the number of tid is too big, please "
                  "increase MAX_TID_NR's value and recompile\n");
        } else {
          fprintf(stderr, "invalid TID: %s\n", arg);
        }

        argp_usage(state);
      }
      break;
    case OPT_STATE:
      errno = 0;
      env.state = argp_parse_long(key, arg, state);
      if (env.state < 0 || env.state > 2) {
        fprintf(stderr, "Invalid task state: %s\n", arg);
        argp_usage(state);
      }
      break;
    case ARGP_KEY_ARG:
      pos_args++;
      if (pos_args == 1) {
        env.interval = argp_parse_long(key, arg, state);
      } else if (pos_args == 2) {
        env.nr_intervals = argp_parse_long(key, arg, state);
      } else {
        fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
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

bool print_header_threads() {
  bool printed = false;

  // 打印 PID 列表
  if (env.pids[0]) {
    printf(" PID [");
    for (size_t i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
      printf("%d%s", env.pids[i],
             (i < MAX_PID_NR - 1 && env.pids[i + 1]) ? ", " : "]");
    }
    printed = true;
  }

  // 打印 TID 列表
  if (env.tids[0]) {
    printf(" TID [");
    for (size_t i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
      printf("%d%s", env.tids[i],
             (i < MAX_TID_NR - 1 && env.tids[i + 1]) ? ", " : "]");
    }
    printed = true;
  }

  return printed;
}

int print_data(struct oncputime_bpf* obj) {
  struct key_t lookup_key = {}, next_key;
  int err, ifd;
  struct val_t val;
  double usr, sys;

  time_t t;
  struct tm* tm;
  char ts[32];

  // 1. 获取 BPF maps 的文件描述符
  // 通过 bpf_map_fd 获取 info 和 stackmap maps 的文件描述符
  ifd = bpf_map__fd(obj->maps.cpu_info);

  // 2. 遍历线程数据
  // 通过 bpf_map_get_next_key 获取 map 中的每个 key(lookup_key 和 next_key)
  while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
    // 获取 key 对应的 val 数据,其中包含进程的 on-cpu 时间,进程名等
    err = bpf_map_lookup_elem(ifd, &next_key, &val);
    if (err < 0) {
      fprintf(stderr, "failed to lookup info: %d\n", err);
      return -1;
    }

    lookup_key = next_key;
    if (val.cswchdelta + val.nvcswchdelta == 0 &&
        val.utimedelta + val.stimedelta == 0) {
      continue;
    }
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (env.interval < 99999999) {
      usr = val.utimedelta * 100.0 / (env.interval * 1000000U);
      sys = val.stimedelta * 100.0 / (env.interval * 1000000U);
      printf("%-8s %-16s %-8d %-8d %-8d %-8d %-8.2f %-8.2f %-8.2f\n", ts,
             val.comm, next_key.tgid, next_key.pid, val.cswchdelta,
             val.nvcswchdelta, usr, sys, usr + sys);
    } else {
      printf("%-8s %-16s %-8d %-8d %-8d %-8d %-12lld\n", ts, val.comm,
             next_key.tgid, next_key.pid, val.cswchdelta, val.nvcswchdelta,
             val.utimedelta + val.stimedelta);
    }
  }

  // 3. 清理数据
  lookup_key = (struct key_t){};
  while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
    err = bpf_map_delete_elem(ifd, &next_key);
    if (err < 0) {
      fprintf(stderr, "failed to cleanup map : %d\n", err);
      return -1;
    }
    lookup_key = next_key;
  }
  return 0;
}
