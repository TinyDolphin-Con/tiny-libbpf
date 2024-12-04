/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "offcputime.h"
#include "offcputime.skel.h"
#include "trace_helpers.h"

// ========= 结构体声明 =========
static struct env {
  pid_t pids[MAX_PID_NR];    // 保存需要分析的进程 ID 列表
  pid_t tids[MAX_TID_NR];    // 保存需要分析的线程 ID 列表
  bool user_threads_only;    // 表示仅分析用户线程的 off-cpu 时间
  bool kernel_threads_only;  // 表示仅分析内核线程的 off-cpu 时间
  int stack_storage_size;  // 指定栈存储空间的大小,用于存储采集的栈帧
  int perf_max_stack_depth;  // 设置最大栈深度,即每个线程调用栈在被采集时的最大深度
  uint64_t min_block_time;  // 最小阻塞时间(单位:纳秒)
  uint64_t max_block_time;  // 最大阻塞时间
  long state;               // 状态过滤器
  int duration;             // 追踪的时间段长度
  bool verbose;             // 控制调试信息的详细程度
} env = {
    .stack_storage_size = 1024,
    .perf_max_stack_depth = 127,
    .min_block_time = 1,
    .max_block_time = -1,
    .state = -1,
    .duration = 99999999,
};

// ========= 宏定义声明 =========
// 用于指定最大栈深度
#define OPT_PERF_MAX_STACK_DEPTH 1 /* --pef-max-stack-depth */
// 用于设置栈存储的大小
#define OPT_STACK_STORAGE_SIZE 2 /* --stack-storage-size */
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
 * @brief 打印头部信息,列出所有指定的 PID 和 TID
 * 返回 true 或 false 表示是否有 PID 或 TID 被指定
 */
static bool print_header_threads();

/**
 * @brief 打印程序的初始说明,指定追踪 off-cpu 时间的线程范围及持续时间
 */
static void print_headers();

/**
 * @brief 读取堆栈信息,解析地址对应的符号(函数名称等),并格式化输出
 *
 * 具体作用:
 *  遍历每个存储在 map 中的堆栈信息(包括时间和线程/进程的调用信息),并打印出来
 *
 * @param ksyms
 *  指向内核符号表的结构体,提供从地址到符号(函数名称)的映射,用于解析内核地址
 * @param syms_cache
 *  符号缓存结构,提供从地址到符号(函数名称)的映射,用于解析内核地址
 * @param obj offcputime_bpf 结构体对象,包含了通过 BPF maps 获取的数据
 */
static void print_map(struct ksyms* ksyms, struct syms_cache* syms_cache,
                      struct offcputime_bpf* obj);

// ========= 全局常量|变量定义 =========
// 程序版本和文档说明
const char* argp_program_version = "offcputime 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_program_doc[] =
    "Summarize off-CPU time by stack trace.\n"
    "\n"
    "USAGE: offcputime [--help] [-p PID | -u | -k] [-m MIN-BLOCK-TIME] "
    "[-M MAX-BLOCK-TIME] [--state] [--perf-max-stack-depth] "
    "[--stack-storage-size] "
    "[duration]\n"
    "EXAMPLES:\n"
    "    offcputime             # trace off-CPU stack time until Ctrl-C\n"
    "    offcputime 5           # trace for 5 seconds only\n"
    "    offcputime -m 1000     # trace only events that last more than 1000 "
    "usec\n"
    "    offcputime -M 10000    # trace only events that last less than 10000 "
    "usec\n"
    "    offcputime -p 185,175,165 # only trace threads for PID 185,175,165\n"
    "    offcputime -t 188,120,134 # only trace threads 188,120,134\n"
    "    offcputime -u          # only trace user threads (no kernel)\n"
    "    offcputime -k          # only trace kernel threads (no user)\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Trace these PIDs only, comma-separated list", 0},
    {"tid", 't', "TID", 0, "Trace these TIDs only, comma-separated list", 0},
    {"user-threads-only", 'u', NULL, 0, "User threads only (no kernel threads)",
     0},
    {"kernel-threads-only", 'k', NULL, 0,
     "Kernel threads only (no user threads)", 0},
    {"perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "PERF-MAX-STACK-DEPTH",
     0, "the limit for both kernel and user stack traces (default 127)", 0},
    {"stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
     "the number of unique stack traces that can be stored and displayed "
     "(default 1024)",
     0},
    {"min-block-time", 'm', "MIN-BLOCK-TIME", 0,
     "the amount of time in microseconds over which we store traces (default "
     "1)",
     0},
    {"max-block-time", 'M', "MAX-BLOCK-TIME", 0,
     "the amount of time in microseconds under which we store traces (default "
     "U64_MAX)",
     0},
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

// ========= 函数实现 =========
/**
 * @brief 主函数
 *
 * 主要实现逻辑:
 *  1. 主函数入口:定义变量 && 解析命令行参数 && 注册信号处理函数 && 环境变量验证
 *  2. 创建子进程并同步(跟踪通过命令启动新进程并跟踪,跟踪现有进程无须这步)
 *  3. 跟踪过程所需的堆栈和内存分配并初始化
 *  4. 设置调试输出:处理调试信息 && 确保内核 BTF 数据可用
 *  5. 打开 BPF 程序并初始化全局数据
 *  6. 加载 BPF 程序,并完成附加程序操作
 *  7. 符合解析设置并解析对应的函数符号
 *  8. 主循环: 定期检查并输出当前的内存分配状态
 *  9. 清理并释放资源(包括终止子进程并清理)
 *
 */
int main(int argc, char** argv) {
  static const struct argp argp = {
      .options = opts,
      .parser = argp_parse_arg,
      .doc = argp_program_doc,
  };
  struct syms_cache* syms_cache = NULL;
  struct ksyms* ksyms = NULL;
  struct offcputime_bpf* obj = NULL;
  int pids_fd, tids_fd;
  int err = 0;
  __u8 val = 0;

  // 1. 命令行参数解析
  if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
    fprintf(stderr, "failed to parse args\n");

    goto cleanup;
  }

  // 2. 信号处理设置
  // 设置 SIGINT 信号的处理函数(SIGINT :通常用于捕获 Ctrl-C 中断信号)
  // 目的:优雅地停止程序,确保清理资源
  if (sigaction(SIGINT, &sig_action, NULL)) {
    perror("failed to set up signal handling");
    err = -errno;

    goto cleanup;
  }

  // 3. 环境变量检查
  // 两个互斥的参数选项是否同时被设置
  if (env.user_threads_only && env.kernel_threads_only) {
    fprintf(
        stderr,
        "user_threads_only and kernel_threads_only cannot be used together.\n");
    err = 1;
    goto cleanup;
  }
  // 防止用户输入不合法参数
  if (env.min_block_time >= env.max_block_time) {
    fprintf(stderr, "min_block_time should be smaller than max_block_time\n");
    err = 1;
    goto cleanup;
  }

  // 4. 设置调试输出
  // 设置一个调试输出函数(libbpf_print_fn),用来处理 libbpf 内部的调试信息
  // 如果用户没有开启 verbose 模式,则不会输出调试信息
  libbpf_set_print(libbpf_print_fn);

  // 5. 打开 BPF 对象
  obj = offcputime_bpf__open();
  if (!obj) {
    fprintf(stderr, "failed to open BPF object\n");
    err = 1;
    goto cleanup;
  }

  // 6. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  // 用于在 BPF 程序中进行条件过滤,这些设置取决于用户在命令行提供的选项
  obj->rodata->user_threads_only = env.user_threads_only;
  obj->rodata->kernel_threads_only = env.kernel_threads_only;
  obj->rodata->state = env.state;
  obj->rodata->min_block_ns = env.min_block_time;
  obj->rodata->max_block_ns = env.max_block_time;

  // 7. 跟踪的 PID/TID 设置
  // 将用户定义的过滤条件(仅追踪用户线程或仅追踪内核线程)
  // 写入 BPF 对象的只读数据段,传递到内核 BPF 程序
  if (env.pids[0]) {
    obj->rodata->filter_by_tgid = true;
  }
  if (env.tids[0]) {
    obj->rodata->filter_by_pid = true;
  }

  bpf_map__set_value_size(obj->maps.stackmap,
                          env.perf_max_stack_depth * sizeof(unsigned long));
  bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

  if (!probe_tp_btf("sched_switch")) {
    bpf_program__set_autoload(obj->progs.sched_switch, false);
  } else {
    bpf_program__set_autoload(obj->progs.sched_switch_raw, false);
  }

  // 8. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = offcputime_bpf__load(obj);
  if (err) {
    fprintf(stderr, "failed to load BPF programs\n");
    goto cleanup;
  }

  // 9. 过滤 PID 和 TID
  // 如果设定了 pids 和 tids,则将其写入 BPF 映射以用于过滤
  if (env.pids[0]) {
    /* User pids_fd points to the tgids map in the BPF program */
    pids_fd = bpf_map__fd(obj->maps.tgids);
    for (size_t i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
      if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
        fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
        goto cleanup;
      }
    }
  }
  if (env.tids[0]) {
    /* User tids_fd points to the pids map in the BPF program */
    tids_fd = bpf_map__fd(obj->maps.pids);
    for (size_t i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
      if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
        fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
        goto cleanup;
      }
    }
  }

  // 10. 加载内核符号
  // 用于内核地址到函数名的映射
  ksyms = ksyms__load();
  if (!ksyms) {
    fprintf(stderr, "failed to load kallsyms\n");
    goto cleanup;
  }
  syms_cache = syms_cache__new(0);
  if (!syms_cache) {
    fprintf(stderr, "failed to create syms_cache\n");
    goto cleanup;
  }

  // 11. 附加程序操作
  // 将 BPF 程序附加到相应的内核钩子上,开始监控相关事件
  err = offcputime_bpf__attach(obj);
  if (err) {
    fprintf(stderr, "failed to attach BPF programs\n");
    goto cleanup;
  }

  // 12. 输出捕获的栈信息和 off-cpu 时间
  print_headers();

  sleep(env.duration);

  print_map(ksyms, syms_cache, obj);

cleanup:
  offcputime_bpf__destroy(obj);
  syms_cache__free(syms_cache);
  ksyms__free(ksyms);
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
    case 'u':
      env.user_threads_only = true;
      break;
    case 'k':
      env.kernel_threads_only = true;
      break;
    case OPT_PERF_MAX_STACK_DEPTH:
      errno = 0;
      env.perf_max_stack_depth = atoi(arg);
      break;
    case OPT_STACK_STORAGE_SIZE:
      errno = 0;
      env.stack_storage_size = atoi(arg);
      break;
    case 'm':
      errno = 0;
      env.min_block_time = argp_parse_long(key, arg, state);
      break;
    case 'M':
      errno = 0;
      env.max_block_time = argp_parse_long(key, arg, state);
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
      if (pos_args++) {
        fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
        argp_usage(state);
      }
      errno = 0;
      env.duration = atoi(arg);
      if (env.duration <= 0) {
        fprintf(stderr, "Invalid duration (in s): %s\n", arg);
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

void print_headers() {
  printf("Tracing off-CPU time (us) of");

  // 打印线程信息
  if (!print_header_threads()) {
    printf(" all threads");
  }

  // 打印追踪持续时间
  if (env.duration < 99999999) {
    printf(" for %d secs.\n", env.duration);
  } else {
    printf("... Hit Ctrl-C to end.\n");
  }
}

void print_map(struct ksyms* ksyms, struct syms_cache* syms_cache,
               struct offcputime_bpf* obj) {
  struct key_t lookup_key = {}, next_key;
  const struct ksym* ksym;
  const struct syms* syms;
  const struct sym* sym;
  int err, ifd, sfd;
  unsigned long* ip;
  struct val_t val;
  struct sym_info sinfo;
  int idx;

  // 1. 内存分配
  // 分配一个堆栈存储空间 ip,用来存储地址
  ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
  if (!ip) {
    fprintf(stderr, "failed to alloc ip\n");
    return;
  }

  // 2. 获取 BPF maps 的文件描述符
  // 通过 bpf_map_fd 获取 info 和 stackmap maps 的文件描述符
  ifd = bpf_map__fd(obj->maps.info);
  sfd = bpf_map__fd(obj->maps.stackmap);

  // 3. 遍历堆栈数据
  // 通过 bpf_map_get_next_key 获取 map 中的每个 key(lookup_key 和 next_key)
  while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
    idx = 0;

    // 获取 key 对应的 val 数据,其中包含进程的 off-cpu 时间,进程名等
    err = bpf_map_lookup_elem(ifd, &next_key, &val);
    if (err < 0) {
      fprintf(stderr, "failed to lookup info: %d\n", err);
      goto cleanup;
    }
    lookup_key = next_key;
    if (val.delta == 0) {
      continue;
    }
    // 4. 获取内核态堆栈信息
    if (bpf_map_lookup_elem(sfd, &next_key.kern_stack_id, ip) != 0) {
      fprintf(stderr, "    [Missed Kernel Stack]\n");
      goto print_ustack;
    }

    // 4.1 遍历堆栈存储空间
    for (size_t i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
      // 4.2 调用 ksyms__map_addr 解析内核地址,并打印符合名称
      ksym = ksyms__map_addr(ksyms, ip[i]);
      if (!env.verbose) {
        printf("    %s\n", ksym ? ksym->name : "unknown");
      } else {
        if (ksym) {
          printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, ip[i], ksym->name,
                 ip[i] - ksym->addr);
        } else {
          printf("    #%-2d 0x%lx [unknown]\n", idx++, ip[i]);
        }
      }
    }

  print_ustack:
    if (next_key.user_stack_id == -1) {
      goto skip_ustack;
    }

    // 5. 获取用户态堆栈信息
    if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
      fprintf(stderr, "    [Missed User Stack]\n");
      goto skip_ustack;
    }

    // 5.1 使用 syms_cache__get_syms 获取符号缓存,并打印符合信息
    syms = syms_cache__get_syms(syms_cache, next_key.tgid);
    if (!syms) {
      if (!env.verbose) {
        fprintf(stderr, "failed to get syms\n");
      } else {
        for (size_t i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
          printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
        }
      }
      goto skip_ustack;
    }
    for (size_t i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
      if (!env.verbose) {
        sym = syms__map_addr(syms, ip[i]);
        if (sym) {
          printf("    %s\n", sym->name);
        } else {
          printf("    [unknown]\n");
        }
      } else {
        printf("    #%-2d 0x%016lx", idx++, ip[i]);
        err = syms__map_addr_dso(syms, ip[i], &sinfo);
        if (err == 0) {
          if (sinfo.sym_name) {
            printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
          }
          printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
        }
        printf("\n");
      }
    }

  skip_ustack:
    printf("    %-16s %s (%d)\n", "-", val.comm, next_key.pid);
    printf("        %lld\n\n", val.delta);
  }

cleanup:
  free(ip);
}
