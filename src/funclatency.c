/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "btf_helpers.h"
#include "funclatency.h"
#include "funclatency.skel.h"
#include "map_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

// 标志程序是否需要退出
// sig_atomic_t 表示该变量是一个可以安全地在信号处理程序中访问的类型,
// 它确保在信号处理期间对变量的访问不会被中断
// 这个变量通常在捕获到退出信号时被设置为 true,从而通知主循环退出
static volatile bool exiting;

static struct env {
  int units;  // 时间单位，用于度量延迟或其他时间相关的值
  pid_t pid;  // 进程 ID，用于筛选特定进程
  unsigned int duration;  // BPF 程序运行的总时长（秒）
  unsigned int interval;  // BPF 程序采样数据的间隔时间（通常以毫秒为单位）
  unsigned int iterations;  // BPF 程序的迭代次数，控制采样的次数
  bool timestamp;  // 是否显示时间戳，标识是否在输出中包含时间信息。
  char* funcname;  // 被追踪的函数名称，通常用于指定内核或用户态函数
  bool verbose;  // 是否开启详细模式，决定是否输出更多调试信息
  bool kprobes;  // 是否启用 kprobe，指定是否使用 kprobe/kretprobe 追踪内核函数
  char* cgroupspath;  // cgroup 路径，指定 BPF 程序作用于哪个 cgroup
  bool cg;  // 标识是否过滤特定 cgroup，控制是否仅在指定的 cgroup 中执行
  bool is_kernel_func;  // 标识要追踪的函数是否为内核函数
} env = {
    .interval = 99999999,
    .iterations = 99999999,
};

// 程序版本和文档说明
const char* argp_program_version = "funclatency 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
    "Time functions and print latency as a histogram\n"
    "\n"
    "Usage: funclatency [-h] [-m|-u] [-p PID] [-d DURATION] [ -i INTERVAL ] "
    "[-c CG]\n"
    "                   [-T] FUNCTION\n"
    "       Choices for FUNCTION: FUNCTION         (kprobe)\n"
    "                             LIBRARY:FUNCTION (uprobe a library in -p "
    "PID)\n"
    "                             :FUNCTION        (uprobe the binary of -p "
    "PID)\n"
    "                             PROGRAM:FUNCTION (uprobe the binary "
    "PROGRAM)\n"
    "\v"
    "Examples:\n"
    "  ./funclatency do_sys_open         # time the do_sys_open() kernel "
    "function\n"
    "  ./funclatency -m do_nanosleep     # time do_nanosleep(), in "
    "milliseconds\n"
    "  ./funclatency -c CG               # Trace process under cgroupsPath CG\n"
    "  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
    "  ./funclatency -p 181 vfs_read     # time process 181 only\n"
    "  ./funclatency -p 181 c:read       # time the read() C library function\n"
    "  ./funclatency -p 181 :foo         # time foo() from pid 181's "
    "userspace\n"
    "  ./funclatency -i 2 -d 10 vfs_read # output every 2 seconds, for 10s\n"
    "  ./funclatency -mTi 5 vfs_read     # output every 5 seconds, with "
    "timestamps\n";

static const struct argp_option opts[] = {
    {"milliseconds", 'm', NULL, 0, "Output in milliseconds", 0},
    {"microseconds", 'u', NULL, 0, "Output in microseconds", 0},
    {0, 0, 0, 0, "", 0},
    {"pid", 'p', "PID", 0, "Process ID to trace", 0},
    {0, 0, 0, 0, "", 0},
    {"interval", 'i', "INTERVAL", 0, "Summary interval in seconds", 0},
    {"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path",
     0},
    {"duration", 'd', "DURATION", 0, "Duration to trace", 0},
    {"timestamp", 'T', NULL, 0, "Print timestamp", 0},
    {"verbose", 'v', NULL, 0, "Verbose debug output", 0},
    {"kprobes", 'k', NULL, 0, "Use kprobes instead of fentry", 0},
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
  long duration, interval, pid;

  switch (key) {
    case 'p':
      errno = 0;
      pid = strtol(arg, NULL, 10);
      if (errno || pid <= 0) {
        warn("Invalid PID: %s\n", arg);
        argp_usage(state);
      }
      env.pid = pid;
      break;
    case 'm':
      if (env.units != NSEC) {
        warn("only set one of -m or -u\n");
        argp_usage(state);
      }
      env.units = MSEC;
      break;
    case 'c':
      env.cgroupspath = arg;
      env.cg = true;
      break;
    case 'u':
      if (env.units != NSEC) {
        warn("only set one of -m or -u\n");
        argp_usage(state);
      }
      env.units = USEC;
      break;
    case 'd':
      errno = 0;
      duration = strtol(arg, NULL, 10);
      if (errno || duration <= 0) {
        warn("Invalid duration: %s\n", arg);
        argp_usage(state);
      }
      env.duration = duration;
      break;
    case 'i':
      errno = 0;
      interval = strtol(arg, NULL, 10);
      if (errno || interval <= 0) {
        warn("Invalid interval: %s\n", arg);
        argp_usage(state);
      }
      env.interval = interval;
      break;
    case 'T':
      env.timestamp = true;
      break;
    case 'k':
      env.kprobes = true;
      break;
    case 'v':
      env.verbose = true;
      break;
    case 'h':
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
      break;
    case ARGP_KEY_ARG:
      if (env.funcname) {
        warn("Too many function names: %s\n", arg);
        argp_usage(state);
      }
      env.funcname = arg;
      break;
    case ARGP_KEY_END:
      if (!env.funcname) {
        warn("Need a function to trace\n");
        argp_usage(state);
      }
      if (env.duration) {
        if (env.interval > env.duration) {
          env.interval = env.duration;
        }
        env.iterations = env.duration / env.interval;
      }
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
 * @brief 将枚举类型的时间单位转换成字符串
 */
static const char* unit_str(void) {
  switch (env.units) {
    case NSEC:
      return "nsec";
    case USEC:
      return "usec";
    case MSEC:
      return "msec";
  };

  return "bad units";
}

/**
 * @brief 选择最佳跟踪机制来监控内核函数(优先考虑:fentry/fexit)
 *
 * 尝试通过 fentry 和 fexit 钩子（hooks）附加到指定的内核函数.
 * 如果失败,则回退到使用 kprobe 和 kretprobe
 *
 * N.B. fentry/fexit 是 BPF 的一种新机制,相比传统的 kprobe/kretprobe 更高效
 *
 * 主要实现逻辑:
 *  1. 判断:是否启用 kprobes | 非内核函数 | 无法附加 fentry 钩子
 *  2. 尝试将 dummy_fentry/dummy_fexit 附加到目标函数
 *  3. 上述 1,2 都符合,则使用 fentry/fexit 并禁用 kprobe/kretprobe
 *  4. 否则,使用 kprobe/kretprobe,禁用 fentry/fexit
 *
 * @param obj 目标函数对象
 */
static bool try_fentry(struct funclatency_bpf* obj) {
  long err;

  // 1. 如果kprobes被启用或非内核函数或无法附加fentry钩子,则跳转到out_no_fentry
  if (env.kprobes || !env.is_kernel_func ||
      !fentry_can_attach(env.funcname, NULL)) {
    goto out_no_fentry;
  }

  // 2. 尝试为 dummy_fentry 程序设置一个目标函数(funcname)
  err =
      bpf_program__set_attach_target(obj->progs.dummy_fentry, 0, env.funcname);
  if (err) {
    warn("failed to set attach fentry: %s\n", strerror(-err));
    goto out_no_fentry;
  }

  // 2. 尝试为 dummy_fexit 程序设置一个目标函数(funcname)
  err = bpf_program__set_attach_target(obj->progs.dummy_fexit, 0, env.funcname);
  if (err) {
    warn("failed to set attach fexit: %s\n", strerror(-err));
    goto out_no_fentry;
  }

  // 4. 禁用自动加载 kprobe 和 kretprobe, 因为 fentry/fexit 已经成功设置
  bpf_program__set_autoload(obj->progs.dummy_kprobe, false);
  bpf_program__set_autoload(obj->progs.dummy_kretprobe, false);

  return true;

out_no_fentry:
  // 5. 如果 fentry/fexit 不能用,禁用 fentry/fexit 并返回 false
  bpf_program__set_autoload(obj->progs.dummy_fentry, false);
  bpf_program__set_autoload(obj->progs.dummy_fexit, false);

  return false;
}

/**
 * @brief 针对内核函数进行附加操作
 *
 *  将 BPF 附加到内核函数的入口以及返回点
 *
 * @param obj 目标函数对象
 */
static int attach_kprobes(struct funclatency_bpf* obj) {
  // 将 BPF 程序附加到内核函数的入口
  // dummy_kprobe 目标函数的入口点
  obj->links.dummy_kprobe =
      bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false, env.funcname);
  if (!obj->links.dummy_kprobe) {
    warn("failed to attach kprobe: %d\n", -errno);
    return -1;
  }

  // 将 BPF 程序附加到内核函数的返回点
  // dummy_kretprobe 目标函数的返回点
  obj->links.dummy_kretprobe = bpf_program__attach_kprobe(
      obj->progs.dummy_kretprobe, true, env.funcname);
  if (!obj->links.dummy_kretprobe) {
    warn("failed to attach kretprobe: %d\n", -errno);
    return -1;
  }

  return 0;
}

/**
 * @brief 针对用户函数进行附加操作
 *
 *  将 BPF 附加到用户态进程的函数上
 *
 * 主要实现逻辑:
 *  1. 获取可执行文件名 & 目标函数名称
 *  2. 查找 ELF 文件中的函数偏移
 *  3. 附加 uprobe 和 uretprobe
 *  4. 清理和返回
 *
 * @param obj 目标函数对象
 */
static int attach_uprobes(struct funclatency_bpf* obj) {
  char *binary, *function;
  char bin_path[PATH_MAX];
  off_t func_off;
  int ret = -1;
  long err;

  // 1. 获取可执行文件名(strdup: 复制字符串)
  binary = strdup(env.funcname);
  if (!binary) {
    warn("strdup failed");
    return -1;
  }
  // 2. 获取目标函数(strchr: 在字符串中查找某个字符)
  function = strchr(binary, ':');
  if (!function) {
    warn("Binary should have contained ':' (internal bug!)\n");
    return -1;
  }
  *function = '\0';
  function++;
  // 3. 解析可执行文件路径
  if (resolve_binary_path(binary, env.pid, bin_path, sizeof(bin_path))) {
    goto out_binary;
  }

  // 4. 查找 ELF 文件中的函数偏移
  func_off = get_elf_func_offset(bin_path, function);
  if (func_off < 0) {
    warn("Could not find %s in %s\n", function, bin_path);
    goto out_binary;
  }

  // 5. 附加 uprobe 和 uretprobes
  obj->links.dummy_kprobe = bpf_program__attach_uprobe(
      obj->progs.dummy_kprobe, false, env.pid ?: -1, bin_path, func_off);
  if (!obj->links.dummy_kprobe) {
    err = -errno;
    warn("Failed to attach uprobe: %ld\n", err);
    goto out_binary;
  }

  obj->links.dummy_kretprobe = bpf_program__attach_uprobe(
      obj->progs.dummy_kretprobe, true, env.pid ?: -1, bin_path, func_off);
  if (!obj->links.dummy_kretprobe) {
    err = -errno;
    warn("Failed to attach uretprobe: %ld\n", err);
    goto out_binary;
  }

  ret = 0;

  // 6. 清理和返回
out_binary:
  free(binary);

  return ret;
}

/**
 * @brief 信号处理函数
 *
 * 收到中断信号(SIGINT, 通常是 Ctrl-C) 时,将 exiting 标志设置为 true,
 * 以便能够检测到并优雅地退出
 */
static void sig_hand(int signr) { exiting = true; }

static struct sigaction sigact = {.sa_handler = sig_hand};

/**
 * @brief 主函数
 *
 * 主要实现逻辑:
 *  1. 主函数入口:定义变量 && 解析命令行参数
 *  2. 设置调试输出:处理调试信息 && 确保内核 BTF 数据可用
 *  3. 打开 BPF 对象并初始化全局数据
 *  5. 选择最佳跟踪机制来进行跟踪(优先 fentry/fexit)
 *  4. 加载 BPF 程序,并完成附加程序操作
 *  5. 注册信号处理的处理函数(建议使用 sigaction)
 *  6. 主循环:根据时间间隔收集数据并打印
 *  7. 清理资源
 */
int main(int argc, char** argv) {
  // LIBBPF_OPTS 用来创建一个结构体 open_opts,
  // 这个结构体会配置 BPF 对象加载时的选项
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .args_doc = args_doc,
      .doc = program_doc,
  };
  struct funclatency_bpf* obj;
  int i, err;
  struct tm* tm;
  char ts[32];
  time_t t;
  int idx, cg_map_fd;
  int cgfd = -1;
  bool used_fentry = false;

  // 1. 解析命令行参数
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err) {
    return err;
  }

  env.is_kernel_func = !strchr(env.funcname, ':');

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
  obj = funclatency_bpf__open_opts(&open_opts);
  if (!obj) {
    warn("failed to open BPF object\n");
    return 1;
  }

  // 5. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  obj->rodata->units = env.units;
  obj->rodata->targ_tgid = env.pid;
  obj->rodata->filter_cg = env.cg;

  // 6. 选择最佳跟踪机制来跟踪(优先:fentry/fexit)
  used_fentry = try_fentry(obj);  // 调用 bpf_program__set_attach_target

  // 7. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  err = funclatency_bpf__load(obj);
  if (err) {
    warn("failed to load BPF object\n");
    goto cleanup;
  }

  /* update cgroup path fd to map */
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

  if (!obj->bss) {
    warn(
        "Memory-mapping BPF maps is supported starting from Linux 5.7, please "
        "upgrade.\n");
    goto cleanup;
  }

  // 使用 kprobe/uprobe: 需要手动附加探针
  // N.B. tracepoint & fentry/fexit 都不需要手动附加探针
  if (!used_fentry) {
    if (env.is_kernel_func) {
      err = attach_kprobes(obj);  // 调用 bpf_program__attach_kprobe
    } else {
      err = attach_uprobes(obj);  // 调用 bpf_program__attach_uprobe
    }
    if (err) {
      goto cleanup;
    }
  }

  // 9. 附加程序操作
  // 将 BPF 程序附加到相应的内核钩子上,开始监控相关事件
  err = funclatency_bpf__attach(obj);
  if (err) {
    fprintf(stderr, "failed to attach BPF programs: %s\n", strerror(-err));
    goto cleanup;
  }

  // 10. 注册信号处理（如按下 Ctrl-C 时）的处理函数，将调用 sig_hand
  sigaction(SIGINT, &sigact, 0);

  printf("Tracing %s.  Hit Ctrl-C to exit\n", env.funcname);

  // 11. 主循环:根据时间间隔收集数据并打印
  for (i = 0; i < env.iterations && !exiting; i++) {
    sleep(env.interval);

    printf("\n");
    if (env.timestamp) {
      time(&t);
      tm = localtime(&t);
      strftime(ts, sizeof(ts), "%H:%M:%S", tm);
      printf("%-8s\n", ts);
    }

    // 打印延迟数据的直方图,并在每次循环结束时将 hist 数据清零
    print_log2_hist(obj->bss->hist, MAX_SLOTS, unit_str());
    /* Cleanup histograms for interval output */
    memset(obj->bss->hist, 0, sizeof(obj->bss->hist));
  }

  printf("Exiting trace of %s\n", env.funcname);

  // 12. 清理资源:销毁 BPF 对象 & 清理 BTF 资源 & 关闭文件描述符
cleanup:
  funclatency_bpf__destroy(obj);
  cleanup_core_btf(&open_opts);
  if (cgfd > 0) {
    close(cgfd);
  }

  return err != 0;
}
