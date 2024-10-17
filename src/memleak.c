/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// 提供 eBPF 程序的辅助函数
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 依赖头文件
#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

// ========= 结构体声明 =========
static struct env {
  time_t interval;      // 采样的时间间隔
  time_t nr_intervals;  // 运行的总间隔数, -1 表示无限次采样
  pid_t pid;            // 目标进程的 PID, -1 表示跟踪所有进程
  bool trace_all;       // 是否跟踪所有的分配事件
  bool show_allocs;     // 显示所有的内存分配统计信息
  bool combined_only;   // 只显示合并后的内存分配统计信息
  int min_age_ns;  // 指定时间窗口,表示内存块的最小存活时间(单位:纳秒),用于过滤
  uint64_t sample_rate;  // 采样率,控制对内存分配事件的抽样处理
  int top_stacks;        // 显示内存分配最多的堆栈,默认前 10
  size_t min_size;  // 跟踪最小的分配大小,允许过滤特定大小范围的分配
  size_t max_size;  // 跟踪最大的分配大小,允许过滤特定大小范围的分配
  char object[32];  // 指定要跟踪的目标程序或对象文件

  bool wa_missing_free;  // 用于检测未释放的内存块,帮助查找内存泄露
  bool percpu;           // 用于跟踪每个 CPU 上的分配
  int perf_max_stack_depth;  // 最大的堆栈深度,影响堆栈跟踪的精度
  int stack_map_max_entries;  // 堆栈映射的最大条目数,用于跟踪分配事件的堆栈
  long page_size;           // 页的大小,常用于计算内存占用
  bool kernel_trace;        // 跟踪内核模式的内存分配
  bool verbose;             // 控制调试信息的详细程度
  char command[32];         // 跟踪某个特定的命令或者程序
  char symbols_prefix[16];  // 可选的符号前缀,用于 uprobe 符号名称
} env = {
    .interval = 5,             // posarg 1
    .nr_intervals = -1,        // posarg 2
    .pid = -1,                 // -p --pid
    .trace_all = false,        // -t --trace
    .show_allocs = false,      // -a --show-allocs
    .combined_only = false,    // --combined-only
    .min_age_ns = 500,         // -o --older (arg * 1e6)
    .wa_missing_free = false,  // --wa-missing-free
    .sample_rate = 1,          // -s --sample-rate
    .top_stacks = 10,          // -T --top
    .min_size = 0,             // -z --min-size
    .max_size = -1,            // -Z --max-size
    .object = {0},             // -O --obj
    .percpu = false,           // --percpu
    .perf_max_stack_depth = 127,
    .stack_map_max_entries = 10240,
    .page_size = 1,
    .kernel_trace = true,
    .verbose = false,
    .command = {0},  // -c --command
    .symbols_prefix = {0},
};

// 用于存储单个分配的详细信息
struct allocation_node {
  uint64_t address;              // 内存块的地址
  size_t size;                   // 内存块的大小
  struct allocation_node* next;  // 指向下一个分配节点的指针
};

// 用于合并和统计多个分配的相关信息
struct allocation {
  uint64_t stack_id;  // 分配时的调用栈ID,可通过 BPF 获取
  size_t size;        // 合并后的总分配大小
  size_t count;       // 合并的分配次数
  struct allocation_node* allocations;  // 链表头指针, 用于跟踪具体分配
};

// ========= 宏定义声明 =========
/**
 * @brief 简化 uprobe 加载的宏
 *
 * 能够根据是否返回探针,自动加载用户态探针
 *
 * @param skel BPF 骨架对象,包含程序和探针
 * @param sym_name 要跟踪的符号名(函数名)
 * @param prog_name 对应的 BPF 程序名称
 * @param is_retprobe 指定是否为返回探针
 *
 * @func LIBBPF_OPTS 简化的方式来设置 bpf_uprobe_opts 选项
 * @func bpf_program__attach_uprobe_opts
 *  该函数通过给定的符号(函数)和对象文件(env.object)将 BPF 程序附加到目标进程
 */
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)       \
  do {                                                                \
    char sym[32];                                                     \
    sprintf(sym, "%s%s", env.symbols_prefix, #sym_name);              \
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = sym,       \
                .retprobe = is_retprobe);                             \
    skel->links.prog_name = bpf_program__attach_uprobe_opts(          \
        skel->progs.prog_name, env.pid, env.object, 0, &uprobe_opts); \
  } while (false)

/**
 * @brief 检查 BPF 程序是否成功附加
 *
 * 如果附加失败,则返回错误代码,并输出错误信息
 *
 * @param skel BPF 骨架对象,包含程序和探针
 * @param prog_name 对应的 BPF 程序名称
 */
#define __CHECK_PROGRAM(skel, prog_name)             \
  do {                                               \
    if (!skel->links.prog_name) {                    \
      perror("no program attached for " #prog_name); \
      return -errno;                                 \
    }                                                \
  } while (false)

/**
 * @brief 先附加,再检查
 *
 * @param skel BPF 骨架对象,包含程序和探针
 * @param sym_name 要跟踪的符号名(函数名)
 * @param prog_name 对应的 BPF 程序名称
 * @param is_retprobe 指定是否为返回探针
 */
#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
  do {                                                                  \
    __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);            \
    __CHECK_PROGRAM(skel, prog_name);                                   \
  } while (false)

// 以下两个宏分别:简化了普通探针和返回探针的附加操作
#define ATTACH_UPROBE(skel, sym_name, prog_name) \
  __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) \
  __ATTACH_UPROBE(skel, sym_name, prog_name, true)

// 与前两个宏类似:先附加,再检查
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) \
  __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) \
  __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

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
 * @brief 初始化 event fd 用于事件通知
 *
 * @param fd 指向创建的 event fd 的指针
 */
static int event_init(int* fd);

/**
 * @brief 等待 event fd 上发生的事件
 *
 * @param fd 事件文件描述符
 * @param expected_event 预期的事件值(用于验证)
 */
static int event_wait(int fd, uint64_t expected_event);

/**
 * @brief 向 event fd 发送一个事件通知
 *
 * @param fd 事件文件描述符
 * @param event 发送的事件值
 */
static int event_notify(int fd, uint64_t event);

/**
 * @brief 创建子进程并同步执行一个命令
 *
 * @param command 要执行的命令字符串
 * @param fd 用于同步的 event fd 文件描述符
 */
static pid_t fork_sync_exec(const char* command, int fd);

#ifdef USE_BLAZESYM
/**
 * @brief 打印通过 blazesym 解析得到的单个堆栈帧信息
 *
 * @param frame 当前堆栈帧的编号(索引)
 * @param addr 堆栈帧的内存地址
 * @param sym 解析得到的符号信息结构体,包含函数名称|文件路径|行号等
 */
static void print_stack_frame_by_blazesym(size_t frame, uint64_t addr,
                                          const blazesym_csym* sym);

/**
 * @brief 遍历并打印整个堆栈的所有帧,使用 blazesym 来解析堆栈帧的符号信息
 */
static void print_stack_frames_by_blazesym();
#else

/**
 * @brief 当 blazesym 不可用时,使用 ksyms
 * 来解析并打印内核符号表中地址映射到的符号信息
 */
static void print_stack_frames_by_ksyms();

/**
 * @brief 从符号缓存中获取符号信息,并根据缓存的符号解析每个堆栈帧的地址
 * 对于每个地址,打印出相应的符号信息及偏移量
 */
static void print_stack_frames_by_syms_cache();
#endif
/**
 * @brief 打印一组内存分配的堆栈信息
 *
 * 函数接收内存分配信息数组,循环处理每个分配,解释并打印每个分配的堆栈信息
 *
 * @param allocs 内存分配信息数组
 * @param nr_allocs 数组中内存分配的数量
 * @param stack_traces_fd BPF 堆栈跟踪映射文件描述符
 */
static int print_stack_frames(struct allocation* allocs, size_t nr_allocs,
                              int stack_traces_fd);

/**
 * @brief 用于按内存分配大小进行排序的比较函数
 *
 * @param a 指向第一个 allocation 结构体的指针
 * @param b 指向第二个 allocation 结构体的指针
 */
static int alloc_size_compare(const void* a, const void* b);

/**
 * @brief 打印按大小排序后的堆栈信息
 *
 * 遍历 BPF 内存分配映射表,收集符合条件的内存分配,按大小排序后,打印堆栈信息
 *
 * @param allocs_fd BPF 内存分配映射文件描述符
 * @param stack_traces_fd BPF 堆栈追踪映射文件描述符
 */
static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd);

/**
 * @brief 类似 print_outstanding_allocs, 用于打印合并后的分配信息,并按堆栈ID分组
 *
 * 从 BPF 映射表读取分配数据,并按堆栈 ID 进行合并,最后打印出合并后的堆栈分配信息
 *
 * @param combined_allocs_fd BPF 合并内存分配映射文件描述符
 * @param stack_traces_fd BPF 堆栈追踪映射文件描述符
 */
static int print_outstanding_combined_allocs(int combined_allocs_fd,
                                             int stack_traces_fd);

/**
 * @brief 判断内核中是否启用了 kmalloc_node 和 kmem_cache_alloc_node 的跟踪点
 */
static bool has_kernel_node_tracepoints();

/**
 * @brief 禁用内核中的跟踪点自动加载,防止不必要的跟踪
 *  kmalloc_node | kmem_cache_alloc_node
 *
 * @param skel BPF 程序结构体, 用于设置相关 BPF 程序是否自动加载
 */
static void disable_kernel_node_tracepoints(struct memleak_bpf* skel);

/**
 * @brief 禁用内核中的跟踪点自动加载,防止不必要的跟踪
 *  percpu_alloc_percpu | percpu_free_percpu
 *
 * @param skel BPF 程序结构体, 用于设置相关 BPF 程序是否自动加载
 */
static void disable_kernel_percpu_tracepoints(struct memleak_bpf* skel);

/**
 * @brief 禁用内核中的跟踪点自动加载,防止不必要的跟踪
 *  kmalloc | kmalloc_node | kfree
 *  kmem_cache_alloc | kmem_cache_alloc_node | kmem_cache_free
 *  mm_page_alloc | mm_page_free
 *  percpu_alloc_percpu | percpu_free_percpu
 *
 * @param skel BPF 程序结构体, 用于设置相关 BPF 程序是否自动加载
 */
static void disable_kernel_tracepoints(struct memleak_bpf* skel);

/**
 * @brief 针对用户函数进行附加操作
 *
 *  将 BPF 附加到用户态进程的函数上
 *
 * @param skel BPF 程序结构体, 用于设置相关 BPF 程序是否自动加载
 */
static int attach_uprobes(struct memleak_bpf* skel);

// ========= 全局常量|变量定义 =========
// 程序版本和文档说明
const char* argp_program_version = "memleak 0.1";
const char* argp_program_bug_address =
    "https://github.com/TinyDolphin-Con/tiny-libbpf";
const char argp_args_doc[] =
    "Trace outstanding memory allocations\n"
    "\n"
    "USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] "
    "[-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O "
    "OBJECT] [-P] [INTERVAL] [INTERVALS]\n"
    "\n"
    "EXAMPLES:\n"
    "./memleak -p $(pidof allocs)\n"
    "        Trace allocations and display a summary of 'leaked' "
    "(outstanding)\n"
    "        allocations every 5 seconds\n"
    "./memleak -p $(pidof allocs) -t\n"
    "        Trace allocations and display each individual allocator function "
    "call\n"
    "./memleak -ap $(pidof allocs) 10\n"
    "        Trace allocations and display allocated addresses, sizes, and "
    "stacks\n"
    "        every 10 seconds for outstanding allocations\n"
    "./memleak -c './allocs'\n"
    "        Run the specified command and trace its allocations\n"
    "./memleak\n"
    "        Trace allocations in kernel mode and display a summary of "
    "outstanding\n"
    "        allocations every 5 seconds\n"
    "./memleak -o 60000\n"
    "        Trace allocations in kernel mode and display a summary of "
    "outstanding\n"
    "        allocations that are at least one minute (60 seconds) old\n"
    "./memleak -s 5\n"
    "        Trace roughly every 5th allocation, to reduce overhead\n"
    "./memleak -p $(pidof allocs) -S je_\n"
    "        Trace task who sue jemalloc\n"
    "";
static const struct argp_option argp_options[] = {
    // name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
    {"pid", 'p', "PID", 0,
     "process ID to trace. if not specified, trace kernel allocs", 0},
    {"trace", 't', 0, 0, "print trace messages for each alloc/free call", 0},
    {"show-allocs", 'a', 0, 0,
     "show allocation addresses and sizes as well as call stacks", 0},
    {"older", 'o', "AGE_MS", 0,
     "prune allocations younger than this age in milliseconds", 0},
    {"command", 'c', "COMMAND", 0, "execute and trace the specified command",
     0},
    {"combined-only", 'C', 0, 0, "show combined allocation statistics only", 0},
    {"wa-missing-free", 'F', 0, 0,
     "workaround to alleviate misjudgments when free is missing", 0},
    {"sample-rate", 's', "SAMPLE_RATE", 0,
     "sample every N-th allocation to decrease the overhead", 0},
    {"top", 'T', "TOP_STACKS", 0,
     "display only this many top allocating stacks (by size)", 0},
    {"min-size", 'z', "MIN_SIZE", 0,
     "capture only allocations larger than this size", 0},
    {"max-size", 'Z', "MAX_SIZE", 0,
     "capture only allocations smaller than this size", 0},
    {"obj", 'O', "OBJECT", 0,
     "attach to allocator functions in the specified object", 0},
    {"percpu", 'P', NULL, 0, "trace percpu allocations", 0},
    {"symbols-prefix", 'S', "SYMBOLS_PREFIX", 0,
     "memory allocator symbols prefix", 0},
    {"verbose", 'v', NULL, 0, "verbose debug output", 0},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
    {},
};

// 定义两个标志位,用于检测程序退出信号(SIGINT)和子进程退出信号(SIGCHLD)
static volatile sig_atomic_t exiting;
static volatile sig_atomic_t child_exited;

// 定义信号处理结构体 sigaction,并将 sig_handler 设置为处理信号的回调函数
static struct sigaction sig_action = {.sa_handler = sig_handler};

// 用于存储事件文件描述符,用于父子进程之间的同步机制
static int child_exec_event_fd = -1;

// 根据编译时的宏定义决定是否使用 BlazeSym 进行符号解析
#ifdef USE_BLAZESYM
static blazesym* symbolizer;
static sym_src_cfg src_cfg;
#else
struct syms_cache* syms_cache;
struct ksyms* ksyms;
#endif

static void (*print_stack_frames_func)();

// 存储堆栈跟踪信息
static uint64_t* stack;
// 存储内存分配信息
static struct allocation* allocs;
// 默认跟踪对象:libc.so.6 即标准 C 库
static const char default_object[] = "libc.so.6";

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
int main(int argc, char* argv[]) {
  int ret = 0;
  struct memleak_bpf* skel = NULL;

  static const struct argp argp = {
      .options = argp_options,
      .parser = argp_parse_arg,
      .doc = argp_args_doc,
  };

  // 1. 命令行参数解析
  if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
    fprintf(stderr, "failed to parse args\n");

    goto cleanup;
  }

  // 2. 信号处理设置
  // 设置 SIGINT 信号的处理函数(SIGINT :通常用于捕获 Ctrl-C 中断信号)
  // 目的:优雅地停止程序,确保清理资源
  if (sigaction(SIGINT, &sig_action, NULL) ||
      sigaction(SIGCHLD, &sig_action, NULL)) {
    perror("failed to set up signal handling");
    ret = -errno;

    goto cleanup;
  }

  // 3. 环境变量验证和设置
  // 检查最小内存块尺寸是否大于最大内存块尺寸
  if (env.min_size > env.max_size) {
    fprintf(stderr, "min size (-z) can't be greater than max_size (-Z)\n");
    ret = 1;

    goto cleanup;
  }

  // 如果用户没有指定跟踪对象,默认设置为 libc.so.6
  if (!strlen(env.object)) {
    printf("using default object: %s\n", default_object);
    strncpy(env.object, default_object, sizeof(env.object) - 1);
  }

  // 获取系统页面大小
  env.page_size = sysconf(_SC_PAGE_SIZE);
  printf("using page size: %ld\n", env.page_size);

  // 判断是否跟踪内核
  env.kernel_trace = env.pid < 0 && !strlen(env.command);
  printf("tracing kernel: %s\n", env.kernel_trace ? "true" : "false");

  // 4. 创建子进程并同步
  // 如果指定了用户空间的命令,程序会创建一个子进程
  if (strlen(env.command)) {
    if (env.pid >= 0) {
      fprintf(stderr, "cannot specify both command and pid\n");
      ret = 1;

      goto cleanup;
    }

    // 初始化 event fd 用于事件通知
    if (event_init(&child_exec_event_fd)) {
      fprintf(stderr, "failed to init child event\n");

      goto cleanup;
    }

    // 创建子进程,并通过 event fd
    // 机制来同步父子进程,确保子进程在父进程准备好后再执行
    const pid_t child_pid = fork_sync_exec(env.command, child_exec_event_fd);
    if (child_pid < 0) {
      perror("failed to spawn child process");
      ret = -errno;

      goto cleanup;
    }

    env.pid = child_pid;
  }

  // 5. 跟踪过程所需的堆栈和内存分配并初始化
  // stack 保存栈帧信息
  stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
  if (!stack) {
    fprintf(stderr, "failed to allocate stack array\n");
    ret = -ENOMEM;

    goto cleanup;
  }

#ifdef USE_BLAZESYM
  if (env.pid < 0) {
    src_cfg.src_type = SRC_T_KERNEL;
    src_cfg.params.kernel.kallsyms = NULL;
    src_cfg.params.kernel.kernel_image = NULL;
  } else {
    src_cfg.src_type = SRC_T_PROCESS;
    src_cfg.params.process.pid = env.pid;
  }
#endif

  // allocs 用于存储内存分配信息
  if (env.combined_only) {
    allocs = calloc(COMBINED_ALLOCS_MAX_ENTRIES, sizeof(*allocs));
  } else {
    allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
  }

  if (!allocs) {
    fprintf(stderr, "failed to allocate array\n");
    ret = -ENOMEM;

    goto cleanup;
  }

  // 6. 设置调试输出
  // 设置一个调试输出函数(libbpf_print_fn),用来处理 libbpf 内部的调试信息
  // 如果用户没有开启 verbose 模式,则不会输出调试信息
  libbpf_set_print(libbpf_print_fn);

  // 7. 打开 BPF 对象
  skel = memleak_bpf__open();
  if (!skel) {
    fprintf(stderr, "failed to open bpf object\n");
    ret = 1;

    goto cleanup;
  }

  // 8. 初始化全局数据:这里对 BPF 程序的只读数据段进行初始化
  skel->rodata->min_size = env.min_size;
  skel->rodata->max_size = env.max_size;
  skel->rodata->page_size = env.page_size;
  skel->rodata->sample_rate = env.sample_rate;
  skel->rodata->trace_all = env.trace_all;
  skel->rodata->stack_flags = env.kernel_trace ? 0 : BPF_F_USER_STACK;
  skel->rodata->wa_missing_free = env.wa_missing_free;

  bpf_map__set_value_size(skel->maps.stack_traces,
                          env.perf_max_stack_depth * sizeof(unsigned long));
  bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);

  // disable kernel tracepoints based on settings or availability
  if (env.kernel_trace) {
    if (!has_kernel_node_tracepoints()) {
      disable_kernel_node_tracepoints(skel);
    }

    if (!env.percpu) {
      disable_kernel_percpu_tracepoints(skel);
    }
  } else {
    disable_kernel_tracepoints(skel);
  }

  // 9. 加载 BPF 程序
  // 将 BPF 对象加载到内核中,如果失败,则跳到 cleanup 进行资源清理
  ret = memleak_bpf__load(skel);
  if (ret) {
    fprintf(stderr, "failed to load BPF object\n");

    goto cleanup;
  }

  const int allocs_fd = bpf_map__fd(skel->maps.allocs);
  const int combined_allocs_fd = bpf_map__fd(skel->maps.combined_allocs);
  const int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

  // if userspace oriented, attach upbrobes
  if (!env.kernel_trace) {
    ret = attach_uprobes(skel);
    if (ret) {
      fprintf(stderr, "failed to attach uprobes\n");

      goto cleanup;
    }
  }

  // 10. 附加程序操作
  // 将 BPF 程序附加到相应的内核钩子上,开始监控相关事件
  ret = memleak_bpf__attach(skel);
  if (ret) {
    fprintf(stderr, "failed to attach bpf program(s)\n");

    goto cleanup;
  }

  // if running a specific userspace program,
  // notify the child process that it can exec its program
  if (strlen(env.command)) {
    ret = event_notify(child_exec_event_fd, 1);
    if (ret) {
      fprintf(stderr, "failed to notify child to perform exec\n");

      goto cleanup;
    }
  }

  // 11. 符合解释设置
  //   根据不同的条件初始化符号解释工具,并设置相应的栈帧打印函数,
  // 用于将内存分配中的地址解析为对应的函数符号;
  //   符号解析是定位内存泄露的重要步骤,因为它可以帮助开发者
  // 确定内存泄露发生在代码的哪个函数或调用栈上
  //
  // ksyms 用于内核符号解析
  // syms_cache 用于用户空间符合缓存和解析
#ifdef USE_BLAZESYM
  symbolizer = blazesym_new();
  if (!symbolizer) {
    fprintf(stderr, "Failed to load blazesym\n");
    ret = -ENOMEM;

    goto cleanup;
  }
  print_stack_frames_func = print_stack_frames_by_blazesym;
#else
  if (env.kernel_trace) {
    ksyms = ksyms__load();
    if (!ksyms) {
      fprintf(stderr, "Failed to load ksyms\n");
      ret = -ENOMEM;

      goto cleanup;
    }
    print_stack_frames_func = print_stack_frames_by_ksyms;
  } else {
    syms_cache = syms_cache__new(0);
    if (!syms_cache) {
      fprintf(stderr, "Failed to create syms_cache\n");
      ret = -ENOMEM;

      goto cleanup;
    }
    print_stack_frames_func = print_stack_frames_by_syms_cache;
  }
#endif

  printf("Tracing outstanding memory allocs...  Hit Ctrl-C to end\n");

  // main loop
  // 12. 主循环
  //  定期检查和输出当前的内存分配状态.
  //  每次迭代等待 interval 秒,然后输出当前未释放的内存分配
  while (!exiting && env.nr_intervals) {
    env.nr_intervals--;

    sleep(env.interval);
    printf("\n");

    if (env.combined_only) {
      print_outstanding_combined_allocs(combined_allocs_fd, stack_traces_fd);
    } else {
      print_outstanding_allocs(allocs_fd, stack_traces_fd);
    }
  }

  // 13. 子进程终止处理与清理
  if (env.pid > 0 && strlen(env.command)) {
    if (!child_exited) {
      // 发送信号以终止子进程
      if (kill(env.pid, SIGTERM)) {
        perror("failed to signal child process");
        ret = -errno;

        goto cleanup;
      }
      printf("signaled child process\n");
    }

    // 使用 waitpid 回收子进程资源
    if (waitpid(env.pid, NULL, 0) < 0) {
      perror("failed to reap child process");
      ret = -errno;

      goto cleanup;
    }
    printf("reaped child process\n");
  }

  // 14. 清理与资源释放
cleanup:
#ifdef USE_BLAZESYM
  blazesym_free(symbolizer);
#else
  if (syms_cache) {
    syms_cache__free(syms_cache);
  }
  if (ksyms) {
    ksyms__free(ksyms);
  }
#endif
  memleak_bpf__destroy(skel);

  free(allocs);
  free(stack);

  printf("done\n");

  return ret;
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
    case 'p':
      env.pid = atoi(arg);
      break;
    case 't':
      env.trace_all = true;
      break;
    case 'a':
      env.show_allocs = true;
      break;
    case 'o':
      env.min_age_ns = 1e6 * atoi(arg);
      break;
    case 'c':
      strncpy(env.command, arg, sizeof(env.command) - 1);
      break;
    case 'C':
      env.combined_only = true;
      break;
    case 'F':
      env.wa_missing_free = true;
      break;
    case 's':
      env.sample_rate = argp_parse_long(key, arg, state);
      break;
    case 'S':
      strncpy(env.symbols_prefix, arg, sizeof(env.symbols_prefix) - 1);
      break;
    case 'T':
      env.top_stacks = atoi(arg);
      break;
    case 'z':
      env.min_size = argp_parse_long(key, arg, state);
      break;
    case 'Z':
      env.max_size = argp_parse_long(key, arg, state);
      break;
    case 'O':
      strncpy(env.object, arg, sizeof(env.object) - 1);
      break;
    case 'P':
      env.percpu = true;
      break;
    case 'v':
      env.verbose = true;
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

void sig_handler(int signo) {
  if (signo == SIGCHLD) {
    child_exited = 1;
  }

  exiting = 1;
}

int event_init(int* fd) {
  // 检查 fd 是否非空,防止空指针操作
  if (!fd) {
    fprintf(stderr, "pointer to fd is null\n");

    return 1;
  }

  // 创建一个带有 EFD_CLOEXEC 标志的 event fd
  // 允许用户空间进程通过文件描述符发现和接收事件通知
  const int tmp_fd = eventfd(0, EFD_CLOEXEC);
  if (tmp_fd < 0) {
    perror("failed to create event fd");

    return -errno;
  }

  *fd = tmp_fd;

  return 0;
}

int event_wait(int fd, uint64_t expected_event) {
  uint64_t event = 0;
  // 从 event fd 中读取事件值
  const ssize_t bytes = read(fd, &event, sizeof(event));
  // 检查读取的字节数是否正确
  if (bytes < 0) {
    perror("failed to read from fd");

    return -errno;
  } else if (bytes != sizeof(event)) {
    fprintf(stderr, "read unexpected size\n");

    return 1;
  }

  // 验证读取的事件值是否与预期值一致
  if (event != expected_event) {
    fprintf(stderr, "read event %lu, expected %lu\n", event, expected_event);

    return 1;
  }

  return 0;
}

int event_notify(int fd, uint64_t event) {
  // 向 event fd 写入事件值,并检查写入的字节数是否正确
  const ssize_t bytes = write(fd, &event, sizeof(event));
  if (bytes < 0) {
    perror("failed to write to fd");

    return -errno;
  } else if (bytes != sizeof(event)) {
    fprintf(stderr, "attempted to write %zu bytes, wrote %zd bytes\n",
            sizeof(event), bytes);

    return 1;
  }

  return 0;
}

pid_t fork_sync_exec(const char* command, int fd) {
  // 创建一个子进程
  const pid_t pid = fork();

  switch (pid) {
    case -1:
      perror("failed to create child process");
      break;
    case 0: {
      const uint64_t event = 1;
      // 子进程调用 event_wait 等待父进程通过 event fd 发送事件通知
      if (event_wait(fd, event)) {
        fprintf(stderr, "failed to wait on event");
        exit(EXIT_FAILURE);
      }

      // 一旦接收到通知
      printf("received go event. executing child command\n");

      // 子进程执行 command 命令
      const int err = execl(command, command, NULL);
      if (err) {
        perror("failed to execute child command");
        return -1;
      }

      break;
    }
    default:
      printf("child created with pid: %d\n", pid);

      break;
  }

  return pid;
}

#if USE_BLAZESYM
void print_stack_frame_by_blazesym(size_t frame, uint64_t addr,
                                   const blazesym_csym* sym) {
  if (!sym) {
    printf("\t%zu [<%016lx>] <%s>\n", frame, addr, "null sym");
  } else if (sym->path && strlen(sym->path)) {
    printf("\t%zu [<%016lx>] %s+0x%lx %s:%ld\n", frame, addr, sym->symbol,
           addr - sym->start_address, sym->path, sym->line_no);
  } else {
    printf("\t%zu [<%016lx>] %s+0x%lx\n", frame, addr, sym->symbol,
           addr - sym->start_address);
  }
}

void print_stack_frames_by_blazesym() {
  const blazesym_result* result = blazesym_symbolize(
      symbolizer, &src_cfg, 1, stack, env.perf_max_stack_depth);

  for (size_t j = 0; j < result->size; ++j) {
    const uint64_t addr = stack[j];

    if (addr == 0) {
      break;
    }

    // no symbol found
    if (!result || j >= result->size || result->entries[j].size == 0) {
      print_stack_frame_by_blazesym(j, addr, NULL);

      continue;
    }

    // single symbol found
    if (result->entries[j].size == 1) {
      const blazesym_csym* sym = &result->entries[j].syms[0];
      print_stack_frame_by_blazesym(j, addr, sym);

      continue;
    }

    // multi symbol found
    printf("\t%zu [<%016lx>] (%lu entries)\n", j, addr,
           result->entries[j].size);

    for (size_t k = 0; k < result->entries[j].size; ++k) {
      const blazesym_csym* sym = &result->entries[j].syms[k];
      if (sym->path && strlen(sym->path)) {
        printf("\t\t%s@0x%lx %s:%ld\n", sym->symbol, sym->start_address,
               sym->path, sym->line_no);
      } else {
        printf("\t\t%s@0x%lx\n", sym->symbol, sym->start_address);
      }
    }
  }

  blazesym_result_free(result);
}
#else
void print_stack_frames_by_ksyms() {
  for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
    const uint64_t addr = stack[i];

    if (addr == 0) {
      break;
    }

    const struct ksym* ksym = ksyms__map_addr(ksyms, addr);
    if (ksym) {
      printf("\t%zu [<%016lx>] %s+0x%lx\n", i, addr, ksym->name,
             addr - ksym->addr);
    } else {
      printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
    }
  }
}

void print_stack_frames_by_syms_cache() {
  const struct syms* syms = syms_cache__get_syms(syms_cache, env.pid);
  if (!syms) {
    fprintf(stderr, "Failed to get syms\n");
    return;
  }

  for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
    const uint64_t addr = stack[i];

    if (addr == 0) {
      break;
    }

    struct sym_info sinfo;
    int ret = syms__map_addr_dso(syms, addr, &sinfo);
    if (ret == 0) {
      printf("\t%zu [<%016lx>]", i, addr);
      if (sinfo.sym_name) {
        printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
      }
      printf(" [%s]\n", sinfo.dso_name);
    } else {
      printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
    }
  }
}
#endif

int print_stack_frames(struct allocation* allocs, size_t nr_allocs,
                       int stack_traces_fd) {
  for (size_t i = 0; i < nr_allocs; ++i) {
    const struct allocation* alloc = &allocs[i];

    printf("%zu bytes in %zu allocations from stack\n", alloc->size,
           alloc->count);

    if (env.show_allocs) {
      struct allocation_node* it = alloc->allocations;
      while (it != NULL) {
        printf("\taddr = %#lx size = %zu\n", it->address, it->size);
        it = it->next;
      }
    }

    if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
      if (errno == ENOENT) {
        continue;
      }

      perror("failed to lookup stack trace");

      return -errno;
    }

    (*print_stack_frames_func)();
  }

  return 0;
}

int alloc_size_compare(const void* a, const void* b) {
  const struct allocation* x = (struct allocation*)a;
  const struct allocation* y = (struct allocation*)b;

  // descending order

  if (x->size > y->size) {
    return -1;
  }

  if (x->size < y->size) {
    return 1;
  }

  return 0;
}

int print_outstanding_allocs(int allocs_fd, int stack_traces_fd) {
  time_t t = time(NULL);
  struct tm* tm = localtime(&t);

  size_t nr_allocs = 0;

  // for each struct alloc_info "alloc_info" in the bpf map "allocs"
  for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
    struct alloc_info alloc_info = {};
    memset(&alloc_info, 0, sizeof(alloc_info));

    if (bpf_map_get_next_key(allocs_fd, &prev_key, &curr_key)) {
      if (errno == ENOENT) {
        break;  // no more keys, done
      }

      perror("map get next key error");

      return -errno;
    }

    if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info)) {
      if (errno == ENOENT) {
        continue;
      }

      perror("map lookup error");

      return -errno;
    }

    // filter by age
    if (get_ktime_ns() - env.min_age_ns < alloc_info.timestamp_ns) {
      continue;
    }

    // filter invalid stacks
    if (alloc_info.stack_id < 0) {
      continue;
    }

    // when the stack_id exists in the allocs array,
    //   increment size with alloc_info.size
    bool stack_exists = false;

    for (size_t i = 0; !stack_exists && i < nr_allocs; ++i) {
      struct allocation* alloc = &allocs[i];

      if (alloc->stack_id == alloc_info.stack_id) {
        alloc->size += alloc_info.size;
        alloc->count++;

        if (env.show_allocs) {
          struct allocation_node* node = malloc(sizeof(struct allocation_node));
          if (!node) {
            perror("malloc failed");
            return -errno;
          }
          node->address = curr_key;
          node->size = alloc_info.size;
          node->next = alloc->allocations;
          alloc->allocations = node;
        }

        stack_exists = true;
        break;
      }
    }

    if (stack_exists) {
      continue;
    }

    // when the stack_id does not exist in the allocs array,
    //   create a new entry in the array
    struct allocation alloc = {.stack_id = alloc_info.stack_id,
                               .size = alloc_info.size,
                               .count = 1,
                               .allocations = NULL};

    if (env.show_allocs) {
      struct allocation_node* node = malloc(sizeof(struct allocation_node));
      if (!node) {
        perror("malloc failed");
        return -errno;
      }
      node->address = curr_key;
      node->size = alloc_info.size;
      node->next = NULL;
      alloc.allocations = node;
    }

    memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
    nr_allocs++;
  }

  // sort the allocs array in descending order
  qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

  // get min of allocs we stored vs the top N requested stacks
  size_t nr_allocs_to_show =
      nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

  printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
         tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs_to_show);

  print_stack_frames(allocs, nr_allocs_to_show, stack_traces_fd);

  // Reset allocs list so that we dont accidentaly reuse data the next time we
  // call this function
  for (size_t i = 0; i < nr_allocs; i++) {
    allocs[i].stack_id = 0;
    if (env.show_allocs) {
      struct allocation_node* it = allocs[i].allocations;
      while (it != NULL) {
        struct allocation_node* this = it;
        it = it->next;
        free(this);
      }
      allocs[i].allocations = NULL;
    }
  }

  return 0;
}

int print_outstanding_combined_allocs(int combined_allocs_fd,
                                      int stack_traces_fd) {
  time_t t = time(NULL);
  struct tm* tm = localtime(&t);

  size_t nr_allocs = 0;

  // for each stack_id "curr_key" and union combined_alloc_info "alloc"
  // in bpf_map "combined_allocs"
  for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
    union combined_alloc_info combined_alloc_info;
    memset(&combined_alloc_info, 0, sizeof(combined_alloc_info));

    if (bpf_map_get_next_key(combined_allocs_fd, &prev_key, &curr_key)) {
      if (errno == ENOENT) {
        break;  // no more keys, done
      }

      perror("map get next key error");

      return -errno;
    }

    if (bpf_map_lookup_elem(combined_allocs_fd, &curr_key,
                            &combined_alloc_info)) {
      if (errno == ENOENT) {
        continue;
      }

      perror("map lookup error");

      return -errno;
    }

    const struct allocation alloc = {
        .stack_id = curr_key,
        .size = combined_alloc_info.total_size,
        .count = combined_alloc_info.number_of_allocs,
        .allocations = NULL};

    memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
    nr_allocs++;
  }

  qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

  // get min of allocs we stored vs the top N requested stacks
  nr_allocs = nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

  printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
         tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);

  print_stack_frames(allocs, nr_allocs, stack_traces_fd);

  return 0;
}

bool has_kernel_node_tracepoints() {
  return tracepoint_exists("kmem", "kmalloc_node") &&
         tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

void disable_kernel_node_tracepoints(struct memleak_bpf* skel) {
  bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
  bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
}

void disable_kernel_percpu_tracepoints(struct memleak_bpf* skel) {
  bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
  bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

void disable_kernel_tracepoints(struct memleak_bpf* skel) {
  bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
  bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
  bpf_program__set_autoload(skel->progs.memleak__kfree, false);
  bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc, false);
  bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
  bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
  bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
  bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
  bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
  bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

int attach_uprobes(struct memleak_bpf* skel) {
  ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
  ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

  ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
  ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

  ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
  ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

  /* third party allocator like jemallloc not support mmap, so remove the check.
   */
  if (strlen(env.symbols_prefix)) {
    ATTACH_UPROBE(skel, mmap, mmap_enter);
    ATTACH_URETPROBE(skel, mmap, mmap_exit);
  } else {
    ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
    ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);
  }

  ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
  ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

  ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
  ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

  ATTACH_UPROBE_CHECKED(skel, free, free_enter);
  if (strlen(env.symbols_prefix)) {
    ATTACH_UPROBE(skel, munmap, munmap_enter);
  } else {
    ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);
  }

  // the following probes are intentinally allowed to fail attachment

  // deprecated in libc.so bionic
  ATTACH_UPROBE(skel, valloc, valloc_enter);
  ATTACH_URETPROBE(skel, valloc, valloc_exit);

  // deprecated in libc.so bionic
  ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
  ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

  // added in C11
  ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
  ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

  return 0;
}
