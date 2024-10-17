/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 TinyDolphin */

#include "btf_helpers.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <zlib.h>

#include "trace_helpers.h"

// 外部变量声明,表示一个包含最小核心 BTF 文件的压缩文件的起始和结束位置
// __attribute__((weak)):弱符号,意味着可能不存在.如果没有链接到这个BTF数据,则为空
extern unsigned char _binary_min_core_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_min_core_btfs_tar_gz_end[] __attribute__((weak));

// 用于限制存储的字符串长度
#define FIELD_LEN 65
// sscanf 用来从 /etc/os-release 中提取操作系统 ID 和版本的格式字符串
#define ID_FMT "ID=%64s"
#define VERSION_FMT "VERSION_ID=\"%64s"

// 结构体,保存了操作系统的基本信息
struct os_info {
  char id[FIELD_LEN];              // 操作系统 ID(例如 ubuntu)
  char version[FIELD_LEN];         // 操作系统版本(例如 22.04)
  char arch[FIELD_LEN];            // 体系结构(例如 x86_64)
  char kernel_release[FIELD_LEN];  // 内核版本号
};

/**
 * @brief 获取操作系统信息的函数
 *
 * 主要实现逻辑:
 *  1. 调用 uname 获取系统内核信息(如:内核版本号,体系结构)
 *  2. 打开 /etc/os-release 文件,并逐行读取其中内容
 *  3. 使用 sscanf 从每一行中提取操作系统的 ID 和版本号,并保存到 os_info 中
 */
static struct os_info* get_os_info() {
  struct os_info* info = NULL;
  struct utsname u;
  size_t len = 0;
  ssize_t read;
  char* line = NULL;
  FILE* f;

  // 1. 使用 uname 获取系统内核信息
  if (uname(&u) == -1) {
    return NULL;
  }

  // 2. 从 /etc/os-release 文件中提取操作系统 ID 和版本信息
  f = fopen("/etc/os-release", "r");
  if (!f) {
    return NULL;
  }

  info = calloc(1, sizeof(*info));
  if (!info) {
    goto out;
  }

  strncpy(info->kernel_release, u.release, FIELD_LEN);
  strncpy(info->arch, u.machine, FIELD_LEN);

  // 逐行读取 /etc/os-release 中的内容
  while ((read = getline(&line, &len, f)) != -1) {
    // 通过 sscanf 从每一行中提取操作系统 ID 和版本号,并保存到 os_info 中
    if (sscanf(line, ID_FMT, info->id) == 1) {
      continue;
    }

    if (sscanf(line, VERSION_FMT, info->version) == 1) {
      /* remove '"' suffix */
      info->version[strlen(info->version) - 1] = 0;
      continue;
    }
  }

out:
  free(line);
  fclose(f);

  return info;
}

#define INITIAL_BUF_SIZE (1024 * 1024 * 4) /* 4MB */

/* adapted from https://zlib.net/zlib_how.html */
/**
 * @brief 解压缩 gz 文件的函数
 *
 * 主要实现逻辑:
 *  1. 初始化 zlib 流对象;
 *  2. 分配初始化大小为 4MB 的缓冲区,用于保存解压后的数据
 *  3. 循环解压输入数据,并将结果存储到 dst 中
 */
static int inflate_gz(unsigned char* src, int src_size, unsigned char** dst,
                      int* dst_size) {
  size_t size = INITIAL_BUF_SIZE;
  size_t next_size = size;
  z_stream strm;
  void* tmp;
  int ret;

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;

  // 1. 初始化 zlib 流对象,指定 16 + MAX_WBITS 以处理 gzip 格式
  ret = inflateInit2(&strm, 16 + MAX_WBITS);
  if (ret != Z_OK) {
    return -EINVAL;
  }

  // 2. 分配一个初始化大小为 4MB 的缓冲区 dst,用于保存解压后的数据
  *dst = malloc(size);
  if (!*dst) {
    return -ENOMEM;
  }

  strm.next_in = src;
  strm.avail_in = src_size;

  /* run inflate() on input until it returns Z_STREAM_END */
  do {
    strm.next_out = *dst + strm.total_out;
    strm.avail_out = next_size;
    // 3. 循环调用 inflate 函数,逐步解压输入数据 src,并将解压结果存储到 dst 中
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) {
      goto out_err;
    }
    /* we need more space */
    // 4. 如果缓冲区不够大,会动态扩容
    if (strm.avail_out == 0) {
      next_size = size;
      size *= 2;
      tmp = realloc(*dst, size);
      if (!tmp) {
        ret = -ENOMEM;
        goto out_err;
      }
      *dst = tmp;
    }
  } while (ret != Z_STREAM_END);

  *dst_size = strm.total_out;

  /* clean up and return */
  ret = inflateEnd(&strm);
  if (ret != Z_OK) {
    ret = -EINVAL;
    goto out_err;
  }
  return 0;

out_err:
  free(*dst);
  *dst = NULL;
  return ret;
}

/* tar header from
 * https://github.com/tklauser/libtar/blob/v1.2.20/lib/libtar.h#L39-L60 */
struct tar_header {
  char name[100];
  char mode[8];
  char uid[8];
  char gid[8];
  char size[12];
  char mtime[12];
  char chksum[8];
  char typeflag;
  char linkname[100];
  char magic[6];
  char version[2];
  char uname[32];
  char gname[32];
  char devmajor[8];
  char devminor[8];
  char prefix[155];
  char padding[12];
};

/**
 * @brief 查找 tar 文件中的指定文件
 *
 * 主要实现逻辑:
 *  遍历 tar 文件头部结构,检查每个文件的 name 字段是否与目标文件匹配,
 *  一旦找到匹配的文件,返回该文件的起始位置,并通过length输出文件大小
 */
static char* tar_file_start(struct tar_header* tar, const char* name,
                            int* length) {
  while (tar->name[0]) {
    sscanf(tar->size, "%o", length);
    if (!strcmp(tar->name, name)) {
      return (char*)(tar + 1);
    }
    tar += 1 + (*length + 511) / 512;
  }
  return NULL;
}

/**
 * @brief BTF 文件确保函数
 *
 * 主要实现逻辑:
 *  如果系统已经提供了 BTF,则直接返回;
 *  如果没有 BTF 文件,
 *    就从 _binary_min_core_btfs_tar_gz_start 和
 * _binary_min_core_btfs_tar_gz_end 之间的压缩 tar 文件中提取 解压 tar
 * 文件后,查找与当前操作系统匹配的 BTF 文件并保存到 /tmp 目录
 */
int ensure_core_btf(struct bpf_object_open_opts* opts) {
  char name_fmt[] = "./%s/%s/%s/%s.btf";
  char btf_path[] = "/tmp/bcc-libbpf-tools.btf.XXXXXX";
  struct os_info* info = NULL;
  unsigned char* dst_buf = NULL;
  char* file_start;
  int dst_size = 0;
  char name[100];
  FILE* dst = NULL;
  int ret;

  /* do nothing if the system provides BTF */
  if (vmlinux_btf_exists()) {
    return 0;
  }

  /* compiled without min core btfs */
  if (!_binary_min_core_btfs_tar_gz_start) {
    return -EOPNOTSUPP;
  }

  info = get_os_info();
  if (!info) {
    return -errno;
  }

  ret = mkstemp(btf_path);
  if (ret < 0) {
    ret = -errno;
    goto out;
  }

  dst = fdopen(ret, "wb");
  if (!dst) {
    ret = -errno;
    goto out;
  }

  ret = snprintf(name, sizeof(name), name_fmt, info->id, info->version,
                 info->arch, info->kernel_release);
  if (ret < 0 || ret == sizeof(name)) {
    ret = -EINVAL;
    goto out;
  }

  ret = inflate_gz(
      _binary_min_core_btfs_tar_gz_start,
      _binary_min_core_btfs_tar_gz_end - _binary_min_core_btfs_tar_gz_start,
      &dst_buf, &dst_size);
  if (ret < 0) {
    goto out;
  }

  ret = 0;
  file_start = tar_file_start((struct tar_header*)dst_buf, name, &dst_size);
  if (!file_start) {
    ret = -EINVAL;
    goto out;
  }

  if (fwrite(file_start, 1, dst_size, dst) != dst_size) {
    ret = -ferror(dst);
    goto out;
  }

  opts->btf_custom_path = strdup(btf_path);
  if (!opts->btf_custom_path) {
    ret = -ENOMEM;
  }

out:
  free(info);
  fclose(dst);
  free(dst_buf);

  return ret;
}

/**
 * @brief 用于删除临时生成的 BTF 文件并释放内存
 */
void cleanup_core_btf(struct bpf_object_open_opts* opts) {
  if (!opts) {
    return;
  }

  if (!opts->btf_custom_path) {
    return;
  }

  unlink(opts->btf_custom_path);
  free((void*)opts->btf_custom_path);
}
