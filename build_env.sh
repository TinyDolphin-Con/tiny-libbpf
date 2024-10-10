#! /bin/bash
#！/bin/sh
export PATH=$PATH:${HOME}/workspace/ebpf/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/bin
export ARCH=arm64
export CROSS_COMPILE=aarch64-none-linux-gnu-
export CC=aarch64-none-linux-gnu-gcc
export CXX=aarch64-none-linux-gnu-g++

# 用 EXTRA_CFLAGS 指定 zlib 和 libelf 库的头文件路径
export EXTRA_CFLAGS="-I${HOME}/workspace/ebpf/zlib-1.3.1/_install/include -I${HOME}/workspace/ebpf/elfutils-0.191/_install/include"

# 用 EXTRA_LDFLAGS 指定 zlib 和 libelf 的库路径
export EXTRA_LDFLAGS="-L${HOME}/workspace/ebpf/zlib-1.3.1/_install/lib -L${HOME}/workspace/ebpf/elfutils-0.191/_install/lib"
