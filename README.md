# libbpf 交叉编译

## 交叉编译工具链准备

- 交叉编译工具链下载网址: [GNU-A Downloads](https://developer.arm.com/downloads/-/gnu-a)
- 需要交叉编译的库: zlib, libelf

```bash
cd /home/qcraft/workspace/ebpf/
wget https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz
tar xJf gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz
cd xJf gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz
# 导出交叉编译工具链
export ARCH=arm64
export CROSS_COMPILE=aarch64-none-linux-gnu-
export PATH=$PATH:/home/qcraft/workspace/ebpf/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/bin
export CC=aarch64-none-linux-gnu-gcc
export CXX=aarch64-none-linux-gnu-g++
```

- 判断是否存在 zlib 和 libelf, 若存在,就不需要再执行以下交叉编译步骤

```bash
cd /home/qcraft/workspace/ebpf/
find . -name libelf.*
find . -name libz.*
```

## 交叉编译 zlib

- 下载地址: [zlib Home Site](https://www.zlib.net/)

```bash
wget https://www.zlib.net/zlib-1.3.1.tar.gz
tar -axf zlib-1.3.1.tar.gz && cd zlib-1.3.1
./configure --prefix=$PWD/_install
make
make install
```

- 编译产出的头文件和 lib 库位于当前目录下的 \_install;
- 路径: /home/qcraft/workspace/ebpf/zlib-1.3.1/\_install

## 交叉编译 libelf

- 下载地址: [The elfutils project](https://sourceware.org/elfutils/)
- N.B. 注意: 依赖上述交叉编译出来的 zlib 库

```bash
wget https://sourceware.org/elfutils/ftp/elfutils-latest.tar.bz2
tar -axf elfutils-latest.tar.bz2 && cd elfutils-0.191
# 需要 CFLAGS 指定 zlib 库的头文件 和 LDFLAGS 指定 zlib 库路径
./configure --prefix=$PWD/_install --build=x86_64-linux-gnu \
	--host=aarch64-none-linux-gnu \
    CC=aarch64-none-linux-gnu-gcc CXX=aarch64-none-linux-gnu-g++ \
    CFLAGS=-I/home/qcraft/workspace/ebpf/zlib-1.3.1/_install/include \
    LDFLAGS=-L/home/qcraft/workspace/ebpf/zlib-1.3.1/_install/lib \
    LIBS=-lz \
    --disable-nls --disable-rpath --disable-libdebuginfod --disable-debuginfod \
    --with-zlib
make
make install
```

- 编译产出的头文件和 lib 库位于当前目录下的 \_install;
- 路径: /home/qcraft/workspace/ebpf/elfutils-0.191/\_install

## 安装 rust 语言环境(cargo)

- 编译 blazesym 需要依赖 rust 语言环境

```bash
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
# 安装 rust 的交叉编译工具链
rustup target add aarch64-unknown-linux-gnu
# 查看安装好的交叉编译工具链
rustup show
```

## 交叉编译 libbpf

- N.B. 注意,若上述安装路径不一致,请修改如下文件内容 /home/qcraft/qcraft/offboard/libbpf/src/build_env.sh

```bash
cd /home/qcraft/qcraft/offboard/libbpf/src
source build_env.sh
# 例子: 交叉编译 memleak
make clean; make memleak V=1
# 或者编译所有 APP
make clean; make V=1
```
