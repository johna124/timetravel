#!/bin/bash
# ============================================================
# Time-Travel CLI — compile_riscv64.sh (The Spartan Musl Edition)
# Cross-compiles for RISC-V 64-bit using the musl.cc toolchain.
# ============================================================

set -euo pipefail

CROSS_DIR="$HOME/cross-tools"
CC="riscv64-linux-musl-gcc"
STRIP_BIN="riscv64-linux-musl-strip"
TARGET="riscv64"

# Inclusión automática del toolchain local en el PATH
if [ -d "$CROSS_DIR/riscv64-linux-musl-cross/bin" ]; then
    export PATH="$CROSS_DIR/riscv64-linux-musl-cross/bin:$PATH"
fi

MAP_FLAGS="-ffile-prefix-map=$(pwd)=."

# Determinismo absoluto para psicópatas de SHA256
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1788118500}"
export ZERO_AR_DATE=1

echo "⚙️ Target: RISC-V 64-bit (Time-Travel) - Forcing direct Musl Cross-Compilation."
echo "🔒 Deterministic build frozen at epoch: $SOURCE_DATE_EPOCH"
echo ""

# Verification and auto-installation of the musl.cc toolchain
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "⚠️  WARNING: Cross-compiler $CC not found in PATH."
    echo "⚙️  Starting automatic download of the spartan musl.cc toolchain..."
    mkdir -p "$CROSS_DIR"
    cd "$CROSS_DIR"
    if [ ! -f "riscv64-linux-musl-cross.tgz" ]; then
        echo "📥 Downloading ~100 MB of pure silicon from musl.cc..."
        wget -q --show-progress https://musl.cc/riscv64-linux-musl-cross.tgz
    fi
    echo "📦 Extracting cross-compilation environment..."
    tar -xzf riscv64-linux-musl-cross.tgz
    cd - >/dev/null
    export PATH="$CROSS_DIR/riscv64-linux-musl-cross/bin:$PATH"
fi

export CC

if ! command -v "$STRIP_BIN" >/dev/null 2>&1; then
    echo "❌ ERROR: $STRIP_BIN not found even after deploying the toolchain."
    exit 1
fi

if [ ! -f third_party/xdelta/xdelta3/xdelta3.c ]; then
    echo "❌ ERROR: missing third_party/xdelta/xdelta3/xdelta3.c"
    exit 1
fi

echo "✅ RISC-V tools ready for battle. Continuing..."
echo ""

# Extensiones estándar rv64gc (Integer, Multiply, Atomic, Float, Double, Compressed)
ARCH_FLAGS="-march=rv64gc -mabi=lp64d -fno-ident -fno-asynchronous-unwind-tables $MAP_FLAGS"

CFLAGS="-std=c11 -Wall -Wextra -O2 -ffunction-sections -fdata-sections -fno-ident -fno-asynchronous-unwind-tables $MAP_FLAGS -Isrc \
        -Ithird_party/xdelta/xdelta3 \
        -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
        -DSIZEOF_UNSIGNED_LONG_LONG=8 \
        -DSIZEOF_UNSIGNED_LONG=8 \
        -DSIZEOF_UNSIGNED_INT=4 \
        -DHAVE_CONFIG_H=0 -DXD3_USE_LARGESIZET=1 -DXD3_MAIN=0 -DXD3_DEBUG=0 \
        -DREGRESSION_TEST=0 -DSECONDARY_DJW=0 -DSECONDARY_FGK=0 \
        -DSECONDARY_LZMA=0 -DEXTERNAL_COMPRESSION=0 -DVCDIFF_TOOLS=0 \
        -DSIZEOF_SIZE_T=8 -Dusize_t=uint64_t -Dxoff_t=uint64_t"

SRC="src/tt_main.c \
     src/tt_util.c \
     src/tt_cache.c \
     src/tt_history.c \
     src/tt_capture.c \
     src/tt_store.c \
     src/tt_delta.c \
     src/tt_filter.c \
     src/tt_debounce.c \
     src/tt_watcher.c \
     src/tt_compact.c \
     src/tt_restore.c \
     src/tt_ipc.c \
     src/tt_dedup.c \
     src/tt_crypto.c \
     src/tt_kdf.c \
     src/tt_cmds.c \
     src/tt_repo.c \
     src/tt_annotation.c \
     src/tt_autotag.c \
     src/tt_reconstruct.c \
     src/tt_exclude.c \
     src/tt_blake2b.c \
     src/tt_verify.c"


mkdir -p build

echo "📦 Compiling xdelta3 for RISC-V..."
$CC -std=gnu11 -O2 -w -fPIC -fno-ident $MAP_FLAGS $CFLAGS \
    -c third_party/xdelta/xdelta3/xdelta3.c -o build/xdelta3.o

echo "🔗 Linking Time-Travel together for RISC-V..."
$CC $CFLAGS $ARCH_FLAGS \
    $SRC \
    build/xdelta3.o \
    -static -no-pie -Wl,--gc-sections \
    -o build/timetravel

if [ ! -f "build/timetravel" ]; then
    echo "❌ FATAL: build/timetravel was not created. Linking failed."
    exit 1
fi

"$STRIP_BIN" --strip-all build/timetravel 2>/dev/null || true

echo ""
echo "============================================================"
echo "✅ RISC-V CROSS-COMPILATION COMPLETED SUCCESSFULLY"
echo "============================================================"
echo ""
file build/timetravel
echo ""
ls -lh build/timetravel

