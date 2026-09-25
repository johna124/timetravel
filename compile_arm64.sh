#!/bin/bash
# ============================================================
# Time-Travel CLI — compile_arm64.sh (The Spartan Musl Edition)
# Cross-compiles for ARM64 (AArch64) using the musl.cc toolchain.
# ============================================================

set -euo pipefail

CROSS_DIR="$HOME/cross-tools"
CC="aarch64-linux-musl-gcc"
STRIP_BIN="aarch64-linux-musl-strip"
TARGET="arm64"

# Inclusión automática del toolchain local en el PATH
if [ -d "$CROSS_DIR/aarch64-linux-musl-cross/bin" ]; then
    export PATH="$CROSS_DIR/aarch64-linux-musl-cross/bin:$PATH"
fi

MAP_FLAGS="-ffile-prefix-map=$(pwd)=."

# Determinismo absoluto para psicópatas de SHA256
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1788118500}"
export ZERO_AR_DATE=1

echo "⚙️ Target: ARM64 / AArch64 (Raspberry Pi 4/5, AWS Graviton) - Forcing Musl Cross-Compilation."
echo "🔒 Deterministic build frozen at epoch: $SOURCE_DATE_EPOCH"
echo ""

# Verification and auto-installation of the musl.cc arm64 toolchain
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "⚠️  WARNING: Cross-compiler $CC not found in PATH."
    echo "⚙️  Starting automatic download of the spartan musl.cc toolchain for ARM64..."
    mkdir -p "$CROSS_DIR"
    cd "$CROSS_DIR"
    if [ ! -f "aarch64-linux-musl-cross.tgz" ]; then
        echo "📥 Downloading ~100 MB of ARM64 cross-compiler from musl.cc..."
        wget -q --show-progress https://musl.cc/aarch64-linux-musl-cross.tgz
    fi
    echo "📦 Extracting arm64 cross-compilation environment..."
    tar -xzf aarch64-linux-musl-cross.tgz
    cd - >/dev/null
    export PATH="$CROSS_DIR/aarch64-linux-musl-cross/bin:$PATH"
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

echo "✅ ARM64 tools ready for battle. Continuing..."
echo ""

# Flags específicos para arquitectura ARM64 limpia (AArch64 genérica)
ARCH_FLAGS="-fno-ident -fno-asynchronous-unwind-tables $MAP_FLAGS"

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

SRC="src/tt_delta.c \
     src/tt_filter.c \
     src/tt_debounce.c \
     src/tt_watcher.c \
     src/tt_store.c \
     src/tt_restore.c \
     src/tt_compact.c \
     src/tt_ipc.c \
     src/tt_blake2b.c \
     src/tt_dedup.c \
     src/tt_verify.c \
     src/tt_kdf.c \
     src/tt_crypto.c \
     src/tt_main.c"

mkdir -p build

echo "📦 Compiling xdelta3 for ARM64..."
$CC -std=gnu11 -O2 -w -fPIC -fno-ident $MAP_FLAGS $CFLAGS \
    -c third_party/xdelta/xdelta3/xdelta3.c -o build/xdelta3_arm64.o

echo "🔗 Linking Time-Travel together for ARM64..."
$CC $CFLAGS $ARCH_FLAGS \
    $SRC \
    build/xdelta3_arm64.o \
    -static -no-pie -Wl,--gc-sections \
    -o build/timetravel-arm64

if [ ! -f "build/timetravel" ]; then
    echo "❌ FATAL: build/timetravel was not created. Linking failed."
    exit 1
fi

"$STRIP_BIN" --strip-all build/timetravel 2>/dev/null || true

echo ""
echo "============================================================"
echo "✅ ARM64 CROSS-COMPILATION COMPLETED SUCCESSFULLY"
echo "============================================================"
echo ""
file build/timetravel
echo ""
ls -lh build/timetravel

