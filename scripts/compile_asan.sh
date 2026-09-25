#!/bin/bash
# ============================================================================
# Time-Travel CLI — compile_san.sh (v1.4 Edition)
# Memory Audit Pipeline: AddressSanitizer + UndefinedBehaviorSanitizer
# ============================================================================
set -e

CC=gcc

# --- Pre-flight checks ---
if [ ! -f third_party/xdelta/xdelta3/xdelta3.c ]; then
    echo "❌ ERROR: missing third_party/xdelta/xdelta3/xdelta3.c"
    exit 1
fi

SRC="src/tt_main.c \
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
     src/tt_blake2b.c \
     src/tt_verify.c"

for f in $SRC \
         src/tt_types.h src/tt_ipc.h \
         src/tt_dedup.h src/tt_crypto.h \
         src/tt_kdf.h src/tt_blake2b.h; do
    if [ ! -f "$f" ]; then
        echo "❌ ERROR: missing $f"
        exit 1
    fi
done

# --- Flags de Auditoría Estricta ---
CFLAGS="-std=c11 -Wall -Wextra -O0 -g -ggdb3 -Isrc \
        -Ithird_party/xdelta/xdelta3 \
        -fsanitize=address,undefined \
        -fno-omit-frame-pointer -fno-optimize-sibling-calls \
        -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
        -DSIZEOF_UNSIGNED_LONG_LONG=8 \
        -DSIZEOF_UNSIGNED_LONG=8 \
        -DSIZEOF_UNSIGNED_INT=4 \
        -DHAVE_CONFIG_H=0 -DXD3_USE_LARGESIZET=1 -DXD3_MAIN=0 -DXD3_DEBUG=0 \
        -DREGRESSION_TEST=0 -DSECONDARY_DJW=0 -DSECONDARY_FGK=0 \
        -DSECONDARY_LZMA=0 -DEXTERNAL_COMPRESSION=0 -DVCDIFF_TOOLS=0 \
        -DSIZEOF_SIZE_T=8 -Dusize_t=uint64_t -Dxoff_t=uint64_t"

XDELTA_CFLAGS="-std=gnu11 -O0 -g -ggdb3 -w -fPIC $CFLAGS"

mkdir -p build_asan

echo "[1/3] Compiling xdelta3 with Sanitizers..."
$CC $XDELTA_CFLAGS -c third_party/xdelta/xdelta3/xdelta3.c -o build_asan/xdelta3.o

echo "[2/3] Compiling and linking Hardened Time-Travel CLI (v1.4)..."
$CC $CFLAGS \
    $SRC \
    build_asan/xdelta3.o \
    -o build_asan/timetravel

echo "[3/3] Preserving symbols for ASan/UBSan..."
ls -lh build_asan/timetravel

echo ""
echo "🛡️  OK: ./build_asan/timetravel listo para la arena"
echo "   → Run: TIMETRAVEL=./build_asan/timetravel ./mega_test.sh"
echo "   → Or:  ./mega_test.sh ./build_asan/timetravel"
