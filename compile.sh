#!/bin/bash
# ============================================================
# Time-Travel CLI — compile.sh
# Generates the static binary ./build/timetravel with musl-gcc.
#
# Modular architecture: ALL modules are compiled.
#   - tt_main.c     → CLI (watch/undo/diff/tag/status/log/compact)
#   - tt_types.h    → shared types
#   - tt_store.c    → .ttd store + reader
#   - tt_delta.c    → xdelta3 encode/decode
#   - tt_filter.c   → robust exclusions (path_has_component)
#   - tt_debounce.c → event debounce
#   - tt_watcher.c  → inotify + directory deletion + rescan
#   - tt_compact.c  → compaction (once a day)
#   - tt_restore.c  → atomic restore + per-file undo
# ============================================================

set -e

CC=musl-gcc

# --- Pre-flight checks ---
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "❌ ERROR: musl-gcc is not installed."
    echo "   → sudo apt install musl-tools   (Debian/Ubuntu)"
    exit 1
fi

if [ ! -f third_party/xdelta/xdelta3/xdelta3.c ]; then
    echo "❌ ERROR: missing third_party/xdelta/xdelta3/xdelta3.c"
    exit 1
fi

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



for f in $SRC src/tt_types.h src/tt_ipc.h; do
    if [ ! -f "$f" ]; then
        echo "❌ ERROR: missing $f"
        exit 1
    fi
done

CFLAGS="-std=c11 -Wall -Wextra -O2 -Isrc \
        -Ithird_party/xdelta/xdelta3 \
        -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
        -DSIZEOF_UNSIGNED_LONG_LONG=8 \
        -DSIZEOF_UNSIGNED_LONG=8 \
        -DSIZEOF_UNSIGNED_INT=4 \
        -DHAVE_CONFIG_H=0 -DXD3_USE_LARGESIZET=1 -DXD3_MAIN=0 -DXD3_DEBUG=0 \
        -DREGRESSION_TEST=0 -DSECONDARY_DJW=0 -DSECONDARY_FGK=0 \
        -DSECONDARY_LZMA=0 -DEXTERNAL_COMPRESSION=0 -DVCDIFF_TOOLS=0 \
        -DSIZEOF_SIZE_T=8 -Dusize_t=uint64_t -Dxoff_t=uint64_t"

mkdir -p build

echo "[1/3] Compiling xdelta3..."
$CC -std=gnu11 -O2 -w -fPIC $CFLAGS \
    -c third_party/xdelta/xdelta3/xdelta3.c -o build/xdelta3.o

echo "[2/3] Compiling and linking Time-Travel CLI..."
$CC $CFLAGS \
    $SRC \
    build/xdelta3.o \
    -static -no-pie -Wl,--gc-sections \
    -o build/timetravel

echo "[3/3] Optimizing (strip)..."
strip build/timetravel 2>/dev/null || true

ls -lh build/timetravel
echo ""
echo "✅ OK: ./build/timetravel"
echo "   → ./build/timetravel help"
