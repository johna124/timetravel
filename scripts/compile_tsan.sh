#!/bin/bash
# ============================================================================
# Time-Travel CLI — compile_tsan.sh (v1.4 Edition)
# Memory Concurrency Audit Pipeline: ThreadSanitizer
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

OUT=build_tsan

# --- Flags para ThreadSanitizer ---
#
# TSan recomienda optimización moderada (-O1 o -O2).
# -O0 puede ser muchísimo más lento y provocar timeouts en el test.
# Si quieres depurar más agresivamente, puedes cambiar -O1 por -O0.

COMMON_FLAGS=""
COMMON_FLAGS="$COMMON_FLAGS -O1 -g -ggdb3"
COMMON_FLAGS="$COMMON_FLAGS -Isrc -Ithird_party/xdelta/xdelta3"
COMMON_FLAGS="$COMMON_FLAGS -fsanitize=thread"
COMMON_FLAGS="$COMMON_FLAGS -fno-omit-frame-pointer"
COMMON_FLAGS="$COMMON_FLAGS -fno-optimize-sibling-calls"
COMMON_FLAGS="$COMMON_FLAGS -fPIE"

COMMON_FLAGS="$COMMON_FLAGS -D_POSIX_C_SOURCE=200809L"
COMMON_FLAGS="$COMMON_FLAGS -D_DEFAULT_SOURCE"

COMMON_FLAGS="$COMMON_FLAGS -DSIZEOF_UNSIGNED_LONG_LONG=8"
COMMON_FLAGS="$COMMON_FLAGS -DSIZEOF_UNSIGNED_LONG=8"
COMMON_FLAGS="$COMMON_FLAGS -DSIZEOF_UNSIGNED_INT=4"

COMMON_FLAGS="$COMMON_FLAGS -DHAVE_CONFIG_H=0"
COMMON_FLAGS="$COMMON_FLAGS -DXD3_USE_LARGESIZET=1"
COMMON_FLAGS="$COMMON_FLAGS -DXD3_MAIN=0"
COMMON_FLAGS="$COMMON_FLAGS -DXD3_DEBUG=0"

COMMON_FLAGS="$COMMON_FLAGS -DREGRESSION_TEST=0"
COMMON_FLAGS="$COMMON_FLAGS -DSECONDARY_DJW=0"
COMMON_FLAGS="$COMMON_FLAGS -DSECONDARY_FGK=0"
COMMON_FLAGS="$COMMON_FLAGS -DSECONDARY_LZMA=0"
COMMON_FLAGS="$COMMON_FLAGS -DEXTERNAL_COMPRESSION=0"
COMMON_FLAGS="$COMMON_FLAGS -DVCDIFF_TOOLS=0"

COMMON_FLAGS="$COMMON_FLAGS -DSIZEOF_SIZE_T=8"
COMMON_FLAGS="$COMMON_FLAGS -Dusize_t=uint64_t"
COMMON_FLAGS="$COMMON_FLAGS -Dxoff_t=uint64_t"

CFLAGS="-std=c11 -Wall -Wextra $COMMON_FLAGS"
XDELTA_CFLAGS="-std=gnu11 -w -fPIC $COMMON_FLAGS"

mkdir -p "$OUT"

echo "[1/3] Compiling xdelta3 with ThreadSanitizer..."
$CC $XDELTA_CFLAGS \
    -c third_party/xdelta/xdelta3/xdelta3.c \
    -o "$OUT/xdelta3.o"

echo "[2/3] Compiling and linking Time-Travel CLI (TSan)..."
$CC $CFLAGS \
    $SRC \
    "$OUT/xdelta3.o" \
    -o "$OUT/timetravel" \
    -pie \
    -lpthread \
    -lm
# Si tu build normal necesita libblake2 externa, añade también:
#    -lblake2

echo "[3/3] Preserving symbols for ThreadSanitizer..."
ls -lh "$OUT/timetravel"

echo ""
echo "🧵 OK: ./build_tsan/timetravel listo para ThreadSanitizer"
echo ""
echo "Modo auditoría (recomendado para pasar todo el mega_test y luego inspeccionar logs):"
echo ""
echo "  TSAN_OPTIONS=\"halt_on_error=0:exitcode=0:second_deadlock_stack=1:log_path=$PWD/$OUT/tsan.log\" \\"
echo "      ./mega_test.sh ./$OUT/timetravel"
echo ""
echo "Después revisa posibles races con:"
echo ""
echo "  grep -a 'WARNING: ThreadSanitizer' $OUT/tsan.log.*"
echo ""
echo "Modo estricto (falla/para en cuanto detecta una race):"
echo ""
echo "  TSAN_OPTIONS=\"halt_on_error=1:second_deadlock_stack=1\" \\"
echo "      ./mega_test.sh ./$OUT/timetravel"
