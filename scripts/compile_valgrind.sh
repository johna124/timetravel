#!/bin/bash
# ============================================================================
# Time-Travel CLI — compile_valgrind.sh (v1.4 Edition)
# Forensic Memory Audit (Valgrind Memcheck Integration Script)
# ============================================================================
set -e

# --- Pre-flight checks ---
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "❌ ERROR: musl-gcc is not installed."
    echo "   → sudo apt install musl-tools   (Debian/Ubuntu)"
    exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
    echo "❌ ERROR: valgrind is not installed."
    echo "   → sudo apt install valgrind"
    exit 1
fi

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

# --- Flags de Depuración Pura ---
CFLAGS="-std=c11 -Wall -Wextra -O0 -g -ggdb3 -Isrc \
        -Ithird_party/xdelta/xdelta3 \
        -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
        -DSIZEOF_UNSIGNED_LONG_LONG=8 \
        -DSIZEOF_UNSIGNED_LONG=8 \
        -DSIZEOF_UNSIGNED_INT=4 \
        -DHAVE_CONFIG_H=0 -DXD3_USE_LARGESIZET=1 -DXD3_MAIN=0 -DXD3_DEBUG=0 \
        -DREGRESSION_TEST=0 -DSECONDARY_DJW=0 -DSECONDARY_FGK=0 \
        -DSECONDARY_LZMA=0 -DEXTERNAL_COMPRESSION=0 -DVCDIFF_TOOLS=0 \
        -DSIZEOF_SIZE_T=8 -Dusize_t=uint64_t -Dxoff_t=uint64_t"

mkdir -p build_valgrind

echo "[1/4] Compiling xdelta3 for Valgrind inspection..."
musl-gcc -std=gnu11 -O0 -g -w -fPIC $CFLAGS \
    -c third_party/xdelta/xdelta3/xdelta3.c -o build_valgrind/xdelta3.o

echo "[2/4] Compiling and linking Time-Travel binary (v1.4)..."
musl-gcc $CFLAGS \
    $SRC \
    build_valgrind/xdelta3.o \
    -static -no-pie -Wl,--gc-sections \
    -o build_valgrind/timetravel

echo "[3/4] Creating Valgrind wrapper for mega_test.sh..."
cat > build_valgrind/timetravel_valgrind <<'WRAPPER'
#!/bin/bash
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
exec valgrind \
    --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --error-exitcode=99 \
    --log-file=/tmp/tt_valgrind_%p.log \
    "$SELF_DIR/timetravel" "$@"
WRAPPER
chmod +x build_valgrind/timetravel_valgrind

echo "[4/4] Preserving debugging symbols..."
ls -lh build_valgrind/timetravel
ls -lh build_valgrind/timetravel_valgrind

echo ""
echo "✅ OK: ./build_valgrind/timetravel ready for forensic analysis"
echo "🚀 Run the battery under Valgrind Memcheck:"
echo ""
echo "   ./mega_test.sh ./build_valgrind/timetravel_valgrind"
echo ""
echo "⚠️  Note: Valgrind slows execution ~10x–20x."
echo "   Logs: /tmp/tt_valgrind_*.log"
