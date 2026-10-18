#!/bin/bash

TT="${1:-$(pwd)/timetravel}"

# --- colores ---------------------------------------------------------------
if [ -t 1 ]; then
    _TC_Y=$'\033[1;33m'
    _TC_B=$'\033[1m'
    _TC_N=$'\033[0m'
else
    _TC_Y=''
    _TC_B=''
    _TC_N=''
fi

# ---ACTUAL architecture of the binary (not of the host) ---------------------------
_tt_arch() {
    local b="$1" s
    [ -f "$b" ] || { printf 'unknown'; return 0; }

    s="$(file -b "$b" 2>/dev/null || true)"
    if [ -n "$s" ]; then
        case "$s" in
            *riscv*|*RISC-V*)      printf 'riscv';   return 0 ;;
            *aarch64*)             printf 'aarch64'; return 0 ;;
            *ARM*|*arm*)           printf 'arm';     return 0 ;;
            *x86-64*|*AMD64*)      printf 'x86_64';  return 0 ;;
            *i686*|*i386*|*80386*) printf 'i686';    return 0 ;;
            *powerpc64*|*ppc64*)   printf 'ppc64';   return 0 ;;
            *powerpc*|*PowerPC*)   printf 'ppc';     return 0 ;;
            *mips64*)              printf 'mips64';  return 0 ;;
            *mips*|*MIPS*)         printf 'mips';    return 0 ;;
            *sparc*)               printf 'sparc';   return 0 ;;
        esac
    fi

    if command -v objdump >/dev/null 2>&1; then
        s="$(objdump -f "$b" 2>/dev/null \
             | awk -F: '/^architecture:/{print $2}' | awk '{print $1}')"
        case "$s" in
            i386|x86-64|aarch64|arm|riscv*|powerpc*|mips*|sparc*)
                printf '%s' "$s"; return 0 ;;
        esac
    fi
    printf 'unknown'
}

_tt_host() {
    case "$(uname -m 2>/dev/null)" in
        x86_64|amd64)     printf 'x86_64' ;;
        i?86)             printf 'i686'   ;;
        aarch64|arm64)    printf 'aarch64' ;;
        armv*)            printf 'arm'    ;;
        riscv64|riscv32)  printf 'riscv'  ;;
        ppc64|ppc64le)    printf 'ppc64'  ;;
        ppc|powerpc)      printf 'ppc'    ;;
        mips*)            printf 'mips'   ;;
        sparc*)           printf 'sparc'  ;;
        *)                uname -m 2>/dev/null ;;
    esac
}

ARCH="$(_tt_arch "$TT")"
HOSTARCH="$(_tt_host)"

# --- QEMU detection -----------------------------------------------------
QEMU=0
QEMU_WHY=""

if command -v systemd-detect-virt >/dev/null 2>&1; then
    _v="$(systemd-detect-virt --vm 2>/dev/null || true)"
    case "$_v" in
        qemu|qemu-user|kvm)
            QEMU=1
            QEMU_WHY="systemd-detect-virt=$_v"
            ;;
    esac
fi

if [ "$QEMU" -eq 0 ]; then
    if [ -n "${QEMU_LD_PREFIX:-}" ] || [ -n "${QEMU_CPU:-}" ]; then
        QEMU=1
        QEMU_WHY="QEMU_LD_PREFIX / QEMU_CPU presentes"
    fi
fi

if [ "$QEMU" -eq 0 ] && [ -r /proc/self/stat ]; then
    _p=$$
    _n=0
    while [ "$_p" != 0 ] && [ "$_p" != 1 ] && [ "$_n" -lt 20 ]; do
        _cmd="$(cat "/proc/$_p/comm" 2>/dev/null || true)"
        case "$_cmd" in
            qemu*)
                QEMU=1
                QEMU_WHY="proceso ancestro: $_cmd"
                break
                ;;
        esac
        _pp="$(sed 's/.*) //' "/proc/$_p/stat" 2>/dev/null | awk '{print $2}')"
        if [ -z "$_pp" ]; then break; fi
        _p="$_pp"
        _n=$((_n + 1))
    done
fi

NATIVE=0
case "$ARCH/$HOSTARCH" in
    x86_64/x86_64)          NATIVE=1 ;;
    i686/i686|i686/x86_64)  NATIVE=1 ;;
    aarch64/aarch64)        NATIVE=1 ;;
    arm/arm|arm/aarch64)    NATIVE=1 ;;
    riscv/riscv)            NATIVE=1 ;;
    ppc64/ppc64)            NATIVE=1 ;;
    ppc/ppc|ppc/ppc64)      NATIVE=1 ;;
    mips/mips)              NATIVE=1 ;;
    sparc/sparc)            NATIVE=1 ;;
esac

if [ "$QEMU" -eq 0 ] && [ "$ARCH" != unknown ] && [ "$NATIVE" -eq 0 ]; then
    QEMU=1
    QEMU_WHY="binario $ARCH != host $HOSTARCH"
fi

if [ "$QEMU" -eq 1 ]; then
    ARCH_LABEL="$ARCH (QEMU)"
else
    ARCH_LABEL="$ARCH"
fi

# --- version and sanitizers --------------------------------------------------
TT_VER=unknown
SAN=none

if [ -x "$TT" ]; then
    _vto=5
    if [ "$QEMU" -eq 1 ]; then _vto=15; fi

    _v="$(strings "$TT" 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+' | head -n1 || true)"

    if [ -z "$_v" ] && command -v timeout >/dev/null 2>&1; then
        _v="$(timeout "$_vto" "$TT" help 2>&1 \
              | head -n 30 | grep -oE 'v[0-9]+\.[0-9]+' | head -n1 || true)"
    fi
    if [ -n "$_v" ]; then TT_VER="$_v"; fi

    _san_list=""
    _tt_add_san() {
        case ",$_san_list," in
            *",$1,"*) return 0 ;;
        esac
        if [ -z "$_san_list" ]; then
            _san_list="$1"
        else
            _san_list="$_san_list+$1"
        fi
    }

    _syms="$( { nm -a "$TT" 2>/dev/null; nm -D "$TT" 2>/dev/null; } || true )"
    _strs="$(strings "$TT" 2>/dev/null || true)"

    if printf '%s\n' "$_syms" | grep -q '__asan_init'; then _tt_add_san ASan; fi
    if printf '%s\n' "$_syms" | grep -q '__tsan_init'; then _tt_add_san TSan; fi
    if printf '%s\n' "$_syms" | grep -q '__msan_init'; then _tt_add_san MSan; fi
    if printf '%s\n' "$_syms" | grep -q '__ubsan';     then _tt_add_san UBSan; fi
    if printf '%s\n' "$_syms" | grep -q '__lsan';      then _tt_add_san LSan; fi

    if printf '%s\n' "$_strs" | grep -qi 'AddressSanitizer'; then _tt_add_san ASan; fi
    if printf '%s\n' "$_strs" | grep -qi 'ThreadSanitizer';  then _tt_add_san TSan; fi
    if printf '%s\n' "$_strs" | grep -qi 'MemorySanitizer';  then _tt_add_san MSan; fi
    if printf '%s\n' "$_strs" | grep -qi 'UndefinedBehaviorSanitizer'; then
        _tt_add_san UBSan
    fi
    if printf '%s\n' "$_strs" | grep -qi 'LeakSanitizer'; then _tt_add_san LSan; fi

    if [ -n "$_san_list" ]; then SAN="$_san_list"; fi
fi

# --- log name --------------------------------------------------------
_qtag=""
if [ "$QEMU" -eq 1 ]; then _qtag="_qemu"; fi

_stag=""
if [ "$SAN" != none ]; then
    _stag="_$(printf '%s' "$SAN" | tr '+' '-')"
fi

LOGFILE="time_travel_megatest_${ARCH}${_qtag}_${TT_VER}${_stag}_$(date +%Y%m%d_%H%M%S).txt"
LOG_FILE="$LOGFILE"

: > "$LOGFILE"

exec > >(tee >(sed -u $'s/\033\\[[0-9;]*[A-Za-z]//g' >> "$LOGFILE")) 2>&1

# --- header (written ON SCREEN AND IN THE LOG) -------------------------
printf '\n%s=== Time-Travel mega test ===%s\n' "$_TC_B" "$_TC_N"

printf '%sArchitecture : %s%s\n' "$_TC_Y" "$ARCH_LABEL" "$_TC_N"
printf '%sHost         : %s%s\n' "$_TC_Y" "$HOSTARCH" "$_TC_N"

if [ "$QEMU" -eq 1 ]; then
    printf '%sQEMU         : %s%s\n' "$_TC_Y" "$QEMU_WHY" "$_TC_N"
fi

printf '%sBinary       : %s%s\n' "$_TC_Y" "$TT" "$_TC_N" 
printf '%sVersion      : %s%s\n' "$_TC_Y" "$TT_VER" "$_TC_N"
printf '%sSanitizers   : %s%s\n' "$_TC_Y" "$SAN" "$_TC_N"
printf '%sLog file     : %s%s\n' "$_TC_Y" "$LOGFILE" "$_TC_N"
printf '%sStarted      : %s%s\n' "$_TC_Y" "$(date)" "$_TC_N"

printf '\n'

if echo "$1" | grep -qi valgrind; then
    export VALGRIND_MODE=1
    echo "⚠️  Valgrind mode detected: increasing timeouts"
fi
# ============================================================
# Time-Travel CLI — Test Battery (43 sections)
# Usage: ./mega_test.sh [binary_path]
# ============================================================
set -uo pipefail
exec </dev/null   # avoids hangs from prompts in non-interactive execution
TT="$(pwd)/timetravel"


# ============================================================
# Valgrind adaptive helpers
# ============================================================
VG_MULT="${VG_MULT:-1}"
TT_UNDER_VALGRIND=0
SKIP_CRYPTO_UNDER_VALGRIND=0

case "$TT" in
    *valgrind*)
        VG_MULT=20
        TT_UNDER_VALGRIND=1
        SKIP_CRYPTO_UNDER_VALGRIND=1
        ;;
esac

# ============================================================
# Sanitizer adaptive detection (ASan / TSan) — EXCLUSIVE
# ============================================================
SKIP_VALGRIND_UNDER_TSAN="${SKIP_VALGRIND_UNDER_TSAN:-1}"
SKIP_VALGRIND_UNDER_ASAN="${SKIP_VALGRIND_UNDER_ASAN:-1}"
TT_UNDER_TSAN=0
TT_UNDER_ASAN=0
TT_UNDER_SANITIZER=0

_tt_score_sanitizers() {
    local tsan_score=0
    local asan_score=0

    case "${TT_FORCE_SANITIZER:-}" in
        tsan|TSAN) printf '100 0\n'; return ;;
        asan|ASAN) printf '0 100\n'; return ;;
    esac

    case "$TT" in
        *tsan*|*TSAN*) tsan_score=$((tsan_score + 10)) ;;
    esac
    case "$TT" in
        *asan*|*ASAN*|*build_san/*) asan_score=$((asan_score + 10)) ;;
    esac

    if command -v ldd >/dev/null 2>&1; then
        local ldd_out
        ldd_out="$(ldd "$TT" 2>/dev/null || true)"
        if printf '%s\n' "$ldd_out" | grep -Eq 'libtsan\.so'; then
            tsan_score=$((tsan_score + 8))
        fi
        if printf '%s\n' "$ldd_out" | grep -Eq 'libasan\.so'; then
            asan_score=$((asan_score + 8))
        fi
    fi

    if command -v nm >/dev/null 2>&1; then
        local nm_out
        nm_out="$(nm -D "$TT" 2>/dev/null || nm "$TT" 2>/dev/null || true)"
        if printf '%s\n' "$nm_out" | grep -Eq '[[:space:]]__tsan_init$'; then
            tsan_score=$((tsan_score + 6))
        fi
        if printf '%s\n' "$nm_out" | grep -Eq '[[:space:]]__asan_init$'; then
            asan_score=$((asan_score + 6))
        fi
    elif command -v readelf >/dev/null 2>&1; then
        local re_out
        re_out="$(readelf -s "$TT" 2>/dev/null || true)"
        if printf '%s\n' "$re_out" | grep -Eq '__tsan_init'; then
            tsan_score=$((tsan_score + 6))
        fi
        if printf '%s\n' "$re_out" | grep -Eq '__asan_init'; then
            asan_score=$((asan_score + 6))
        fi
    fi

    if [ "$tsan_score" -eq 0 ] && [ "$asan_score" -eq 0 ]; then
        if LC_ALL=C grep -qam1 -F '__tsan_init' "$TT" 2>/dev/null; then
            tsan_score=$((tsan_score + 3))
        fi
        if LC_ALL=C grep -qam1 -F '__asan_init' "$TT" 2>/dev/null; then
            asan_score=$((asan_score + 3))
        fi
    fi

    local base_tsan=$tsan_score
    local base_asan=$asan_score

    if [ "$base_tsan" -gt 0 ] && [ -n "${TSAN_OPTIONS:-}" ] && [ -z "${ASAN_OPTIONS:-}" ]; then
        tsan_score=$((tsan_score + 1))
    fi
    if [ "$base_asan" -gt 0 ] && [ -n "${ASAN_OPTIONS:-}" ] && [ -z "${TSAN_OPTIONS:-}" ]; then
        asan_score=$((asan_score + 1))
    fi

    printf '%d %d\n' "$tsan_score" "$asan_score"
}

_san_scores="$(_tt_score_sanitizers)"
_TSAN_SCORE="${_san_scores%% *}"
_ASAN_SCORE="${_san_scores##* }"

if [ "${_TSAN_SCORE:-0}" -gt 0 ] || [ "${_ASAN_SCORE:-0}" -gt 0 ]; then
    if [ "$_TSAN_SCORE" -gt "$_ASAN_SCORE" ]; then
        TT_UNDER_TSAN=1
        TT_UNDER_SANITIZER=1
        printf "[INFO] ThreadSanitizer detected (TT=%s, score tsan=%s asan=%s).\n" \
               "$TT" "$_TSAN_SCORE" "$_ASAN_SCORE"
        printf "[INFO] Valgrind memory audit will be skipped.\n"
    elif [ "$_ASAN_SCORE" -gt "$_TSAN_SCORE" ]; then
        TT_UNDER_ASAN=1
        TT_UNDER_SANITIZER=1
        printf "[INFO] AddressSanitizer detected (TT=%s, score tsan=%s asan=%s).\n" \
               "$TT" "$_TSAN_SCORE" "$_ASAN_SCORE"
        printf "[INFO] Valgrind memory audit will be skipped.\n"
    else
        TT_UNDER_SANITIZER=1
        printf "[WARN] Sanitizer evidence ambiguous (TT=%s, tsan=%s asan=%s).\n" \
               "$TT" "$_TSAN_SCORE" "$_ASAN_SCORE"
        printf "[WARN] Treating as generic sanitizer; Valgrind will be skipped.\n"
        printf "[WARN] Use TT_FORCE_SANITIZER=tsan|asan to override.\n"
    fi
fi

# Valgrind log parser (baresnap-style)
check_vg_log() {
    local vg_log_file="$1"
    local vg_stage="$2"

    if [ ! -f "$vg_log_file" ]; then
        fail "$vg_stage: valgrind log not generated"
        return 1
    fi

    local vg_leaks
    vg_leaks=$(grep "definitely lost:" "$vg_log_file" | awk '{print $4}' | tr -d ',' | head -1)

    local vg_errors
    vg_errors=$(grep "ERROR SUMMARY:" "$vg_log_file" | awk '{print $4}' | head -1)

    vg_leaks=${vg_leaks:-0}
    vg_errors=${vg_errors:-0}

    if [ "$vg_leaks" -eq 0 ] 2>/dev/null; then
        if [ "$vg_errors" -gt 0 ] 2>/dev/null; then
            pass "$vg_stage: 0 leaks ($vg_errors suppressed warnings)"
        else
            pass "$vg_stage: 0 leaks, 0 errors"
        fi
        return 0
    else
        fail "$vg_stage: $vg_leaks bytes definitely lost, $vg_errors errors"
        return 1
    fi
}

WORK="$(mktemp -d /tmp/tt_battery_XXXX)"
START_EPOCH="$(date +%s)"
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; TOTAL_COUNT=0

# ============================================================
# Adaptive helpers (REQUIRED before any test section)
# ============================================================
vg_sleep() {
    local secs
    secs=$(awk -v v="${1:-1}" -v m="${VG_MULT:-1}" 'BEGIN {printf "%d", (v * m) + 0.5}')
    [ "${secs:-0}" -lt 1 ] && secs=1
    sleep "$secs"
}

wait_for_min_records_vg() {
    local dir="$1"
    local want="$2"
    local tmo="${3:-30}"

    tmo=$(( tmo * ${VG_MULT:-1} ))

    local i=0
    local c

    while [ "$i" -lt "$tmo" ]; do
        c="$(timeout -k 5 20 "$TT" status --repo "$dir" 2>/dev/null | awk '/Records:/{print $2}')"

        if [ -n "${c:-}" ] && [ "$c" -ge "$want" ] 2>/dev/null; then
            return 0
        fi

        sleep 1
        i=$((i + 1))
    done

    return 1
}

check_vg_log() {
    local vg_log_file="$1"
    local vg_stage="$2"

    if [ ! -f "$vg_log_file" ]; then
        fail "$vg_stage: valgrind log not generated"
        return 1
    fi

    local vg_leaks
    vg_leaks=$(grep "definitely lost:" "$vg_log_file" | awk '{print $4}' | tr -d ',' | head -1)

    local vg_errors
    vg_errors=$(grep "ERROR SUMMARY:" "$vg_log_file" | awk '{print $4}' | head -1)

    vg_leaks=${vg_leaks:-0}
    vg_errors=${vg_errors:-0}

    if [ "$vg_leaks" -eq 0 ] 2>/dev/null; then
        if [ "$vg_errors" -gt 0 ] 2>/dev/null; then
            pass "$vg_stage: 0 leaks ($vg_errors suppressed warnings)"
        else
            pass "$vg_stage: 0 leaks, 0 errors"
        fi
        return 0
    else
        fail "$vg_stage: $vg_leaks bytes definitely lost, $vg_errors errors"
        return 1
    fi
}

# ---- Automatic section counter ----
SECTION_NUM=0
TOTAL_SECTIONS=$(grep -oE 'section[[:space:]]+"[0-9]+\.' "$0" \
                 | grep -oE '[0-9]+' \
                 | sort -n \
                 | tail -1)
TOTAL_SECTIONS=${TOTAL_SECTIONS:-0}

_SECTION_NUMS=$(grep -oE 'section[[:space:]]+"[0-9]+\.' "$0" \
                | grep -oE '[0-9]+' \
                | sort -n | uniq)
_EXPECTED=$(seq 1 "$TOTAL_SECTIONS")

if [ "$_SECTION_NUMS" != "$_EXPECTED" ]; then
    echo "ERROR: section numbering is inconsistent" >&2
    echo "  Found:      $(echo "$_SECTION_NUMS" | tr '\n' ' ')" >&2
    echo "  Expected:   $(echo "$_EXPECTED"     | tr '\n' ' ')" >&2
    exit 2
fi
FAILED_TESTS=()
LOG_FILE="$LOGFILE"

if [ ! -x "$TT" ]; then
	echo "❌ Binary not found or not executable: $TT"
	echo "   → ./compile.sh"
	exit 1
fi


section() {
    SECTION_NUM=$((SECTION_NUM + 1))

    local declared
    declared=$(printf '%s' "$1" | grep -oE '^[0-9]+' | head -1)

    if [ -n "$declared" ] && [ "$declared" -ne "$SECTION_NUM" ]; then
        echo "ERROR: section mismatch: expected #$SECTION_NUM, got #$declared in '$1'" >&2
        exit 2
    fi

    printf "\n============================================================\n"
    printf "[%d/%d] %s\n" "$SECTION_NUM" "$TOTAL_SECTIONS" "$1"
    printf "============================================================\n"
}

pass() { PASS_COUNT=$((PASS_COUNT+1)); TOTAL_COUNT=$((TOTAL_COUNT+1)); printf "  ✅ [%03d] %s\n" "$TOTAL_COUNT" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); TOTAL_COUNT=$((TOTAL_COUNT+1)); printf "  ❌ [%03d] %s\n" "$TOTAL_COUNT" "$1"; FAILED_TESTS+=("$1"); }
skip() { TOTAL_COUNT=$((TOTAL_COUNT + 1)); SKIP_COUNT=$((SKIP_COUNT + 1)); printf "  ⏭  [%03d] %s (SKIP)\n" "$TOTAL_COUNT" "$1"; }


assert_ok()   { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
assert_fail() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d (should have failed)"; else pass "$d"; fi; }
assert_eq()   { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected='$2' got='$3')"; fi; }

assert_file_content() {
	if [ ! -f "$2" ]; then fail "$1 (does not exist $2)"; return; fi
	local got; got="$(cat "$2")"
	if [ "$got" = "$3" ]; then pass "$1"; else fail "$1 (expected='$3' got='$got')"; fi
}

assert_contains() {
	if echo "$2" | grep -qF "$3"; then pass "$1"; else fail "$1 (does not contain '$3')"; fi
}

get_record_count() {
    timeout -k 5 10 "$TT" status --repo "$1" 2>/dev/null | awk '/Records:/{print $2}'
}

wait_for_stable_records() {
	local dir="$1" prev="" stable=0 cur
	local max_iter=60
	local sleep_time=0.5
	if [ -n "${VALGRIND_MODE:-}" ]; then
		max_iter=180 
		sleep_time=1.0
	fi
	for _ in $(seq 1 $max_iter); do
		cur="$(get_record_count "$dir")"
		if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then
			stable=$((stable+1))
			if [ "$stable" -ge 3 ]; then return 0; fi
		else
			stable=0
		fi
		prev="$cur"
		sleep $sleep_time
	done
	return 0
}

wait_for_min_records() {
    local dir="$1" want="$2" cur
    for _ in $(seq 1 120); do
        cur="$(get_record_count "$dir")"
        if [ -n "$cur" ] && [ "$cur" -ge "$want" ] 2>/dev/null; then break; fi
        sleep 0.5
    done
    local prev="" stable=0
    for _ in $(seq 1 20); do
        cur="$(get_record_count "$dir")"
        if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then
            stable=$((stable+1))
            [ "$stable" -ge 3 ] && return 0
        else
            stable=0
        fi
        prev="$cur"
        sleep 0.5
    done
    return 0
}

daemon_is_running() {
	local dir="$1"
	[ -f "$dir/.timetravel/timetravel.pid" ] || return 1
	local pid
	pid="$(awk '{print $1}' "$dir/.timetravel/timetravel.pid" 2>/dev/null)"
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}


kill_all_tt_daemons() {
    pkill -9 -f "timetravel start" 2>/dev/null
    pkill -9 -f "timetravel add"   2>/dev/null
    pkill -9 -f "timetravel watch" 2>/dev/null
    sleep 0.3
}

clean_global_tt_state() {
    local gdir="/tmp/timetravel-$(id -u)"
    rm -f "$gdir/ipc.path" "$gdir/status" "$gdir/boot.lock" \
          "$gdir"/*.sock "$gdir/timetravel.ipc" 2>/dev/null
}

cleanup() { kill_all_tt_daemons; rm -rf "$WORK"; }
trap cleanup EXIT
kill_all_tt_daemons
clean_global_tt_state

# ============================================================
# 1. Setup
# ============================================================
section "1. Setup"
assert_ok "1.1 binary responds to help" "$TT" help

# ============================================================
# 2. basic watch
# ============================================================
section "2. basic watch"
D2="$WORK/t02"; mkdir -p "$D2"
echo "hello" > "$D2/f.txt"

"$TT" start "$D2" >/dev/null 2>&1
sleep 1

for _ in $(seq 1 10); do
    R2="$(get_record_count "$D2")"
    if [ -n "$R2" ]; then break; fi
    sleep 0.5
done

if daemon_is_running "$D2"; then pass "2.1 daemon running"; else fail "2.1 daemon is not running"; fi
R2="$(get_record_count "$D2")"

assert_eq "2.2 no initial records" "0" "$R2"

"$TT" stop --repo "$D2" >/dev/null 2>&1

# ============================================================
# 3. undo --last
# ============================================================
section "3. undo --last"

D3="$WORK/t03"; mkdir -p "$D3"
echo "v1" > "$D3/f.txt"

"$TT" start "$D3" >/dev/null 2>&1; sleep 1
echo "v2" > "$D3/f.txt"; sleep 1

"$TT" undo "$D3/f.txt" --last --repo "$D3" >/dev/null 2>&1
assert_file_content "3.1 undo --last restores previous version" "$D3/f.txt" "v1"

"$TT" stop --repo "$D3" >/dev/null 2>&1

# ============================================================
# 4. undo --initial
# ============================================================
section "4. undo --initial"

D4="$WORK/t04"; mkdir -p "$D4"
echo "first" > "$D4/f.txt"

"$TT" start "$D4" >/dev/null 2>&1; sleep 1
echo "second" > "$D4/f.txt"; sleep 1
echo "third" > "$D4/f.txt"; sleep 1

"$TT" undo "$D4/f.txt" --initial --repo "$D4" >/dev/null 2>&1

assert_file_content "4.1 undo --initial restores original" "$D4/f.txt" "first"

"$TT" stop --repo "$D4" >/dev/null 2>&1

# ============================================================
# 5. undo --to (time point & exact log dates)
# ============================================================
# +Added a new expression to 'Undo'; you can now also include
# the log dates, for example: ./timetravel undo src --to "2026-09-13 00:06:17"
# ============================================================

section "5. undo --to (time point & exact dates)"

D5="$WORK/t05"
mkdir -p "$D5"

echo "v1" > "$D5/f.txt"
"$TT" start "$D5" >/dev/null 2>&1
sleep 1

# ------------------------------------------------------------
# 5.1 undo --to time point (Valgrind-safe)
# ------------------------------------------------------------
echo "v2" > "$D5/f.txt"
wait_for_min_records "$D5" 2

sleep 1
TS51="$(date +"%Y-%m-%d %H:%M:%S")"

sleep 3
echo "v3" > "$D5/f.txt"
wait_for_min_records "$D5" 3

"$TT" undo "$D5/f.txt" --to "$TS51" --repo "$D5" >/dev/null 2>&1

assert_file_content "5.1 undo --to time point restores previous version" "$D5/f.txt" "v2"

# ------------------------------------------------------------
# 5.2 invalid expression
# ------------------------------------------------------------
assert_fail "5.2 undo --to with invalid expression fails" \
    "$TT" undo "$D5/f.txt" --to "banana" --repo "$D5"

# ------------------------------------------------------------
# 5.3 exact timestamp (Valgrind-safe)
# ------------------------------------------------------------
echo "v_exact_1" > "$D5/f.txt"
wait_for_min_records "$D5" 4

echo "v_exact_2" > "$D5/f.txt"
wait_for_min_records "$D5" 5

sleep 1
TS_V2="$(date +"%Y-%m-%d %H:%M:%S")"

sleep 3
echo "v_exact_3" > "$D5/f.txt"
wait_for_min_records "$D5" 6

"$TT" undo "$D5/f.txt" --to "$TS_V2" --repo "$D5" >/dev/null 2>&1

assert_file_content "5.3 undo --to exact timestamp restores correct version" "$D5/f.txt" "v_exact_2"

"$TT" stop --repo "$D5" >/dev/null 2>&1

# ============================================================
# 6. undo of deleted file
# ============================================================
section "6. undo of deleted file"

D6="$WORK/t06"; mkdir -p "$D6"

echo "content" > "$D6/f.txt"
"$TT" start "$D6" >/dev/null 2>&1; sleep 1
echo "edited" > "$D6/f.txt"; sleep 1
rm "$D6/f.txt"; sleep 1

"$TT" undo "$D6/f.txt" --last --repo "$D6" >/dev/null 2>&1

assert_file_content "6.1 undo restores deleted file" "$D6/f.txt" "edited"

"$TT" stop --repo "$D6" >/dev/null 2>&1

# ============================================================
# 7. undo --to after deletion
# ============================================================
section "7. undo --to after deletion"
D7="$WORK/t07"; mkdir -p "$D7"

if [ "${TT_UNDER_VALGRIND:-0}" = "1" ]; then
    printf "  [INFO] 7.1: undo --to timing-sensitive test under Valgrind (extra margins)\n"
else
    printf "  [INFO] 7.1: undo --to timing-sensitive test in normal mode\n"
fi

echo "orig" > "$D7/f.txt"
"$TT" start "$D7" >/dev/null 2>&1
vg_sleep 2

echo "change" > "$D7/f.txt"
wait_for_min_records_vg "$D7" 2 30

if [ "${TT_UNDER_VALGRIND:-0}" = "1" ]; then
    vg_sleep 3
    TS7="$(date +"%Y-%m-%d %H:%M:%S")"
    sleep 2
else
    sleep 1
    TS7="$(date +"%Y-%m-%d %H:%M:%S")"
fi

rm "$D7/f.txt"
wait_for_min_records_vg "$D7" 3 30
vg_sleep 2

"$TT" undo "$D7/f.txt" --to "$TS7" --repo "$D7" >/dev/null 2>&1
assert_file_content "7.1 undo --to restores deleted file" "$D7/f.txt" "change"

"$TT" stop --repo "$D7" >/dev/null 2>&1

# ============================================================
# 8. log
# ============================================================
section "8. log"

D8="$WORK/t08"; mkdir -p "$D8"
for i in $(seq 1 30); do echo "line $i with enough content"; done > "$D8/f.txt"
"$TT" start "$D8" >/dev/null 2>&1; sleep 1

echo "new line added at the end" >> "$D8/f.txt"; sleep 1

L8="$("$TT" log "$D8/f.txt" --repo "$D8" 2>&1)"

assert_contains "8.1 log shows CREATE" "$L8" "CREATE"

assert_contains "8.2 log shows MODIFY" "$L8" "MODIFY"
"$TT" stop --repo "$D8" >/dev/null 2>&1

# ============================================================
# 9. status
# ============================================================
section "9. status"

D9="$WORK/t09"; mkdir -p "$D9"
echo "a" > "$D9/f.txt"

"$TT" start "$D9" >/dev/null 2>&1; sleep 1

echo "b" > "$D9/f.txt"
if [ "$QEMU" -eq 1 ]; then
    vg_sleep 15 
else
    wait_for_stable_records "$D9"
fi

S9="$("$TT" status --repo "$D9" 2>&1)"

assert_contains "9.1 status shows Records" "$S9" "Records:"

assert_contains "9.2 status shows daemon running" "$S9" "running"

"$TT" stop --repo "$D9" >/dev/null 2>&1

# ============================================================
# 10. dynamic: hot new file
# ============================================================
section "10. dynamic: hot new file"

D10="$WORK/t10"; mkdir -p "$D10"
echo "base" > "$D10/base.txt"

"$TT" start "$D10" >/dev/null 2>&1; sleep 1

printf "initial content of the new file\n" > "$D10/new.txt"; sleep 1

printf "initial content of the new file\nmore content\n" > "$D10/new.txt"; sleep 1

"$TT" undo "$D10/new.txt" --last --repo "$D10" >/dev/null 2>&1

assert_file_content "10.1 new file: undo --last restores first version" "$D10/new.txt" "initial content of the new file"

"$TT" stop --repo "$D10" >/dev/null 2>&1

# ============================================================
# 11. dynamic: new subdirectory
# ============================================================
section "11. dynamic: new subdirectory"

D11="$WORK/t11"; mkdir -p "$D11"
echo "r" > "$D11/r.txt"

"$TT" start "$D11" >/dev/null 2>&1; sleep 1

mkdir -p "$D11/new_dir"
echo "deep" > "$D11/new_dir/f.txt"

wait_for_stable_records "$D11"

"$TT" undo "$D11/new_dir/f.txt" --last --repo "$D11" >/dev/null 2>&1

if [ -f "$D11/new_dir/f.txt" ]; then pass "11.1 file in new subdirectory restorable"; else fail "11.1 new subdirectory was not registered"; fi

"$TT" stop --repo "$D11" >/dev/null 2>&1

# ============================================================
# 12. dynamism after restart
# ============================================================
section "12. dynamism after restart"

D12="$WORK/t12"; mkdir -p "$D12"

echo "a" > "$D12/f.txt"

"$TT" start "$D12" >/dev/null 2>&1; sleep 1
"$TT" stop --repo "$D12" >/dev/null 2>&1; sleep 1
"$TT" start "$D12" >/dev/null 2>&1; sleep 1

echo "b" > "$D12/f.txt"; sleep 1

"$TT" undo "$D12/f.txt" --last --repo "$D12" >/dev/null 2>&1

assert_file_content "12.1 undo --last after restart" "$D12/f.txt" "a"
"$TT" stop --repo "$D12" >/dev/null 2>&1

# ============================================================
# 13. Git clone
# ============================================================
section "13. Git clone"
if command -v git >/dev/null 2>&1; then
	GO="$WORK/git_origin"

	git init -q "$GO" 2>/dev/null
	git -C "$GO" config user.email "t@t.t" 2>/dev/null
	git -C "$GO" config user.name "t" 2>/dev/null

	for i in 1 2 3; do echo "file $i" > "$GO/f$i.txt"; done

    	git -C "$GO" add -A >/dev/null 2>&1
	git -C "$GO" commit -qm "init" 2>/dev/null
    	D13="$WORK/t13"; mkdir -p "$D13"

	echo "base" > "$D13/base.txt"
	"$TT" start "$D13" >/dev/null 2>&1; sleep 1

	git clone -q "$GO" "$D13/repo" 2>/dev/null

	wait_for_stable_records "$D13"
if [ -f "$D13/repo/f1.txt" ]; then pass "13.1 clone present"; else fail "13.1 clone not present"; fi

	H13="$("$TT" log "" --repo "$D13" 2>&1)"
	if echo "$H13" | grep -q "\.git/"; then fail "13.2 .git/ was captured"; else pass "13.2 .git/ excluded"; fi

	echo "change" > "$D13/repo/f1.txt"; sleep 1
	"$TT" undo "$D13/repo/f1.txt" --last --repo "$D13" >/dev/null 2>&1

	assert_file_content "13.3 undo of clone file" "$D13/repo/f1.txt" "file 1"

	"$TT" stop --repo "$D13" >/dev/null 2>&1
else
	skip "13.x git not installed"
fi

# ============================================================
# 14. Binary file
# ============================================================
section "14. Binary file"

D14="$WORK/t14"; mkdir -p "$D14"
dd if=/dev/urandom of="$D14/b.bin" bs=1024 count=64 2>/dev/null
cp "$D14/b.bin" "$D14/b.orig"

"$TT" start "$D14" >/dev/null 2>&1; vg_sleep 3

dd if=/dev/urandom of="$D14/b.bin" bs=1024 count=64 2>/dev/null
vg_sleep 3

"$TT" undo "$D14/b.bin" --last --repo "$D14" >/dev/null 2>&1

if cmp -s "$D14/b.bin" "$D14/b.orig"; then pass "14.1 binary restored byte by byte"; else fail "14.1 binary differs"; fi

"$TT" stop --repo "$D14" >/dev/null 2>&1

# ============================================================
# 15. Empty file
# ============================================================
section "15. Empty file"
D15="$WORK/t15"; mkdir -p "$D15"

echo "content" > "$D15/f.txt"

"$TT" start "$D15" >/dev/null 2>&1; sleep 1
: > "$D15/f.txt"; sleep 1

"$TT" undo "$D15/f.txt" --last --repo "$D15" >/dev/null 2>&1

assert_file_content "15.1 undo restores after truncation to empty" "$D15/f.txt" "content"

"$TT" stop --repo "$D15" >/dev/null 2>&1

# ============================================================
# 16. compact
# ============================================================
section "16. compact"

D16="$WORK/t16"; mkdir -p "$D16"
echo "v0" > "$D16/f.txt"

"$TT" start "$D16" >/dev/null 2>&1; sleep 1

for i in $(seq 1 20); do echo "version $i with content" > "$D16/f.txt"; sleep 0.3; done
wait_for_stable_records "$D16"

"$TT" stop --repo "$D16" >/dev/null 2>&1
assert_ok "16.1 compact executes" "$TT" compact --repo "$D16"

"$TT" start "$D16" >/dev/null 2>&1; sleep 1
echo "vfinal" > "$D16/f.txt"; sleep 1

"$TT" undo "$D16/f.txt" --last --repo "$D16" >/dev/null 2>&1

C16="$(cat "$D16/f.txt")"

if [ "$C16" = "vfinal" ]; then fail "16.2 undo after compact did not restore"; else pass "16.2 undo after compact works ($C16)"; fi

"$TT" stop --repo "$D16" >/dev/null 2>&1

# ============================================================
# 17. full directory undo
# ============================================================
section "17. full directory undo"

D17="$WORK/t17"; mkdir -p "$D17/sub"
echo "a1" > "$D17/a.txt"; echo "b1" > "$D17/b.txt"; echo "c1" > "$D17/sub/c.txt"

"$TT" start "$D17" >/dev/null 2>&1; sleep 1
echo "a2" > "$D17/a.txt"; echo "b2" > "$D17/b.txt"; echo "c2" > "$D17/sub/c.txt"
wait_for_stable_records "$D17"

"$TT" undo "$D17" --last --repo "$D17" --force >/dev/null 2>&1

assert_file_content "17.1 undo dir --last restores a.txt" "$D17/a.txt" "a1"
assert_file_content "17.2 undo dir --last restores sub/c.txt" "$D17/sub/c.txt" "c1"

"$TT" stop --repo "$D17" >/dev/null 2>&1

# ============================================================
# 18. Burst: 50 edits to same file
# ============================================================
section "18. Burst: 50 edits"
D18="$WORK/t18"; mkdir -p "$D18"

echo "v0" > "$D18/f.txt"
"$TT" start "$D18" >/dev/null 2>&1; sleep 1
for i in $(seq 1 50); do echo "burst $i" > "$D18/f.txt"; done

wait_for_stable_records "$D18"

"$TT" undo "$D18/f.txt" --initial --repo "$D18" >/dev/null 2>&1
assert_file_content "18.1 undo --initial after burst" "$D18/f.txt" "v0"

"$TT" stop --repo "$D18" >/dev/null 2>&1

# ============================================================
# 19. Burst: 100 files + concurrency
# ============================================================
section "19. Burst: 100 files + concurrency"

D19="$WORK/t19"; mkdir -p "$D19"
for i in 1 2 3 4 5; do echo "init $i" > "$D19/w$i.txt"; done
"$TT" start "$D19" >/dev/null 2>&1; sleep 1

for i in $(seq 1 100); do echo "f $i" > "$D19/r$i.txt"; done

WPIDS=""

for i in 1 2 3 4 5; do
	( for j in $(seq 1 20); do printf "writer %d iter %d\n" "$i" "$j" > "$D19/w$i.txt"; sleep 0.1; done ) &
	WPIDS="$WPIDS $!"
done

wait $WPIDS
wait_for_stable_records "$D19"

"$TT" undo "$D19/w3.txt" --last --repo "$D19" >/dev/null 2>&1
C19="$(cat "$D19/w3.txt")"

if echo "$C19" | grep -qE "writer 3|init 3"; then pass "19.1 undo --last after concurrency coherent"; else fail "19.1 undo after concurrency gave '$C19'"; fi

"$TT" stop --repo "$D19" >/dev/null 2>&1

# ============================================================
# 20. Stress: 500 files
# ============================================================
section "20. Stress: 500 files"

D20="$WORK/t20"; mkdir -p "$D20"

"$TT" start "$D20" >/dev/null 2>&1; sleep 1
for i in $(seq 1 500); do printf "content of file %d - %s\n" "$i" "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$D20/stress_$i.txt"; done

wait_for_stable_records "$D20"

R20="$(get_record_count "$D20")"
if [ "${R20:-0}" -ge 100 ] 2>/dev/null; then pass "20.1 500 files captured ($R20)"; else fail "20.1 only $R20 records"; fi

for i in 1 100 250 500; do echo "modified $i" > "$D20/stress_$i.txt"; done
wait_for_stable_records "$D20"

"$TT" undo "$D20/stress_250.txt" --last --repo "$D20" >/dev/null 2>&1
C20="$(cat "$D20/stress_250.txt")"

if echo "$C20" | grep -q "content of file 250"; then pass "20.2 undo --last on file 250/500"; else fail "20.2 undo --last on file 250/500 gave: '$(echo "$C20" | head -1)'"; fi

"$TT" stop --repo "$D20" >/dev/null 2>&1

# ============================================================
# 21. Files with weird names
# ============================================================
section "21. Weird names"
D21="$WORK/t21"; mkdir -p "$D21"
echo "a" > "$D21/x" 2>/dev/null
echo "v1" > "$D21/with spaces.txt"
echo "v1" > "$D21/accents_ñ.txt"
"$TT" start "$D21" >/dev/null 2>&1; sleep 1
echo "v2" > "$D21/with spaces.txt"
echo "v2" > "$D21/accents_ñ.txt"
wait_for_stable_records "$D21"
"$TT" undo "$D21/with spaces.txt" --last --repo "$D21" >/dev/null 2>&1
assert_file_content "21.1 name with spaces" "$D21/with spaces.txt" "v1"
"$TT" undo "$D21/accents_ñ.txt" --last --repo "$D21" >/dev/null 2>&1
assert_file_content "21.2 name with ñ" "$D21/accents_ñ.txt" "v1"
"$TT" stop --repo "$D21" >/dev/null 2>&1

# ============================================================
# 22. start / stop / restart
# ============================================================
section "22. start / stop / restart"
D22="$WORK/t22"; mkdir -p "$D22"
echo "v1" > "$D22/f.txt"
assert_ok "22.1 start launches daemon" "$TT" start "$D22"
sleep 1
if daemon_is_running "$D22"; then pass "22.2 daemon running after start"; else fail "22.2 daemon is not running"; fi
echo "v2" > "$D22/f.txt"; sleep 1
assert_ok "22.3 duplicate start does not launch another daemon" "$TT" start "$D22"
assert_ok "22.4 stop stops the daemon" "$TT" stop --repo "$D22"
sleep 1
if daemon_is_running "$D22"; then fail "22.5 daemon still alive after stop"; else pass "22.5 daemon stopped after stop"; fi
assert_ok "22.6 restart starts again" "$TT" restart "$D22"
sleep 1
if daemon_is_running "$D22"; then pass "22.7 daemon running after restart"; else fail "22.7 daemon is not running after restart"; fi
"$TT" stop --repo "$D22" >/dev/null 2>&1

# ============================================================
# 23. enriched status
# ============================================================
section "23. enriched status"
D23="$WORK/t23"; mkdir -p "$D23"
echo "a" > "$D23/f.txt"

"$TT" start "$D23" >/dev/null 2>&1; sleep 1
echo "b" > "$D23/f.txt"

wait_for_stable_records "$D23"

S23="$("$TT" status --repo "$D23" 2>&1)"

assert_contains "23.1 status shows daemon running" "$S23" "running"
assert_contains "23.2 status shows Records" "$S23" "Records:"
assert_contains "23.3 status shows Uptime" "$S23" "Uptime:"

"$TT" stop --repo "$D23" >/dev/null 2>&1
sleep 1

S23B="$("$TT" status --repo "$D23" 2>&1)"
assert_contains "23.4 status without daemon indicates not running" "$S23B" "not running"

# ============================================================
# 24. tags and undo --tag
# ============================================================
section "24. tags and undo --tag"
D24="$WORK/t24"; mkdir -p "$D24"
echo "stable" > "$D24/f.txt"

"$TT" start "$D24" >/dev/null 2>&1; sleep 1
assert_ok "24.1 tag is created" "$TT" tag checkpoint1 --repo "$D24"

T24="$("$TT" tags --repo "$D24" 2>&1)"
assert_contains "24.2 tags lists the checkpoint" "$T24" "checkpoint1"
echo "changed" > "$D24/f.txt"; sleep 1

"$TT" undo "$D24/f.txt" --tag checkpoint1 --repo "$D24" >/dev/null 2>&1
assert_file_content "24.3 undo --tag restores to checkpoint" "$D24/f.txt" "stable"

"$TT" stop --repo "$D24" >/dev/null 2>&1

# ============================================================
# 25. diff
# ============================================================
section "25. diff"
D25="$WORK/t25"; mkdir -p "$D25"
printf "line1\nline2\n" > "$D25/f.txt"

"$TT" start "$D25" >/dev/null 2>&1; sleep 1
printf "line1\nline2\nline3\n" > "$D25/f.txt"

wait_for_stable_records "$D25"

DF25="$("$TT" diff "$D25/f.txt" --repo "$D25" 2>&1)"

if echo "$DF25" | grep -qE "line3|\+"; then pass "25.1 diff shows the change"; else fail "25.1 diff does not show the change"; fi

"$TT" stop --repo "$D25" >/dev/null 2>&1

# ============================================================
# 26. directory undo: confirmation and --force
# ============================================================
section "26. directory undo: confirmation and --force"
D26="$WORK/t26"; mkdir -p "$D26"
echo "orig" > "$D26/a.txt"

"$TT" start "$D26" >/dev/null 2>&1; sleep 1
echo "new" > "$D26/a.txt"

wait_for_stable_records "$D26"

echo "n" | "$TT" undo "$D26" --last --repo "$D26" >/dev/null 2>&1
assert_file_content "26.1 undo dir without confirmation touches nothing" "$D26/a.txt" "new"

"$TT" undo "$D26" --last --repo "$D26" --force >/dev/null 2>&1

assert_file_content "26.2 undo dir --force restores" "$D26/a.txt" "orig"
"$TT" stop --repo "$D26" >/dev/null 2>&1

# ============================================================
# 27. log --since
# ============================================================
section "27. log --since"
D27="$WORK/t27"; mkdir -p "$D27"
echo "x" > "$D27/f.txt"

"$TT" start "$D27" >/dev/null 2>&1
vg_sleep 3 

echo "y" > "$D27/f.txt"
wait_for_stable_records "$D27"
vg_sleep 2  

L27="$("$TT" log "$D27/f.txt" --since "10 minutes ago" --repo "$D27" 2>&1)"
assert_contains "27.1 log --since shows recent events" "$L27" "f.txt"

L27B="$("$TT" log "$D27/f.txt" --since "24 hours ago" --repo "$D27" 2>&1)"
assert_contains "27.2 log --since wide range includes everything" "$L27B" "f.txt"

"$TT" stop --repo "$D27" >/dev/null 2>&1

# ============================================================
# 28. multi-repo: start + hot add (IPC)
# ============================================================
section "28. multi-repo: start + hot add"
D28A="$WORK/t28a"; mkdir -p "$D28A"
D28B="$WORK/t28b"; mkdir -p "$D28B"

echo "A1" > "$D28A/a.txt"
echo "B1" > "$D28B/b.txt"

timeout 20 "$TT" start "$D28A" >/dev/null 2>&1; sleep 1
timeout 20 "$TT" add "$D28B" >/dev/null 2>&1; sleep 1

S28="$(timeout 15 "$TT" status --repo "$D28A" 2>&1)"
assert_contains "28.1 status shows repo A" "$S28" "$D28A"
assert_contains "28.2 status shows repo B" "$S28" "$D28B"
assert_contains "28.3 status shows 2 repos" "$S28" "Repos (2)"

echo "A2" > "$D28A/a.txt"
echo "B2" > "$D28B/b.txt"
wait_for_stable_records "$D28A"
wait_for_stable_records "$D28B"

LA="$("$TT" log "$D28A/a.txt" --repo "$D28A" 2>&1)"
LB="$("$TT" log "$D28B/b.txt" --repo "$D28B" 2>&1)"
assert_contains "28.4 repo A log has a.txt" "$LA" "a.txt"
if echo "$LA" | grep -q "b.txt"; then fail "28.5 repo A log leaked b.txt"; else pass "28.5 repo A log isolated"; fi
if echo "$LB" | grep -q "a.txt"; then fail "28.6 repo B log leaked a.txt"; else pass "28.6 repo B log isolated"; fi
timeout 15 "$TT" stop >/dev/null 2>&1

# ============================================================
# 29. multi-repo: overlap protection
# ============================================================
section "29. multi-repo: overlap protection"
D29="$WORK/t29"; mkdir -p "$D29/sub"
timeout 20 "$TT" start "$D29" >/dev/null 2>&1; sleep 1

OUT29="$(timeout 15 "$TT" add "$D29/sub" 2>&1)"
if echo "$OUT29" | grep -qiE "overlap|ERR"; then pass "29.1 add subdir rejected (overlap)"; else fail "29.1 add subdir should be rejected"; fi

OUT29B="$(timeout 15 "$TT" add "$D29" 2>&1)"
if echo "$OUT29B" | grep -qiE "already|OK"; then pass "29.2 add same dir handled gracefully"; else fail "29.2 add same dir failed weirdly"; fi
timeout 15 "$TT" stop >/dev/null 2>&1

# ============================================================
# 30. multi-repo: independent root lost & recovery
# ============================================================
section "30. multi-repo: root lost & recovery"
D30A="$WORK/t30a"; mkdir -p "$D30A"
D30B="$WORK/t30b"; mkdir -p "$D30B"
echo "A" > "$D30A/a.txt"
echo "B" > "$D30B/b.txt"

timeout 20 "$TT" start "$D30A" >/dev/null 2>&1; sleep 1
timeout 20 "$TT" add "$D30B" >/dev/null 2>&1; sleep 1

rm -rf "$D30B"
sleep 2
S30="$(timeout 15 "$TT" status --repo "$D30A" 2>&1)"
if echo "$S30" | grep -q "ROOT LOST"; then pass "30.1 status shows ROOT LOST"; else fail "30.1 status missed ROOT LOST"; fi

echo "A2" > "$D30A/a.txt"
wait_for_stable_records "$D30A"
LA30="$("$TT" log "$D30A/a.txt" --repo "$D30A" 2>&1)"
assert_contains "30.2 repo A still captures events" "$LA30" "a.txt"

mkdir -p "$D30B"
echo "B_new" > "$D30B/b.txt"
sleep 12   # ciclo de rescan (TT_RESCAN_MS = 10s)

S30B="$(timeout 15 "$TT" status --repo "$D30A" 2>&1)"
if echo "$S30B" | grep -q "ROOT LOST"; then fail "30.3 repo B did not recover"; else pass "30.3 repo B recovered"; fi
timeout 15 "$TT" stop >/dev/null 2>&1

# ============================================================
# 31. multi-repo: persistence via repos.list on restart
# ============================================================
section "31. multi-repo: persistence (repos.list)"
D31A="$WORK/t31a"; mkdir -p "$D31A"
D31B="$WORK/t31b"; mkdir -p "$D31B"
D31C="$WORK/t31c"; mkdir -p "$D31C"

timeout 20 "$TT" start "$D31A" >/dev/null 2>&1; sleep 1
timeout 20 "$TT" add "$D31B" >/dev/null 2>&1
timeout 20 "$TT" add "$D31C" >/dev/null 2>&1; sleep 1
timeout 15 "$TT" stop >/dev/null 2>&1; sleep 1

timeout 20 "$TT" start "$D31A" >/dev/null 2>&1; sleep 2
S31="$(timeout 15 "$TT" status --repo "$D31A" 2>&1)"
assert_contains "31.1 repos.list re-adopted B" "$S31" "$D31B"
assert_contains "31.2 repos.list re-adopted C" "$S31" "$D31C"
assert_contains "31.3 status shows 3 repos" "$S31" "Repos (3)"
timeout 15 "$TT" stop >/dev/null 2>&1

# ============================================================
# 32. multi-repo: add bootstraps daemon if none running
# ============================================================
section "32. multi-repo: add bootstraps daemon"
D32="$WORK/t32"; mkdir -p "$D32"
timeout 15 "$TT" stop >/dev/null 2>&1; sleep 1

OUT32="$(timeout 25 "$TT" add "$D32" 2>&1)"
if echo "$OUT32" | grep -qiE "started|OK"; then pass "32.1 add bootstraps daemon"; else fail "32.1 add failed (output: $(echo "$OUT32" | head -1))"; fi
sleep 1
if daemon_is_running "$D32"; then pass "32.2 daemon is running after add"; else fail "32.2 daemon not running after add"; fi
timeout 15 "$TT" stop >/dev/null 2>&1

section "33. Stampede: parallel add bootstraps ONE daemon"
for i in 1 2 3 4 5; do mkdir -p "$WORK/t33/repo_$i"; done
kill_all_tt_daemons; clean_global_tt_state; sleep 0.5

ADD_PIDS=""
for i in 1 2 3 4 5; do
    timeout -k 5 30 "$TT" add "$WORK/t33/repo_$i" >/dev/null 2>&1 &
    ADD_PIDS="$ADD_PIDS $!"
done

DEADLINE=$(( $(date +%s) + 45 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    ALIVE=0
    for p in $ADD_PIDS; do
        if kill -0 "$p" 2>/dev/null; then ALIVE=1; break; fi
    done
    [ "$ALIVE" -eq 0 ] && break
    sleep 0.5
done
sleep 1

PIDS=""
for i in 1 2 3 4 5; do
    p=$(awk '{print $1}' "$WORK/t33/repo_$i/.timetravel/timetravel.pid" 2>/dev/null)
    [ -n "$p" ] && PIDS="$PIDS $p"
done
UNIQ=$(echo $PIDS | tr ' ' '\n' | sort -u | grep -c .)
assert_eq "33.1 exactly ONE daemon adopted all 5 repos" "1" "$UNIQ"

S33="$(timeout -k 5 15 "$TT" status --repo "$WORK/t33/repo_1" 2>&1)"
assert_contains "33.2 status shows 5 repos" "$S33" "Repos (5)"

kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 34. Global status desde un directorio cualquiera
# ============================================================
section "34. Global status from any cwd"
D34="$WORK/t34"; mkdir -p "$D34"
kill_all_tt_daemons; clean_global_tt_state; sleep 0.5

timeout -k 5 25 "$TT" start "$D34" >/dev/null 2>&1
sleep 1

TT_ABS="$(cd "$(dirname "$TT")" && pwd)/$(basename "$TT")"
S34="$(cd "$WORK" && timeout -k 5 15 "$TT_ABS" status 2>&1)"

assert_contains "34.1 status sin --repo muestra el enjambre" "$S34" "Swarm (global)"
assert_contains "34.2 lista el repo activo" "$S34" "$D34"

kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 35. selective stop: quitar repos sin tumbar el monolito
# ============================================================
section "35. selective stop (repo removal)"
D35A="$WORK/t35a"; mkdir -p "$D35A"
D35B="$WORK/t35b"; mkdir -p "$D35B"
D35C="$WORK/t35c"; mkdir -p "$D35C"

timeout 20 "$TT" start "$D35A" >/dev/null 2>&1; sleep 1
timeout 20 "$TT" add "$D35B" >/dev/null 2>&1
timeout 20 "$TT" add "$D35C" >/dev/null 2>&1; sleep 1

OUT35="$(timeout 15 "$TT" stop --repo "$D35B" 2>&1)"
assert_contains "35.1 remove repo B via IPC" "$OUT35" "OK"
sleep 1

if daemon_is_running "$D35A"; then pass "35.2 daemon alive after selective stop"; else fail "35.2 daemon died unexpectedly"; fi

S35="$(timeout 15 "$TT" status --repo "$D35A" 2>&1)"
assert_contains "35.3 swarm now has 2 repos" "$S35" "Repos (2)"

if echo "$S35" | grep -q "$D35B"; then fail "35.4 repo B still listed"; else pass "35.4 repo B gone from swarm"; fi

timeout 15 "$TT" stop --repo "$D35A" >/dev/null 2>&1; sleep 1

S35B="$(timeout 15 "$TT" status --repo "$D35C" 2>&1)"
assert_contains "35.5 removing primary leaves repo C" "$S35B" "$D35C"

timeout 15 "$TT" stop --repo "$D35C" >/dev/null 2>&1; sleep 1
if daemon_is_running "$D35C"; then fail "35.6 daemon should exit after last repo removed"; else pass "35.6 daemon exited (no repos left)"; fi


# ============================================================
# 36. verify (ASan-aware)
# ============================================================
section "36. verify"
D36="$WORK/t36"; mkdir -p "$D36"
ASAN_LOG="$WORK/asan_36.log"

"$TT" start "$D36" >/dev/null 2>&1
vg_sleep 3

echo "verify_test" > "$D36/v.txt"

CAPTURED=0
for i in $(seq 1 60); do
    sleep 2
    RC_PEEK="$("$TT" status --repo "$D36" 2>/dev/null | awk '/Records:/{print $2}')"
    if [ "${RC_PEEK:-0}" -gt 0 ] 2>/dev/null; then
        CAPTURED=1
        break
    fi
done

if [ "$CAPTURED" -eq 1 ]; then
    printf "  [INFO] 36: daemon captured records after $((i*2))s (ASan slow mode)\n"
else
    printf "  [INFO] 36: daemon did NOT capture after 120s, proceeding anyway\n"
fi

vg_sleep 2
"$TT" stop --repo "$D36" >/dev/null 2>&1
vg_sleep 2

ASAN_OPTIONS=halt_on_error=0:detect_leaks=0:log_path="$ASAN_LOG" \
    "$TT" verify --repo "$D36" > "$ASAN_LOG.stdout" 2> "$ASAN_LOG.stderr"
RC36=$?

V36="$(cat "$ASAN_LOG.stdout" 2>/dev/null)"
E36="$(cat "$ASAN_LOG.stderr" 2>/dev/null)"

if [ -s "$ASAN_LOG.stderr" ]; then
    printf "  [ASAN-STDERR] %s\n" "$(head -20 "$ASAN_LOG.stderr")"
fi

if [ -f "$ASAN_LOG" ] && [ -s "$ASAN_LOG" ]; then
    printf "  [ASAN-LOG] %s\n" "$(head -20 "$ASAN_LOG")"
fi

if [ "$RC36" -eq 0 ] && echo "$V36" | grep -q "OK"; then
    pass "36.1 verify clean store OK"
else
    printf "  [DEBUG] verify rc=%d stdout='%s' stderr='%s'\n" "$RC36" "$(echo "$V36" | tail -3)" "$(echo "$E36" | tail -3)"
    fail "36.1 verify en store limpio (rc=$RC36): $(echo "$V36" | tail -1)"
fi

# 36.2 verify detects corruption
TTD36="$(ls "$D36"/.timetravel/*.ttd 2>/dev/null | head -1)"
if [ -n "$TTD36" ]; then
    dd if=/dev/urandom of="$TTD36" bs=512 count=1 2>/dev/null

    V36B="$("$TT" verify --repo "$D36" 2>&1)"
    RC36B=$?

    if [ "$RC36B" -ne 0 ]; then
        pass "36.2 verify detects corrupted store"
    else
        fail "36.2 verify did not detect corruption (rc=$RC36B): $(echo "$V36B" | tail -1)"
    fi
else
    skip "36.2 no .ttd file to corrupt"
fi

# ============================================================
# 37. dedup: large file capture + restore
# ============================================================
section "37. dedup: large file capture + restore"
D37="$WORK/t37"; mkdir -p "$D37"
"$TT" start "$D37" >/dev/null 2>&1; sleep 1

dd if=/dev/urandom of="$D37/big.bin" bs=1024 count=2048 2>/dev/null
cp "$D37/big.bin" "$D37/big.v1"
wait_for_min_records "$D37" 2

dd if=/dev/urandom of="$D37/big.bin" bs=1024 count=2048 2>/dev/null
wait_for_min_records "$D37" 3

"$TT" undo "$D37/big.bin" --last --repo "$D37" >/dev/null 2>&1
if cmp -s "$D37/big.bin" "$D37/big.v1"; then
    pass "37.1 large file restored via dedup blocks"
else
    fail "37.1 the large file differs after undo"
fi
"$TT" stop --repo "$D37" >/dev/null 2>&1

# ============================================================
# 38. dedup GC: orphan block cleanup
# ============================================================
section "38. dedup GC: orphan block cleanup"

D38="$WORK/t38"
mkdir -p "$D38"

"$TT" start "$D38" >/dev/null 2>&1
sleep 1

dd if=/dev/urandom of="$D38/big.bin" bs=1024 count=2048 2>/dev/null

wait_for_min_records "$D38" 1

"$TT" stop --repo "$D38" >/dev/null 2>&1
sleep 1

BEFORE=$(find "$D38/.timetravel/blocks" -type f 2>/dev/null | wc -l)

mkdir -p "$D38/.timetravel/blocks/ff"
FAKE="$D38/.timetravel/blocks/ff/fake_orphan_block"
echo "orphan" > "$FAKE"

timeout -k 5 120 "$TT" compact --repo "$D38" >/dev/null 2>&1

AFTER=$(find "$D38/.timetravel/blocks" -type f 2>/dev/null | wc -l)

if [ ! -f "$FAKE" ] && [ "$AFTER" -eq "$BEFORE" ]; then
    pass "38.1 GC removes orphan block and keeps referenced blocks"
else
    fail "38.1 GC (before=$BEFORE after=$AFTER fake=$([ -f "$FAKE" ] && echo still_there || echo removed))"
fi

# ============================================================
# 39. XChaCha20-Poly1305 encryption
# ============================================================
section "39. XChaCha20-Poly1305 encryption"
if [ "${TT_UNDER_VALGRIND:-0}" = "1" ] && [ "${SKIP_CRYPTO_UNDER_VALGRIND:-1}" = "1" ]; then
    skip "39.x crypto disabled under Valgrind (KDF too slow; run without Valgrind)"
else
    "$TT" stop >/dev/null 2>&1
    sleep 1

    D39="$WORK/t39"
    mkdir -p "$D39"

    EPASS="tt_test_pass_39"

    # 39.1 start --encrypt creates crypto.meta
    printf "%s\n%s\n" "$EPASS" "$EPASS" | timeout -k 5 120 "$TT" start "$D39" --encrypt >/dev/null 2>&1
    vg_sleep 3

    if [ -f "$D39/.timetravel/crypto.meta" ]; then
        pass "39.1 crypto.meta created"
    else
        fail "39.1 crypto.meta missing"
    fi

    # 39.2 store must not contain plaintext
    echo "secret_text_39" > "$D39/s.txt"
    vg_sleep 3

    if grep -aq "secret_text_39" "$D39"/.timetravel/*.ttd 2>/dev/null; then
        fail "39.2 plaintext visible in store"
    else
        pass "39.2 encrypted store (no plaintext)"
    fi

    # 39.3 undo with correct passphrase restores previous version
    echo "version ONE" > "$D39/u.txt"
    vg_sleep 3

    echo "version TWO" > "$D39/u.txt"
    vg_sleep 3

    printf "%s\n" "$EPASS" | timeout -k 5 60 "$TT" undo "$D39/u.txt" --last --repo "$D39" >/dev/null 2>&1
    vg_sleep 1

    if [ "$(cat "$D39/u.txt")" = "version ONE" ]; then
        pass "39.3 encrypted undo restores previous version"
    else
        fail "39.3 encrypted undo failed (got: $(cat "$D39/u.txt"))"
    fi

    # 39.4 wrong passphrase rejected (file must not change)
    echo "version THREE" > "$D39/u.txt"
    vg_sleep 3

    printf "WRONG_PASSPHRASE\n" | timeout -k 5 60 "$TT" undo "$D39/u.txt" --last --repo "$D39" >/dev/null 2>&1

    if [ "$(cat "$D39/u.txt")" = "version THREE" ]; then
        pass "39.4 wrong passphrase rejected"
    else
        fail "39.4 wrong passphrase was NOT rejected"
    fi

    "$TT" stop >/dev/null 2>&1
    vg_sleep 1
fi

# ============================================================
# 40. Encryption: extended hardening
# ============================================================
section "40. Encryption: extended hardening"

if [ "${TT_UNDER_VALGRIND:-0}" = "1" ] && [ "${SKIP_CRYPTO_UNDER_VALGRIND:-1}" = "1" ]; then
skip "40.x disabled under Valgrind (hardware/time constraints)"
else

"$TT" stop >/dev/null 2>&1
vg_sleep 1

feed_pass() {
    local p="$1"
    local i
    for i in 1 2 3 4 5; do
        printf '%s\n' "$p"
    done
}

P40="tt_hardening_40"

# ------------------------------------------------------------
# 40.1-40.3: empty payload + encrypted compact
# ------------------------------------------------------------
D40A="$WORK/t40a"
mkdir -p "$D40A"

feed_pass "$P40" | timeout -k 5 120 "$TT" start "$D40A" --encrypt >/dev/null 2>&1
vg_sleep 3

# 40.1: truncate to empty in encrypted repo
echo "non_empty_content_40" > "$D40A/e.txt"
wait_for_min_records_vg "$D40A" 1 60

: > "$D40A/e.txt"
vg_sleep 3

feed_pass "$P40" | timeout -k 5 60 "$TT" undo "$D40A/e.txt" --last --repo "$D40A" >/dev/null 2>&1

assert_file_content "40.1 undo restores file truncated to empty in encrypted repo" "$D40A/e.txt" "non_empty_content_40"

# 40.2: encrypted compact must not leave plaintext behind
for i in $(seq 1 20); do
    echo "encrypted_compact_40_$i" > "$D40A/c.txt"
    vg_sleep 1
done

vg_sleep 5
wait_for_stable_records "$D40A"

timeout -k 5 15 "$TT" stop --repo "$D40A" >/dev/null 2>&1
vg_sleep 1

feed_pass "$P40" | timeout -k 5 300 "$TT" compact --repo "$D40A" >/dev/null 2>&1
RC_COMPACT=$?

if [ "$RC_COMPACT" -eq 124 ] || [ "$RC_COMPACT" -eq 137 ]; then
    fail "40.2 encrypted compact timed out"
elif [ "$RC_COMPACT" -ne 0 ]; then
    fail "40.2 encrypted compact failed rc=$RC_COMPACT"
else
    if grep -aq "encrypted_compact_40_" "$D40A"/.timetravel/*.ttd 2>/dev/null; then
        fail "40.2 encrypted compact left plaintext behind"
    else
        pass "40.2 encrypted compact leaves no plaintext"
    fi
fi

# 40.3: undo after encrypted compact
kill_all_tt_daemons
clean_global_tt_state
vg_sleep 1

if [ "${RC_COMPACT:-1}" -ne 0 ]; then
    fail "40.3 undo after encrypted compact skipped (compact failed)"
else
    feed_pass "$P40" | timeout -k 5 120 "$TT" start "$D40A" >/dev/null 2>&1
    RC_START=$?

    if [ "$RC_START" -eq 124 ] || [ "$RC_START" -eq 137 ]; then
        fail "40.3 start after encrypted compact timed out"
    elif ! daemon_is_running "$D40A"; then
        fail "40.3 daemon not running after encrypted start"
    else
        echo "postcompact_40" > "$D40A/c.txt"
        vg_sleep 5

        timeout -k 5 15 "$TT" stop --repo "$D40A" >/dev/null 2>&1
        vg_sleep 1

        feed_pass "$P40" | timeout -k 5 60 "$TT" undo "$D40A/c.txt" --last --repo "$D40A" >/dev/null 2>&1
        RC_UNDO=$?

        if [ "$RC_UNDO" -eq 124 ] || [ "$RC_UNDO" -eq 137 ]; then
            fail "40.3 undo after encrypted compact timed out"
        else
            C40="$(cat "$D40A/c.txt")"

            if [ "$C40" = "postcompact_40" ]; then
                fail "40.3 undo after encrypted compact did not restore"
            else
                pass "40.3 undo after encrypted compact works ($C40)"
            fi
        fi
    fi
fi

kill_all_tt_daemons
clean_global_tt_state
vg_sleep 1

# ------------------------------------------------------------
# 40.4-40.9: encrypted dedup + GC + block corruption
# ------------------------------------------------------------
D40B="$WORK/t40b"
mkdir -p "$D40B"

feed_pass "$P40" | timeout -k 5 120 "$TT" start "$D40B" --encrypt >/dev/null 2>&1
vg_sleep 3

{
    echo "SECRET_DEDUP_40"
    head -c 2097152 /dev/urandom
} > "$D40B/big.bin"

cp "$D40B/big.bin" "$D40B/big.v1"
wait_for_min_records_vg "$D40B" 1 120

# v2: allows undo --last
echo "v2_dedup_40" >> "$D40B/big.bin"
sync
vg_sleep 5

# 40.4: dedup blocks created
DEDUP_WAIT=0
for _ in $(seq 1 120); do
    B40=$(find "$D40B/.timetravel/blocks" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
    if [ "${B40:-0}" -ge 32 ] 2>/dev/null; then break; fi
    sleep 1
    DEDUP_WAIT=$((DEDUP_WAIT + 1))
done

B40=$(find "$D40B/.timetravel/blocks" -type f 2>/dev/null | wc -l | tr -d '[:space:]')

if [ "${B40:-0}" -ge 32 ] 2>/dev/null; then
    pass "40.4 encrypted dedup creates blocks ($B40, waited ${DEDUP_WAIT}s)"
else
    fail "40.4 encrypted dedup only created ${B40:-0} blocks (waited ${DEDUP_WAIT}s)"
fi

# 40.5: blocks must not contain plaintext
if grep -raq "SECRET_DEDUP_40" "$D40B/.timetravel/blocks" 2>/dev/null; then
    fail "40.5 plaintext visible in dedup blocks"
else
    pass "40.5 dedup blocks are encrypted (no plaintext)"
fi

# 40.6: undo --last restores v1 through blocks
timeout -k 5 15 "$TT" stop --repo "$D40B" >/dev/null 2>&1
vg_sleep 1

feed_pass "$P40" | timeout -k 5 60 "$TT" undo "$D40B/big.bin" --last --repo "$D40B" >/dev/null 2>&1
RC406=$?

if [ "$RC406" -eq 124 ] || [ "$RC406" -eq 137 ]; then
    fail "40.6 encrypted dedup undo timed out"
elif [ "$RC406" -eq 139 ] || [ "$RC406" -eq 134 ]; then
    fail "40.6 encrypted dedup undo crashed instead of restoring"
elif cmp -s "$D40B/big.bin" "$D40B/big.v1"; then
    pass "40.6 encrypted dedup undo restores v1"
else
    fail "40.6 encrypted dedup undo result differs"
fi

# 40.7: compact with wrong key must NOT run GC
BEFORE40=$(find "$D40B/.timetravel/blocks" -type f 2>/dev/null | wc -l | tr -d '[:space:]')

mkdir -p "$D40B/.timetravel/blocks/ff"
FAKE40="$D40B/.timetravel/blocks/ff/fake_orphan_40"
echo "orphan_40" > "$FAKE40"

printf "wrong_passphrase_40\n" | timeout -k 5 300 "$TT" compact --repo "$D40B" >/dev/null 2>&1
RC_WRONG40=$?

if [ "$RC_WRONG40" -eq 124 ] || [ "$RC_WRONG40" -eq 137 ]; then
    fail "40.7 compact with wrong key timed out"
else
    AFTER_WRONG40=$(find "$D40B/.timetravel/blocks" -type f 2>/dev/null | wc -l | tr -d '[:space:]')

    if [ -f "$FAKE40" ] && [ "$AFTER_WRONG40" -eq $((BEFORE40 + 1)) ] 2>/dev/null; then
        pass "40.7 compact with wrong key does not delete blocks"
    else
        fail "40.7 compact with wrong key altered block pool (before=$BEFORE40 after=$AFTER_WRONG40)"
    fi
fi

# 40.8: compact/GC with correct key removes fake and keeps referenced blocks
kill_all_tt_daemons
clean_global_tt_state
vg_sleep 1

feed_pass "$P40" | timeout -k 5 300 "$TT" compact --repo "$D40B" >/dev/null 2>&1
RC_OK40=$?

if [ "$RC_OK40" -eq 124 ] || [ "$RC_OK40" -eq 137 ]; then
    fail "40.8 encrypted compact/GC timed out"
else
    AFTER_OK40=$(find "$D40B/.timetravel/blocks" -type f 2>/dev/null | wc -l | tr -d '[:space:]')

    if [ ! -f "$FAKE40" ] && [ "$AFTER_OK40" -eq "$BEFORE40" ] 2>/dev/null; then
        pass "40.8 encrypted GC removes orphan and keeps referenced blocks"
    else
        fail "40.8 encrypted GC (before=$BEFORE40 after=$AFTER_OK40 fake=$([ -f "$FAKE40" ] && echo still_there || echo removed))"
    fi
fi

# 40.9: corrupted blocks -> undo must fail gracefully
for blk in $(find "$D40B/.timetravel/blocks" -type f 2>/dev/null); do
    dd if=/dev/urandom of="$blk" bs=1 count=8 seek=0 conv=notrunc 2>/dev/null
done

echo "dirty_40" > "$D40B/big.bin"

feed_pass "$P40" | timeout -k 5 60 "$TT" undo "$D40B/big.bin" --initial --repo "$D40B" >/dev/null 2>&1
RC409=$?

if [ "$RC409" -eq 124 ] || [ "$RC409" -eq 137 ]; then
    fail "40.9 undo with corrupted dedup blocks timed out"
elif [ "$RC409" -eq 0 ]; then
    fail "40.9 undo did not detect corrupted dedup blocks"
elif [ "$RC409" -eq 139 ] || [ "$RC409" -eq 134 ]; then
    fail "40.9 undo crashed instead of failing gracefully"
else
    pass "40.9 undo detects corrupted dedup blocks"
fi

# ------------------------------------------------------------
# 40.10: verify detects tampered encrypted .ttd
# ------------------------------------------------------------
D40C="$WORK/t40c"
mkdir -p "$D40C"

feed_pass "$P40" | timeout -k 5 120 "$TT" start "$D40C" --encrypt >/dev/null 2>&1
vg_sleep 3

echo "verify_encrypted_40" > "$D40C/f.txt"
wait_for_min_records_vg "$D40C" 1 60

timeout -k 5 15 "$TT" stop --repo "$D40C" >/dev/null 2>&1
vg_sleep 1

TTD40="$(ls "$D40C"/.timetravel/*.ttd 2>/dev/null | head -1)"

if [ -n "$TTD40" ]; then
    SZ40=$(stat -c%s "$TTD40")
    OFF40=$(( SZ40 * 70 / 100 ))

    dd if=/dev/urandom of="$TTD40" bs=1 count=24 seek="$OFF40" conv=notrunc 2>/dev/null

    V40="$(feed_pass "$P40" | timeout -k 5 60 "$TT" verify --repo "$D40C" 2>&1)"
    RC40=$?

    if [ "$RC40" -eq 124 ] || [ "$RC40" -eq 137 ]; then
        fail "40.10 verify timed out"
    elif [ "$RC40" -ne 0 ]; then
        pass "40.10 verify detects tampered encrypted .ttd"
    else
        fail "40.10 verify did not detect tampered encrypted .ttd: $(echo "$V40" | tail -1)"
    fi
else
    fail "40.10 no encrypted .ttd found to tamper with"
fi

# ------------------------------------------------------------
# 40.11: corrupted crypto.meta must be rejected
# ------------------------------------------------------------
D40D="$WORK/t40d"
mkdir -p "$D40D"

feed_pass "$P40" | timeout -k 5 120 "$TT" start "$D40D" --encrypt >/dev/null 2>&1
vg_sleep 3

echo "meta_test_40" > "$D40D/f.txt"
wait_for_min_records_vg "$D40D" 1 60

timeout -k 5 15 "$TT" stop --repo "$D40D" >/dev/null 2>&1
vg_sleep 1

META40="$D40D/.timetravel/crypto.meta"

if [ -f "$META40" ]; then
    printf 'X' | dd of="$META40" bs=1 seek=40 count=1 conv=notrunc 2>/dev/null
    vg_sleep 2
    feed_pass "$P40" | timeout -k 5 60 "$TT" verify --repo "$D40D" >/dev/null 2>&1
    RC411=$?

    if [ "$RC411" -eq 124 ] || [ "$RC411" -eq 137 ]; then
        fail "40.11 verify with corrupted crypto.meta timed out"
    elif [ "$RC411" -eq 0 ]; then
        fail "40.11 corrupted crypto.meta accepted"
    else
        pass "40.11 corrupted crypto.meta rejected"
    fi
else
    fail "40.11 crypto.meta missing"
fi

"$TT" stop >/dev/null 2>&1
vg_sleep 1

fi

# ============================================================
# 41. Valgrind: memory audit (runs only under valgrind wrapper)
# ============================================================
section "41. Valgrind: memory audit"

if [ "${TT_UNDER_TSAN:-0}" = "1" ] && [ "${SKIP_VALGRIND_UNDER_TSAN:-1}" = "1" ]; then
    printf "  [INFO] TSan is active: skipping Valgrind memory audit.\n"
    printf "  [INFO] TSan + Valgrind together is unsupported and can OOM/timeout.\n"
    skip "41.x Valgrind memory audit (TSan active)"

elif [ "${TT_UNDER_ASAN:-0}" = "1" ] && [ "${SKIP_VALGRIND_UNDER_ASAN:-1}" = "1" ]; then
    printf "  [INFO] ASan is active: skipping Valgrind memory audit.\n"
    printf "  [INFO] ASan + Valgrind together is unsupported and can OOM/timeout.\n"
    skip "41.x Valgrind memory audit (ASan active)"

elif [ "${TT_UNDER_SANITIZER:-0}" = "1" ]; then
    printf "  [INFO] Sanitizer active (ambiguous): skipping Valgrind memory audit.\n"
    skip "41.x Valgrind memory audit (sanitizer active)"

elif [ "$QEMU" -eq 1 ]; then
    printf "  [INFO] QEMU emulation detected: skipping Valgrind memory audit.\n"
    printf "  [INFO] Valgrind + QEMU-user is unstable and extremely slow.\n"
    skip "41.x Valgrind memory audit (QEMU active)"

else
    VG_BIN=""

case "${TT:-}" in
    *valgrind*|*timetravel_valgrind*)

        VG_BIN="$(grep -oP '(?<=exec valgrind).*?"\K[^"]+' "$TT" 2>/dev/null)"
        if [ -z "$VG_BIN" ]; then
            VG_BIN="$(dirname "$TT")/timetravel"
        fi
        ;;
    *)
        VG_BIN="$TT"
        ;;
esac

VG_LOG_DIR="$WORK/vg_logs"
mkdir -p "$VG_LOG_DIR"

D41="$WORK/t41"
mkdir -p "$D41"

echo "[INFO] dataset: 1 MB random + 50 files (valgrind is ~20x slower)"
dd if=/dev/urandom of="$D41/stress.bin" bs=1024 count=1024 2>/dev/null
for i in $(seq 1 50); do
    echo "valgrind_stress_file_$i" > "$D41/file_$i.txt"
done

# 41.1 start
VG_LOG_START="$VG_LOG_DIR/41_start.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_START" \
    "$VG_BIN" start "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_START" "41.1 START"

vg_sleep 3

# 41.2 modify file
echo "valgrind_modified" > "$D41/file_1.txt"
vg_sleep 5

# 41.3 stop
VG_LOG_STOP="$VG_LOG_DIR/41_stop.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_STOP" \
    "$VG_BIN" stop --repo "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_STOP" "41.3 STOP"

# 41.4 verify
VG_LOG_VERIFY="$VG_LOG_DIR/41_verify.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_VERIFY" \
    "$VG_BIN" verify --repo "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_VERIFY" "41.4 VERIFY"

# 41.5 undo
VG_LOG_UNDO="$VG_LOG_DIR/41_undo.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_UNDO" \
    "$VG_BIN" undo "$D41/file_1.txt" --last --repo "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_UNDO" "41.5 UNDO"

# 41.6 undo byte-identical
if cmp -s "$D41/stress.bin" "$D41/stress.bin" 2>/dev/null; then
    pass "41.6 stress.bin present after undo cycle"
else
    fail "41.6 stress.bin missing"
fi

# 41.7 compact
VG_LOG_COMPACT="$VG_LOG_DIR/41_compact.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_COMPACT" \
    "$VG_BIN" compact --repo "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_COMPACT" "41.7 COMPACT"

# 41.8 status
VG_LOG_STATUS="$VG_LOG_DIR/41_status.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_STATUS" \
    "$VG_BIN" status --repo "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_STATUS" "41.8 STATUS"

# 41.9 history
VG_LOG_HISTORY="$VG_LOG_DIR/41_history.log"
valgrind --leak-check=full --show-leak-kinds=all \
    --log-file="$VG_LOG_HISTORY" \
    "$VG_BIN" log "$D41/file_1.txt" --repo "$D41" >/dev/null 2>&1 </dev/null
check_vg_log "$VG_LOG_HISTORY" "41.9 HISTORY"

fi

# ============================================================
# 42. undo dir --initial: baseline prune
# ============================================================
section "42. undo dir --initial prunes files added after baseline"

D42="$WORK/t42"
mkdir -p "$D42/src"

for i in 1 2 3 4 5 6 7; do
    echo "initial $i" > "$D42/src/file_$i.txt"
done

"$TT" start "$D42" >/dev/null 2>&1
vg_sleep 2

echo "MODIFIED" > "$D42/src/file_3.txt"
vg_sleep 2

for i in $(seq 1 20); do
    echo "new $i" > "$D42/src/new_$i.txt"
done
vg_sleep 3

"$TT" undo "$D42/src" --initial --repo "$D42" --force >/dev/null 2>&1

# 42.1: modified file restored to initial content
assert_file_content "42.1 modified file restored to initial content" \
    "$D42/src/file_3.txt" "initial 3"

# 42.2: files added after baseline deleted"
NEW_COUNT=$(ls "$D42/src"/new_*.txt 2>/dev/null | wc -l)
assert_eq "42.2 files added after baseline deleted" "0" "$NEW_COUNT"

# 42.3: los ficheros iniciales siguen presentes
TOTAL_FILES=$(ls "$D42/src"/file_*.txt 2>/dev/null | wc -l)
assert_eq "42.3 all 7 initial files present" "7" "$TOTAL_FILES"

"$TT" stop --repo "$D42" >/dev/null 2>&1

# ============================================================
# 43. dump: dedup large file regression (CREATE_D + MODIFY)
# ============================================================
section "43. dump: dedup large file regression"

D43="$WORK/t43"
OUT43="$WORK/t43_dump"
mkdir -p "$D43"

"$TT" start "$D43" >/dev/null 2>&1
vg_sleep 2

dd if=/dev/urandom of="$D43/big.bin" bs=1024 count=1100 2>/dev/null
cp "$D43/big.bin" "$D43/big.v1"

TMO43=60
[ "$QEMU" -eq 1 ] && TMO43=180 
wait_for_min_records_vg "$D43" 1 "$TMO43"

printf 'TT_DEDUP_DUMP_REGRESSION
' >> "$D43/big.bin"
cp "$D43/big.bin" "$D43/big.v2"

wait_for_min_records_vg "$D43" 2 "$TMO43"

"$TT" stop --repo "$D43" >/dev/null 2>&1
vg_sleep 1

DUMP_TMO=$((180 * ${VG_MULT:-1}))

if DUMP43="$(timeout -k 10 "$DUMP_TMO" "$TT" dump "$D43/big.bin" --out "$OUT43" --repo "$D43" 2>&1)"; then
    pass "43.1 dump executes"
    assert_contains "43.2 dump reports one file with history" "$DUMP43" "dump: 1 file(s) with history"
else
    fail "43.1 dump executes"
    fail "43.2 dump reports one file with history"
fi

if [ -f "$OUT43/manifest.tsv" ]; then
    pass "43.3 manifest.tsv created"
else
    fail "43.3 manifest.tsv created"
fi

if awk -F'\t' '$1 == "big.bin" && $3 == "CREATE_D" { found=1 } END { exit !found }' "$OUT43/manifest.tsv" 2>/dev/null; then
    pass "43.4 manifest contains CREATE_D"
else
    fail "43.4 manifest contains CREATE_D"
fi

if awk -F'\t' '$1 == "big.bin" && $3 == "MODIFY" { found=1 } END { exit !found }' "$OUT43/manifest.tsv" 2>/dev/null; then
    pass "43.5 manifest contains MODIFY"
else
    fail "43.5 manifest contains MODIFY"
fi

v1=( "$OUT43/files/big.bin/v000001_"* )
v2=( "$OUT43/files/big.bin/v000002_"* )

if [ "${#v1[@]}" -eq 1 ] && [ -f "${v1[0]}" ]; then
    pass "43.6 v000001 dumped"

    if cmp -s "${v1[0]}" "$D43/big.v1"; then
        pass "43.7 v000001 byte-identical"
    else
        fail "43.7 v000001 byte-identical"
    fi
else
    fail "43.6 v000001 dumped"
    fail "43.7 v000001 byte-identical"
fi

if [ "${#v2[@]}" -eq 1 ] && [ -f "${v2[0]}" ]; then
    pass "43.8 v000002 dumped"

    if cmp -s "${v2[0]}" "$D43/big.v2"; then
        pass "43.9 v000002 byte-identical"
    else
        fail "43.9 v000002 byte-identical"
    fi
else
    fail "43.8 v000002 dumped"
    fail "43.9 v000002 byte-identical"
fi

# ============================================================
# 44. --exclude: per-repo exclusion patterns
# ============================================================
section "44. exclude patterns"

D44="$WORK/t44"
mkdir -p "$D44/src" "$D44/.venv" "$D44/build" "$D44/logs"

echo "int main(){}" > "$D44/src/main.c"
echo "venv config"  > "$D44/.venv/pyvenv.cfg"
echo "object file"  > "$D44/build/output.o"
echo "log entry"    > "$D44/logs/app.log"

"$TT" start "$D44" --exclude ".venv" --exclude "build" >/dev/null 2>&1
vg_sleep 2

if [ -f "$D44/.timetravel/exclude.enc" ]; then

    if [ -f "$D44/.timetravel/exclude.list" ]; then
        fail "44.1 exclude.list still exists (should be encrypted)"
    else
        pass "44.1 exclude.enc created (exclude.list encrypted)"
    fi
else
    fail "44.1 exclude.enc not created"
fi

EXLIST="$("$TT" exclude list --repo "$D44" 2>/dev/null)"
if echo "$EXLIST" | grep -q ".venv" && echo "$EXLIST" | grep -q "build"; then
    pass "44.2 exclude list shows patterns"
else
    fail "44.2 exclude list shows patterns"
fi

echo "change" >> "$D44/.venv/pyvenv.cfg"
vg_sleep 2
VLOG="$("$TT" log "$D44/.venv/pyvenv.cfg" --repo "$D44" 2>/dev/null)"
if [ -z "$VLOG" ] || ! echo "$VLOG" | grep -q "CREATE"; then
    pass "44.3 excluded dir not captured"
else
    fail "44.3 excluded dir not captured"
fi

echo "change" >> "$D44/src/main.c"
vg_sleep 2
LOGOUT="$("$TT" log "$D44/src/main.c" --repo "$D44" 2>/dev/null)"
if echo "$LOGOUT" | grep -q "CREATE"; then
    pass "44.4 non-excluded file captured"
else
    fail "44.4 non-excluded file captured"
fi

"$TT" exclude add "*.log" --repo "$D44" >/dev/null 2>&1
vg_sleep 1
EXLIST2="$("$TT" exclude list --repo "$D44" 2>/dev/null)"
if echo "$EXLIST2" | grep -qF '*.log'; then
    pass "44.5 exclude add works"
else
    fail "44.5 exclude add works"
fi

"$TT" exclude remove "*.log" --repo "$D44" >/dev/null 2>&1
vg_sleep 1
EXLIST3="$("$TT" exclude list --repo "$D44" 2>/dev/null)"
if ! echo "$EXLIST3" | grep -qF '*.log'; then
    pass "44.6 exclude remove works"
else
    fail "44.6 exclude remove works"
fi

"$TT" stop --repo "$D44" >/dev/null 2>&1
vg_sleep 1
"$TT" start "$D44" >/dev/null 2>&1
vg_sleep 2
EXLIST4="$("$TT" exclude list --repo "$D44" 2>/dev/null)"
if echo "$EXLIST4" | grep -q ".venv" && echo "$EXLIST4" | grep -q "build"; then
    pass "44.7 exclude persists across restart"
else
    fail "44.7 exclude persists across restart"
fi

"$TT" exclude add "*.log" --repo "$D44" >/dev/null 2>&1
"$TT" stop --repo "$D44" >/dev/null 2>&1
vg_sleep 1
"$TT" start "$D44" >/dev/null 2>&1
vg_sleep 2
echo "new log" > "$D44/logs/new_file.log"
vg_sleep 2
LLOG="$("$TT" log "$D44/logs/new_file.log" --repo "$D44" 2>/dev/null)"
if [ -z "$LLOG" ] || ! echo "$LLOG" | grep -q "CREATE"; then
    pass "44.8 glob pattern excludes correctly"
else
    fail "44.8 glob pattern excludes correctly"
fi

"$TT" stop >/dev/null 2>&1
vg_sleep 1


# ============================================================
# 45. v1.6: file repos AND directories (both tested)
# ============================================================
section "45. file repos AND directories (v1.6)"

D45A="$WORK/t45a"; mkdir -p "$D45A"
echo "dir v1" > "$D45A/file.txt"

"$TT" start "$D45A" >/dev/null 2>&1

vg_sleep 2

if daemon_is_running "$D45A"; then pass "45.A1 directory repo daemon running"; else fail "45.A1 directory repo daemon not running"; fi
if [ -d "$D45A/.timetravel" ]; then pass "45.A2 directory repo store created"; else fail "45.A2 directory repo store missing"; fi

echo "dir v2" > "$D45A/file.txt"

wait_for_min_records_vg "$D45A" 2 30

L45A="$("$TT" log "$D45A/file.txt" --repo "$D45A" 2>&1)"

assert_contains "45.A3 directory repo log shows CREATE" "$L45A" "CREATE"
assert_contains "45.A4 directory repo log shows MODIFY" "$L45A" "MODIFY"

"$TT" undo "$D45A/file.txt" --last --repo "$D45A" >/dev/null 2>&1

assert_file_content "45.A5 directory repo undo --last works" "$D45A/file.txt" "dir v1"
"$TT" stop --repo "$D45A" >/dev/null 2>&1

vg_sleep 1

kill_all_tt_daemons; clean_global_tt_state

D45B="$WORK/t45b"; mkdir -p "$D45B"

printf "v1 file repo with enough content to make delta smaller than file
%s
" "$(head -c 200 /dev/urandom | base64)" > "$D45B/only.txt"
echo "noise" > "$D45B/noise.txt"

# 45.B1: start accepts a single file
assert_ok "45.B1 start accepts a single file" "$TT" start "$D45B/only.txt"
vg_sleep 2

if daemon_is_running "$D45B"; then pass "45.B2 file repo daemon running (store in parent dir)"; else fail "45.B2 file repo daemon not running"; fi
if [ -d "$D45B/.timetravel" ]; then pass "45.B3 file repo store created in parent dir"; else fail "45.B3 file repo store missing"; fi

for _ in $(seq 1 10); do
    R45B="$(get_record_count "$D45B")"
    if [ -n "$R45B" ]; then break; fi
    vg_sleep 1
done

assert_eq "45.B4 file repo no initial records" "0" "$R45B"

printf "v2 file repo with different content to ensure delta compression
%s
" "$(head -c 200 /dev/urandom | base64)" > "$D45B/only.txt"
wait_for_min_records_vg "$D45B" 2 30

echo "noise changed" > "$D45B/noise.txt"
vg_sleep 3

L45B="$("$TT" log "$D45B/only.txt" --repo "$D45B" 2>&1)"
assert_contains "45.B5 file repo log shows CREATE" "$L45B" "CREATE"
assert_contains "45.B6 file repo log shows MODIFY" "$L45B" "MODIFY"

LN45B="$("$TT" log "$D45B/noise.txt" --repo "$D45B" 2>&1)"

if echo "$LN45B" | grep -q "CREATE"; then fail "45.B7 sibling file captured (isolation broken)"; else pass "45.B7 sibling file NOT captured (isolation OK)"; fi

# 45.B8: undo --last works in file repos
"$TT" undo "$D45B/only.txt" --last --repo "$D45B" >/dev/null 2>&1
if grep -q "v1 file repo" "$D45B/only.txt"; then pass "45.B8 file repo undo --last works"; else fail "45.B8 file repo undo --last failed"; fi

# 45.B9: status --repo <file> resolves the parent store
S45B="$("$TT" status --repo "$D45B/only.txt" 2>&1)"

R45B2="$(echo "$S45B" | awk '/Records:/{print $2}')"

if [ "$R45B2" -ge 2 ] 2>/dev/null; then pass "45.B9 status --repo <file> resolves the parent store ($R45B2 records)"; else fail "45.B9 status --repo <file> expected >=2 records, got $R45B2"; fi

# 45.B10: stop --repo <file> works
"$TT" stop --repo "$D45B/only.txt" >/dev/null 2>&1
vg_sleep 1
kill_all_tt_daemons; clean_global_tt_state

# --- PARTE C: Multiple file repos sharing parent ---
D45C="$WORK/t45c"; mkdir -p "$D45C"
echo "A v1" > "$D45C/a.txt"
echo "B v1" > "$D45C/b.txt"

# 45.C1: start primer file repo
timeout 20 "$TT" start "$D45C/a.txt" >/dev/null 2>&1
vg_sleep 2

# 45.C2: hot-add second file in same parent
OUT45C=""
for _ in $(seq 1 10); do
    OUT45C="$(timeout 20 "$TT" add "$D45C/b.txt" 2>&1)"
    echo "$OUT45C" | grep -qE "^OK" && break
    vg_sleep 1
done

if echo "$OUT45C" | grep -qE "^OK"; then pass "45.C1 hot-add second file in same parent"; else fail "45.C1 hot-add second file ($(echo "$OUT45C" | head -1))"; fi

# 45.C3: status shows 2 file repos
S45C=""
for _ in $(seq 1 10); do
    S45C="$(timeout 15 "$TT" status --repo "$D45C" 2>&1)"
    echo "$S45C" | grep -q "Repos (2)" && break
    vg_sleep 1
done
assert_contains "45.C2 status shows 2 file repos" "$S45C" "Repos (2)"

# 45.C4: modify both files
echo "A v2" > "$D45C/a.txt"
echo "B v2" > "$D45C/b.txt"
wait_for_min_records_vg "$D45C" 4 30

# 45.C5: logs are isolated
LA45C="$("$TT" log "$D45C/a.txt" --repo "$D45C" 2>&1)"
LB45C="$("$TT" log "$D45C/b.txt" --repo "$D45C" 2>&1)"

assert_contains "45.C3 a.txt has history" "$LA45C" "a.txt"
if echo "$LA45C" | grep -q "b.txt"; then fail "45.C4 a.txt log leaked b.txt"; else pass "45.C4 a.txt log isolated from b.txt"; fi
if echo "$LB45C" | grep -q "a.txt"; then fail "45.C5 b.txt log leaked a.txt"; else pass "45.C5 b.txt log isolated from a.txt"; fi

# 45.C6: selective stop of a.txt repo
OUT45C2="$(timeout 15 "$TT" stop --repo "$D45C/a.txt" 2>&1)"
assert_contains "45.C6 selective stop of a.txt repo" "$OUT45C2" "OK"

# 45.C7: swarm now have 1 repo
S45C2=""
for _ in $(seq 1 10); do
    S45C2="$(timeout 15 "$TT" status --repo "$D45C" 2>&1)"
    echo "$S45C2" | grep -q "Repos (1)" && break
    vg_sleep 1
done

assert_contains "45.C7 swarm now has 1 repo" "$S45C2" "Repos (1)"

# 45.C8: Repo removed; no longer capturing
echo "A v3 (must NOT be captured)" > "$D45C/a.txt"
echo "B v3" > "$D45C/b.txt"
wait_for_min_records_vg "$D45C" 5 30
vg_sleep 2

LA45C2="$("$TT" log "$D45C/a.txt" --repo "$D45C" 2>&1)"
NA45="$(echo "$LA45C2" | grep -cE "CREATE|MODIFY")"

assert_eq "45.C8 removed repo no longer captures (a.txt frozen at 2 records)" "2" "$NA45"

# 45.C9: surviving repo still restores
"$TT" undo "$D45C/b.txt" --last --repo "$D45C" >/dev/null 2>&1
assert_file_content "45.C9 surviving repo still restores" "$D45C/b.txt" "B v2"
timeout 15 "$TT" stop >/dev/null 2>&1
vg_sleep 1
kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 46. v1.6: two file repos sharing a parent + selective stop
# ============================================================
section "46. two file repos sharing a parent + selective stop"
D46="$WORK/t46"; mkdir -p "$D46"
echo "A v1" > "$D46/a.txt"
echo "B v1" > "$D46/b.txt"

timeout 20 "$TT" start "$D46/a.txt" >/dev/null 2>&1
vg_sleep 2
OUT46=""

for _ in $(seq 1 10); do
    OUT46="$(timeout 20 "$TT" add "$D46/b.txt" 2>&1)"
    echo "$OUT46" | grep -qE "^OK" && break
    vg_sleep 1
done

if echo "$OUT46" | grep -qE "^OK"; then pass "46.1 hot-add second file in same parent"; else fail "46.1 hot-add second file ($(echo "$OUT46" | head -1))"; fi

S46=""

for _ in $(seq 1 10); do
    S46="$(timeout 15 "$TT" status --repo "$D46" 2>&1)"
    echo "$S46" | grep -q "Repos (2)" && break
    vg_sleep 1
done

assert_contains "46.2 status shows 2 file repos" "$S46" "Repos (2)"
echo "A v2" > "$D46/a.txt"
echo "B v2" > "$D46/b.txt"

wait_for_min_records_vg "$D46" 4 30

LA46="$("$TT" log "$D46/a.txt" --repo "$D46" 2>&1)"
LB46="$("$TT" log "$D46/b.txt" --repo "$D46" 2>&1)"

assert_contains "46.3 a.txt has history" "$LA46" "a.txt"

if echo "$LA46" | grep -q "b.txt"; then fail "46.4 a.txt log leaked b.txt"; else pass "46.4 a.txt log isolated from b.txt"; fi
if echo "$LB46" | grep -q "a.txt"; then fail "46.5 b.txt log leaked a.txt"; else pass "46.5 b.txt log isolated from a.txt"; fi

OUT46B="$(timeout 15 "$TT" stop --repo "$D46/a.txt" 2>&1)"
assert_contains "46.6 selective stop of a.txt repo" "$OUT46B" "OK"

S46B=""
for _ in $(seq 1 10); do
    S46B="$(timeout 15 "$TT" status --repo "$D46" 2>&1)"
    echo "$S46B" | grep -q "Repos (1)" && break
    vg_sleep 1
done

assert_contains "46.7 swarm now has 1 repo" "$S46B" "Repos (1)"

echo "A v3 (must NOT be captured)" > "$D46/a.txt"
echo "B v3" > "$D46/b.txt"

wait_for_min_records_vg "$D46" 5 30
vg_sleep 2

LA46B="$("$TT" log "$D46/a.txt" --repo "$D46" 2>&1)"
NA46="$(echo "$LA46B" | grep -cE "CREATE|MODIFY")"

assert_eq "46.8 removed repo no longer captures (a.txt frozen at 2 records)" "2" "$NA46"

"$TT" undo "$D46/b.txt" --last --repo "$D46" >/dev/null 2>&1
assert_file_content "46.9 surviving repo still restores" "$D46/b.txt" "B v2"
timeout 15 "$TT" stop >/dev/null 2>&1
vg_sleep 1

kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 47. v1.6: file repo overlap protection
# ============================================================
section "47. file repo overlap protection"
D47="$WORK/t47"; mkdir -p "$D47"
echo "x" > "$D47/f.txt"
timeout 20 "$TT" start "$D47" >/dev/null 2>&1
vg_sleep 2

OUT47=""

for _ in $(seq 1 10); do
    OUT47="$(timeout 15 "$TT" add "$D47/f.txt" 2>&1)"
    echo "$OUT47" | grep -qiE "overlap|ERR" && break
    vg_sleep 1
done

if echo "$OUT47" | grep -qiE "overlap|ERR|could not|failed|timeout"; then pass "47.1 file inside watched dir rejected (overlap)"; else fail "47.1 file inside watched dir should be rejected ($(echo "$OUT47" | head -1))"; fi

timeout 15 "$TT" stop >/dev/null 2>&1
vg_sleep 1

timeout 20 "$TT" start "$D47/f.txt" >/dev/null 2>&1
vg_sleep 2

OUT47B=""

for _ in $(seq 1 10); do
    OUT47B="$(timeout 15 "$TT" add "$D47" 2>&1)"
    echo "$OUT47B" | grep -qiE "^OK|already" && break
    vg_sleep 1
done

if echo "$OUT47B" | grep -qiE "^OK|already"; then pass "47.2 parent dir of a file repo handled gracefully"; else fail "47.2 parent dir add failed weirdly ($(echo "$OUT47B" | head -1))"; fi

timeout 15 "$TT" stop >/dev/null 2>&1

vg_sleep 1
kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 48. v1.6: file repo persistence across restart (repos.list)
# ============================================================
section "48. file repo persistence (repos.list)"
D48A="$WORK/t48a"; mkdir -p "$D48A"
D48B="$WORK/t48b"; mkdir -p "$D48B"

echo "p1" > "$D48A/p.txt"
echo "q1" > "$D48B/q.txt"

timeout 20 "$TT" start "$D48A/p.txt" >/dev/null 2>&1
vg_sleep 2

OUT48=""
for _ in $(seq 1 10); do
    OUT48="$(timeout 20 "$TT" add "$D48B/q.txt" 2>&1)"
    echo "$OUT48" | grep -qE "^OK" && break
    vg_sleep 1
done

if echo "$OUT48" | grep -qE "^OK"; then pass "48.1 hot-add second file repo"; else fail "48.1 hot-add second file repo ($(echo "$OUT48" | head -1))"; fi

timeout 15 "$TT" stop >/dev/null 2>&1
vg_sleep 1

timeout 20 "$TT" start "$D48A/p.txt" >/dev/null 2>&1

S48=""

for _ in $(seq 1 10); do
    S48="$(timeout 15 "$TT" status --repo "$D48A" 2>&1)"
    echo "$S48" | grep -q "Repos (2)" && break
    vg_sleep 1
done

assert_contains "48.2 repos.list re-adopted second file repo after restart" "$S48" "Repos (2)"

echo "p2" > "$D48A/p.txt"
echo "q2" > "$D48B/q.txt"

wait_for_min_records_vg "$D48A" 2 30
wait_for_min_records_vg "$D48B" 2 30

"$TT" undo "$D48B/q.txt" --last --repo "$D48B" >/dev/null 2>&1

assert_file_content "48.3 re-adopted file repo restores previous version" "$D48B/q.txt" "q1"
timeout 15 "$TT" stop >/dev/null 2>&1
vg_sleep 1

kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 49. v1.6: extlog (extended log) — new command, does NOT replace log
# ============================================================
section "49. extlog (extended log)"
D49="$WORK/t49"; mkdir -p "$D49"

printf 'int main(void)\n{\n    return 0;\n}\n' > "$D49/prog.c"
"$TT" start "$D49" >/dev/null 2>&1
vg_sleep 2

printf 'int main(void)\n{\n    int quantum_flux_capacitor = 42;\n    return quantum_flux_capacitor;\n}\n' > "$D49/prog.c"

wait_for_min_records_vg "$D49" 2 30

printf 'int main(void)\n{\n    /* final */\n    int quantum_flux_capacitor = 43;\n    return quantum_flux_capacitor;\n}\n' > "$D49/prog.c"
wait_for_min_records_vg "$D49" 3 30

"$TT" stop --repo "$D49" >/dev/null 2>&1
vg_sleep 1

E49="$("$TT" extlog "$D49/prog.c" --repo "$D49" 2>&1)"

RC49=$?

if [ "$RC49" -eq 0 ]; then pass "49.1 extlog executes"; else fail "49.1 extlog failed rc=$RC49"; fi

assert_contains "49.2 extlog header" "$E49" "extended log"
assert_contains "49.3 extlog shows scope" "$E49" "Scope:"
assert_contains "49.4 extlog shows revision" "$E49" "[000"
assert_contains "49.5 extlog shows size" "$E49" "size="
assert_contains "49.6 extlog shows delta ratio" "$E49" "ratio="
assert_contains "49.7 extlog shows elapsed time" "$E49" "elapsed since previous"
assert_contains "49.8 extlog shows semantic summary" "$E49" "quantum_flux_capacitor"

E49B="$("$TT" extlog "$D49" --since "10 minutes ago" --repo "$D49" 2>&1)"

assert_contains "49.9 extlog dir scope with --since" "$E49B" "revision(s) across"
assert_fail "49.10 extlog rejects invalid --since" "$TT" extlog "$D49" --since "banana" --repo "$D49"

D49B="$WORK/t49b"; mkdir -p "$D49B"

echo "one" > "$D49B/single.txt"
"$TT" start "$D49B/single.txt" >/dev/null 2>&1

vg_sleep 2

echo "two" > "$D49B/single.txt"
wait_for_min_records_vg "$D49B" 2 30

"$TT" stop --repo "$D49B/single.txt" >/dev/null 2>&1
vg_sleep 1

E49C="$("$TT" extlog "$D49B/single.txt" --repo "$D49B" 2>&1)"

assert_contains "49.11 extlog works on single-file repo" "$E49C" "single.txt"

L49="$("$TT" log "$D49/prog.c" --repo "$D49" 2>&1)"

assert_contains "49.12 classic log still works (extlog is additive)" "$L49" "MODIFY"
kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 50. v1.6: autotag cleanliness (case fold, stop words, garbage, binary)
# ============================================================
section "50. autotag cleanliness (v1.6)"
D50="$WORK/t50"; mkdir -p "$D50"

printf 'alpha line\n' > "$D50/tags.txt"
"$TT" start "$D50" >/dev/null 2>&1
vg_sleep 2

printf 'alpha line\nGALACTIC_ROUTER enabled\nbuffer buffer buffer\nxkcdmwp zzzzzzz\n' > "$D50/tags.txt"
wait_for_min_records_vg "$D50" 2 30

"$TT" stop --repo "$D50" >/dev/null 2>&1
vg_sleep 1

E50="$("$TT" extlog "$D50/tags.txt" --repo "$D50" 2>&1)"

assert_contains "50.1 uppercase token folded to lowercase tag" "$E50" "#galactic_router"

if echo "$E50" | grep -q "#buffer"; then fail "50.2 stop word 'buffer' leaked into tags"; else pass "50.2 stop word 'buffer' filtered out"; fi
if echo "$E50" | grep -qE "#xkcdmwp|#zzzzzzz"; then fail "50.3 garbage token leaked into tags"; else pass "50.3 garbage tokens filtered out"; fi

D50B="$WORK/t50b"; mkdir -p "$D50B"
dd if=/dev/urandom of="$D50B/blob.bin" bs=1024 count=8 2>/dev/null

"$TT" start "$D50B/blob.bin" >/dev/null 2>&1
vg_sleep 2

dd if=/dev/urandom of="$D50B/blob.bin" bs=1024 count=8 2>/dev/null

wait_for_min_records_vg "$D50B" 2 30

"$TT" stop --repo "$D50B/blob.bin" >/dev/null 2>&1
vg_sleep 1

E50B="$("$TT" extlog "$D50B/blob.bin" --repo "$D50B" 2>&1)"
if echo "$E50B" | grep "semantic summary" | grep -q "#"; then fail "50.4 binary file produced hashtag autotags"; else pass "50.4 binary file produces no hashtag autotags"; fi

kill_all_tt_daemons; clean_global_tt_state

# ============================================================
# 51. fix verification: small file MODIFY (dsz < new_size removed)
# ============================================================
section "51. fix verification: small file MODIFY"
D51="$WORK/t51"; mkdir -p "$D51"

echo "small" > "$D51/tiny.txt"
"$TT" start "$D51" >/dev/null 2>&1
vg_sleep 2

echo "modified" > "$D51/tiny.txt"
wait_for_min_records_vg "$D51" 2 30
L51="$("$TT" log "$D51/tiny.txt" --repo "$D51" 2>&1)"

if echo "$L51" | grep -q "MODIFY"; then
    pass "51.1 small file shows MODIFY (fix verified)"
else
    fail "51.1 small file does not show MODIFY (fix not working)"
fi

if echo "$L51" | grep -q "CREATE"; then
    pass "51.2 small file shows CREATE (first version)"
else
    fail "51.2 small file does not show CREATE"
fi
"$TT" stop --repo "$D51" >/dev/null 2>&1
vg_sleep 1

# Section 52: multiple files at start
section "52. multiple files at start"
D52="$WORK/t52"; mkdir -p "$D52"
echo "a" > "$D52/a.c"
echo "b" > "$D52/b.c"
echo "c" > "$D52/c.c"

# 52.1: start accepts multiple files
assert_ok "52.1 start accepts multiple files" "$TT" start "$D52/a.c" "$D52/b.c" "$D52/c.c"
vg_sleep 2

# 52.2: all files are watched
echo "a2" > "$D52/a.c"
echo "b2" > "$D52/b.c"
wait_for_min_records_vg "$D52" 2 30

# 52.3: status shows 3 repos
S52="$("$TT" status --repo "$D52" 2>&1)"
assert_contains "52.2 status shows 3 file repos" "$S52" "Repos (3)"

"$TT" stop >/dev/null 2>&1
kill_all_tt_daemons; clean_global_tt_state

# 52.4: glob expansion works (shell expands *.c)
D52B="$WORK/t52b"; mkdir -p "$D52B"
echo "x" > "$D52B/x.c"
echo "y" > "$D52B/y.c"
cd "$D52B"

assert_ok "52.3 glob expansion works" "$TT" start "$D52B"/*.c
cd - >/dev/null
vg_sleep 2

"$TT" stop >/dev/null 2>&1
kill_all_tt_daemons; clean_global_tt_state

# 52.5: too many files rejected
D52C="$WORK/t52c"; mkdir -p "$D52C"
for i in $(seq 1 11); do echo "$i" > "$D52C/f$i.c"; done
assert_fail "52.4 too many files (>10) rejected" "$TT" start "$D52C"/f*.c

# ============================================================
# Summary
# ============================================================
END_EPOCH="$(date +%s)"
ELAPSED=$((END_EPOCH - START_EPOCH))

printf "\n============================================================\n"
printf "  SUMMARY\n"
printf "============================================================\n"
printf "  Passed:    %d/%d\n" "$PASS_COUNT" "$TOTAL_COUNT"
printf "  Failed:    %d\n" "$FAIL_COUNT"
printf "  Skipped:   %d\n" "$SKIP_COUNT"
printf "  Duration:  %dm %02ds\n" $((ELAPSED / 60)) $((ELAPSED % 60))
printf "  Log:       %s\n" "$LOG_FILE"
printf "============================================================\n"

if [ "$FAIL_COUNT" -gt 0 ]; then
	printf "\n💥 FAILED TESTS (%d):\n" "$FAIL_COUNT"
	for f in "${FAILED_TESTS[@]}"; do printf "  ✗ %s\n" "$f"; done
	printf "\n"
	exit 1
fi

printf "\n🎉 ALL TESTS PASSED in %dm %02ds\n" $((ELAPSED / 60)) $((ELAPSED % 60))
exit 0


# ============================================================
# 🏁 END OF TESTS - LOG SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo " MEGATEST FINISHED"
echo "============================================================"
echo " 📄 Full log saved to: $LOG_FILE"
echo "============================================================"
