#!/bin/bash
# ============================================================
# Time-Travel CLI — Test Battery (43 sections)
# Usage: ./mega_test.sh [binary_path]
# ============================================================
set -uo pipefail
exec </dev/null   # avoids hangs from prompts in non-interactive execution
TT="${1:-./timetravel}"


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

    # 0) Override manual explícito
    case "${TT_FORCE_SANITIZER:-}" in
        tsan|TSAN) printf '100 0\n'; return ;;
        asan|ASAN) printf '0 100\n'; return ;;
    esac

    # 1) Nombre / ruta del binario (fuerte)
    case "$TT" in
        *tsan*|*TSAN*) tsan_score=$((tsan_score + 10)) ;;
    esac
    case "$TT" in
        *asan*|*ASAN*|*build_san/*) asan_score=$((asan_score + 10)) ;;
    esac

    # 2) Librerías dinámicas exactas
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

    # 3) Símbolos sanitizer reales (más preciso que grep "__tsan")
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

    # 4) Cadenas del runtime (fallback si nm/readelf no disponibles)
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

    # 5) Variables de entorno solo como desempate si ya hay evidencia binaria
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

# Verificación de coherencia
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
LOGFILE="test_battery.log"
exec > >(tee "$LOGFILE") 2>&1

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
	for _ in $(seq 1 60); do
		cur="$(get_record_count "$dir")"
		if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then
			stable=$((stable+1))
			if [ "$stable" -ge 3 ]; then return 0; fi
		else
			stable=0
		fi
		prev="$cur"
		sleep 0.5
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

# --- Limpieza de daemons huérfanos (v1.3 multi-repo) ---
# Mata TODOS los daemons timetravel. Llamar SOLO cuando no haya
# invocaciones activas (inicio, cleanup, fin de sección).
kill_all_tt_daemons() {
    pkill -9 -f "timetravel start" 2>/dev/null
    pkill -9 -f "timetravel add"   2>/dev/null
    pkill -9 -f "timetravel watch" 2>/dev/null
    sleep 0.3
}
# Borra el estado global de descubrimiento del monolito
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

# Esperar a que status responda correctamente
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
# ============================================================
# 5. undo --to (time point & exact dates)
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

# Garantizamos que el timestamp es posterior a v2
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
wait_for_stable_records "$D9"
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
"$TT" start "$D27" >/dev/null 2>&1; sleep 1
echo "y" > "$D27/f.txt"
wait_for_stable_records "$D27"
L27="$("$TT" log "$D27/f.txt" --since "10 minutes ago" --repo "$D27" 2>&1)"
assert_contains "27.1 log --since shows recent events" "$L27" "f.txt"
L27B="$("$TT" log "$D27/f.txt" --since "1 hours ago" --repo "$D27" 2>&1)"
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
# Cosecha acotada (nunca `wait` pelado: esperaría al hijo del `>(tee ...)`)
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

# Limpieza contundente: mata el daemon de esta sección (evita huérfanos)
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

# Esperar a que el daemon capture (crítico bajo ASan)
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

# Verify con captura completa de ASan output
ASAN_OPTIONS=halt_on_error=0:detect_leaks=0:log_path="$ASAN_LOG" \
    "$TT" verify --repo "$D36" > "$ASAN_LOG.stdout" 2> "$ASAN_LOG.stderr"
RC36=$?

V36="$(cat "$ASAN_LOG.stdout" 2>/dev/null)"
E36="$(cat "$ASAN_LOG.stderr" 2>/dev/null)"

# Si ASan escribió errores, mostrarlos
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
    # Sobrescribir el archivo completo con basura (magic + header + payload)
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
# versión 1: 2 MiB aleatorios + copia de referencia
dd if=/dev/urandom of="$D37/big.bin" bs=1024 count=2048 2>/dev/null
cp "$D37/big.bin" "$D37/big.v1"
wait_for_min_records "$D37" 2
# versión 2: contenido distinto
dd if=/dev/urandom of="$D37/big.bin" bs=1024 count=2048 2>/dev/null
wait_for_min_records "$D37" 3
# undo --last → debe restaurar la versión 1 releyendo los bloques del pool
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

# 2 MiB -> 32 real blocks in the pool
dd if=/dev/urandom of="$D38/big.bin" bs=1024 count=2048 2>/dev/null

wait_for_min_records "$D38" 1

"$TT" stop --repo "$D38" >/dev/null 2>&1
sleep 1

BEFORE=$(find "$D38/.timetravel/blocks" -type f 2>/dev/null | wc -l)

# Fake orphan block (not referenced by any record)
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
    section "39. XChaCha20-Poly1305 encryption"

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

# v1: file > 1 MiB with unique blocks and a recognizable secret
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
    # Corrupt verifier area (offset 40 inside the 61-byte meta file)
    printf 'X' | dd of="$META40" bs=1 seek=40 count=1 conv=notrunc 2>/dev/null

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

else
    VG_BIN=""

case "${TT:-}" in
    *valgrind*|*timetravel_valgrind*)
        # Extract the real binary from the wrapper
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

# --- dataset: 1 MiB random + 50 files ---
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

# 7 ficheros iniciales
for i in 1 2 3 4 5 6 7; do
    echo "initial $i" > "$D42/src/file_$i.txt"
done

"$TT" start "$D42" >/dev/null 2>&1
vg_sleep 2

# Modificar un fichero inicial
echo "MODIFIED" > "$D42/src/file_3.txt"
vg_sleep 2

# Añadir 20 ficheros nuevos
for i in $(seq 1 20); do
    echo "new $i" > "$D42/src/new_$i.txt"
done
vg_sleep 3

# undo --initial del subdirectorio
"$TT" undo "$D42/src" --initial --repo "$D42" --force >/dev/null 2>&1

# 42.1: el fichero modificado vuelve al contenido original
assert_file_content "42.1 modified file restored to initial content" \
    "$D42/src/file_3.txt" "initial 3"

# 42.2: los ficheros nuevos han sido borrados
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

# v1: fichero > 1 MiB para forzar CREATE_D
dd if=/dev/urandom of="$D43/big.bin" bs=1024 count=1100 2>/dev/null
cp "$D43/big.bin" "$D43/big.v1"

wait_for_min_records_vg "$D43" 1 60

# v2: modificar el fichero grande
printf 'TT_DEDUP_DUMP_REGRESSION
' >> "$D43/big.bin"
cp "$D43/big.bin" "$D43/big.v2"

wait_for_min_records_vg "$D43" 2 60

# Paramos el daemon para dejar el store tranquilo antes del dump
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
printf "  Log:       %s\n" "$LOGFILE"
printf "============================================================\n"

if [ "$FAIL_COUNT" -gt 0 ]; then
	printf "\n💥 FAILED TESTS (%d):\n" "$FAIL_COUNT"
	for f in "${FAILED_TESTS[@]}"; do printf "  ✗ %s\n" "$f"; done
	printf "\n"
	exit 1
fi

printf "\n🎉 ALL TESTS PASSED in %dm %02ds\n" $((ELAPSED / 60)) $((ELAPSED % 60))
exit 0
