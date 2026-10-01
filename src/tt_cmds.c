/* ============================================================
   Time-Travel v1.5 — tt_cmds.c
   Comandos CLI: verify, watch, stop, undo, status, log, etc.
   ============================================================ */
#include "tt_cmds.h"
#include "tt_util.h"
#include "tt_cache.h"
#include "tt_history.h"
#include "tt_capture.h"
#include "tt_repo.h"


#include <signal.h>

/* ---------------- core daemon (tt_main.c) ---------------- */
extern TtDaemon g_core;
extern volatile sig_atomic_t g_signal_received;
extern void signal_handler(int sig);
extern int run_watch_loop(TtDaemon *d);
extern int try_client_add(const char *abs);

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "tt_exclude.h"

/* ---------------- externs: core ---------------- */
extern TtDaemon g_core;
extern volatile sig_atomic_t g_signal_received;
extern void signal_handler(int sig);

/* ---------------- externs: store ---------------- */
extern int tt_store_init(const char *);
extern void tt_store_free(void);
extern void tt_store_compat_set_key(const uint8_t key[32]);
extern void tt_store_set_key(TtStore *, const uint8_t key[32]);

/* ---------------- externs: restore/compact/verify ---------------- */
extern int tt_restore_file(const char *, const char *, uint64_t, const char *);
extern int tt_restore_dir(const char *, const char *, uint64_t, const char *);
extern int tt_restore_dir_per_file(const char *, const char *, const char *, int);
extern int tt_list_history(const char *, const char *);
extern int tt_compact_run(const char *store_dir);
extern int tt_verify_store(const char *store_dir, uint64_t *n_records, uint64_t *n_paths,
                           uint64_t *n_corrupt_records, uint64_t *n_corrupt_paths);

/* ---------------- externs: crypto ---------------- */
extern int tt_crypto_is_encrypted(const char *store_dir);
extern int tt_crypto_setup_repo(const char *store_dir, const uint8_t *pass, size_t passlen);
extern int tt_crypto_unlock_repo(const char *store_dir, const uint8_t *pass, size_t passlen, uint8_t key_out[32]);

/* ---------------- externs: ipc/boot ---------------- */
extern int tt_ipc_discover(char *, size_t, pid_t *);
extern int tt_ipc_client(const char *, const char *, char *, size_t);
extern int tt_ipc_global_status_path(char *, size_t);
extern void tt_boot_lock_acquire(void);
extern void tt_boot_lock_release(void);

/* ---------------- externs: store reader ---------------- */
extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *hdr, char *path_out, size_t max_path, uint8_t **payload_out, size_t *payload_sz);
extern void tt_store_reader_free(void);

/* ---------------- externs: dedup / compat key ---------------- */
extern int tt_dedup_reconstruct(const char *store_dir, const uint8_t *payload, size_t payload_size,
                                uint8_t **out, size_t *out_size, const uint8_t *key);
extern const uint8_t *tt_store_compat_get_key(void);

/* ---------------- externs: delta decoder ---------------- */
extern int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *delta_data, size_t delta_size,
                           size_t expected_new_size,
                           uint8_t **new_out, size_t *new_size_out);

/* ==================== Crypto helpers ==================== */

int tt_read_passphrase(const char *prompt, char *buf, size_t bufsz, int confirm)
{
    if (bufsz < 2)
        return -1;

    struct termios oldt, newt;
    int tty = isatty(STDIN_FILENO);

    if (tty) {
        if (tcgetattr(STDIN_FILENO, &oldt) != 0)
            tty = 0;
        else {
            newt = oldt;
            newt.c_lflag &= ~(tcflag_t)ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    char *r = fgets(buf, (int)bufsz, stdin);

    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fprintf(stderr, "\n");
    }

    if (!r) {
        buf[0] = '\0';
        return -1;
    }

    buf[strcspn(buf, "\r\n")] = '\0';

    if (confirm) {
        char again[256];
        if (tt_read_passphrase("Confirm passphrase: ", again, sizeof again, 0) != 0) {
            memset(again, 0, sizeof again);
            return -1;
        }
        int eq = (strcmp(buf, again) == 0);
        memset(again, 0, sizeof again);
        if (!eq) {
            fprintf(stderr, "error: passphrases do not match\n");
            return -1;
        }
    }

    return 0;
}

int tt_store_has_records(const char *store_dir)
{
    DIR *d = opendir(store_dir);
    if (!d)
        return 0;

    struct dirent *de;
    int found = 0;

    while ((de = readdir(d)) != NULL) {
        size_t ln = strlen(de->d_name);
        if (ln > 4 && strcmp(de->d_name + ln - 4, ".ttd") == 0) {
            found = 1;
            break;
        }
    }

    closedir(d);
    return found;
}

int tt_unlock_store_key(const char *store_dir, uint8_t key_out[32])
{
    if (!tt_crypto_is_encrypted(store_dir))
        return 0;

    char pass[256];
    if (tt_read_passphrase("Passphrase: ", pass, sizeof pass, 0) != 0)
        return -1;

    int rc = tt_crypto_unlock_repo(store_dir, (const uint8_t *)pass, strlen(pass), key_out);
    memset(pass, 0, sizeof pass);

    if (rc != 0) {
        fprintf(stderr, "error: wrong passphrase\n");
        return -1;
    }

    return 1;
}

int tt_unlock_compat_store(const char *store_dir)
{
    uint8_t key[32];
    int rc = tt_unlock_store_key(store_dir, key);
    if (rc < 0)
        return -1;
    if (rc == 1)
        tt_store_compat_set_key(key);
    memset(key, 0, sizeof key);
    return 0;
}

/* ==================== cmd_verify ==================== */

int tt_cmd_verify(const char *repo_dir)
{
    char wd[TT_PATH_MAX];
    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    char sd[TT_PATH_MAX * 2];
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    if (tt_store_init(sd) != 0) {
        fprintf(stderr, "error: could not open store\n");
        return 1;
    }

    if (tt_unlock_compat_store(sd) != 0) {
        tt_store_free();
        return 1;
    }

    uint64_t nrec = 0, npath = 0, ncrec = 0, ncpath = 0;

    printf("Verifying: %s\n", sd);

    int rc = tt_verify_store(sd, &nrec, &npath, &ncrec, &ncpath);
    tt_store_free();

    if (rc != 0) {
        fprintf(stderr, "error: could not read store\n");
        return 1;
    }

    printf("Records:   %llu\n", (unsigned long long)nrec);
    printf("Paths:     %llu\n", (unsigned long long)npath);

    if (ncpath == 0) {
        printf("Integrity: OK - no corruption detected\n");
        return 0;
    }

    printf("Integrity: CORRUPT - %llu bad record(s) in %llu path(s)\n",
           (unsigned long long)ncrec, (unsigned long long)ncpath);
    return 2;
}

/* ==================== cmd_watch ==================== */

int tt_cmd_watch(const char *dir, int fg, int encrypt)
{
    char wd[TT_PATH_MAX];
    if (!realpath(dir, wd)) {
        fprintf(stderr, "error: cannot resolve '%s': %s\n", dir, strerror(errno));
        return 1;
    }

    struct stat st;
    if (stat(wd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: not a directory: %s\n", wd);
        return 1;
    }

    tt_boot_lock_acquire();

    int crc = try_client_add(wd);
    if (crc >= 0) {
        tt_boot_lock_release();
        return crc;
    }

    char sd[TT_PATH_MAX * 2];
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    mkdir(sd, 0700);

    if (tt_find_running_daemon(sd, NULL) > 0) {
        printf("Daemon is already running in %s\nUse 'timetravel stop' or 'timetravel add <dir>'\n", wd);
        tt_boot_lock_release();
        return 0;
    }

    /* --- cifrado (antes del fork: el padre puede pedir passphrase) --- */
    int is_enc = tt_crypto_is_encrypted(sd);
    uint8_t repo_key[32];
    int have_key = 0;

    if (encrypt || is_enc) {
        if (encrypt && !is_enc && tt_store_has_records(sd)) {
            fprintf(stderr, "error: repo already has unencrypted history; cannot encrypt in place\n");
            tt_boot_lock_release();
            return 1;
        }

        char pass[256];
        int prc = (encrypt && !is_enc)
            ? tt_read_passphrase("New passphrase: ", pass, sizeof pass, 1)
            : tt_read_passphrase("Passphrase: ", pass, sizeof pass, 0);

        if (prc != 0) {
            tt_boot_lock_release();
            return 1;
        }

        if (encrypt && !is_enc &&
            tt_crypto_setup_repo(sd, (const uint8_t *)pass, strlen(pass)) != 0) {
            fprintf(stderr, "error: could not create crypto.meta\n");
            memset(pass, 0, sizeof pass);
            tt_boot_lock_release();
            return 1;
        }

        if (tt_crypto_unlock_repo(sd, (const uint8_t *)pass, strlen(pass), repo_key) != 0) {
            fprintf(stderr, "error: wrong passphrase\n");
            memset(pass, 0, sizeof pass);
            tt_boot_lock_release();
            return 1;
        }

        memset(pass, 0, sizeof pass);
        have_key = 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (!fg) {
        pid_t p = fork();
        if (p < 0) {
            tt_boot_lock_release();
            return 1;
        }

        if (p > 0) {
            char pf[TT_PATH_MAX + 64];
            tt_pid_file_path(pf, sizeof pf, sd);

            for (int i = 0; i < 120 && access(pf, F_OK) != 0; ++i)
                usleep(100 * 1000);

            if (kill(p, 0) != 0) {
                tt_boot_lock_release();
                fprintf(stderr, "error: daemon failed to start (check %s/timetravel.log)\n", sd);
                return 1;
            }

            printf("Time-Travel v1.5 started in background\n"
                   "PID:   %d\nRepo:  %s%s\n"
                   "Add:   timetravel add <dir>\nStop:  timetravel stop\n",
                   (int)p, wd, have_key ? "  [ENCRYPTED]" : "");

            if (access(pf, F_OK) != 0)
                printf("note: daemon alive, still indexing; IPC available shortly\n");

            return 0;
        }

        setsid();

        char lp[TT_PATH_MAX + 64];
        snprintf(lp, sizeof lp, "%s/.timetravel/timetravel.log", wd);

        int lf = open(lp, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (lf >= 0) {
            dup2(lf, 1);
            dup2(lf, 2);
            if (lf > 2)
                close(lf);
        }

        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) {
            dup2(dn, 0);
            if (dn > 2)
                close(dn);
        }
    }

    memset(&g_core, 0, sizeof g_core);
    g_core.ipc_fd = -1;
    g_core.running = 1;

    if (have_key) {
        g_core.has_crypto_key = 1;
        memcpy(g_core.crypto_key, repo_key, 32);
    }

    char err[256] = "";
    if (tt_repo_adopt_base(&g_core, wd, err, sizeof err) < 0) {
        fprintf(stderr, "error: %s", err);
        tt_boot_lock_release();
        return 1;
    }


    /* v1.5: aplicar exclusiones inline */
    tt_apply_pending_excludes(&g_core.repos[g_core.repo_count - 1]);
    if (have_key)
        tt_store_set_key(g_core.repos[0].store, repo_key);

    memset(repo_key, 0, sizeof repo_key);

    tt_repo_list_load(&g_core);

    return run_watch_loop(&g_core);
}

/* ==================== cmd_add / cmd_stop ==================== */

int tt_cmd_add(const char *dir)
{
    char wd[TT_PATH_MAX];
    if (!realpath(dir, wd)) {
        fprintf(stderr, "error: cannot resolve '%s': %s\n", dir, strerror(errno));
        return 1;
    }

    struct stat st;
    if (stat(wd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: not a directory: %s\n", wd);
        return 1;
    }

    return tt_cmd_watch(dir, 0, 0);
}

int tt_cmd_stop(const char *repo_dir)
{
    if (repo_dir && repo_dir[0]) {
        char sock[TT_PATH_MAX];
        pid_t dpid = -1;

        if (tt_ipc_discover(sock, sizeof sock, &dpid) == 0 && dpid > 0 && kill(dpid, 0) == 0) {
            char abs[TT_PATH_MAX];
            if (realpath(repo_dir, abs)) {
                char line[TT_PATH_MAX + 16], resp[TT_PATH_MAX + 128];
                snprintf(line, sizeof line, "REMOVE %s", abs);
                if (tt_ipc_client(sock, line, resp, sizeof resp) == 0) {
                    printf("%s", resp);
                    return (strncmp(resp, "OK", 2) == 0) ? 0 : 1;
                }
            }
        }
    }

    pid_t pid = -1;
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2];
    int have_local = 0;

    char sock[TT_PATH_MAX];
    pid_t dpid = -1;

    if (tt_ipc_discover(sock, sizeof sock, &dpid) == 0 && dpid > 0 && kill(dpid, 0) == 0)
        pid = dpid;

    if (pid < 0 && resolve_repo_arg(repo_dir, ".", wd, sizeof wd) == 0) {
        snprintf(sd, sizeof sd, "%s/.timetravel", wd);
        pid = tt_find_running_daemon(sd, NULL);
        have_local = 1;
    }

    if (pid < 0) {
        printf("No daemon running\n");
        return 0;
    }

    printf("Stopping Time-Travel (pid=%d)...\n", (int)pid);
    kill(pid, SIGTERM);

    for (int i = 0; i < 50; ++i) {
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            if (have_local) {
                char pf[TT_PATH_MAX + 64];
                tt_pid_file_path(pf, sizeof pf, sd);
                unlink(pf);
            }
            printf("Daemon stopped.\n");
            return 0;
        }
        usleep(100 * 1000);
    }

    fprintf(stderr, "warning: did not respond to SIGTERM; sending SIGKILL\n");
    kill(pid, SIGKILL);

    if (have_local) {
        char pf[TT_PATH_MAX + 64];
        tt_pid_file_path(pf, sizeof pf, sd);
        unlink(pf);
    }

    return 0;
}

/* ==================== cmd_undo ==================== */

int tt_cmd_undo(const char *path, const char *time_expr, const char *repo_dir,
                TtUndoMode mode, const char *tag_name, int force)
{
    char watch_dir[TT_PATH_MAX];
    if (resolve_repo_arg(repo_dir, path, watch_dir, sizeof watch_dir) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    char store_dir[TT_PATH_MAX * 2];
    snprintf(store_dir, sizeof store_dir, "%s/.timetravel", watch_dir);

    if (tt_store_init(store_dir) != 0)
        return 1;

    if (tt_unlock_compat_store(store_dir) != 0) {
        tt_store_free();
        return 1;
    }

    char rel_path[TT_PATH_MAX];
    if (make_rel_from_arg(watch_dir, path, rel_path, sizeof rel_path) != 0)
        rel_path[0] = '\0';

    char full_path[TT_PATH_MAX * 2];
    if (rel_path[0])
        snprintf(full_path, sizeof full_path, "%s/%s", watch_dir, rel_path);
    else
        snprintf(full_path, sizeof full_path, "%s", watch_dir);

    struct stat st;
    int is_dir = (rel_path[0] == '\0') || (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode));

    uint64_t target_ns = 0;
    int v_idx = 0;
    size_t v_total = 0;

    if (mode == UNDO_MODE_TIME) {
        char tdesc[128];
        int resolved = 0;

        if (!is_dir && rel_path[0])
            resolved = (tt_resolve_file_target_ns(store_dir, rel_path, time_expr, &target_ns, tdesc, sizeof tdesc) == 0);

        if (!resolved) {
            int tok = 0;
            target_ns = parse_time_expr(time_expr, &tok);
            if (!tok) {
                fprintf(stderr, "error: invalid time expression: '%s'\n", time_expr ? time_expr : "");
                tt_store_free();
                return 1;
            }
        }
    } else if (mode == UNDO_MODE_TAG) {
        if (tt_tag_lookup(store_dir, tag_name, &target_ns) != 0) {
            fprintf(stderr, "error: tag '%s' not found (use 'timetravel tags')\n", tag_name);
            tt_store_free();
            return 1;
        }
    } else if (!(is_dir && (mode == UNDO_MODE_LAST || mode == UNDO_MODE_INITIAL))) {
        uint64_t *ts = NULL;
        size_t n = 0;

        if (tt_scan_timestamps(rel_path, 0, &ts, &n) != 0 || n == 0) {
            fprintf(stderr, "error: no history for '%s'\n", path);
            free(ts);
            tt_store_free();
            return 1;
        }

        if (mode == UNDO_MODE_INITIAL) {
            target_ns = ts[0];
            v_idx = 1;
            v_total = n;
        } else {
            if (n < 2) {
                fprintf(stderr, "error: only %zu record(s); no previous version\n", n);
                free(ts);
                tt_store_free();
                return 1;
            }
            target_ns = ts[n - 2];
            v_idx = (int)n - 1;
            v_total = n;
        }

        free(ts);
    }

    /* --- Confirmation prompt --- */
    if (is_dir && !force) {
        if (mode == UNDO_MODE_INITIAL) {
            fprintf(stderr,
                    "WARNING: restore '%s' to its INITIAL state.\n"
                    "  - Files present at initial capture will be restored.\n"
                    "  - Files added AFTER the initial capture will be DELETED.\n"
                    "Continue? [y/N] ",
                    path[0] ? path : ".");
        } else {
            fprintf(stderr,
                    "WARNING: You are about to restore directory '%s' (files will be overwritten).\n"
                    "Continue? [y/N] ",
                    path[0] ? path : ".");
        }

        fflush(stderr);

        char ans[8] = {0};
        if (!fgets(ans, sizeof ans, stdin) || (ans[0] != 'y' && ans[0] != 'Y')) {
            printf("Canceled.\n");
            tt_store_free();
            return 0;
        }
    }

    /* --- Compute the actual target directory --- */
    char undo_dir[TT_PATH_MAX * 2];
    if (rel_path[0])
        snprintf(undo_dir, sizeof undo_dir, "%s/%s", watch_dir, rel_path);
    else
        snprintf(undo_dir, sizeof undo_dir, "%s", watch_dir);

    int rc;

    if (is_dir && (mode == UNDO_MODE_LAST || mode == UNDO_MODE_INITIAL))
        rc = tt_restore_dir_per_file(store_dir, rel_path, undo_dir, mode == UNDO_MODE_INITIAL ? 1 : 0);
    else if (is_dir)
        rc = tt_restore_dir(store_dir, rel_path, target_ns, undo_dir);
    else
        rc = tt_restore_file(store_dir, rel_path, target_ns, full_path);

    tt_store_free();

    if (rc == 0) {
        char ts_str[64];
        format_timestamp(target_ns, ts_str, sizeof ts_str);

        printf("OK '%s' restored successfully\n", path);

        if (mode == UNDO_MODE_TIME || mode == UNDO_MODE_TAG)
            printf("  Time point: %s\n", ts_str);
        if (mode == UNDO_MODE_TAG)
            printf("  Tag:            %s\n", tag_name);
        else if (mode != UNDO_MODE_TIME && v_total > 0)
            printf("  Version:        %d of %zu\n", v_idx, v_total);

        printf("  Destination:    %s\n", is_dir ? undo_dir : full_path);
    } else if (rc == 1) {
        fprintf(stderr, "info: '%s' did not exist at that time point.\n", path);
    } else {
        fprintf(stderr, "error: failed to restore '%s'.\n", path);
    }

    return (rc == 0 || rc == 1) ? 0 : 1;
}

/* ==================== cmd_status ==================== */

int tt_cmd_status_global(void)
{
    char sf_path[TT_PATH_MAX];
    tt_ipc_global_status_path(sf_path, sizeof sf_path);

    TtStatusFile sf;
    if (tt_status_read_file(sf_path, &sf) != 0 || !proc_alive(sf.pid)) {
        printf("No Time-Travel daemon running.\nStart one with: timetravel start <dir>\n");
        return 0;
    }

    uint64_t now = tt_now_ns();
    uint64_t up = (now > sf.start_ns) ? (now - sf.start_ns) : 0;

    char upbuf[128], b[64];
    format_ns_duration(up, upbuf, sizeof upbuf);
    format_bytes(sf.bytes, b, sizeof b);

    printf("=== Time-Travel v1.5 Swarm (global) ===\n");
    printf("Daemon:    running (pid=%d)\nUptime:    %s\n", (int)sf.pid, upbuf);

    double cpu = proc_cpu_percent(sf.pid);
    if (cpu >= 0.0)
        printf("CPU:       %.1f%%\n", cpu);

    long rss = proc_rss_kb(sf.pid);
    if (rss >= 0) {
        char mem[64];
        format_bytes((uint64_t)rss * 1024ULL, mem, sizeof mem);
        printf("RAM:       %s\n", mem);
    }

    printf("Written:   %llu deltas, %s\n", (unsigned long long)sf.deltas, b);
    printf("Records:   %llu\n", (unsigned long long)sf.deltas);
    printf("Repos (%d):\n", sf.repo_count);

    for (int i = 0; i < sf.repo_count; ++i) {
        char rb[64];
        format_bytes(sf.repos[i].bytes, rb, sizeof rb);
        printf("  [%2d] %-40s deltas=%-8llu bytes=%-10s files=%-6llu%s\n",
               i, sf.repos[i].root,
               (unsigned long long)sf.repos[i].deltas, rb,
               (unsigned long long)sf.repos[i].files,
               sf.repos[i].lost ? "  [ROOT LOST]" : "");
    }

    printf("Per-repo disk stats: timetravel status --repo <dir>\n");
    return 0;
}

int tt_cmd_status(const char *repo_dir)
{
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2];

    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        if (repo_dir == NULL)
            return tt_cmd_status_global();
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    TtStatusFile sf;
    int have_sf = (tt_status_read(sd, &sf) == 0);

    uint64_t pid_start = 0;
    pid_t pid = tt_find_running_daemon(sd, &pid_start);

    if (pid <= 0 && have_sf && proc_alive(sf.pid)) {
        pid = sf.pid;
        pid_start = sf.start_ns;
    }

    printf("=== Time-Travel v1.5 Status ===\nRepo anchor: %s\n", wd);

    if (pid > 0 && proc_alive(pid)) {
        uint64_t start_ns = have_sf ? sf.start_ns : pid_start;
        uint64_t now = tt_now_ns();
        uint64_t up = (now > start_ns) ? (now - start_ns) : 0;

        char upbuf[128];
        format_ns_duration(up, upbuf, sizeof upbuf);

        double cpu = proc_cpu_percent(pid);
        long rss = proc_rss_kb(pid);

        printf("Daemon:    running (pid=%d)\nUptime:    %s\n", (int)pid, upbuf);

        if (cpu >= 0.0)
            printf("CPU:       %.1f%%\n", cpu);
        else
            printf("CPU:       ?\n");

        if (rss >= 0) {
            char mem[64];
            format_bytes((uint64_t)rss * 1024ULL, mem, sizeof mem);
            printf("RAM:       %s\n", mem);
        } else {
            printf("RAM:       ?\n");
        }

        if (have_sf) {
            char b[64];
            format_bytes(sf.bytes, b, sizeof b);
            printf("Written:   %llu deltas, %s\nPending:   %llu\n",
                   (unsigned long long)sf.deltas, b, (unsigned long long)sf.pending);

            if (sf.repo_count > 0) {
                printf("Repos (%d):\n", sf.repo_count);
                for (int i = 0; i < sf.repo_count; ++i) {
                    char rb[64];
                    format_bytes(sf.repos[i].bytes, rb, sizeof rb);
                    printf("  [%2d] %-40s deltas=%-8llu bytes=%-10s files=%-6llu%s\n",
                           i, sf.repos[i].root,
                           (unsigned long long)sf.repos[i].deltas, rb,
                           (unsigned long long)sf.repos[i].files,
                           sf.repos[i].lost ? "  [ROOT LOST]" : "");
                }
            }
        }
    } else {
        printf("Daemon:    not running\n");
    }

    uint64_t nrecords = 0, nbytes = 0, fts = 0, lts = 0;
    uint8_t skey[32];
    int have_skey = 0;

    {
        uint8_t k[32];
        int rc = tt_unlock_store_key(sd, k);
        if (rc == 1) {
            memcpy(skey, k, 32);
            have_skey = 1;
        }
        memset(k, 0, sizeof k);
    }

    tt_scan_stats_dir(sd, have_skey ? skey : NULL, &nrecords, &nbytes, &fts, &lts);
    memset(skey, 0, sizeof skey);

    char b[64];
    format_bytes(nbytes, b, sizeof b);

    printf("Records:   %llu\nBytes:     %s\n", (unsigned long long)nrecords, b);

    char b1[64], b2[64];
    if (fts)
        format_timestamp(fts, b1, sizeof b1);
    else
        snprintf(b1, sizeof b1, "-");
    if (lts)
        format_timestamp(lts, b2, sizeof b2);
    else
        snprintf(b2, sizeof b2, "-");

    printf("First:     %s\nLast:      %s\n==========================\n", b1, b2);

    return 0;
}

/* ==================== cmd_log / compact / tag / diff / dump ==================== */

int tt_cmd_log(const char *path, const char *repo_dir, const char *since_expr)
{
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2], rel[TT_PATH_MAX];

    if (resolve_repo_arg(repo_dir, path, wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    if (tt_store_init(sd) != 0)
        return 1;

    if (tt_unlock_compat_store(sd) != 0) {
        tt_store_free();
        return 1;
    }

    if (make_rel_from_arg(wd, path, rel, sizeof rel) != 0)
        rel[0] = '\0';

    if (!since_expr) {
        int rc = tt_list_history(sd, rel[0] ? rel : NULL);
        tt_store_free();
        return rc;
    }

    int tok = 0;
    uint64_t since_ns = parse_time_expr(since_expr, &tok);
    if (!tok) {
        fprintf(stderr, "error: invalid time expression: '%s'\n", since_expr);
        tt_store_free();
        return 1;
    }

    if (tt_store_reader_init() != 0) {
        tt_store_free();
        return 1;
    }

    printf("History of: %s (since %s)\n", rel[0] ? rel : "(all)", since_expr);

    int any = 0;

    for (;;) {
        TtDeltaHeader hdr;
        char p2[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, p2, sizeof p2, &pl, &plsz);
        if (rc <= 0)
            break;

        if (rel[0] && strcmp(p2, rel) != 0) {
            free(pl);
            continue;
        }

        if (hdr.timestamp_ns < since_ns) {
            free(pl);
            continue;
        }

        char ts[64];
        format_timestamp(hdr.timestamp_ns, ts, sizeof ts);

        const char *ev = hdr.event_type == TT_EV_CREATE ? "CREATE" :
                         hdr.event_type == TT_EV_MODIFY ? "MODIFY" :
                         hdr.event_type == TT_EV_DELETE ? "DELETE" : "???";

        printf("  %-20s  %-8s  delta=%10u  file=%10llu  %s\n",
               ts, ev, hdr.delta_size, (unsigned long long)hdr.file_size, p2);
        any = 1;

        free(pl);
    }

    tt_store_reader_free();
    tt_store_free();

    if (!any)
        printf("  (no events in that range)\n");

    return 0;
}

int tt_cmd_compact(const char *repo_dir)
{
    char wd[TT_PATH_MAX];

    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    char sd[TT_PATH_MAX * 2];
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    if (tt_store_init(sd) != 0)
        return 1;

    if (tt_unlock_compat_store(sd) != 0) {
        tt_store_free();
        return 1;
    }

    int rc = tt_compact_run(sd);
    tt_store_free();

    if (rc < 0) {
        fprintf(stderr, "error: compaction failed\n");
        return 1;
    }

    printf("compaction: %d chain(s) collapsed\n", rc);
    return 0;
}

int tt_cmd_tag(const char *name, const char *repo_dir)
{
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2];

    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    mkdir(sd, 0700);

    uint64_t ts = tt_now_ns();

    if (tt_tag_add(sd, name, ts) != 0) {
        fprintf(stderr, "error: could not write tag\n");
        return 1;
    }

    char tsbuf[64];
    format_timestamp(ts, tsbuf, sizeof tsbuf);

    printf("OK Tag '%s' created at %s\nRestore: timetravel undo <path> --tag %s --repo %s\n",
           name, tsbuf, name, wd);

    return 0;
}

int tt_cmd_diff(const char *path, const char *repo_dir, const char *time_expr)
{
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2], rel[TT_PATH_MAX];

    if (resolve_repo_arg(repo_dir, path, wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    if (tt_store_init(sd) != 0)
        return 1;

    if (tt_unlock_compat_store(sd) != 0) {
        tt_store_free();
        return 1;
    }

    if (make_rel_from_arg(wd, path, rel, sizeof rel) != 0 || rel[0] == '\0') {
        fprintf(stderr, "error: diff requires a file inside the repo\n");
        tt_store_free();
        return 1;
    }

    uint64_t target_ns = 0;
    char tdesc[128];

    if (tt_resolve_file_target_ns(sd, rel, time_expr, &target_ns, tdesc, sizeof tdesc) != 0) {
        fprintf(stderr, "error: no history for '%s'\n", path);
        tt_store_free();
        return 1;
    }

    uint8_t *old_data = NULL;
    size_t old_size = 0;
    int exists = 0;

    tt_load_version_content(sd, rel, target_ns, &old_data, &old_size, &exists);
    tt_store_free();

    char fp[TT_PATH_MAX * 2];
    snprintf(fp, sizeof fp, "%s/%s", wd, rel);

    uint8_t *cur_data = NULL;
    size_t cur_size = 0;
    read_file_all(fp, &cur_data, &cur_size);

    char ta[] = "/tmp/tt_diff_old_XXXXXX";
    char tb[] = "/tmp/tt_diff_new_XXXXXX";

    int fda = mkstemp(ta);
    int fdb = mkstemp(tb);

    if (fda < 0 || fdb < 0) {
        fprintf(stderr, "error: could not create temporaries (%s)\n", strerror(errno));
        if (fda >= 0)
            close(fda);
        if (fdb >= 0)
            close(fdb);
        free(old_data);
        free(cur_data);
        return 1;
    }

    if (old_size > 0) {
        ssize_t wr = write(fda, old_data, old_size);
        (void)wr;
    }
    if (cur_size > 0) {
        ssize_t wr = write(fdb, cur_data, cur_size);
        (void)wr;
    }

    close(fda);
    close(fdb);

    char cmdbuf[1024];
    snprintf(cmdbuf, sizeof cmdbuf,
             "diff -u --label \"%s (%s)\" --label \"%s (current)\" \"%s\" \"%s\" 2>/dev/null",
             path, tdesc, path, ta, tb);

    int rc = system(cmdbuf);

    if (rc == -1)
        fprintf(stderr, "warning: could not execute 'diff'\n");
    else if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0)
        printf("(no differences)\n");

    unlink(ta);
    unlink(tb);

    free(old_data);
    free(cur_data);

    return 0;
}

static int dump_one_file(const char *store_dir, const char *rel, const char *outdir,
                         int with_diff, FILE *manifest)
{
    char safe[TT_PATH_MAX];
    sanitize_component(rel[0] ? rel : "root", safe, sizeof safe);

    char fdir[TT_PATH_MAX * 2];
    char ddir[TT_PATH_MAX * 2];

    snprintf(fdir, sizeof fdir, "%s/files/%s", outdir, safe);
    mkdir_p(fdir);

    if (with_diff) {
        snprintf(ddir, sizeof ddir, "%s/diffs/%s", outdir, safe);
        mkdir_p(ddir);
    }

    if (tt_store_reader_init() != 0)
        return -1;

    uint8_t *state = NULL;
    size_t state_size = 0;
    int have = 0;
    uint64_t seq = 0;
    char prev_file[(TT_PATH_MAX * 2) + 64] = "";



    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;

        if (strcmp(path, rel) != 0) {
            free(pl);
            continue;
        }

        int changed = 0;

        if (hdr.event_type == TT_EV_DELETE) {
            free(state);
            state = NULL;
            state_size = 0;
            have = 0;

            if (manifest)
                fprintf(manifest, "%s\t%llu\tDELETE\t0\t-\n",
                        rel, (unsigned long long)hdr.timestamp_ns);

        } else if (hdr.event_type == TT_EV_CREATE) {
            free(state);
            state = NULL;
            state_size = 0;

            if (plsz > 0 && pl) {
                state = malloc(plsz);
                if (state) {
                    memcpy(state, pl, plsz);
                    state_size = plsz;
                }
            }

            have = 1;
            changed = 1;

        } else if (hdr.event_type == TT_EV_CREATE_DEDUP) {
            free(state);
            state = NULL;
            state_size = 0;

            uint8_t *rec = NULL;
            size_t rec_sz = 0;

            if (pl && plsz > 0 &&
                tt_dedup_reconstruct(store_dir, pl, plsz,
                                     &rec, &rec_sz,
                                     tt_store_compat_get_key()) == 0 &&
                (uint64_t)rec_sz == hdr.file_size) {
                state = rec;
                state_size = rec_sz;
                have = 1;
                changed = 1;
            } else {
                free(rec);
                fprintf(stderr,
                        "tt_dump: cannot reconstruct dedup object for '%s'\n",
                        rel);
            }

        } else if (hdr.event_type == TT_EV_MODIFY) {
            if (plsz > 0) {
                if (have) {
                    uint8_t *ns = NULL;
                    size_t nss = 0;

                    if (tt_delta_decode(state, state_size,
                                        pl, plsz,
                                        hdr.file_size,
                                        &ns, &nss) == 0) {
                        free(state);
                        state = ns;
                        state_size = nss;
                        changed = 1;
                    }
                }

/* Fallback: some MODIFY records may store full content. */
                if (!changed && plsz == hdr.file_size) {
                    free(state);
                    state = malloc(plsz);
                    if (state) {
                        memcpy(state, pl, plsz);
                        state_size = plsz;
                        have = 1;
                        changed = 1;
                    }
                }
            }
        }

        free(pl);

        if (changed) {
            seq++;

            char cur[(TT_PATH_MAX * 2) + 64];
            snprintf(cur, sizeof cur, "%s/v%06llu_%llu",
                     fdir,
                     (unsigned long long)seq,
                     (unsigned long long)hdr.timestamp_ns);

            write_file_all(cur, state, state_size);

            if (with_diff && prev_file[0]) {
                char diff_file[(TT_PATH_MAX * 2) + 64];
                snprintf(diff_file, sizeof diff_file,
                         "%s/%06llu_to_%06llu.diff",
                         ddir,
                         (unsigned long long)(seq - 1),
                         (unsigned long long)seq);

                run_diff_file(prev_file, cur, diff_file);
            }

            snprintf(prev_file, sizeof prev_file, "%s", cur);

            if (manifest) {
                const char *ev_name =
                    hdr.event_type == TT_EV_CREATE ? "CREATE" :
                    hdr.event_type == TT_EV_CREATE_DEDUP ? "CREATE_D" :
                    "MODIFY";

                fprintf(manifest, "%s\t%llu\t%s\t%zu\t%s\n",
                        rel,
                        (unsigned long long)hdr.timestamp_ns,
                        ev_name,
                        state_size,
                        cur);
            }
        }
    } 
  
    free(state);

    return seq > 0 ? 0 : 1;
}

int tt_cmd_dump(const char *path, const char *repo_dir, const char *outdir, int with_diff)
{
    if (!outdir || !outdir[0]) {
        fprintf(stderr, "error: dump requires --out <dir>\n");
        return 1;
    }

    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2], rel[TT_PATH_MAX];

    if (resolve_repo_arg(repo_dir, path, wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    if (tt_store_init(sd) != 0)
        return 1;

    if (tt_unlock_compat_store(sd) != 0) {
        tt_store_free();
        return 1;
    }

    if (make_rel_from_arg(wd, path, rel, sizeof rel) != 0)
        rel[0] = '\0';

    if (mkdir_p(outdir) != 0) {
        fprintf(stderr, "error: could not create '%s'\n", outdir);
        tt_store_free();
        return 1;
    }

    char manifest_path[TT_PATH_MAX * 2];
    snprintf(manifest_path, sizeof manifest_path, "%s/manifest.tsv", outdir);

    FILE *manifest = fopen(manifest_path, "w");
    if (!manifest) {
        fprintf(stderr, "error: could not create manifest.tsv\n");
        tt_store_free();
        return 1;
    }

    fprintf(manifest, "path\ttimestamp\tevent\tsize\tversion_file\n");

    TtPathSet set;
    tt_store_collect_matching(&set, rel);

    if (set.n == 0) {
        printf("no history for '%s'\n", path);
        fclose(manifest);
        tt_pathset_free(&set);
        tt_store_free();
        return 1;
    }

    int ok = 0;

    for (size_t i = 0; i < set.n; ++i) {
        int rc = dump_one_file(sd, set.v[i], outdir, with_diff, manifest);
        if (rc == 0)
            ok++;
    }

    fclose(manifest);
    tt_pathset_free(&set);
    tt_store_free();

    printf("dump: %d file(s) with history in %s\n", ok, outdir);
    return ok > 0 ? 0 : 1;
}

/* ==================== cmd_exclude (v1.5) ==================== */

int tt_cmd_exclude(const char *action, const char *pattern, const char *repo_dir)
{
    char wd[TT_PATH_MAX];
    char sd[TT_PATH_MAX * 2];

    if (!action || !action[0]) {
        fprintf(stderr, "error: exclude requires add|remove|list\n");
        return 1;
    }

    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }

    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    mkdir(sd, 0700);

    TtExcludeList list;
    tt_exclude_init(&list);
    tt_exclude_load(sd, &list);

    int rc = 0;

    if (strcmp(action, "add") == 0) {
        if (!pattern || !pattern[0]) {
            fprintf(stderr, "error: exclude add requires a pattern\n");
            rc = 1;
        } else {
            tt_exclude_add(&list, pattern);
            if (tt_exclude_save(sd, &list) == 0)
                printf("OK excluded: %s\n", pattern);
            else {
                fprintf(stderr, "error: could not save exclude.list\n");
                rc = 1;
            }
        }

    } else if (strcmp(action, "remove") == 0) {
        if (!pattern || !pattern[0]) {
            fprintf(stderr, "error: exclude remove requires a pattern\n");
            rc = 1;
        } else if (tt_exclude_remove(&list, pattern) == 0) {
            tt_exclude_save(sd, &list);
            printf("OK removed: %s\n", pattern);
        } else {
            printf("Pattern not found: %s\n", pattern);
        }

    } else if (strcmp(action, "list") == 0) {
        if (list.count == 0) {
            printf("No exclude patterns.\n");
        } else {
            printf("Exclude patterns (%zu):\n", list.count);
            for (size_t i = 0; i < list.count; ++i)
                printf("  %s\n", list.patterns[i]);
        }

    } else {
        fprintf(stderr,
                "error: unknown exclude action '%s' (use add|remove|list)\n",
                action);
        rc = 1;
    }

    tt_exclude_free(&list);
    return rc;
}
