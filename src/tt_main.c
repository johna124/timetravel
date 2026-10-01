/*
 * Time-Travel is a real-time file versioning daemon that watches a directory
 * tree via inotify and records every change as compact xdelta3 deltas.
 * Copyright (C) 2026  John (johna124)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Source, issues, contact: https://github.com/johna124
 */
/* ============================================================
   Time-Travel v1.5 — MONOLITO MULTI-REPO + CIFRADO
   ============================================================ */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include  "tt_types.h"
#include  "tt_ipc.h"
#include  <dirent.h>
#include  <errno.h>
#include  <fcntl.h>
#include  <poll.h>
#include  <signal.h>
#include  <stdarg.h>
#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>
#include  <strings.h>
#include  <sys/stat.h>
#include  <sys/wait.h>
#include  <termios.h>
#include  <time.h>
#include  <unistd.h>
#include "tt_blake2b.h"
#include "tt_util.h"
#include "tt_cache.h"
#include "tt_history.h"
#include "tt_capture.h"
#include "tt_repo.h"
#include "tt_cmds.h"
#include "tt_exclude.h"
#include "tt_reconstruct.h"
#include "tt_autotag.h"
#include "tt_annotation.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

/* ---------------- externs ---------------- */
extern int tt_dedup_split(const char *store_dir, const uint8_t *data, size_t size,
                          uint8_t **hashes_out, size_t *nblocks_out, const uint8_t *key);
extern int tt_dedup_reconstruct(const char *store_dir, const uint8_t *payload, size_t payload_size,
                                uint8_t **out, size_t *out_size, const uint8_t *key);

extern const uint8_t *tt_store_get_key(const TtStore *s);
extern const uint8_t *tt_store_compat_get_key(void);

extern const uint8_t *tt_store_get_key(const TtStore *s);

extern int tt_verify_store(const char *store_dir, uint64_t *n_records, uint64_t *n_paths,
                           uint64_t *n_corrupt_records, uint64_t *n_corrupt_paths);

extern int  tt_watcher_remove_repo(TtDaemon*, int);
extern int tt_delta_encode(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t**, size_t*);
extern int tt_delta_decode(const uint8_t*, size_t, const uint8_t*, size_t, size_t, uint8_t**, size_t*);

/* store: API global de compatibilidad (CLI, restore, compact) */
extern int tt_store_init(const char*);
extern void tt_store_free(void);
extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader*, char*, size_t, uint8_t**, size_t*);
extern void tt_store_reader_free(void);
extern void tt_store_compat_set_key(const uint8_t key[32]);

/* store: API por contexto (daemon multi-repo) */
extern TtStore* tt_store_open(const char*, int);
extern void tt_store_close(TtStore*);
extern int tt_store_write_ctx(TtStore*, const TtDeltaHeader*, const char*, const uint8_t*);
extern void tt_store_set_key(TtStore*, const uint8_t key[32]);
extern TtStoreReader* tt_reader_open(const char*);
extern int tt_reader_next(TtStoreReader*, TtDeltaHeader*, char*, size_t, uint8_t**, size_t*);
extern void tt_reader_close(TtStoreReader*);
extern void tt_reader_set_key(TtStoreReader*, const uint8_t key[32]);

/* cifrado (F3/F4) */
extern int tt_crypto_is_encrypted(const char *store_dir);
extern int tt_crypto_setup_repo(const char *store_dir, const uint8_t *pass, size_t passlen);
extern int tt_crypto_unlock_repo(const char *store_dir, const uint8_t *pass, size_t passlen, uint8_t key_out[32]);

/* restore / historial / compact */
extern int tt_restore_file(const char*, const char*, uint64_t, const char*);
extern int tt_restore_dir(const char*, const char*, uint64_t, const char*);
extern int tt_restore_dir_per_file(const char*, const char*, const char*, int);
extern int tt_list_history(const char*, const char*);
extern int tt_compact_run(const char *store_dir);

/* filtro */
extern int tt_is_excluded(const char*);

/* debounce (cola explícita por repo) */
extern void tt_debounce_init(TtDebounce*);
extern void tt_debounce_free(TtDebounce*);
extern void tt_debounce_add(TtDebounce*, const char*, uint8_t);
extern int  tt_debounce_process(TtDaemon*, TtDebounce*, TtProcessCb, void*);

/* watcher (un inotify_fd, N repos) */
extern int  tt_watcher_init(TtDaemon*);
extern void tt_watcher_free(TtDaemon*);
extern int  tt_watcher_add_repo(TtDaemon*, int);
extern int  tt_watcher_rebuild_repo(TtDaemon*, int);
extern int  tt_watcher_rebuild_all(TtDaemon*);
extern void tt_watcher_process_events(TtDaemon*);

extern void tt_set_pending_excludes(const char **patterns, int n);

/* ---------------- núcleo ---------------- */
TtDaemon g_core;
volatile sig_atomic_t g_signal_received = 0;

// En src/tt_main.c:
void signal_handler(int sig) {
    (void)sig;
    
    static int ya_saliendo = 0;
    if (ya_saliendo) return;
    ya_saliendo = 1;

    g_signal_received = 1;

   _exit(0); 
}


/* ---------------- handlers IPC ---------------- */
int tt_core_ipc_add(TtDaemon *d, const char *path, char *resp, size_t respsz) {
    char abs[TT_PATH_MAX];
    if (!realpath(path, abs)) {
        snprintf(resp, respsz, "ERR realpath failed: %s\n", strerror(errno));
        return -1;
    }
    char err[256] = "";
    int rc = tt_repo_adopt_base(d, abs, err, sizeof err);
    if (rc < 0) {
        snprintf(resp, respsz, "%s", err[0] ? err : "ERR adopt failed\n");
        return -1;
    }
    if (rc == 1) {
        snprintf(resp, respsz, "OK already watching %s (%d repos)\n", abs, d->repo_count);
        return 0;
    }
    tt_repo_finish_watch(d, d->repo_count - 1);
    tt_repo_list_sync(d);
    tt_status_write(d);
    snprintf(resp, respsz, "OK watching %s (%d repos)\n", abs, d->repo_count);
    return 0;
}

int tt_core_ipc_list(TtDaemon *d, char *resp, size_t respsz) {
    size_t off = 0;
    off += (size_t)snprintf(resp + off, respsz - off, "OK %d repos\n", d->repo_count);
    for (int i = 0; i < d->repo_count && off + 128 < respsz; ++i) {
        TtLocalRepo *r = &d->repos[i];
        off += (size_t)snprintf(resp + off, respsz - off,
                                "  [%d] %s deltas=%llu bytes=%llu files=%zu%s\n",
                                i, r->root,
                                (unsigned long long)r->deltas_written,
                                (unsigned long long)r->bytes_stored,
                                r->cache.active_count,
                                r->root_lost ? " [ROOT LOST]" : "");
    }
    return 0;
}

int tt_core_ipc_remove(TtDaemon *d, const char *path, char *resp, size_t respsz) {
    char abs[TT_PATH_MAX];
    if (!realpath(path, abs)) {
        snprintf(resp, respsz, "ERR realpath failed: %s\n", strerror(errno));
        return -1;
    }
    int idx = -1;
    for (int i = 0; i < d->repo_count; ++i)
        if (d->repos[i].active && strcmp(d->repos[i].root, abs) == 0) { idx = i; break; }
    if (idx < 0) {
        snprintf(resp, respsz, "ERR not watching %s\n", abs);
        return -1;
    }
    tt_log("REMOVE  %s (repo #%d)\n", abs, idx);
    tt_repo_release(d, idx);
    tt_repo_list_sync(d);
    if (d->repo_count == 0) {
        d->running = 0;
        snprintf(resp, respsz, "OK removed %s; no repos left, daemon exiting\n", abs);
    } else {
        tt_status_write(d);
        snprintf(resp, respsz, "OK removed %s (%d repos)\n", abs, d->repo_count);
    }
    return 0;
}

int run_watch_loop(TtDaemon *d) {
    if (d->repo_count < 1) return 1;
    if (tt_watcher_init(d) != 0) return 1;
    for (int i = 0; i < d->repo_count; ++i) tt_repo_finish_watch(d, i);
    if (tt_ipc_listen(d) != 0)
        tt_log("warning: IPC socket unavailable; hot 'add' disabled\n");
    tt_boot_lock_release();
    for (int i = 0; i < d->repo_count; ++i) tt_write_pid_file(d->repos[i].store_dir);
    d->start_ns = tt_now_ns();
    tt_status_write(d);
    fprintf(stderr, "=== Time-Travel v1.5 (multi-repo monolith + crypto) ===\n");
    for (int i = 0; i < d->repo_count; ++i)
        fprintf(stderr, "Watching: %s\n", d->repos[i].root);
    fprintf(stderr, "Ctrl+C to exit.\n");

    uint64_t last_status_ns = 0;
    struct pollfd fds[3];
    int nfds = 0;
    fds[nfds].fd = d->inotify_fd; fds[nfds].events = POLLIN; fds[nfds].revents = 0; nfds++;
    fds[nfds].fd = d->timer_fd;   fds[nfds].events = POLLIN; fds[nfds].revents = 0; nfds++;
    int ipc_idx = -1;
    if (d->ipc_fd >= 0) {
        ipc_idx = nfds;
        fds[nfds].fd = d->ipc_fd; fds[nfds].events = POLLIN; fds[nfds].revents = 0; nfds++;
    }

    while (d->running && !g_signal_received) {
        if (poll(fds, (nfds_t)nfds, 1000) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[0].revents & POLLIN) tt_watcher_process_events(d);
        if (ipc_idx >= 0 && (fds[ipc_idx].revents & POLLIN)) tt_ipc_accept_all(d);
        if (fds[1].revents & POLLIN) {
            uint64_t exp = 0;
            if (read(d->timer_fd, &exp, sizeof exp) == (ssize_t)sizeof exp) {
                for (int i = 0; i < d->repo_count; ++i) {
                    TtLocalRepo *r = &d->repos[i];
                    if (r->active && r->debounce)
                        tt_debounce_process(d, r->debounce, tt_capture_on_debounced, NULL);
                }
                d->rescan_accum_ms += exp * TT_TICK_MS;
                if (d->rescan_needed || d->rescan_accum_ms >= TT_RESCAN_MS) {
                    d->rescan_needed = 0;
                    d->rescan_accum_ms = 0;
                    for (int i = 0; i < d->repo_count; ++i) {
                        TtLocalRepo *r = &d->repos[i];
                        if (r->active && !r->root_lost) tt_capture_rescan_and_sync_repo(d, r);
                    }
                }
                for (int i = 0; i < d->repo_count; ++i)
                    if (d->repos[i].active) tt_handle_root_health_repo(d, &d->repos[i]);
                uint64_t now_status = tt_now_ns();
                if (now_status - last_status_ns >= 1000000000ULL) {
                    tt_status_write(d);
                    last_status_ns = now_status;
                }
            }
        }
    }

    tt_watcher_free(d);
    tt_ipc_close(d);
    for (int i = 0; i < d->repo_count; ++i) {
        TtLocalRepo *r = &d->repos[i];
        if (!r->active) continue;
        if (r->store) tt_store_close(r->store);
        tt_cache_free(&r->cache);
        if (r->debounce) {
            tt_debounce_free(r->debounce);
            free(r->debounce);
            r->debounce = NULL;
        }
        tt_exclude_free(&r->excludes);
        char pf[TT_PATH_MAX + 64], sf[TT_PATH_MAX + 64];
        tt_pid_file_path(pf, sizeof pf, r->store_dir);    unlink(pf);
        tt_status_file_path(sf, sizeof sf, r->store_dir); unlink(sf);
    }
    return 0;
}

/* ---------------- cliente ligero IPC ---------------- */
int try_client_add(const char *abs) {
    char sock[TT_PATH_MAX];
    pid_t dpid = -1;
    if (tt_ipc_discover(sock, sizeof sock, &dpid) != 0) return -1;
    if (dpid <= 0 || kill(dpid, 0) != 0) return -1;
    char line[TT_PATH_MAX + 8], resp[TT_PATH_MAX + 128];
    snprintf(line, sizeof line, "ADD %s", abs);
    if (tt_ipc_client(sock, line, resp, sizeof resp) != 0) return -1;
    printf("%s", resp);
    return (strncmp(resp, "OK", 2) == 0) ? 0 : 1;
}


/* ---------------- usage ---------------- */
static void usage(void) {
    printf("\n"
    "============================================================\n"
    " Time-Travel v1.5 — Filesystem-level Ctrl+Z\n"
    " multi-repo + content dedup + encryption\n"
    "============================================================\n"
    "\n"
    "COMMANDS:\n"
    "  timetravel start <dir> [--encrypt]   start monolith (optionally encrypted)\n"
    "  timetravel add <dir>                 hot-add another repo (or start if none)\n"
    "  timetravel stop                      stop the monolith (all repos)\n"
    "  timetravel stop --repo <dir>         remove ONLY that repo\n"
    "  timetravel restart <dir>             stop + start\n"
    "  timetravel watch <dir> [-f] [--encrypt]   foreground with -f\n"
    "  timetravel status [--repo <dir>]     swarm table + per-repo stats\n"
    "  timetravel log <path> [--since <expr>] [--repo <dir>]\n"
    "  timetravel undo <path> [--to <expr> | --last | --initial | --tag <name>]\n"
    "                         [--repo <dir>] [--force]\n"
    "  timetravel diff <path> [--to <expr>] [--repo <dir>]\n"
    "  timetravel dump <path> --out <dir> [--with-diff] [--repo <dir>]\n"
    "  timetravel tag <name> [--repo <dir>]      / tags [--repo <dir>]\n"
    "  timetravel compact [--repo <dir>]    manual compaction\n"
    "  timetravel verify [--repo <dir>]     integrity check\n"
    "  timetravel exclude add <pattern> [--repo <dir>]     add exclusion\n"
    "  timetravel exclude remove <pattern> [--repo <dir>]  remove exclusion\n"
    "  timetravel exclude list [--repo <dir>]              list exclusions\n"
    "\n"
    "ENCRYPTION (XChaCha20-Poly1305):\n"
    "  start/watch --encrypt  creates crypto.meta, asks passphrase twice.\n"
    "                         Every command on that repo then asks for it.\n"
    "                         A repo can only be encrypted at CREATION time.\n"
    "\n"
    "DEDUP (BLAKE2b content-addressed):\n"
    "  Files >= 1 MiB are split into 64 KiB blocks under .timetravel/blocks/.\n"
    "  Identical blocks are shared across versions/files (no duplicate storage).\n"
    "  Transparent: undo/diff/dump behave exactly the same.\n"
    "\n"
    "--to / --since accepts:\n"
    "  \"2026-09-13 00:07:08\" | \"10 minutes ago\" | now | head | latest |\n"
    "  prev | first | N | -N | tag:<name> | @<timestamp_ns>\n"
    "\n"
    "EXAMPLES:\n"
    "  # Encrypted repo, full cycle\n"
    "  timetravel start ~/secret --encrypt        # asks passphrase twice\n"
    "  timetravel undo ~/secret/notes.md --last --repo ~/secret   # asks passphrase\n"
    "  timetravel stop\n"
    "\n"
    "  # Multi-repo swarm\n"
    "  timetravel start ~/src\n"
    "  timetravel start ~/src/ bin/ docs/ \n"
    "  timetravel add ~/docs\n"
    "  timetravel add /mnt/datos/notas\n"
    "  timetravel status                          # swarm view from any cwd\n"
    "\n"
    "  # Point-in-time restore & compare\n"
    "  timetravel undo ~/src/main.c --to \"2 hours ago\" --repo ~/src\n"
    "  timetravel diff ~/src/main.c --to prev --repo ~/src\n"
    "  timetravel log ~/src/main.c --since \"1 day ago\" --repo ~/src\n"
    "\n"
    "  # Tags, rollback a whole dir, export history\n"
    "  timetravel tag pre-refactor --repo ~/src\n"
    "  timetravel undo ~/src --tag pre-refactor --repo ~/src --force\n"
    "  timetravel dump ~/src/main.c --out /tmp/versions --with-diff --repo ~/src\n"
    "\n"
    "  # Maintenance\n"
    "  timetravel verify --repo ~/src             # integrity check\n"
    "  timetravel compact --repo ~/src            # collapse long delta chains\n");
}

/* ============================================================
 * MULTI-DIR START/ADD HELPERS
 * ============================================================ */
static int collect_dir_args(int argc, char **argv, int start_idx,
                            const char **dirs, int max_dirs)
{
    int n = 0;
    int no_more_flags = 0;

    for (int i = start_idx; i < argc && n < max_dirs; ++i) {
        if (!no_more_flags && strcmp(argv[i], "--") == 0) {
            no_more_flags = 1;
            continue;
        }

        if (!no_more_flags && argv[i][0] == '-') {
           
            if (strcmp(argv[i], "--repo") == 0 || strcmp(argv[i], "--exclude") == 0) {
                if (i + 1 < argc) {
                    i++; 
                }
            }
            continue;
        }

        if (argv[i] && argv[i][0] != '\0') {
            dirs[n++] = argv[i];
        }
    }
    return n;
}



static int cmd_start_multi(int argc, char **argv, int start_idx)
{
    int enc = 0;

    for (int i = start_idx; i < argc; ++i) {
        if (strcmp(argv[i], "--encrypt") == 0)
            enc = 1;
    }

    const char *raw[TT_MAX_REPOS + 1];
    int nraw = collect_dir_args(argc, argv, start_idx, raw, TT_MAX_REPOS + 1);

    if (nraw == 0) {
        raw[0] = ".";
        nraw = 1;
    }

    if (nraw > TT_MAX_REPOS) {
        fprintf(stderr, "error: too many directories (max %d repos)\n",
                TT_MAX_REPOS);
        return 1;
    }

    if (enc && nraw > 1) {
        fprintf(stderr,
                "error: --encrypt currently supports only one directory\n");
        return 1;
    }

    static char dirs[TT_MAX_REPOS + 1][TT_PATH_MAX];

    for (int i = 0; i < nraw; ++i) {
        if (normalize_dir_arg(raw[i], dirs[i], TT_PATH_MAX) != 0)
            return 1;
    }

    if (check_start_overlaps(dirs, nraw) != 0)
        return 1;

    int failed = 0;

    for (int i = 0; i < nraw; ++i) {
        int rc;

        if (i == 0) {
            rc = tt_cmd_watch(dirs[i], 0, enc);
            
            if (rc == 0 && nraw > 1) {
                usleep(200 * 1000); 
            }
        } else {
            rc = tt_cmd_add(dirs[i]);
        }

        if (rc != 0) {
            fprintf(stderr, "error: could not adopt '%s'\n", dirs[i]);
            failed = 1;
        }
    }

    return failed ? 1 : 0;
}



static int cmd_add_multi(int argc, char **argv, int start_idx)
{
    const char *raw[TT_MAX_REPOS + 1];
    int nraw = collect_dir_args(argc, argv, start_idx, raw, TT_MAX_REPOS + 1);

    if (nraw == 0) {
        raw[0] = ".";
        nraw = 1;
    }

    if (nraw > TT_MAX_REPOS) {
        fprintf(stderr, "error: too many directories (max %d repos)\n",
                TT_MAX_REPOS);
        return 1;
    }

    static char dirs[TT_MAX_REPOS + 1][TT_PATH_MAX];

    for (int i = 0; i < nraw; ++i) {
        if (normalize_dir_arg(raw[i], dirs[i], TT_PATH_MAX) != 0)
            return 1;
    }

    if (check_start_overlaps(dirs, nraw) != 0)
        return 1;

    int failed = 0;

    for (int i = 0; i < nraw; ++i) {
        if (tt_cmd_add(dirs[i]) != 0) {
            fprintf(stderr, "error: could not add '%s'\n", dirs[i]);
            failed = 1;
        }
    }

    return failed ? 1 : 0;
}

/* ============================================================
 * END MULTI-DIR HELPERS
 * ============================================================ */

/* ---------------- main ---------------- */
int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "verify") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return tt_cmd_verify(r);
    }
    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(cmd, "start") == 0) {
        if (argc < 3) { usage(); return 1; }
        
        /* v1.5: parse --exclude flags (antes de cmd_start_multi) */
        {
            const char *excl[64];
            int n_excl = 0;
            for (int i = 2; i < argc; ++i) {
                if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc)
                    if (n_excl < 64) excl[n_excl++] = argv[++i];
            }
            if (n_excl > 0)
                tt_set_pending_excludes(excl, n_excl);
        }
        
        /* v1.5: usar cmd_start_multi para soportar múltiples directorios */
        return cmd_start_multi(argc, argv, 2);
    }

    if (strcmp(cmd, "add") == 0) {
    return cmd_add_multi(argc, argv, 2);
}

    if (strcmp(cmd, "stop") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return tt_cmd_stop(r);
    }
    if (strcmp(cmd, "restart") == 0) {
        if (argc < 3) { usage(); return 1; }
        tt_cmd_stop(argv[2]);
        return tt_cmd_watch(argv[2], 0, 0);
    }
    if (strcmp(cmd, "watch") == 0) {
        if (argc < 3) { usage(); return 1; }
        int fg = 0, enc = 0;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "-f") == 0) fg = 1;
            else if (strcmp(argv[i], "--encrypt") == 0) enc = 1;
        }
        return tt_cmd_watch(argv[2], fg, enc);
    }
    if (strcmp(cmd, "undo") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *path = argv[2];
        const char *expr = "now";
        const char *repo = NULL;
        const char *tag = NULL;
        TtUndoMode mode = UNDO_MODE_LAST;
        int force = 0;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) { expr = argv[++i]; mode = UNDO_MODE_TIME; }
            else if (strcmp(argv[i], "--last") == 0) mode = UNDO_MODE_LAST;
            else if (strcmp(argv[i], "--initial") == 0) mode = UNDO_MODE_INITIAL;
            else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) { tag = argv[++i]; mode = UNDO_MODE_TAG; }
            else if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (strcmp(argv[i], "--force") == 0) force = 1;
        }
        return tt_cmd_undo(path, expr, repo, mode, tag, force);
    }
    if (strcmp(cmd, "diff") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL, *expr = NULL;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) expr = argv[++i];
        }
        return tt_cmd_diff(argv[2], repo, expr);
    }
    if (strcmp(cmd, "dump") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL, *out = NULL;
        int with_diff = 0;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out = argv[++i];
            else if (strcmp(argv[i], "--with-diff") == 0) with_diff = 1;
        }
        return tt_cmd_dump(argv[2], repo, out, with_diff);
    }
    if (strcmp(cmd, "tag") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL;
        for (int i = 3; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
        return tt_cmd_tag(argv[2], repo);
    }
    if (strcmp(cmd, "tags") == 0) {
        char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2];
        const char *repo = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
        if (repo) snprintf(wd, sizeof wd, "%s", repo);
        else if (find_repo_dir(".", wd, sizeof wd) != 0) {
            fprintf(stderr, "error: .timetravel not found\n");
            return 1;
        }
        snprintf(sd, sizeof sd, "%s/.timetravel", wd);
        return tt_tag_list(sd);
    }
    if (strcmp(cmd, "status") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return tt_cmd_status(r);
    }
    if (strcmp(cmd, "log") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL, *since = NULL;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc) since = argv[++i];
        }
        return tt_cmd_log(argv[2], repo, since);
    }
    if (strcmp(cmd, "compact") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return tt_cmd_compact(r);
    }

        if (strcmp(cmd, "exclude") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *action = argv[2];
        const char *pattern = NULL;
        const char *repo = NULL;

        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc)
                repo = argv[++i];
            else if (!pattern)
                pattern = argv[i];
        }

        return tt_cmd_exclude(action, pattern, repo);
    }

    fprintf(stderr, "error: unknown command '%s'\n", cmd);
    usage();
    return 1;
}
