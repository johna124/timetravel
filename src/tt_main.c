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
   Time-Travel v1.4 — MONOLITO MULTI-REPO + CIFRADO
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

/* ---------------- núcleo ---------------- */
static TtDaemon g_core;
static volatile sig_atomic_t g_signal_received = 0;

static void signal_handler(int sig) { (void)sig; g_signal_received = 1; }

static void tt_log(const char *fmt, ...) {
    char tsbuf[32];
    time_t t = time(NULL);
    struct tm tmv;
    if (localtime_r(&t, &tmv)) strftime(tsbuf, sizeof tsbuf, "%Y-%m-%d %H:%M:%S", &tmv);
    else snprintf(tsbuf, sizeof tsbuf, "?");
    fprintf(stderr, "[%s] ", tsbuf);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static uint64_t next_ts(void) {
    static uint64_t last_ts = 0;
    uint64_t now = tt_now_ns();
    if (now <= last_ts) now = last_ts + 1;
    last_ts = now;
    return now;
}

/* ---------------- cache de estado (por repo) ---------------- */
static void cache_init(TtStateCache *c) { memset(c, 0, sizeof *c); }

static void cache_free(TtStateCache *c) {
    if (!c) return;
    for (size_t i = 0; i < c->count; ++i)
        if (c->entries[i].active) free(c->entries[i].data);
    free(c->entries);
    memset(c, 0, sizeof *c);
}

static TtStateEntry *cache_find(TtStateCache *c, const char *path) {
    for (size_t i = 0; i < c->count; ++i)
        if (c->entries[i].active && strcmp(c->entries[i].path, path) == 0)
            return &c->entries[i];
    return NULL;
}

static void cache_remove(TtStateCache *c, const char *path) {
    TtStateEntry *e = cache_find(c, path);
    if (!e) return;
    free(e->data);
    memset(e, 0, sizeof *e);
    if (c->active_count > 0) c->active_count--;
}

static int cache_put(TtStateCache *c, const char *path, const uint8_t *data, size_t size,
                     int anchored, int baseline_pending) {
    TtStateEntry *e = cache_find(c, path);
    if (!e) {
        size_t slot = c->count;
        for (size_t i = 0; i < c->count; ++i)
            if (!c->entries[i].active) { slot = i; break; }
        if (slot == c->count) {
            if (c->count == c->cap) {
                size_t ncap = c->cap ? c->cap * 2 : 64;
                TtStateEntry *ne = realloc(c->entries, ncap * sizeof(TtStateEntry));
                if (!ne) return -1;
                c->entries = ne;
                c->cap = ncap;
            }
            c->count++;
        }
        e = &c->entries[slot];
        memset(e, 0, sizeof *e);
        e->active = 1;
        snprintf(e->path, sizeof e->path, "%s", path);
        c->active_count++;
    } else {
        free(e->data);
        e->data = NULL;
        e->size = 0;
    }
    if (size > 0 && data) {
        e->data = malloc(size);
        if (!e->data) return -1;
        memcpy(e->data, data, size);
    }
    e->size = size;
    e->anchored = anchored;
    e->baseline_pending = baseline_pending;
    return 0;
}

static int read_file_all(const char *full, uint8_t **out, size_t *out_size) {
    *out = NULL;
    *out_size = 0;
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return -1; }
    size_t sz = (size_t)st.st_size;
    if (sz == 0) { close(fd); return 0; }
    uint8_t *buf = malloc(sz);
    if (!buf) { close(fd); return -1; }
    size_t off = 0;
    while (off < sz) {
        ssize_t r = read(fd, buf + off, sz - off);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return -1; }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_size = off;
    return 0;
}

/* ---------------- escritura de records (por repo) ---------------- */

static int write_create_record_ts(TtLocalRepo *r, const char *rel,
                                  const uint8_t *data, size_t size, uint64_t ts) {
    /* ficheros grandes → dedup por bloques */
    if (size >= TT_DEDUP_MIN_SIZE) {
        uint8_t *hashes = NULL;
        size_t nblocks = 0;
        if (tt_dedup_split(r->store_dir, data, size, &hashes, &nblocks,
                           tt_store_get_key(r->store)) == 0 && nblocks > 0) {
            TtDeltaHeader hdr;
            memset(&hdr, 0, sizeof hdr);
            hdr.timestamp_ns = ts;
            hdr.event_type = TT_EV_CREATE_DEDUP;
            hdr.path_len = (uint32_t)strlen(rel);
            hdr.delta_size = (uint32_t)(nblocks * TT_DEDUP_HASH_LEN);
            hdr.file_size = (uint64_t)size;
            int rc = tt_store_write_ctx(r->store, &hdr, rel, hashes);
            free(hashes);
            if (rc == 0) {
                r->deltas_written++;
                r->bytes_stored += sizeof(hdr) + strlen(rel) + nblocks * TT_DEDUP_HASH_LEN;
            }
            return rc;
        }
        free(hashes);   /* fallo del split → fallback a CREATE normal */
    }
    TtDeltaHeader hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.timestamp_ns = ts;
    hdr.event_type = TT_EV_CREATE;
    hdr.path_len = (uint32_t)strlen(rel);
    hdr.delta_size = (uint32_t)size;
    hdr.file_size = (uint64_t)size;
    int rc = tt_store_write_ctx(r->store, &hdr, rel, size > 0 ? data : NULL);
    if (rc == 0) {
        r->deltas_written++;
        r->bytes_stored += sizeof(hdr) + strlen(rel) + size;
    }
    return rc;
}

static int write_create_record(TtLocalRepo *r, const char *rel, const uint8_t *data, size_t size) {
    return write_create_record_ts(r, rel, data, size, next_ts());
}

static int write_version_record(TtLocalRepo *r, const char *rel,
                                const uint8_t *old, size_t old_size,
                                const uint8_t *newd, size_t new_size) {
    if (old && old_size > 0) {
        uint8_t *delta = NULL;
        size_t dsz = 0;
        if (tt_delta_encode(old, old_size, newd, new_size, &delta, &dsz) == 0 &&
            dsz > 0 && dsz < new_size) {
            TtDeltaHeader hdr;
            memset(&hdr, 0, sizeof hdr);
            hdr.timestamp_ns = next_ts();
            hdr.event_type = TT_EV_MODIFY;
            hdr.path_len = (uint32_t)strlen(rel);
            hdr.delta_size = (uint32_t)dsz;
            hdr.file_size = (uint64_t)new_size;
            int rc = tt_store_write_ctx(r->store, &hdr, rel, delta);
            free(delta);
            if (rc == 0) {
                r->deltas_written++;
                r->bytes_stored += sizeof(hdr) + strlen(rel) + dsz;
            }
            return rc;
        }
        free(delta);
    }
    return write_create_record(r, rel, newd, new_size);
}

/* ---------------- captura (enrutada a su repo) ---------------- */
static int capture_path(TtDaemon *d, TtLocalRepo *r, const char *rel, int quiet) {
    if (!d || !r || !rel || !rel[0]) return -1;
    if (tt_is_excluded(rel)) return -1;
    char full[TT_PATH_MAX * 2];
    snprintf(full, sizeof full, "%s/%s", r->root, rel);

    struct stat st;
    if (lstat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
        TtStateEntry *e = cache_find(&r->cache, rel);
        if (!e) return 0;
        if (e->baseline_pending) { cache_remove(&r->cache, rel); return 0; }
        TtDeltaHeader hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.timestamp_ns = next_ts();
        hdr.event_type = TT_EV_DELETE;
        hdr.path_len = (uint32_t)strlen(rel);
        if (tt_store_write_ctx(r->store, &hdr, rel, NULL) == 0) {
            cache_remove(&r->cache, rel);
            r->deltas_written++;
            r->bytes_stored += sizeof(hdr) + strlen(rel);
            tt_log("DELETE  %s\n", rel);
            return 1;
        }
        return -1;
    }

    if ((uint64_t)st.st_size > TT_MAX_CAPTURE_SIZE) {
        if (!quiet) tt_log("warning: '%s' exceeds maximum size; ignored\n", rel);
        return 0;
    }

    uint8_t *new_data = NULL;
    size_t new_size = 0;
    if (read_file_all(full, &new_data, &new_size) != 0) return -1;

    struct stat st2;
    if (lstat(full, &st2) != 0 || st2.st_size != st.st_size ||
        st2.st_mtim.tv_sec != st.st_mtim.tv_sec ||
        st2.st_mtim.tv_nsec != st.st_mtim.tv_nsec) {
        free(new_data);
        tt_debounce_add(r->debounce, full, TT_EV_MODIFY);
        return 0;
    }

    TtStateEntry *e = cache_find(&r->cache, rel);
    if (!e) {
        int rc = write_create_record(r, rel, new_data, new_size);
        if (rc == 0) {
            cache_put(&r->cache, rel, new_data, new_size, 1, 0);
            tt_log("CREATE  %s (%zu bytes)\n", rel, new_size);
            free(new_data);
            return 1;
        }
        free(new_data);
        return -1;
    }

    if (e->size == new_size &&
        (new_size == 0 || (e->data && memcmp(e->data, new_data, new_size) == 0))) {
        free(new_data);
        return 0;
    }

    int rc;
    if (e->baseline_pending) {
        uint64_t orig_ts = r->start_ns ? r->start_ns : next_ts();
        rc = write_create_record_ts(r, rel, e->data, e->size, orig_ts);
        if (rc == 0) {
            tt_log("CREATE  %s (%zu bytes) [original]\n", rel, e->size);
            rc = write_version_record(r, rel, e->data, e->size, new_data, new_size);
            if (rc == 0) {
                cache_put(&r->cache, rel, new_data, new_size, 1, 0);
                tt_log("MODIFY  %s (%zu bytes)\n", rel, new_size);
                free(new_data);
                return 1;
            }
            e->baseline_pending = 0;
            e->anchored = 0;
        }
        free(new_data);
        return -1;
    }

    if (!e->anchored) {
        rc = write_create_record(r, rel, new_data, new_size);
        if (rc == 0) {
            cache_put(&r->cache, rel, new_data, new_size, 1, 0);
            tt_log("CREATE  %s (%zu bytes) [reanchor]\n", rel, new_size);
            free(new_data);
            return 1;
        }
        free(new_data);
        return -1;
    }

    rc = write_version_record(r, rel, e->data, e->size, new_data, new_size);
    if (rc == 0) {
        cache_put(&r->cache, rel, new_data, new_size, 1, 0);
        tt_log("MODIFY  %s (%zu bytes)\n", rel, new_size);
        free(new_data);
        return 1;
    }
    free(new_data);
    return -1;
}

/* ---------------- pathset + índices ---------------- */
typedef struct { char **v; size_t n, cap; } TtPathSet;

static int pathset_has(TtPathSet *s, const char *p) {
    for (size_t i = 0; i < s->n; ++i)
        if (strcmp(s->v[i], p) == 0) return 1;
    return 0;
}

static void pathset_add(TtPathSet *s, const char *p) {
    if (pathset_has(s, p)) return;
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 256;
        char **nv = realloc(s->v, ncap * sizeof(char *));
        if (!nv) return;
        s->v = nv;
        s->cap = ncap;
    }
    s->v[s->n] = strdup(p);
    if (s->v[s->n]) s->n++;
}

static void pathset_free(TtPathSet *s) {
    for (size_t i = 0; i < s->n; ++i) free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof *s);
}

static void store_collect_paths_ctx(const char *store_dir, TtPathSet *out) {
    memset(out, 0, sizeof *out);
    TtStoreReader *rd = tt_reader_open(store_dir);
    if (!rd) return;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_reader_next(rd, &hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0) break;
        pathset_add(out, path);
        free(pl);
    }
    tt_reader_close(rd);
}

static void cache_build_walk_repo(TtDaemon *d, TtLocalRepo *r, TtPathSet *hist,
                                  const char *dir_full, const char *rel_prefix, size_t *n_files) {
    DIR *dp = opendir(dir_full);
    if (!dp) return;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char rel[TT_PATH_MAX];
        if (rel_prefix[0]) snprintf(rel, sizeof rel, "%s/%s", rel_prefix, de->d_name);
        else snprintf(rel, sizeof rel, "%s", de->d_name);
        if (tt_is_excluded(rel)) continue;
        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", dir_full, de->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            cache_build_walk_repo(d, r, hist, full, rel, n_files);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if ((uint64_t)st.st_size > TT_MAX_CAPTURE_SIZE) continue;
        uint8_t *data = NULL;
        size_t size = 0;
        if (read_file_all(full, &data, &size) != 0) continue;
        int has_hist = pathset_has(hist, rel);
        cache_put(&r->cache, rel, data, size, has_hist ? 0 : 1, has_hist ? 0 : 1);
        free(data);
        (*n_files)++;
    }
    closedir(dp);
}

static void cache_build_initial_repo(TtDaemon *d, TtLocalRepo *r) {
    TtPathSet hist;
    store_collect_paths_ctx(r->store_dir, &hist);
    size_t n_files = 0;
    struct stat st;
    if (stat(r->root, &st) == 0 && S_ISDIR(st.st_mode))
        cache_build_walk_repo(d, r, &hist, r->root, "", &n_files);
    tt_log("[%s] in memory: %zu file(s)\n", r->root, n_files);
    pathset_free(&hist);
}

static void rescan_walk_repo(TtDaemon *d, TtLocalRepo *r,
                             const char *dir_full, const char *rel_prefix, int *written) {
    DIR *dp = opendir(dir_full);
    if (!dp) return;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char rel[TT_PATH_MAX];
        if (rel_prefix[0]) snprintf(rel, sizeof rel, "%s/%s", rel_prefix, de->d_name);
        else snprintf(rel, sizeof rel, "%s", de->d_name);
        if (tt_is_excluded(rel)) continue;
        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", dir_full, de->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            rescan_walk_repo(d, r, full, rel, written);
        } else if (S_ISREG(st.st_mode)) {
            int rc = capture_path(d, r, rel, 1);
            if (rc > 0 && written) (*written)++;
        }
    }
    closedir(dp);
}

static void rescan_and_sync_repo(TtDaemon *d, TtLocalRepo *r) {
    struct stat st;
    if (stat(r->root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        r->root_lost = 1;
        return;
    }
    int written = 0;
    rescan_walk_repo(d, r, r->root, "", &written);
    size_t i = 0;
    while (i < r->cache.count) {
        TtStateEntry *e = &r->cache.entries[i];
        if (!e->active) { i++; continue; }
        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", r->root, e->path);
        struct stat st2;
        if (lstat(full, &st2) != 0 || !S_ISREG(st2.st_mode)) {
            int rc = capture_path(d, r, e->path, 1);
            if (rc > 0) written++;
        }
        i++;
    }
    if (written > 0) tt_log("[%s] rescan: %d record(s)\n", r->root, written);
}

static void on_debounced(TtDaemon *d, const char *full_path, uint8_t event_type, void *user) {
    (void)event_type;
    (void)user;
    for (int i = 0; i < d->repo_count; ++i) {
        TtLocalRepo *r = &d->repos[i];
        if (!r->active) continue;
        size_t len = strlen(r->root);
        if (strncmp(full_path, r->root, len) == 0 &&
            (full_path[len] == '/' || full_path[len] == '\0')) {
            const char *rel = full_path + len;
            while (*rel == '/') rel++;
            if (*rel) capture_path(d, r, rel, 0);
            return;
        }
    }
}

/* ---------------- resolución de rutas CLI ---------------- */
static int find_repo_dir(const char *path, char *out, size_t out_size)
{
    char tmp[TT_PATH_MAX * 2];
    struct stat st;

    if (!path || !path[0])
        path = ".";

    /*
       Si el path existe, lo canonicalizamos.
       Si no existe, por ejemplo porque quieres restaurar un directorio
       borrado, construimos igualmente una ruta absoluta.
    */
    char *rp = realpath(path, NULL);
    if (rp) {
        snprintf(tmp, sizeof(tmp), "%s", rp);
        free(rp);
    } else {
        if (path[0] == '/') {
            snprintf(tmp, sizeof(tmp), "%s", path);
        } else {
            char cwd[TT_PATH_MAX];
            if (!getcwd(cwd, sizeof(cwd)))
                return -1;

            if (strcmp(cwd, "/") == 0)
                snprintf(tmp, sizeof(tmp), "/%s", path);
            else
                snprintf(tmp, sizeof(tmp), "%s/%s", cwd, path);
        }
    }

    /* Si el argumento es un fichero, buscamos desde su directorio. */
    if (stat(tmp, &st) == 0 && S_ISREG(st.st_mode)) {
        char *s = strrchr(tmp, '/');
        if (s == tmp)
            tmp[1] = '\0';       /* /fichero -> / */
        else if (s)
            *s = '\0';           /* /dir/fichero -> /dir */
    }

    /* Quitar barras finales. */
    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';

    while (tmp[0] != '\0') {
        char cand[TT_PATH_MAX * 2 + 32];

        if (strcmp(tmp, "/") == 0)
            snprintf(cand, sizeof(cand), "/.timetravel");
        else
            snprintf(cand, sizeof(cand), "%s/.timetravel", tmp);

        if (stat(cand, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(out, out_size, "%s", tmp);
            return 0;
        }

        /* Límite: no seguir subiendo. */
        if (strcmp(tmp, "/") == 0)
            break;

        char *s = strrchr(tmp, '/');
        if (!s)
            break;

        if (s == tmp)
            tmp[1] = '\0';       /* /foo -> / */
        else
            *s = '\0';           /* /foo/bar -> /foo */
    }

    return -1;
}

static int normalize_dir(const char *in, char *out, size_t outsz) {
    if (!in || !in[0]) return -1;
    char *rp = realpath(in, NULL);
    if (!rp) return -1;
    snprintf(out, outsz, "%s", rp);
    free(rp);
    return 0;
}

static int resolve_repo_arg(const char *repo_dir, const char *fallback_path, char *wd, size_t wdsz) {
    char raw[TT_PATH_MAX];
    if (repo_dir && repo_dir[0]) {
        snprintf(raw, sizeof raw, "%s", repo_dir);
    } else {
        const char *p = (fallback_path && fallback_path[0]) ? fallback_path : ".";
        if (find_repo_dir(p, raw, sizeof raw) != 0) return -1;
    }
    if (normalize_dir(raw, wd, wdsz) == 0) return 0;
    snprintf(wd, wdsz, "%s", raw);
    return 0;
}

static int make_rel_from_arg(const char *wd, const char *path, char *rel, size_t relsz) {
    if (!path || !path[0] || strcmp(path, ".") == 0) { rel[0] = '\0'; return 0; }
    char abs[TT_PATH_MAX * 2];
    if (path[0] == '/') snprintf(abs, sizeof abs, "%s", path);
    else {
        char cwd[TT_PATH_MAX];
        if (!getcwd(cwd, sizeof cwd)) return -1;
        snprintf(abs, sizeof abs, "%s/%s", cwd, path);
    }
    char *rp = realpath(abs, NULL);
    if (rp) { snprintf(abs, sizeof abs, "%s", rp); free(rp); }
    size_t wlen = strlen(wd);
    if (strncmp(abs, wd, wlen) == 0 && (abs[wlen] == '\0' || abs[wlen] == '/')) {
        const char *r = abs + wlen;
        while (*r == '/') r++;
        snprintf(rel, relsz, "%s", r);
        return 0;
    }
    snprintf(rel, relsz, "%s", path);
    return 0;
}

/* ---------------- tiempo / formato ---------------- */
static uint64_t parse_time_expr(const char *expr, int *ok) {
    if (ok) *ok = 1;
    if (!expr || !expr[0] || strcmp(expr, "now") == 0) return tt_now_ns();
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    if (strptime(expr, "%Y-%m-%d %H:%M:%S", &tm) != NULL) {
        time_t t = mktime(&tm);
        if (t != (time_t)-1) return (uint64_t)t * 1000000000ULL;
    }
    long long val = 0;
    char unit[32] = {0}, extra[32] = {0};
    int n = sscanf(expr, "%lld %31s %31s", &val, unit, extra);
    if (n >= 2) {
        long long sec = 0;
        if (strncmp(unit, "sec", 3) == 0) sec = val;
        else if (strncmp(unit, "min", 3) == 0) sec = val * 60;
        else if (strncmp(unit, "hour", 4) == 0) sec = val * 3600;
        else if (strncmp(unit, "day", 3) == 0) sec = val * 86400;
        else if (strncmp(unit, "week", 4) == 0) sec = val * 604800;
        else { if (ok) *ok = 0; return 0; }
        if (sec < 0) sec = -sec;
        uint64_t delta = (uint64_t)sec * 1000000000ULL;
        uint64_t now = tt_now_ns();
        return (delta >= now) ? 0 : (now - delta);
    }
    if (ok) *ok = 0;
    return 0;
}

static void format_timestamp(uint64_t ns, char *out, size_t sz) {
    time_t s = (time_t)(ns / 1000000000ULL);
    struct tm t;
    if (localtime_r(&s, &t)) strftime(out, sz, "%Y-%m-%d %H:%M:%S", &t);
    else snprintf(out, sz, "%llu", (unsigned long long)ns);
}

static void format_bytes(uint64_t b, char *out, size_t sz) {
    if (b < 1024ULL) snprintf(out, sz, "%llu B", (unsigned long long)b);
    else if (b < 1024ULL * 1024ULL) snprintf(out, sz, "%.1f KiB", (double)b / 1024.0);
    else if (b < 1024ULL * 1024ULL * 1024ULL) snprintf(out, sz, "%.1f MiB", (double)b / (1024.0 * 1024.0));
    else snprintf(out, sz, "%.2f GiB", (double)b / (1024.0 * 1024.0 * 1024.0));
}

static void format_ns_duration(uint64_t ns, char *out, size_t sz) {
    uint64_t s = ns / 1000000000ULL;
    uint64_t d = s / 86400ULL; s %= 86400ULL;
    uint64_t h = s / 3600ULL;  s %= 3600ULL;
    uint64_t m = s / 60ULL;    s %= 60ULL;
    if (d) snprintf(out, sz, "%llud %lluh %llum %llus", (unsigned long long)d, (unsigned long long)h, (unsigned long long)m, (unsigned long long)s);
    else if (h) snprintf(out, sz, "%lluh %llum %llus", (unsigned long long)h, (unsigned long long)m, (unsigned long long)s);
    else if (m) snprintf(out, sz, "%llum %llus", (unsigned long long)m, (unsigned long long)s);
    else snprintf(out, sz, "%llus", (unsigned long long)s);
}

/* ---------------- pid / status ---------------- */
static void pid_file_path(char *out, size_t n, const char *store_dir) {
    snprintf(out, n, "%s/timetravel.pid", store_dir);
}

static int write_pid_file(const char *store_dir) {
    char pf[TT_PATH_MAX + 64];
    pid_file_path(pf, sizeof pf, store_dir);
    int fd = open(pf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    char buf[64];
    int n = snprintf(buf, sizeof buf, "%d %llu\n", (int)getpid(), (unsigned long long)tt_now_ns());
    if (write(fd, buf, (size_t)n) != n) { close(fd); return -1; }
    close(fd);
    return 0;
}

static pid_t read_pid_file(const char *store_dir, uint64_t *start_ns) {
    char pf[TT_PATH_MAX + 64];
    pid_file_path(pf, sizeof pf, store_dir);
    FILE *f = fopen(pf, "r");
    if (!f) return -1;
    pid_t pid = -1;
    unsigned long long sns = 0;
    if (fscanf(f, "%d %llu", &pid, &sns) < 1) pid = -1;
    fclose(f);
    if (start_ns) *start_ns = (uint64_t)sns;
    return pid;
}

static pid_t find_running_daemon(const char *store_dir, uint64_t *start_ns) {
    pid_t pid = read_pid_file(store_dir, start_ns);
    if (pid > 0 && kill(pid, 0) == 0) return pid;
    return -1;
}

static void status_file_path(char *out, size_t n, const char *store_dir) {
    snprintf(out, n, "%s/timetravel.status", store_dir);
}

typedef struct {
    int valid;
    pid_t pid;
    uint64_t start_ns, deltas, bytes, pending, updated_ns;
    char watch_dir[TT_PATH_MAX];
    int repo_count;
    struct {
        char root[TT_PATH_MAX];
        uint64_t deltas, bytes, files;
        int lost;
    } repos[TT_MAX_REPOS];
} TtStatusFile;

static void status_write_content(TtDaemon *d, FILE *f, uint64_t td, uint64_t tb, uint64_t tp) {
    fprintf(f, "pid=%d\nstart_ns=%llu\ndeltas=%llu\nbytes=%llu\npending=%llu\nrepos=%d\nwatch_dir=%s\n",
            (int)getpid(), (unsigned long long)d->start_ns,
            (unsigned long long)td, (unsigned long long)tb, (unsigned long long)tp,
            d->repo_count, d->repos[0].root);
    for (int j = 0; j < d->repo_count; ++j) {
        TtLocalRepo *r = &d->repos[j];
        if (!r->active) continue;
        fprintf(f, "repo.%d=%s|%llu|%llu|%zu|%d\n", j, r->root,
                (unsigned long long)r->deltas_written,
                (unsigned long long)r->bytes_stored,
                r->cache.active_count, r->root_lost);
    }
    fprintf(f, "updated_ns=%llu\n", (unsigned long long)tt_now_ns());
}

static void status_write(TtDaemon *d) {
    if (!d || d->repo_count < 1) return;
    uint64_t td = 0, tb = 0, tp = 0;
    for (int i = 0; i < d->repo_count; ++i) {
        TtLocalRepo *r = &d->repos[i];
        if (!r->active) continue;
        td += r->deltas_written;
        tb += r->bytes_stored;
        if (r->debounce) tp += r->debounce->count;
    }
    for (int i = 0; i < d->repo_count; ++i) {
        char fin[TT_PATH_MAX + 64], tmp[TT_PATH_MAX + 64];
        status_file_path(fin, sizeof fin, d->repos[i].store_dir);
        snprintf(tmp, sizeof tmp, "%s.tmp", fin);
        FILE *f = fopen(tmp, "w");
        if (!f) continue;
        status_write_content(d, f, td, tb, tp);
        fclose(f);
        if (rename(tmp, fin) != 0) unlink(tmp);
    }
    char gfin[TT_PATH_MAX], gtmp[TT_PATH_MAX + 40];
    tt_ipc_global_status_path(gfin, sizeof gfin);
    snprintf(gtmp, sizeof gtmp, "%s.tmp.%d", gfin, (int)getpid());
    FILE *gf = fopen(gtmp, "w");
    if (gf) {
        status_write_content(d, gf, td, tb, tp);
        fclose(gf);
        if (rename(gtmp, gfin) != 0) unlink(gtmp);
    }
}

static int status_read_file(const char *path, TtStatusFile *sf) {
    memset(sf, 0, sizeof *sf);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[TT_PATH_MAX + 128];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!strncmp(line, "pid=", 4)) sf->pid = (pid_t)atol(line + 4);
        else if (!strncmp(line, "start_ns=", 9)) sf->start_ns = strtoull(line + 9, NULL, 10);
        else if (!strncmp(line, "deltas=", 7)) sf->deltas = strtoull(line + 7, NULL, 10);
        else if (!strncmp(line, "bytes=", 6)) sf->bytes = strtoull(line + 6, NULL, 10);
        else if (!strncmp(line, "pending=", 8)) sf->pending = strtoull(line + 8, NULL, 10);
        else if (!strncmp(line, "updated_ns=", 11)) sf->updated_ns = strtoull(line + 11, NULL, 10);
        else if (!strncmp(line, "watch_dir=", 10)) snprintf(sf->watch_dir, sizeof sf->watch_dir, "%s", line + 10);
        else if (!strncmp(line, "repo.", 5) && sf->repo_count < TT_MAX_REPOS) {
            char *eq = strchr(line, '=');
            if (eq) {
                int idx = sf->repo_count;
                char *p = eq + 1;
                char *bar = strchr(p, '|');
                size_t rl = bar ? (size_t)(bar - p) : strlen(p);
                if (rl >= sizeof sf->repos[idx].root) rl = sizeof sf->repos[idx].root - 1;
                memcpy(sf->repos[idx].root, p, rl);
                sf->repos[idx].root[rl] = '\0';
                unsigned long long dd = 0, bb = 0, ff = 0;
                int lo = 0;
                if (bar && sscanf(bar + 1, "%llu|%llu|%llu|%d", &dd, &bb, &ff, &lo) >= 3) {
                    sf->repos[idx].deltas = dd;
                    sf->repos[idx].bytes = bb;
                    sf->repos[idx].files = ff;
                    sf->repos[idx].lost = lo;
                }
                sf->repo_count++;
            }
        }
    }
    fclose(f);
    sf->valid = (sf->pid > 0);
    return sf->valid ? 0 : -1;
}

static int status_read(const char *store_dir, TtStatusFile *sf) {
    char path[TT_PATH_MAX + 64];
    status_file_path(path, sizeof path, store_dir);
    return status_read_file(path, sf);
}

/* ---------------- tags ---------------- */
static void tags_file_path(char *out, size_t n, const char *store_dir) {
    snprintf(out, n, "%s/tags", store_dir);
}

static int tag_add(const char *store_dir, const char *name, uint64_t ts) {
    char tf[TT_PATH_MAX + 64];
    tags_file_path(tf, sizeof tf, store_dir);
    FILE *f = fopen(tf, "a");
    if (!f) return -1;
    fprintf(f, "%s\t%llu\n", name, (unsigned long long)ts);
    fclose(f);
    return 0;
}

static int tag_lookup(const char *store_dir, const char *name, uint64_t *out_ts) {
    char tf[TT_PATH_MAX + 64];
    tags_file_path(tf, sizeof tf, store_dir);
    FILE *f = fopen(tf, "r");
    if (!f) return -1;
    char line[TT_PATH_MAX + 64];
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        if (strcmp(line, name) == 0) {
            *out_ts = strtoull(tab + 1, NULL, 10);
            found = 0;
        }
    }
    fclose(f);
    return found;
}

static int tag_list(const char *store_dir) {
    char tf[TT_PATH_MAX + 64];
    tags_file_path(tf, sizeof tf, store_dir);
    FILE *f = fopen(tf, "r");
    if (!f) { printf("No tags.\n"); return 0; }
    char line[TT_PATH_MAX + 64];
    int any = 0;
    printf("Tags:\n");
    while (fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *nl = strchr(tab + 1, '\n');
        if (nl) *nl = '\0';
        uint64_t ts = strtoull(tab + 1, NULL, 10);
        char tsbuf[64];
        format_timestamp(ts, tsbuf, sizeof tsbuf);
        printf("  %-20s  %s\n", line, tsbuf);
        any = 1;
    }
    fclose(f);
    if (!any) printf("  (none)\n");
    return 0;
}

/* ---------------- consultas de historial ---------------- */
static int load_version_content(const char *store_dir, const char *rel_path, uint64_t target_ns,
                                uint8_t **out, size_t *out_size, int *exists) {
    *out = NULL; *out_size = 0; *exists = 0;
    if (tt_store_reader_init() != 0) return -1;
    uint8_t *state = NULL;
    size_t state_size = 0;
    int have = 0;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0) break;
        if (strcmp(path, rel_path) != 0) { free(pl); continue; }
        if (hdr.timestamp_ns > target_ns) { free(pl); continue; }
        if (hdr.event_type == TT_EV_DELETE) {
            free(state); state = NULL; state_size = 0; have = 0;
        } else if (hdr.event_type == TT_EV_CREATE) {
            free(state); state = NULL; state_size = 0;
            if (plsz > 0 && pl) {
                state = malloc(plsz);
                if (!state) { free(pl); tt_store_reader_free(); return -1; }
                memcpy(state, pl, plsz);
                state_size = plsz;
            }
            have = 1;
            } else if (hdr.event_type == TT_EV_CREATE_DEDUP) {
            free(state); state = NULL; state_size = 0;
            uint8_t *rec = NULL; size_t rec_sz = 0;
            if (pl && plsz > 0 &&
        tt_dedup_reconstruct(store_dir, pl, plsz, &rec, &rec_sz,
                             tt_store_compat_get_key()) == 0) {
        state = rec; state_size = rec_sz;
    }
    have = 1;

        } else if (hdr.event_type == TT_EV_MODIFY && have && plsz > 0) {
            uint8_t *ns = NULL;
            size_t nss = 0;
            if (tt_delta_decode(state, state_size, pl, plsz, hdr.file_size, &ns, &nss) == 0) {
                free(state);
                state = ns;
                state_size = nss;
            }
        }
        free(pl);
    }
    tt_store_reader_free();
    if (!have) { free(state); return 0; }
    *exists = 1;
    *out = state;
    *out_size = state_size;
    return 0;
}


static int find_last_two_ts(const char *rel_path, uint64_t *prev_ts, uint64_t *last_ts) {
    *prev_ts = 0; *last_ts = 0;
    if (tt_store_reader_init() != 0) return -1;
    uint64_t a = 0, b = 0;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0) break;
        if (strcmp(path, rel_path) == 0) { a = b; b = hdr.timestamp_ns; }
        free(pl);
    }
    tt_store_reader_free();
    if (b == 0) return -1;
    *prev_ts = a;
    *last_ts = b;
    return 0;
}

static int scan_timestamps(const char *rel, int prefix_mode, uint64_t **out_ts, size_t *out_n) {
    *out_ts = NULL; *out_n = 0;
    if (tt_store_reader_init() != 0) return -1;
    uint64_t *ts = NULL;
    size_t n = 0, cap = 0;
    size_t plen = rel ? strlen(rel) : 0;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0) break;
        int m = 0;
        if (!rel || !rel[0]) m = 1;
        else if (strcmp(path, rel) == 0) m = 1;
        else if (prefix_mode && strncmp(path, rel, plen) == 0 && path[plen] == '/') m = 1;
        free(pl);
        if (!m) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            uint64_t *nt = realloc(ts, cap * sizeof(uint64_t));
            if (!nt) { free(ts); tt_store_reader_free(); return -1; }
            ts = nt;
        }
        ts[n++] = hdr.timestamp_ns;
    }
    tt_store_reader_free();
    if (n > 1) {
        for (size_t i = 1; i < n; ++i) {
            uint64_t k = ts[i];
            size_t j = i;
            while (j > 0 && ts[j - 1] > k) { ts[j] = ts[j - 1]; j--; }
            ts[j] = k;
        }
    }
    *out_ts = ts;
    *out_n = n;
    return 0;
}

/* ---------------- utilidades ---------------- */
static int mkdir_p(const char *path) {
    char tmp[TT_PATH_MAX * 2];
    int n = snprintf(tmp, sizeof tmp, "%s", path);
    if (n < 0 || (size_t)n >= sizeof tmp) return -1;
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int write_file_all(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (size > 0 && fwrite(data, 1, size, f) != size) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static void sanitize_component(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    if (!in || !in[0]) in = "root";
    for (const char *p = in; *p && o + 1 < outsz; ++p) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ' ') out[o++] = (char)c;
        else out[o++] = ' ';
    }
    out[o] = '\0';
}

static int run_diff_file(const char *a, const char *b, const char *out) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        }
        execlp("diff", "diff", "-u", a, b, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    if (!WIFEXITED(st)) return -1;
    int code = WEXITSTATUS(st);
    return (code == 0 || code == 1) ? 0 : -1;
}

static int proc_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static long proc_rss_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/status", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld kB", &rss) == 1) break;
    fclose(f);
    return rss;
}

static int proc_stat_fields(pid_t pid, unsigned long *utime, unsigned long *stime, unsigned long long *starttime) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[4096];
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return -1; }
    fclose(f);
    char *rp = strrchr(buf, ')');
    if (!rp) return -1;
    rp += 2;
    int field = 3;
    char *save = NULL;
    char *tok = strtok_r(rp, " ", &save);
    unsigned long u = 0, s = 0;
    unsigned long long st = 0;
    while (tok) {
        if (field == 14) u = strtoul(tok, NULL, 10);
        else if (field == 15) s = strtoul(tok, NULL, 10);
        else if (field == 22) st = strtoull(tok, NULL, 10);
        field++;
        tok = strtok_r(NULL, " ", &save);
    }
    if (utime) *utime = u;
    if (stime) *stime = s;
    if (starttime) *starttime = st;
    return 0;
}

static double proc_cpu_total_sec(pid_t pid) {
    unsigned long u = 0, s = 0;
    if (proc_stat_fields(pid, &u, &s, NULL) != 0) return -1.0;
    static long hz = 0;
    if (!hz) hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    return (double)(u + s) / (double)hz;
}

static double proc_cpu_percent(pid_t pid) {
    double c1 = proc_cpu_total_sec(pid);
    if (c1 < 0.0) return -1.0;
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    usleep(200 * 1000);
    double c2 = proc_cpu_total_sec(pid);
    if (c2 < 0.0) return -1.0;
    struct timespec t2;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    double wall = (double)(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_nsec - t1.tv_nsec) / 1e9;
    if (wall <= 0.0001) return 0.0;
    double pct = (c2 - c1) / wall * 100.0;
    if (pct < 0.0) pct = 0.0;
    return pct;
}

/* key opcional: si el repo está cifrado, se pasa la clave derivada */
static int scan_stats_dir(const char *store_dir, const uint8_t *key,
                          uint64_t *nrecords, uint64_t *nbytes,
                          uint64_t *first_ts, uint64_t *last_ts) {
    uint64_t n = 0, b = 0, fts = 0, lts = 0;
    TtStoreReader *rd = tt_reader_open(store_dir);
    if (!rd) return -1;
    if (key) tt_reader_set_key(rd, key);
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_reader_next(rd, &hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0) break;
        n++;
        b += sizeof(TtDeltaHeader) + hdr.path_len + hdr.delta_size;
        if (fts == 0 || hdr.timestamp_ns < fts) fts = hdr.timestamp_ns;
        if (hdr.timestamp_ns > lts) lts = hdr.timestamp_ns;
        free(pl);
    }
    tt_reader_close(rd);
    if (nrecords) *nrecords = n;
    if (nbytes) *nbytes = b;
    if (first_ts) *first_ts = fts;
    if (last_ts) *last_ts = lts;
    return 0;
}

static int is_integer(const char *s, long long *out) {
    if (!s || !s[0]) return 0;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return 0;
    *out = v;
    return 1;
}

static int resolve_file_target_ns(const char *store_dir, const char *rel, const char *expr,
                                  uint64_t *out, char *desc, size_t descsz) {
    if (!expr || !expr[0]) {
        uint64_t prev = 0, last = 0;
        if (find_last_two_ts(rel, &prev, &last) != 0) return -1;
        *out = prev ? prev : last;
        snprintf(desc, descsz, "%s", prev ? "previous" : "first");
        return 0;
    }
    if (!strcasecmp(expr, "now") || !strcasecmp(expr, "head") ||
        !strcasecmp(expr, "latest") || !strcasecmp(expr, "last")) {
        uint64_t prev = 0, last = 0;
        if (find_last_two_ts(rel, &prev, &last) != 0) return -1;
        *out = last;
        snprintf(desc, descsz, "last");
        return 0;
    }
    if (!strcasecmp(expr, "prev") || !strcasecmp(expr, "previous")) {
        uint64_t prev = 0, last = 0;
        if (find_last_two_ts(rel, &prev, &last) != 0) return -1;
        if (prev == 0) { *out = 0; snprintf(desc, descsz, "empty"); }
        else { *out = prev; snprintf(desc, descsz, "previous"); }
        return 0;
    }
    if (!strcasecmp(expr, "first") || !strcasecmp(expr, "initial")) {
        uint64_t *ts = NULL;
        size_t n = 0;
        if (scan_timestamps(rel, 0, &ts, &n) != 0 || n == 0) { free(ts); return -1; }
        *out = ts[0];
        snprintf(desc, descsz, "first");
        free(ts);
        return 0;
    }
    if (!strncmp(expr, "tag:", 4)) {
        uint64_t ts = 0;
        if (tag_lookup(store_dir, expr + 4, &ts) != 0) return -1;
        *out = ts;
        snprintf(desc, descsz, "tag:%s", expr + 4);
        return 0;
    }
    if (expr[0] == '@') {
        long long v = 0;
        if (!is_integer(expr + 1, &v)) return -1;
        uint64_t ns = (v < 10000000000LL) ? (uint64_t)v * 1000000000ULL : (uint64_t)v;
        *out = ns;
        snprintf(desc, descsz, "timestamp");
        return 0;
    }
    long long rev = 0;
    if (is_integer(expr, &rev)) {
        uint64_t *ts = NULL;
        size_t n = 0;
        if (scan_timestamps(rel, 0, &ts, &n) != 0 || n == 0) { free(ts); return -1; }
        if (rev == 0) {
            *out = 0;
            snprintf(desc, descsz, "empty");
        } else {
            long long idx = (rev > 0) ? rev - 1 : (long long)n + rev;
            if (idx < 0) { *out = 0; snprintf(desc, descsz, "empty"); }
            else if ((size_t)idx >= n) { *out = ts[n - 1]; snprintf(desc, descsz, "last"); }
            else { *out = ts[idx]; snprintf(desc, descsz, "revision %lld", rev); }
        }
        free(ts);
        return 0;
    }
    int ok = 0;
    uint64_t t = parse_time_expr(expr, &ok);
    if (ok) {
        *out = t;
        snprintf(desc, descsz, "%s", expr);
        return 0;
    }
    return -1;
}

static void store_collect_matching(TtPathSet *out, const char *rel) {
    memset(out, 0, sizeof *out);
    if (tt_store_reader_init() != 0) return;
    size_t plen = rel ? strlen(rel) : 0;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0) break;
        int m = 0;
        if (!rel || !rel[0]) m = 1;
        else if (strcmp(path, rel) == 0) m = 1;
        else if (plen && strncmp(path, rel, plen) == 0 && path[plen] == '/') m = 1;
        if (m) pathset_add(out, path);
        free(pl);
    }
    tt_store_reader_free();
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
    char prev_file[TT_PATH_MAX] = "";

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

            char cur[TT_PATH_MAX * 2];
            snprintf(cur, sizeof cur, "%s/v%06llu_%llu",
                     fdir,
                     (unsigned long long)seq,
                     (unsigned long long)hdr.timestamp_ns);

            write_file_all(cur, state, state_size);

            if (with_diff && prev_file[0]) {
                char diff_file[TT_PATH_MAX * 2];
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

    tt_store_reader_free();
    free(state);

    return seq > 0 ? 0 : 1;
}

/* ---------------- salud de raíz (por repo) ---------------- */
static void handle_root_health_repo(TtDaemon *d, TtLocalRepo *r) {
    struct stat st;
    int exists = (stat(r->root, &st) == 0 && S_ISDIR(st.st_mode));
    if (!exists) {
        if (!r->root_lost) {
            r->root_lost = 1;
            tt_log("WARNING: watched directory '%s' deleted; waiting for recovery...\n", r->root);
        }
        return;
    }
    if (!r->root_lost) return;
    tt_log("[%s] recovered; reindexing...\n", r->root);
    if (r->store) tt_store_close(r->store);
    r->store = tt_store_open(r->store_dir, 1);
    if (!r->store) return;
    if (d->has_crypto_key) tt_store_set_key(r->store, d->crypto_key);
    cache_free(&r->cache);
    cache_init(&r->cache);
    r->start_ns = tt_now_ns();
    cache_build_initial_repo(d, r);
    tt_watcher_rebuild_repo(d, r->repo_id);
    r->root_lost = 0;
}

/* ---------------- adopción de repos ---------------- */
static void repo_list_path(char *out, size_t n, const char *store_dir) {
    snprintf(out, n, "%s/repos.list", store_dir);
}

static void repo_list_sync(TtDaemon *d) {
    for (int i = 0; i < d->repo_count; ++i) {
        char lp[TT_PATH_MAX + 64], lpt[TT_PATH_MAX + 96];
        repo_list_path(lp, sizeof lp, d->repos[i].store_dir);
        snprintf(lpt, sizeof lpt, "%s.tmp", lp);
        FILE *f = fopen(lpt, "w");
        if (!f) continue;
        for (int j = 1; j < d->repo_count; ++j)
            fprintf(f, "%s\n", d->repos[j].root);
        fclose(f);
        if (rename(lpt, lp) != 0) unlink(lpt);
    }
}

static int repo_overlaps(TtDaemon *d, const char *abs) {
    for (int i = 0; i < d->repo_count; ++i) {
        if (!d->repos[i].active) continue;
        const char *a = d->repos[i].root, *b = abs;
        size_t la = strlen(a), lb = strlen(b);
        if ((strncmp(a, b, lb) == 0 && (a[lb] == '/' || a[lb] == '\0')) ||
            (strncmp(b, a, la) == 0 && (b[la] == '/' || b[la] == '\0')))
            return 1;
    }
    return 0;
}

static int repo_adopt_base(TtDaemon *d, const char *abs_dir, char *err, size_t errsz) {
    for (int i = 0; i < d->repo_count; ++i)
        if (d->repos[i].active && strcmp(d->repos[i].root, abs_dir) == 0) return 1;
    if (d->repo_count >= TT_MAX_REPOS) {
        snprintf(err, errsz, "ERR full: maximum %d repos\n", TT_MAX_REPOS);
        return -1;
    }
    struct stat st;
    if (stat(abs_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        snprintf(err, errsz, "ERR not a real directory: %s\n", abs_dir);
        return -1;
    }
    if (repo_overlaps(d, abs_dir)) {
        snprintf(err, errsz, "ERR overlaps an already-watched repo\n");
        return -1;
    }
    TtLocalRepo *r = &d->repos[d->repo_count];
    memset(r, 0, sizeof *r);
    r->repo_id = d->repo_count;
    r->root_wd = -1;
    snprintf(r->root, sizeof r->root, "%s", abs_dir);
    snprintf(r->store_dir, sizeof r->store_dir, "%s/.timetravel", abs_dir);
    mkdir(r->store_dir, 0700);
     r->store = tt_store_open(r->store_dir, 1);
    if (!r->store) {
        snprintf(err, errsz, "ERR cannot open store in %s\n", r->store_dir);
        return -1;
    }
    if (d->has_crypto_key) tt_store_set_key(r->store, d->crypto_key);   /* v1.4 */
    
    cache_init(&r->cache);
    r->debounce = calloc(1, sizeof(TtDebounce));
    if (!r->debounce) {
        tt_store_close(r->store);
        snprintf(err, errsz, "ERR out of memory\n");
        return -1;
    }
    tt_debounce_init(r->debounce);
    r->start_ns = tt_now_ns();
    r->active = 1;
    d->repo_count++;
    tt_log("ADOPT   %s (repo #%d)\n", abs_dir, r->repo_id);
    return 0;
}

static void repo_finish_watch(TtDaemon *d, int repo_id) {
    if (!d || repo_id < 0 || repo_id >= d->repo_count) return;
    tt_watcher_add_repo(d, repo_id);
    cache_build_initial_repo(d, &d->repos[repo_id]);
    write_pid_file(d->repos[repo_id].store_dir);
}

static void repo_list_load(TtDaemon *d) {
    if (!d || d->repo_count < 1) return;
    char lp[TT_PATH_MAX + 64];
    repo_list_path(lp, sizeof lp, d->repos[0].store_dir);
    FILE *f = fopen(lp, "r");
    if (!f) return;
    char line[TT_PATH_MAX];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) continue;
        struct stat st;
        if (stat(line, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        char err[256] = "";
        if (repo_adopt_base(d, line, err, sizeof err) == 0)
            tt_log("re-adopted from repos.list: %s\n", line);
    }
    fclose(f);
}

static void repo_release(TtDaemon *d, int idx) {
    TtLocalRepo *r = &d->repos[idx];
    if (!r->active) return;
    tt_watcher_remove_repo(d, r->repo_id);
    if (r->store) tt_store_close(r->store);
    cache_free(&r->cache);
    if (r->debounce) { tt_debounce_free(r->debounce); free(r->debounce); }
    char pf[TT_PATH_MAX + 64], sf[TT_PATH_MAX + 64];
    pid_file_path(pf, sizeof pf, r->store_dir);    unlink(pf);
    status_file_path(sf, sizeof sf, r->store_dir); unlink(sf);
    memset(r, 0, sizeof *r);
    for (int i = idx; i < d->repo_count - 1; ++i) {
        d->repos[i] = d->repos[i + 1];
        d->repos[i].repo_id = i;
    }
    d->repo_count--;
    for (size_t w = 0; w < d->wmap.count; ++w)
        if (d->wmap.entries[w].repo_id > idx)
            d->wmap.entries[w].repo_id--;
}

/* ---------------- handlers IPC ---------------- */
int tt_core_ipc_add(TtDaemon *d, const char *path, char *resp, size_t respsz) {
    char abs[TT_PATH_MAX];
    if (!realpath(path, abs)) {
        snprintf(resp, respsz, "ERR realpath failed: %s\n", strerror(errno));
        return -1;
    }
    char err[256] = "";
    int rc = repo_adopt_base(d, abs, err, sizeof err);
    if (rc < 0) {
        snprintf(resp, respsz, "%s", err[0] ? err : "ERR adopt failed\n");
        return -1;
    }
    if (rc == 1) {
        snprintf(resp, respsz, "OK already watching %s (%d repos)\n", abs, d->repo_count);
        return 0;
    }
    repo_finish_watch(d, d->repo_count - 1);
    repo_list_sync(d);
    status_write(d);
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
    repo_release(d, idx);
    repo_list_sync(d);
    if (d->repo_count == 0) {
        d->running = 0;
        snprintf(resp, respsz, "OK removed %s; no repos left, daemon exiting\n", abs);
    } else {
        status_write(d);
        snprintf(resp, respsz, "OK removed %s (%d repos)\n", abs, d->repo_count);
    }
    return 0;
}

static int run_watch_loop(TtDaemon *d) {
    if (d->repo_count < 1) return 1;
    if (tt_watcher_init(d) != 0) return 1;
    for (int i = 0; i < d->repo_count; ++i) repo_finish_watch(d, i);
    if (tt_ipc_listen(d) != 0)
        tt_log("warning: IPC socket unavailable; hot 'add' disabled\n");
    tt_boot_lock_release();
    for (int i = 0; i < d->repo_count; ++i) write_pid_file(d->repos[i].store_dir);
    d->start_ns = tt_now_ns();
    status_write(d);
    fprintf(stderr, "=== Time-Travel v1.4 (multi-repo monolith + crypto) ===\n");
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
                        tt_debounce_process(d, r->debounce, on_debounced, NULL);
                }
                d->rescan_accum_ms += exp * TT_TICK_MS;
                if (d->rescan_needed || d->rescan_accum_ms >= TT_RESCAN_MS) {
                    d->rescan_needed = 0;
                    d->rescan_accum_ms = 0;
                    for (int i = 0; i < d->repo_count; ++i) {
                        TtLocalRepo *r = &d->repos[i];
                        if (r->active && !r->root_lost) rescan_and_sync_repo(d, r);
                    }
                }
                for (int i = 0; i < d->repo_count; ++i)
                    if (d->repos[i].active) handle_root_health_repo(d, &d->repos[i]);
                uint64_t now_status = tt_now_ns();
                if (now_status - last_status_ns >= 1000000000ULL) {
                    status_write(d);
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
        cache_free(&r->cache);
        if (r->debounce) { tt_debounce_free(r->debounce); free(r->debounce); r->debounce = NULL; }
        char pf[TT_PATH_MAX + 64], sf[TT_PATH_MAX + 64];
        pid_file_path(pf, sizeof pf, r->store_dir);    unlink(pf);
        status_file_path(sf, sizeof sf, r->store_dir); unlink(sf);
    }
    return 0;
}

/* ---------------- cliente ligero IPC ---------------- */
static int try_client_add(const char *abs) {
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

/* ---------------- F4: passphrase / cifrado ---------------- */
static int read_passphrase(const char *prompt, char *buf, size_t bufsz, int confirm) {
    if (bufsz < 2) return -1;
    struct termios oldt, newt;
    int tty = isatty(STDIN_FILENO);
    if (tty) {
        if (tcgetattr(STDIN_FILENO, &oldt) != 0) tty = 0;
        else { newt = oldt; newt.c_lflag &= ~(tcflag_t)ECHO;
               tcsetattr(STDIN_FILENO, TCSANOW, &newt); }
    }
    fprintf(stderr, "%s", prompt); fflush(stderr);
    char *r = fgets(buf, (int)bufsz, stdin);
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); fprintf(stderr, "\n"); }
    if (!r) { buf[0] = '\0'; return -1; }
    buf[strcspn(buf, "\r\n")] = '\0';
    if (confirm) {
        char again[256];
        if (read_passphrase("Confirm passphrase: ", again, sizeof again, 0) != 0)
            { memset(again, 0, sizeof again); return -1; }
        int eq = (strcmp(buf, again) == 0);
        memset(again, 0, sizeof again);
        if (!eq) { fprintf(stderr, "error: passphrases do not match\n"); return -1; }
    }
    return 0;
}

static int store_has_records(const char *store_dir) {
    DIR *d = opendir(store_dir);
    if (!d) return 0;
    struct dirent *de; int found = 0;
    while ((de = readdir(d)) != NULL) {
        size_t ln = strlen(de->d_name);
        if (ln > 4 && strcmp(de->d_name + ln - 4, ".ttd") == 0) { found = 1; break; }
    }
    closedir(d);
    return found;
}

/* 0 = no cifrado (sin clave), 1 = clave derivada en key_out, -1 = error */
static int unlock_store_key(const char *store_dir, uint8_t key_out[32]) {
    if (!tt_crypto_is_encrypted(store_dir)) return 0;
    char pass[256];
    if (read_passphrase("Passphrase: ", pass, sizeof pass, 0) != 0) return -1;
    int rc = tt_crypto_unlock_repo(store_dir, (const uint8_t *)pass, strlen(pass), key_out);
    memset(pass, 0, sizeof pass);
    if (rc != 0) { fprintf(stderr, "error: wrong passphrase\n"); return -1; }
    return 1;
}

static int unlock_compat_store(const char *store_dir) {
    uint8_t key[32];
    int rc = unlock_store_key(store_dir, key);
    if (rc < 0) return -1;
    if (rc == 1) tt_store_compat_set_key(key);
    memset(key, 0, sizeof key);
    return 0;
}

/* ---------------- comandos ---------------- */
static int cmd_verify(const char *repo_dir) {
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
    if (unlock_compat_store(sd) != 0) { tt_store_free(); return 1; }
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

static int cmd_watch(const char *dir, int fg, int encrypt) {
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
    if (crc >= 0) { tt_boot_lock_release(); return crc; }

    char sd[TT_PATH_MAX * 2];
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    mkdir(sd, 0700);
    if (find_running_daemon(sd, NULL) > 0) {
        printf("Daemon is already running in %s\nUse 'timetravel stop' or 'timetravel add <dir>'\n", wd);
        tt_boot_lock_release();
        return 0;
    }

    /* --- F4: cifrado (antes del fork: el padre puede pedir passphrase) --- */
    int is_enc = tt_crypto_is_encrypted(sd);
    uint8_t repo_key[32];
    int have_key = 0;
    if (encrypt || is_enc) {
        if (encrypt && !is_enc && store_has_records(sd)) {
            fprintf(stderr, "error: repo already has unencrypted history; cannot encrypt in place\n");
            tt_boot_lock_release(); return 1;
        }
        char pass[256];
        int prc = (encrypt && !is_enc)
            ? read_passphrase("New passphrase: ", pass, sizeof pass, 1)
            : read_passphrase("Passphrase: ", pass, sizeof pass, 0);
        if (prc != 0) { tt_boot_lock_release(); return 1; }
        if (encrypt && !is_enc &&
            tt_crypto_setup_repo(sd, (const uint8_t *)pass, strlen(pass)) != 0) {
            fprintf(stderr, "error: could not create crypto.meta\n");
            memset(pass, 0, sizeof pass); tt_boot_lock_release(); return 1;
        }
        if (tt_crypto_unlock_repo(sd, (const uint8_t *)pass, strlen(pass), repo_key) != 0) {
            fprintf(stderr, "error: wrong passphrase\n");
            memset(pass, 0, sizeof pass); tt_boot_lock_release(); return 1;
        }
        memset(pass, 0, sizeof pass);
        have_key = 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (!fg) {
        pid_t p = fork();
        if (p < 0) { tt_boot_lock_release(); return 1; }
        if (p > 0) {
            char pf[TT_PATH_MAX + 64];
            pid_file_path(pf, sizeof pf, sd);
            for (int i = 0; i < 120 && access(pf, F_OK) != 0; ++i) usleep(100 * 1000);
            if (kill(p, 0) != 0) {
                tt_boot_lock_release();
                fprintf(stderr, "error: daemon failed to start (check %s/timetravel.log)\n", sd);
                return 1;
            }
            printf("Time-Travel v1.4 started in background\n"
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
        if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); if (lf > 2) close(lf); }
        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) { dup2(dn, 0); if (dn > 2) close(dn); }
    }

    memset(&g_core, 0, sizeof g_core);
    g_core.ipc_fd = -1;
    g_core.running = 1;
    if (have_key) {
        g_core.has_crypto_key = 1;
        memcpy(g_core.crypto_key, repo_key, 32);
    }
    char err[256] = "";
    if (repo_adopt_base(&g_core, wd, err, sizeof err) < 0) {
        fprintf(stderr, "error: %s", err);
        tt_boot_lock_release();
        return 1;
    }
    if (have_key) tt_store_set_key(g_core.repos[0].store, repo_key);
    memset(repo_key, 0, sizeof repo_key);
    repo_list_load(&g_core);
    return run_watch_loop(&g_core);
}

static int cmd_add(const char *dir) {
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
    return cmd_watch(dir, 0, 0);
}

static int cmd_stop(const char *repo_dir) {
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
        pid = find_running_daemon(sd, NULL);
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
                pid_file_path(pf, sizeof pf, sd);
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
        pid_file_path(pf, sizeof pf, sd);
        unlink(pf);
    }
    return 0;
}

/* ---------------- undo ---------------- */
typedef enum {
    UNDO_MODE_TIME,
    UNDO_MODE_LAST,
    UNDO_MODE_INITIAL,
    UNDO_MODE_TAG
} TtUndoMode;

static int cmd_undo(const char *path, const char *time_expr, const char *repo_dir,
                    TtUndoMode mode, const char *tag_name, int force) {
    char watch_dir[TT_PATH_MAX];
    if (resolve_repo_arg(repo_dir, path, watch_dir, sizeof watch_dir) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }
    char store_dir[TT_PATH_MAX * 2];
    snprintf(store_dir, sizeof store_dir, "%s/.timetravel", watch_dir);
    if (tt_store_init(store_dir) != 0) return 1;
    if (unlock_compat_store(store_dir) != 0) { tt_store_free(); return 1; }

    char rel_path[TT_PATH_MAX];
    if (make_rel_from_arg(watch_dir, path, rel_path, sizeof rel_path) != 0) rel_path[0] = '\0';
    char full_path[TT_PATH_MAX * 2];
    if (rel_path[0]) snprintf(full_path, sizeof full_path, "%s/%s", watch_dir, rel_path);
    else snprintf(full_path, sizeof full_path, "%s", watch_dir);

    struct stat st;
    int is_dir = (rel_path[0] == '\0') || (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode));

    uint64_t target_ns = 0;
    int v_idx = 0;
    size_t v_total = 0;

    if (mode == UNDO_MODE_TIME) {
        char tdesc[128];
        int resolved = 0;
        if (!is_dir && rel_path[0])
            resolved = (resolve_file_target_ns(store_dir, rel_path, time_expr, &target_ns, tdesc, sizeof tdesc) == 0);
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
        if (tag_lookup(store_dir, tag_name, &target_ns) != 0) {
            fprintf(stderr, "error: tag '%s' not found (use 'timetravel tags')\n", tag_name);
            tt_store_free();
            return 1;
        }
    } else if (!(is_dir && (mode == UNDO_MODE_LAST || mode == UNDO_MODE_INITIAL))) {
        uint64_t *ts = NULL;
        size_t n = 0;
        if (scan_timestamps(rel_path, 0, &ts, &n) != 0 || n == 0) {
            fprintf(stderr, "error: no history for '%s'\n", path);
            free(ts);
            tt_store_free();
            return 1;
        }
        if (mode == UNDO_MODE_INITIAL) { target_ns = ts[0]; v_idx = 1; v_total = n; }
        else {
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

    /* --- Compute the actual target directory for directory restores --- */
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
        if (mode == UNDO_MODE_TIME || mode == UNDO_MODE_TAG) printf("  Time point: %s\n", ts_str);
        if (mode == UNDO_MODE_TAG) printf("  Tag:            %s\n", tag_name);
        else if (mode != UNDO_MODE_TIME && v_total > 0) printf("  Version:        %d of %zu\n", v_idx, v_total);
        printf("  Destination:    %s\n", is_dir ? undo_dir : full_path);
    } else if (rc == 1) {
        fprintf(stderr, "info: '%s' did not exist at that time point.\n", path);
    } else {
        fprintf(stderr, "error: failed to restore '%s'.\n", path);
    }
    return (rc == 0 || rc == 1) ? 0 : 1;
}

/* ---------------- status ---------------- */
static int cmd_status_global(void) {
    char sf_path[TT_PATH_MAX];
    tt_ipc_global_status_path(sf_path, sizeof sf_path);
    TtStatusFile sf;
    if (status_read_file(sf_path, &sf) != 0 || !proc_alive(sf.pid)) {
        printf("No Time-Travel daemon running.\nStart one with: timetravel start <dir>\n");
        return 0;
    }
    uint64_t now = tt_now_ns();
    uint64_t up = (now > sf.start_ns) ? (now - sf.start_ns) : 0;
    char upbuf[128], b[64];
    format_ns_duration(up, upbuf, sizeof upbuf);
    format_bytes(sf.bytes, b, sizeof b);
    printf("=== Time-Travel v1.4 Swarm (global) ===\n");
    printf("Daemon:    running (pid=%d)\nUptime:    %s\n", (int)sf.pid, upbuf);
    double cpu = proc_cpu_percent(sf.pid);
    if (cpu >= 0.0) printf("CPU:       %.1f%%\n", cpu);
    long rss = proc_rss_kb(sf.pid);
    if (rss >= 0) {
        char mem[64];
        format_bytes((uint64_t)rss * 1024ULL, mem, sizeof mem);
        printf("RAM:       %s\n", mem);
    }
    printf("Written:   %llu deltas, %s\n", (unsigned long long)sf.deltas, b);
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

static int cmd_status(const char *repo_dir) {
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2];
    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        if (repo_dir == NULL) return cmd_status_global();
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);

    TtStatusFile sf;
    int have_sf = (status_read(sd, &sf) == 0);
    uint64_t pid_start = 0;
    pid_t pid = find_running_daemon(sd, &pid_start);
    if (pid <= 0 && have_sf && proc_alive(sf.pid)) { pid = sf.pid; pid_start = sf.start_ns; }

    printf("=== Time-Travel v1.4 Status ===\nRepo anchor: %s\n", wd);
    if (pid > 0 && proc_alive(pid)) {
        uint64_t start_ns = have_sf ? sf.start_ns : pid_start;
        uint64_t now = tt_now_ns();
        uint64_t up = (now > start_ns) ? (now - start_ns) : 0;
        char upbuf[128];
        format_ns_duration(up, upbuf, sizeof upbuf);
        double cpu = proc_cpu_percent(pid);
        long rss = proc_rss_kb(pid);
        printf("Daemon:    running (pid=%d)\nUptime:    %s\n", (int)pid, upbuf);
        if (cpu >= 0.0) printf("CPU:       %.1f%%\n", cpu);
        else printf("CPU:       ?\n");
        if (rss >= 0) {
            char mem[64];
            format_bytes((uint64_t)rss * 1024ULL, mem, sizeof mem);
            printf("RAM:       %s\n", mem);
        } else printf("RAM:       ?\n");
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
    uint8_t skey[32]; int have_skey = 0;
    { uint8_t k[32]; int rc = unlock_store_key(sd, k);
      if (rc == 1) { memcpy(skey, k, 32); have_skey = 1; }
      memset(k, 0, sizeof k); }
    scan_stats_dir(sd, have_skey ? skey : NULL, &nrecords, &nbytes, &fts, &lts);
    memset(skey, 0, sizeof skey);

    char b[64];
    format_bytes(nbytes, b, sizeof b);
    printf("Records:   %llu\nBytes:     %s\n", (unsigned long long)nrecords, b);
    char b1[64], b2[64];
    if (fts) format_timestamp(fts, b1, sizeof b1);
    else snprintf(b1, sizeof b1, "-");
    if (lts) format_timestamp(lts, b2, sizeof b2);
    else snprintf(b2, sizeof b2, "-");
    printf("First:     %s\nLast:      %s\n==========================\n", b1, b2);
    return 0;
}

/* ---------------- log / compact / tag / diff / dump ---------------- */
static int cmd_log(const char *path, const char *repo_dir, const char *since_expr) {
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2], rel[TT_PATH_MAX];
    if (resolve_repo_arg(repo_dir, path, wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    if (tt_store_init(sd) != 0) return 1;
    if (unlock_compat_store(sd) != 0) { tt_store_free(); return 1; }
    if (make_rel_from_arg(wd, path, rel, sizeof rel) != 0) rel[0] = '\0';

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
    if (tt_store_reader_init() != 0) { tt_store_free(); return 1; }
    printf("History of: %s (since %s)\n", rel[0] ? rel : "(all)", since_expr);
    int any = 0;
    for (;;) {
        TtDeltaHeader hdr;
        char p2[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, p2, sizeof p2, &pl, &plsz);
        if (rc <= 0) break;
        if (rel[0] && strcmp(p2, rel) != 0) { free(pl); continue; }
        if (hdr.timestamp_ns < since_ns) { free(pl); continue; }
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
    if (!any) printf("  (no events in that range)\n");
    return 0;
}

static int cmd_compact(const char *repo_dir) {
    char wd[TT_PATH_MAX];
    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }
    char sd[TT_PATH_MAX * 2];
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    if (tt_store_init(sd) != 0) return 1;
    if (unlock_compat_store(sd) != 0) { tt_store_free(); return 1; }
    int rc = tt_compact_run(sd);
    tt_store_free();
    if (rc < 0) {
        fprintf(stderr, "error: compaction failed\n");
        return 1;
    }
    printf("compaction: %d chain(s) collapsed\n", rc);
    return 0;
}

static int cmd_tag(const char *name, const char *repo_dir) {
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2];
    if (resolve_repo_arg(repo_dir, ".", wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    mkdir(sd, 0700);
    uint64_t ts = tt_now_ns();
    if (tag_add(sd, name, ts) != 0) {
        fprintf(stderr, "error: could not write tag\n");
        return 1;
    }
    char tsbuf[64];
    format_timestamp(ts, tsbuf, sizeof tsbuf);
    printf("OK Tag '%s' created at %s\nRestore: timetravel undo <path> --tag %s --repo %s\n",
           name, tsbuf, name, wd);
    return 0;
}

static int cmd_diff(const char *path, const char *repo_dir, const char *time_expr) {
    char wd[TT_PATH_MAX], sd[TT_PATH_MAX * 2], rel[TT_PATH_MAX];
    if (resolve_repo_arg(repo_dir, path, wd, sizeof wd) != 0) {
        fprintf(stderr, "error: .timetravel not found\n");
        return 1;
    }
    snprintf(sd, sizeof sd, "%s/.timetravel", wd);
    if (tt_store_init(sd) != 0) return 1;
    if (unlock_compat_store(sd) != 0) { tt_store_free(); return 1; }
    if (make_rel_from_arg(wd, path, rel, sizeof rel) != 0 || rel[0] == '\0') {
        fprintf(stderr, "error: diff requires a file inside the repo\n");
        tt_store_free();
        return 1;
    }
    uint64_t target_ns = 0;
    char tdesc[128];
    if (resolve_file_target_ns(sd, rel, time_expr, &target_ns, tdesc, sizeof tdesc) != 0) {
        fprintf(stderr, "error: no history for '%s'\n", path);
        tt_store_free();
        return 1;
    }
    uint8_t *old_data = NULL;
    size_t old_size = 0;
    int exists = 0;
    load_version_content(sd, rel, target_ns, &old_data, &old_size, &exists);
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
        if (fda >= 0) close(fda);
        if (fdb >= 0) close(fdb);
        free(old_data);
        free(cur_data);
        return 1;
    }
    if (old_size > 0) { ssize_t wr = write(fda, old_data, old_size); (void)wr; }
    if (cur_size > 0) { ssize_t wr = write(fdb, cur_data, cur_size); (void)wr; }
    close(fda);
    close(fdb);

    char cmdbuf[1024];
    snprintf(cmdbuf, sizeof cmdbuf,
             "diff -u --label \"%s (%s)\" --label \"%s (current)\" \"%s\" \"%s\" 2>/dev/null",
             path, tdesc, path, ta, tb);
    int rc = system(cmdbuf);
    if (rc == -1) fprintf(stderr, "warning: could not execute 'diff'\n");
    else if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) printf("(no differences)\n");
    unlink(ta);
    unlink(tb);
    free(old_data);
    free(cur_data);
    return 0;
}

static int cmd_dump(const char *path, const char *repo_dir, const char *outdir, int with_diff) {
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
    if (tt_store_init(sd) != 0) return 1;
    if (unlock_compat_store(sd) != 0) { tt_store_free(); return 1; }
    if (make_rel_from_arg(wd, path, rel, sizeof rel) != 0) rel[0] = '\0';
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
    store_collect_matching(&set, rel);
    if (set.n == 0) {
        printf("no history for '%s'\n", path);
        fclose(manifest);
        pathset_free(&set);
        tt_store_free();
        return 1;
    }
    int ok = 0;
    for (size_t i = 0; i < set.n; ++i) {
        int rc = dump_one_file(sd, set.v[i], outdir, with_diff, manifest);
        if (rc == 0) ok++;
    }
    fclose(manifest);
    pathset_free(&set);
    tt_store_free();
    printf("dump: %d file(s) with history in %s\n", ok, outdir);
    return ok > 0 ? 0 : 1;
}

/* ---------------- usage ---------------- */
static void usage(void) {
    printf("\n"
    "============================================================\n"
    " Time-Travel v1.4 — Filesystem-level Ctrl+Z\n"
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

static int normalize_dir_arg(const char *in, char *out, size_t outsz)
{
    if (!in || !in[0])
        in = ".";

    char *rp = realpath(in, NULL);
    if (!rp) {
        fprintf(stderr, "error: cannot resolve directory '%s': %s\n",
                in, strerror(errno));
        return -1;
    }

    struct stat st;
    if (stat(rp, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: '%s' is not a directory\n", in);
        free(rp);
        return -1;
    }

    snprintf(out, outsz, "%s", rp);
    free(rp);
    return 0;
}

static int dir_is_inside(const char *parent, const char *child)
{
    if (strcmp(parent, "/") == 0)
        return 1;

    size_t plen = strlen(parent);

    if (strncmp(child, parent, plen) != 0)
        return 0;

    return child[plen] == '\0' || child[plen] == '/';
}

static int check_start_overlaps(char dirs[][TT_PATH_MAX], int n)
{
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            if (i == j)
                continue;

            if (strcmp(dirs[i], dirs[j]) == 0) {
                fprintf(stderr, "error: duplicate directory '%s'\n", dirs[i]);
                return -1;
            }

            if (dir_is_inside(dirs[i], dirs[j])) {
                fprintf(stderr,
                        "error: '%s' is inside '%s' (overlapping repositories)\n",
                        dirs[j], dirs[i]);
                return -1;
            }
        }
    }

    return 0;
}

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

        if (!no_more_flags && argv[i][0] == '-' && argv[i][1] != '\0')
            continue;

        dirs[n++] = argv[i];
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

        if (i == 0)
            rc = cmd_watch(dirs[i], 0, enc);
        else
            rc = cmd_add(dirs[i]);

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
        if (cmd_add(dirs[i]) != 0) {
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
        return cmd_verify(r);
    }
    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(cmd, "start") == 0) {
        if (argc < 3) { usage(); return 1; }
        int enc = 0;
        for (int i = 3; i < argc; ++i)
            if (strcmp(argv[i], "--encrypt") == 0) enc = 1;
        return cmd_watch(argv[2], 0, enc);
    }

    if (strcmp(cmd, "add") == 0) {
    return cmd_add_multi(argc, argv, 2);
}

    if (strcmp(cmd, "stop") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return cmd_stop(r);
    }
    if (strcmp(cmd, "restart") == 0) {
        if (argc < 3) { usage(); return 1; }
        cmd_stop(argv[2]);
        return cmd_watch(argv[2], 0, 0);
    }
    if (strcmp(cmd, "watch") == 0) {
        if (argc < 3) { usage(); return 1; }
        int fg = 0, enc = 0;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "-f") == 0) fg = 1;
            else if (strcmp(argv[i], "--encrypt") == 0) enc = 1;
        }
        return cmd_watch(argv[2], fg, enc);
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
        return cmd_undo(path, expr, repo, mode, tag, force);
    }
    if (strcmp(cmd, "diff") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL, *expr = NULL;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) expr = argv[++i];
        }
        return cmd_diff(argv[2], repo, expr);
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
        return cmd_dump(argv[2], repo, out, with_diff);
    }
    if (strcmp(cmd, "tag") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL;
        for (int i = 3; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
        return cmd_tag(argv[2], repo);
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
        return tag_list(sd);
    }
    if (strcmp(cmd, "status") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return cmd_status(r);
    }
    if (strcmp(cmd, "log") == 0) {
        if (argc < 3) { usage(); return 1; }
        const char *repo = NULL, *since = NULL;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc) since = argv[++i];
        }
        return cmd_log(argv[2], repo, since);
    }
    if (strcmp(cmd, "compact") == 0) {
        const char *r = NULL;
        for (int i = 2; i < argc; ++i)
            if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) r = argv[++i];
        return cmd_compact(r);
    }

    fprintf(stderr, "error: unknown command '%s'\n", cmd);
    usage();
    return 1;
}
