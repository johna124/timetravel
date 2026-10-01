/* ============================================================
   Time-Travel v1.5 — tt_capture.c
   Pipeline de captura: CREATE/MODIFY/DELETE, walks y rescans.
   ============================================================ */
#include "tt_capture.h"
#include "tt_util.h"
#include "tt_cache.h"
#include "tt_history.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tt_exclude.h"
#include "tt_autotag.h"
#include "tt_annotation.h"

/* ---------------- externs ---------------- */
extern int tt_dedup_split(const char *store_dir,
                          const uint8_t *data, size_t size,
                          uint8_t **hashes_out, size_t *nblocks_out,
                          const uint8_t *key);

extern int tt_delta_encode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *new_data, size_t new_size,
                           uint8_t **delta_out, size_t *delta_size_out);

extern const uint8_t *tt_store_get_key(const TtStore *s);

extern int tt_store_write_ctx(TtStore *s,
                              const TtDeltaHeader *hdr,
                              const char *path,
                              const uint8_t *payload);

extern int tt_is_excluded(const char *rel);

extern void tt_debounce_add(TtDebounce *q, const char *path, uint8_t ev);

/* ==================== escritura de records ==================== */

int tt_write_create_record_ts(TtLocalRepo *r, const char *rel,
                              const uint8_t *data, size_t size,
                              uint64_t ts)
{
    /* Ficheros grandes -> dedup por bloques */
    if (size >= TT_DEDUP_MIN_SIZE) {
        uint8_t *hashes = NULL;
        size_t nblocks = 0;

        if (tt_dedup_split(r->store_dir, data, size,
                           &hashes, &nblocks,
                           tt_store_get_key(r->store)) == 0 &&
            nblocks > 0) {

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
                r->bytes_stored += sizeof(hdr) + strlen(rel) +
                                   nblocks * TT_DEDUP_HASH_LEN;
            }
return rc;
        }

        free(hashes); /* fallo del split -> fallback a CREATE normal */
    }

    TtDeltaHeader hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.timestamp_ns = ts;
    hdr.event_type = TT_EV_CREATE;
    hdr.path_len = (uint32_t)strlen(rel);
    hdr.delta_size = (uint32_t)size;
    hdr.file_size = (uint64_t)size;

    int rc = tt_store_write_ctx(r->store, &hdr, rel,
                                size > 0 ? data : NULL);
    if (rc == 0) {
        r->deltas_written++;
        r->bytes_stored += sizeof(hdr) + strlen(rel) + size;
    }
/* v1.5: autotag del CREATE */
{
    char _tg[512];
    tt_generate_autotag(NULL, 0, data, size, _tg, sizeof _tg);
    char _sm[1024];
    if (_tg[0])
        snprintf(_sm, sizeof _sm, "CREATE (%zu B) %s", size, _tg);
    else
        snprintf(_sm, sizeof _sm, "CREATE (%zu B)", size);
    tt_annotation_write(r->store_dir, rel, ts, _sm);
}
return rc;
}

int tt_write_create_record(TtLocalRepo *r, const char *rel,
                           const uint8_t *data, size_t size)
{
    return tt_write_create_record_ts(r, rel, data, size, tt_next_ts());
}

int tt_write_version_record(TtLocalRepo *r, const char *rel,
                            const uint8_t *old, size_t old_size,
                            const uint8_t *newd, size_t new_size)
{
    if (old && old_size > 0) {
        uint8_t *delta = NULL;
        size_t dsz = 0;

        if (tt_delta_encode(old, old_size, newd, new_size,
                            &delta, &dsz) == 0 &&
            dsz > 0 && dsz < new_size) {

            TtDeltaHeader hdr;
            memset(&hdr, 0, sizeof hdr);
            hdr.timestamp_ns = tt_next_ts();
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
/* v1.5: autotag del MODIFY */
{
    char _at[512];
    tt_delta_full_summary(old, old_size, newd, new_size,
                          _at, sizeof _at);
    if (_at[0])
        tt_annotation_write(r->store_dir, rel,
                            hdr.timestamp_ns, _at);
}
return rc;
        }

        free(delta);
    }

    return tt_write_create_record(r, rel, newd, new_size);
}

/* ==================== captura ==================== */

int tt_capture_path(TtDaemon *d, TtLocalRepo *r, const char *rel, int quiet)
{
    if (!d || !r || !rel || !rel[0])
        return -1;

    if (tt_is_excluded(rel))
        return -1;
    if (tt_exclude_match(&r->excludes, rel)) return -1;

    char full[TT_PATH_MAX * 2];
    snprintf(full, sizeof full, "%s/%s", r->root, rel);

    struct stat st;
    if (lstat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
        TtStateEntry *e = tt_cache_find(&r->cache, rel);
        if (!e)
            return 0;

        if (e->baseline_pending) {
            tt_cache_remove(&r->cache, rel);
            return 0;
        }

        TtDeltaHeader hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.timestamp_ns = tt_next_ts();
        hdr.event_type = TT_EV_DELETE;
        hdr.path_len = (uint32_t)strlen(rel);

        if (tt_store_write_ctx(r->store, &hdr, rel, NULL) == 0) {
            tt_cache_remove(&r->cache, rel);
            r->deltas_written++;
            r->bytes_stored += sizeof(hdr) + strlen(rel);
            tt_log("DELETE  %s\n", rel);
            return 1;
        }
        return -1;
    }

    if ((uint64_t)st.st_size > TT_MAX_CAPTURE_SIZE) {
        if (!quiet)
            tt_log("warning: '%s' exceeds maximum size; ignored\n", rel);
        return 0;
    }

    uint8_t *new_data = NULL;
    size_t new_size = 0;

    if (read_file_all(full, &new_data, &new_size) != 0)
        return -1;

    struct stat st2;
    if (lstat(full, &st2) != 0 ||
        st2.st_size != st.st_size ||
        st2.st_mtim.tv_sec != st.st_mtim.tv_sec ||
        st2.st_mtim.tv_nsec != st.st_mtim.tv_nsec) {
        free(new_data);
        tt_debounce_add(r->debounce, full, TT_EV_MODIFY);
        return 0;
    }

    TtStateEntry *e = tt_cache_find(&r->cache, rel);

    if (!e) {
        int rc = tt_write_create_record(r, rel, new_data, new_size);
        if (rc == 0) {
            tt_cache_put(&r->cache, rel, new_data, new_size, 1, 0);
            tt_log("CREATE  %s (%zu bytes)\n", rel, new_size);
            free(new_data);
            return 1;
        }
        free(new_data);
        return -1;
    }

    if (e->size == new_size &&
        (new_size == 0 ||
         (e->data && memcmp(e->data, new_data, new_size) == 0))) {
        free(new_data);
        return 0;
    }

    int rc;

    if (e->baseline_pending) {
        uint64_t orig_ts = r->start_ns ? r->start_ns : tt_next_ts();

        rc = tt_write_create_record_ts(r, rel, e->data, e->size, orig_ts);
        if (rc == 0) {
            tt_log("CREATE  %s (%zu bytes) [original]\n", rel, e->size);

            rc = tt_write_version_record(r, rel, e->data, e->size,
                                         new_data, new_size);
            if (rc == 0) {
                tt_cache_put(&r->cache, rel, new_data, new_size, 1, 0);
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
        rc = tt_write_create_record(r, rel, new_data, new_size);
        if (rc == 0) {
            tt_cache_put(&r->cache, rel, new_data, new_size, 1, 0);
            tt_log("CREATE  %s (%zu bytes) [reanchor]\n", rel, new_size);
            free(new_data);
            return 1;
        }
        free(new_data);
        return -1;
    }

    rc = tt_write_version_record(r, rel, e->data, e->size,
                                 new_data, new_size);
    if (rc == 0) {
        tt_cache_put(&r->cache, rel, new_data, new_size, 1, 0);
        tt_log("MODIFY  %s (%zu bytes)\n", rel, new_size);
        free(new_data);
        return 1;
    }

    free(new_data);
    return -1;
}

/* ==================== builds / rescans ==================== */

void tt_capture_build_walk_repo(TtDaemon *d, TtLocalRepo *r, TtPathSet *hist,
                                const char *dir_full, const char *rel_prefix,
                                size_t *n_files)
{
    DIR *dp = opendir(dir_full);
    if (!dp)
        return;

    struct dirent *de;

    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char rel[TT_PATH_MAX];
        if (rel_prefix[0])
            snprintf(rel, sizeof rel, "%s/%s", rel_prefix, de->d_name);
        else
            snprintf(rel, sizeof rel, "%s", de->d_name);

        if (tt_is_excluded(rel))
            continue;
        if (tt_exclude_match(&r->excludes, rel)) continue;

        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", dir_full, de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            tt_capture_build_walk_repo(d, r, hist, full, rel, n_files);
            continue;
        }

        if (!S_ISREG(st.st_mode))
            continue;

        if ((uint64_t)st.st_size > TT_MAX_CAPTURE_SIZE)
            continue;

        uint8_t *data = NULL;
        size_t size = 0;

        if (read_file_all(full, &data, &size) != 0)
            continue;

        int has_hist = tt_pathset_has(hist, rel);

        tt_cache_put(&r->cache, rel, data, size,
                     has_hist ? 0 : 1,
                     has_hist ? 0 : 1);

        free(data);
        (*n_files)++;
    }

    closedir(dp);
}

void tt_capture_build_initial_repo(TtDaemon *d, TtLocalRepo *r)
{
    TtPathSet hist;
    tt_store_collect_paths_ctx(r->store_dir, &hist);

    size_t n_files = 0;

    struct stat st;
    if (stat(r->root, &st) == 0 && S_ISDIR(st.st_mode))
        tt_capture_build_walk_repo(d, r, &hist, r->root, "", &n_files);

    tt_log("[%s] in memory: %zu file(s)\n", r->root, n_files);

    tt_pathset_free(&hist);
}

void tt_capture_rescan_walk_repo(TtDaemon *d, TtLocalRepo *r,
                                 const char *dir_full, const char *rel_prefix,
                                 int *written)
{
    DIR *dp = opendir(dir_full);
    if (!dp)
        return;

    struct dirent *de;

    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char rel[TT_PATH_MAX];
        if (rel_prefix[0])
            snprintf(rel, sizeof rel, "%s/%s", rel_prefix, de->d_name);
        else
            snprintf(rel, sizeof rel, "%s", de->d_name);

        if (tt_is_excluded(rel))
            continue;
        if (tt_exclude_match(&r->excludes, rel)) continue;

        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", dir_full, de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            tt_capture_rescan_walk_repo(d, r, full, rel, written);
        } else if (S_ISREG(st.st_mode)) {
            int rc = tt_capture_path(d, r, rel, 1);
            if (rc > 0 && written)
                (*written)++;
        }
    }

    closedir(dp);
}

void tt_capture_rescan_and_sync_repo(TtDaemon *d, TtLocalRepo *r)
{
    struct stat st;

    if (stat(r->root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        r->root_lost = 1;
        return;
    }

    int written = 0;
    tt_capture_rescan_walk_repo(d, r, r->root, "", &written);

    size_t i = 0;
    while (i < r->cache.count) {
        TtStateEntry *e = &r->cache.entries[i];

        if (!e->active) {
            i++;
            continue;
        }

        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", r->root, e->path);

        struct stat st2;
        if (lstat(full, &st2) != 0 || !S_ISREG(st2.st_mode)) {
            int rc = tt_capture_path(d, r, e->path, 1);
            if (rc > 0)
                written++;
        }

        i++;
    }

    if (written > 0)
        tt_log("[%s] rescan: %d record(s)\n", r->root, written);
}

/* ==================== debounce callback ==================== */

void tt_capture_on_debounced(TtDaemon *d, const char *full_path,
                             uint8_t event_type, void *user)
{
    (void)event_type;
    (void)user;

    for (int i = 0; i < d->repo_count; ++i) {
        TtLocalRepo *r = &d->repos[i];
        if (!r->active)
            continue;

        size_t len = strlen(r->root);

        if (strncmp(full_path, r->root, len) == 0 &&
            (full_path[len] == '/' || full_path[len] == '\0')) {

            const char *rel = full_path + len;
            while (*rel == '/')
                rel++;

            if (*rel)
                tt_capture_path(d, r, rel, 0);

            return;
        }
    }
}
