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
/* tt_compact.c */
#include "tt_types.h"
#include "tt_dedup.h"
#include "tt_crypto.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps, uint8_t **pl, size_t *plsz);
extern void tt_store_reader_free(void);

extern TtStore *tt_store_open(const char *store_dir, int continue_last);
extern void tt_store_close(TtStore *s);

extern const uint8_t *tt_store_compat_get_key(void);
extern void tt_store_set_key(TtStore *s, const uint8_t key[TT_KEY_LEN]);
extern void tt_store_set_encrypted(TtStore *s, int enc);

extern int tt_store_write_ctx(TtStore *s,
                              const TtDeltaHeader *h,
                              const char *path,
                              const uint8_t *payload);

extern int tt_delta_encode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *new_data, size_t new_size,
                           uint8_t **delta_out, size_t *delta_size_out);

extern int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *delta_data, size_t delta_size,
                           size_t expected_new_size,
                           uint8_t **new_out, size_t *new_size_out);

typedef struct {
    TtDeltaHeader hdr;
    char path[TT_PATH_MAX];
    uint8_t *payload;
    size_t payload_size;
    size_t seq;
} CompactRecord;

typedef struct {
    char path[TT_PATH_MAX];
    CompactRecord *records;
    size_t count, cap;
} CompactGroup;

typedef struct {
    CompactGroup *groups;
    size_t count, cap;
} CompactSet;

static void compact_record_destroy(CompactRecord *r)
{
    free(r->payload);
    r->payload = NULL;
    r->payload_size = 0;
}

static void compact_set_destroy(CompactSet *cs)
{
    if (!cs) return;

    for (size_t i = 0; i < cs->count; ++i) {
        CompactGroup *g = &cs->groups[i];

        for (size_t j = 0; j < g->count; ++j)
            compact_record_destroy(&g->records[j]);

        free(g->records);
    }

    free(cs->groups);
    memset(cs, 0, sizeof *cs);
}

static CompactGroup *compact_set_touch(CompactSet *cs, const char *path)
{
    for (size_t i = 0; i < cs->count; ++i) {
        if (strcmp(cs->groups[i].path, path) == 0)
            return &cs->groups[i];
    }

    if (cs->count == cs->cap) {
        size_t ncap = cs->cap ? cs->cap * 2 : 16;
        CompactGroup *ng = realloc(cs->groups, ncap * sizeof(CompactGroup));
        if (!ng) return NULL;

        cs->groups = ng;
        cs->cap = ncap;
    }

    CompactGroup *g = &cs->groups[cs->count++];

    memset(g, 0, sizeof *g);
    snprintf(g->path, sizeof g->path, "%s", path);

    return g;
}

static int compact_read_all(CompactSet *cs)
{
    memset(cs, 0, sizeof *cs);

    if (tt_store_reader_init() != 0)
        return -1;

    size_t seq = 0;

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);

        if (rc == 0)
            break;

        if (rc < 0) {
            tt_store_reader_free();
            compact_set_destroy(cs);
            return -1;
        }

        CompactGroup *g = compact_set_touch(cs, path);
        if (!g) {
            free(pl);
            tt_store_reader_free();
            compact_set_destroy(cs);
            return -1;
        }

        if (g->count == g->cap) {
            size_t ncap = g->cap ? g->cap * 2 : 8;
            CompactRecord *nr = realloc(g->records, ncap * sizeof(CompactRecord));
            if (!nr) {
                free(pl);
                tt_store_reader_free();
                compact_set_destroy(cs);
                return -1;
            }

            g->records = nr;
            g->cap = ncap;
        }

        CompactRecord *r = &g->records[g->count++];

        r->hdr = hdr;
        snprintf(r->path, sizeof r->path, "%s", path);
        r->payload = pl;
        r->payload_size = plsz;
        r->seq = seq++;
    }

    tt_store_reader_free();

    return 0;
}

static int collapse_replay(CompactRecord *recs,
                           size_t start,
                           size_t end,
                           uint8_t **out_state,
                           size_t *out_size)
{
    if (recs[start].hdr.event_type != TT_EV_CREATE)
        return -1;

    size_t bsz = recs[start].payload_size;

    uint8_t *state = malloc(bsz ? bsz : 1);
    if (!state) return -1;

    if (bsz && recs[start].payload)
        memcpy(state, recs[start].payload, bsz);

    size_t state_size = bsz;

    for (size_t i = start + 1; i <= end; ++i) {
        CompactRecord *r = &recs[i];

        if (r->hdr.event_type == TT_EV_DELETE) {
            free(state);
            return -1;
        }

        if (r->hdr.event_type == TT_EV_CREATE) {
            free(state);

            size_t s = r->payload_size;

            state = malloc(s ? s : 1);
            if (!state) return -1;

            if (s && r->payload)
                memcpy(state, r->payload, s);

            state_size = s;
            continue;
        }

        if (r->hdr.delta_size == 0) {
            free(state);

            state = malloc(1);
            if (!state) return -1;

            state_size = 0;
            continue;
        }

        if (!r->payload) {
            free(state);
            return -1;
        }

        uint8_t *ns = NULL;
        size_t nss = 0;

        if (tt_delta_decode(state, state_size,
                            r->payload, r->payload_size,
                            r->hdr.file_size,
                            &ns, &nss) != 0) {
            free(state);
            return -1;
        }

        free(state);
        state = ns;
        state_size = nss;
    }

    *out_state = state;
    *out_size = state_size;

    return 0;
}

static int compact_flat_cmp(const void *a, const void *b)
{
    const CompactRecord *ra = a, *rb = b;

    if (ra->hdr.timestamp_ns < rb->hdr.timestamp_ns) return -1;
    if (ra->hdr.timestamp_ns > rb->hdr.timestamp_ns) return 1;

    if (ra->seq < rb->seq) return -1;
    if (ra->seq > rb->seq) return 1;

    return 0;
}

static void rm_rf(const char *path)
{
    DIR *dp = opendir(path);

    if (!dp) {
        unlink(path);
        return;
    }

    struct dirent *de;
    char sub[TT_PATH_MAX + 280];

    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        snprintf(sub, sizeof sub, "%s/%s", path, de->d_name);

        struct stat st;

        if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(sub);
        else
            unlink(sub);
    }

    closedir(dp);
    rmdir(path);
}

int tt_compact_run(const char *store_dir)
{
    if (!store_dir || !store_dir[0])
        return -1;

    char tmpdir[TT_PATH_MAX + 64];
    snprintf(tmpdir, sizeof tmpdir, "%s/.compact_tmp", store_dir);

    rm_rf(tmpdir);                          /* restos de un compact previo cortado */
    int src_encrypted = tt_crypto_is_encrypted(store_dir);
    const uint8_t *compact_key = NULL;
    compact_key = NULL;
    if (src_encrypted) {
    compact_key = tt_store_compat_get_key();
    if (!compact_key) return -1;
    }
    CompactSet cs;



    if (compact_read_all(&cs) != 0)
        return -1;

    if (cs.count == 0) {
        compact_set_destroy(&cs);
        (void)tt_dedup_gc(store_dir);
        return 0;
    }

    int collapsed = 0;

    for (size_t gi = 0; gi < cs.count; ++gi) {
        CompactGroup *g = &cs.groups[gi];

        if (g->count <= (size_t)TT_COMPACT_THRESHOLD)
            continue;

        CompactRecord *nr = calloc(g->count, sizeof(CompactRecord));
        if (!nr) continue;

        size_t n = 0, run_start = 0;

        for (size_t i = 0; i <= g->count; ++i) {
            int is_del = (i < g->count && g->records[i].hdr.event_type == TT_EV_DELETE);
            int is_end = (i == g->count);

            if (!is_del && !is_end)
                continue;

            size_t run_len = i - run_start;
            int did = 0;

            if (run_len > (size_t)TT_COMPACT_THRESHOLD &&
                g->records[run_start].hdr.event_type == TT_EV_CREATE) {

                uint8_t *state = NULL;
                size_t state_size = 0;

                if (collapse_replay(g->records, run_start, i - 1,
                                    &state, &state_size) == 0) {

                    CompactRecord *base = &g->records[run_start];

                    uint8_t *super = NULL;
                    size_t super_size = 0;
                    int full_copy = 1;

                    if (state_size > 0 &&
                        base->payload &&
                        base->payload_size > 0 &&
                        tt_delta_encode(base->payload, base->payload_size,
                                        state, state_size,
                                        &super, &super_size) == 0 &&
                        super_size > 0 &&
                        super_size < state_size) {
                        full_copy = 0;
                    } else {
                        free(super);
                        super = NULL;
                    }

                    nr[n++] = *base;

                    CompactRecord *sr = &nr[n++];
                    memset(sr, 0, sizeof *sr);

                    sr->hdr = g->records[i - 1].hdr;
                    sr->hdr.path_len = (uint32_t)strlen(g->path);
                    sr->hdr.file_size = (uint64_t)state_size;

                    snprintf(sr->path, sizeof sr->path, "%s", g->path);
                    sr->seq = g->records[i - 1].seq;

                    if (full_copy) {
                        sr->hdr.event_type = TT_EV_CREATE;
                        sr->payload = state;
                        state = NULL;
                        sr->payload_size = state_size;
                        sr->hdr.delta_size = (uint32_t)state_size;
                    } else {
                        sr->hdr.event_type = TT_EV_MODIFY;
                        sr->payload = super;
                        super = NULL;
                        sr->payload_size = super_size;
                        sr->hdr.delta_size = (uint32_t)super_size;
                    }

                    for (size_t k = run_start + 1; k < i; ++k)
                        compact_record_destroy(&g->records[k]);

                    free(state);
                    free(super);

                    did = 1;
                    collapsed++;
                }
            }

            if (!did) {
                for (size_t k = run_start; k < i; ++k)
                    nr[n++] = g->records[k];
            }

            if (is_del)
                nr[n++] = g->records[i];

            run_start = i + 1;
        }

        free(g->records);

        g->records = nr;
        g->count = n;
        g->cap = n;
    }

    if (collapsed == 0) {
        compact_set_destroy(&cs);
        (void)tt_dedup_gc(store_dir);
        return 0;
    }

    size_t total = 0;

    for (size_t gi = 0; gi < cs.count; ++gi)
        total += cs.groups[gi].count;

    CompactRecord *flat = malloc((total ? total : 1) * sizeof(CompactRecord));
    if (!flat) {
        compact_set_destroy(&cs);
        return -1;
    }

    size_t f = 0;

    for (size_t gi = 0; gi < cs.count; ++gi) {
        CompactGroup *g = &cs.groups[gi];

        for (size_t i = 0; i < g->count; ++i)
            flat[f++] = g->records[i];

        free(g->records);
        g->records = NULL;
        g->count = g->cap = 0;
    }

    free(cs.groups);
    cs.groups = NULL;
    cs.count = cs.cap = 0;

    if (total > 1)
        qsort(flat, total, sizeof(CompactRecord), compact_flat_cmp);

    /* snapshot de los .ttd viejos (a borrar SOLO si todo sale bien) */
    char **old_names = NULL;
    size_t old_n = 0, old_cap = 0;

    DIR *od = opendir(store_dir);
    if (od) {
        struct dirent *de;

        while ((de = readdir(od)) != NULL) {
            size_t ln = strlen(de->d_name);

            if (ln > 4 && strcmp(de->d_name + ln - 4, ".ttd") == 0) {
                if (old_n == old_cap) {
                    old_cap = old_cap ? old_cap * 2 : 16;
                    char **nn = realloc(old_names, old_cap * sizeof(char *));
                    if (!nn) break;
                    old_names = nn;
                }

                old_names[old_n] = strdup(de->d_name);
                if (old_names[old_n]) old_n++;
            }
        }

        closedir(od);
    }

    /* escribir TODO en el directorio temporal */
    if (mkdir(tmpdir, 0700) != 0) {
        collapsed = -1;
        goto done;
    }

    TtStore *ts = tt_store_open(tmpdir, 0);
    if (!ts) {
        collapsed = -1;
        goto done;
    }

    if (src_encrypted) {
    tt_store_set_encrypted(ts, 1);
    tt_store_set_key(ts, compact_key);
}

    for (size_t i = 0; i < total; ++i) {
        if (tt_store_write_ctx(ts, &flat[i].hdr, flat[i].path, flat[i].payload) != 0) {
            tt_store_close(ts);
            collapsed = -1;
            goto done;
        }
    }

    tt_store_close(ts);

    /* mover lo generado al store real y luego borrar lo viejo */
    {
        int move_ok = 1;

        DIR *td = opendir(tmpdir);
        if (!td) {
            move_ok = 0;
        } else {
            struct dirent *de;

            while ((de = readdir(td)) != NULL) {
                size_t ln = strlen(de->d_name);

                if (ln > 4 && strcmp(de->d_name + ln - 4, ".ttd") == 0) {
                    char from[TT_PATH_MAX + 96];
                    char to[TT_PATH_MAX + 96];

                    snprintf(from, sizeof from, "%s/%s", tmpdir, de->d_name);
                    snprintf(to, sizeof to, "%s/%s", store_dir, de->d_name);

                    if (rename(from, to) != 0)
                        move_ok = 0;
                }
            }

            closedir(td);
        }

        if (move_ok) {
            for (size_t i = 0; i < old_n; ++i) {
                char p[TT_PATH_MAX + 96];
                snprintf(p, sizeof p, "%s/%s", store_dir, old_names[i]);
                unlink(p);
            }

            int dfd = open(store_dir, O_RDONLY); /* persistir renames+unlinks */
            if (dfd >= 0) {
                fsync(dfd);
                close(dfd);
            }
        } else {
            collapsed = -1; /* fallo de move: los viejos quedan intactos */
        }
    }

    if (collapsed >= 0)
        (void)tt_dedup_gc(store_dir);

done:
    rm_rf(tmpdir);

    for (size_t i = 0; i < old_n; ++i)
        free(old_names[i]);

    free(old_names);

    for (size_t i = 0; i < total; ++i)
        compact_record_destroy(&flat[i]);

   free(flat);
    compact_key = NULL;
    return collapsed;
}
