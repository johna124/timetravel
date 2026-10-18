/* ============================================================
   Time-Travel v1.5 — tt_history.c
   Consultas de historial, tags, pathsets y resolución de targets.
   ============================================================ */
#include "tt_history.h"
#include "tt_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "tt_reconstruct.h"

/* ---------------- externs ---------------- */
extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps,
                                uint8_t **pl, size_t *plsz);
extern void tt_store_reader_free(void);
extern int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *delta_data, size_t delta_size,
                           size_t expected_new_size,
                           uint8_t **new_out, size_t *new_size_out);
extern int tt_dedup_reconstruct(const char *store_dir,
                                const uint8_t *payload, size_t payload_size,
                                uint8_t **out, size_t *out_size,
                                const uint8_t *key);
extern const uint8_t *tt_store_compat_get_key(void);
extern TtStoreReader *tt_reader_open(const char *store_dir);
extern int tt_reader_next(TtStoreReader *rd, TtDeltaHeader *out_hdr,
                          char *out_path, size_t out_path_size,
                          uint8_t **out_payload, size_t *out_payload_size);
extern void tt_reader_close(TtStoreReader *rd);
extern void tt_reader_set_key(TtStoreReader *rd, const uint8_t key[32]);

/* ==================== PathSet ==================== */

int tt_pathset_has(TtPathSet *s, const char *p)
{
    for (size_t i = 0; i < s->n; ++i)
        if (strcmp(s->v[i], p) == 0)
            return 1;
    return 0;
}

void tt_pathset_add(TtPathSet *s, const char *p)
{
    if (tt_pathset_has(s, p))
        return;
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 256;
        char **nv = realloc(s->v, ncap * sizeof(char *));
        if (!nv)
            return;
        s->v = nv;
        s->cap = ncap;
    }
    s->v[s->n] = strdup(p);
    if (s->v[s->n])
        s->n++;
}

void tt_pathset_free(TtPathSet *s)
{
    for (size_t i = 0; i < s->n; ++i)
        free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof *s);
}

/* ==================== Tags ==================== */

static void tt_tags_file_path(char *out, size_t n, const char *store_dir)
{
    snprintf(out, n, "%s/tags", store_dir);
}

int tt_tag_add(const char *store_dir, const char *name, uint64_t ts)
{
    char tf[TT_PATH_MAX + 64];
    tt_tags_file_path(tf, sizeof tf, store_dir);
    FILE *f = fopen(tf, "a");
    if (!f)
        return -1;
    fprintf(f, "%s\t%llu\n", name, (unsigned long long)ts);
    fclose(f);
    return 0;
}

int tt_tag_lookup(const char *store_dir, const char *name, uint64_t *out_ts)
{
    char tf[TT_PATH_MAX + 64];
    tt_tags_file_path(tf, sizeof tf, store_dir);
    FILE *f = fopen(tf, "r");
    if (!f)
        return -1;
    char line[TT_PATH_MAX + 64];
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        if (!tab)
            continue;
        *tab = '\0';
        if (strcmp(line, name) == 0) {
            *out_ts = strtoull(tab + 1, NULL, 10);
            found = 0;
        }
    }
    fclose(f);
    return found;
}

int tt_tag_list(const char *store_dir)
{
    char tf[TT_PATH_MAX + 64];
    tt_tags_file_path(tf, sizeof tf, store_dir);
    FILE *f = fopen(tf, "r");
    if (!f) {
        printf("No tags.\n");
        return 0;
    }
    char line[TT_PATH_MAX + 64];
    int any = 0;
    printf("Tags:\n");
    while (fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        if (!tab)
            continue;
        *tab = '\0';
        char *nl = strchr(tab + 1, '\n');
        if (nl)
            *nl = '\0';
        uint64_t ts = strtoull(tab + 1, NULL, 10);
        char tsbuf[64];
        format_timestamp(ts, tsbuf, sizeof tsbuf);
        printf("  %-20s  %s\n", line, tsbuf);
        any = 1;
    }
    fclose(f);
    if (!any)
        printf("  (none)\n");
    return 0;
}

/* ==================== History queries ==================== */

int tt_load_version_content(const char *store_dir, const char *rel_path,
                            uint64_t target_ns, uint8_t **out,
                            size_t *out_size, int *exists)
{
    return tt_reconstruct_file(store_dir, rel_path, target_ns, out, out_size, exists);
}

int tt_find_last_two_ts(const char *rel_path,
                        uint64_t *prev_ts, uint64_t *last_ts)
{
    *prev_ts = 0;
    *last_ts = 0;

    if (tt_store_reader_init() != 0)
        return -1;

    uint64_t a = 0, b = 0;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;
        if (strcmp(path, rel_path) == 0) {
            a = b;
            b = hdr.timestamp_ns;
        }
        free(pl);
    }

    tt_store_reader_free();

    if (b == 0)
        return -1;
    *prev_ts = a;
    *last_ts = b;
    return 0;
}

int tt_scan_timestamps(const char *rel, int prefix_mode,
                       uint64_t **out_ts, size_t *out_n)
{
    *out_ts = NULL;
    *out_n = 0;

    if (tt_store_reader_init() != 0)
        return -1;

    uint64_t *ts = NULL;
    size_t n = 0, cap = 0;
    size_t plen = rel ? strlen(rel) : 0;

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;

        int m = 0;
        if (!rel || !rel[0])
            m = 1;
        else if (strcmp(path, rel) == 0)
            m = 1;
        else if (prefix_mode && strncmp(path, rel, plen) == 0 && path[plen] == '/')
            m = 1;
        free(pl);

        if (!m)
            continue;

        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            uint64_t *nt = realloc(ts, cap * sizeof(uint64_t));
            if (!nt) {
                free(ts);
                tt_store_reader_free();
                return -1;
            }
            ts = nt;
        }
        ts[n++] = hdr.timestamp_ns;
    }

    tt_store_reader_free();

    /* insertion sort */
    if (n > 1) {
        for (size_t i = 1; i < n; ++i) {
            uint64_t k = ts[i];
            size_t j = i;
            while (j > 0 && ts[j - 1] > k) {
                ts[j] = ts[j - 1];
                j--;
            }
            ts[j] = k;
        }
    }

    *out_ts = ts;
    *out_n = n;
    return 0;
}

/* ==================== Target resolution ==================== */

int tt_resolve_file_target_ns(const char *store_dir, const char *rel,
                              const char *expr, uint64_t *out,
                              char *desc, size_t descsz)
{
    if (!expr || !expr[0]) {
        uint64_t prev = 0, last = 0;
        if (tt_find_last_two_ts(rel, &prev, &last) != 0)
            return -1;
        *out = prev ? prev : last;
        snprintf(desc, descsz, "%s", prev ? "previous" : "first");
        return 0;
    }

    if (!strcasecmp(expr, "now") || !strcasecmp(expr, "head") ||
        !strcasecmp(expr, "latest") || !strcasecmp(expr, "last")) {
        uint64_t prev = 0, last = 0;
        if (tt_find_last_two_ts(rel, &prev, &last) != 0)
            return -1;
        *out = last;
        snprintf(desc, descsz, "last");
        return 0;
    }

    if (!strcasecmp(expr, "prev") || !strcasecmp(expr, "previous")) {
        uint64_t prev = 0, last = 0;
        if (tt_find_last_two_ts(rel, &prev, &last) != 0)
            return -1;
        if (prev == 0) {
            *out = 0;
            snprintf(desc, descsz, "empty");
        } else {
            *out = prev;
            snprintf(desc, descsz, "previous");
        }
        return 0;
    }

    if (!strcasecmp(expr, "first") || !strcasecmp(expr, "initial")) {
        uint64_t *ts = NULL;
        size_t n = 0;
        if (tt_scan_timestamps(rel, 0, &ts, &n) != 0 || n == 0) {
            free(ts);
            return -1;
        }
        *out = ts[0];
        snprintf(desc, descsz, "first");
        free(ts);
        return 0;
    }

    if (!strncmp(expr, "tag:", 4)) {
        uint64_t ts = 0;
        if (tt_tag_lookup(store_dir, expr + 4, &ts) != 0)
            return -1;
        *out = ts;
        snprintf(desc, descsz, "tag:%s", expr + 4);
        return 0;
    }

    if (expr[0] == '@') {
        long long v = 0;
        if (!is_integer(expr + 1, &v))
            return -1;
        uint64_t ns = (v < 10000000000LL)
            ? (uint64_t)v * 1000000000ULL
            : (uint64_t)v;
        *out = ns;
        snprintf(desc, descsz, "timestamp");
        return 0;
    }

    long long rev = 0;
    if (is_integer(expr, &rev)) {
        uint64_t *ts = NULL;
        size_t n = 0;
        if (tt_scan_timestamps(rel, 0, &ts, &n) != 0 || n == 0) {
            free(ts);
            return -1;
        }
        if (rev == 0) {
            *out = 0;
            snprintf(desc, descsz, "empty");
        } else {
            long long idx = (rev > 0) ? rev - 1 : (long long)n + rev;
            if (idx < 0) {
                *out = 0;
                snprintf(desc, descsz, "empty");
            } else if ((size_t)idx >= n) {
                *out = ts[n - 1];
                snprintf(desc, descsz, "last");
            } else {
                *out = ts[idx];
                snprintf(desc, descsz, "revision %lld", rev);
            }
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

/* ==================== Store collection ==================== */

void tt_store_collect_paths_ctx(const char *store_dir, TtPathSet *out)
{
    memset(out, 0, sizeof *out);
    TtStoreReader *rd = tt_reader_open(store_dir);
    if (!rd)
        return;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_reader_next(rd, &hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;
        tt_pathset_add(out, path);
        free(pl);
    }
    tt_reader_close(rd);
}

void tt_store_collect_matching(TtPathSet *out, const char *rel)
{
    memset(out, 0, sizeof *out);
    if (tt_store_reader_init() != 0)
        return;
    size_t plen = rel ? strlen(rel) : 0;
    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;
        int m = 0;
        if (!rel || !rel[0])
            m = 1;
        else if (strcmp(path, rel) == 0)
            m = 1;
        else if (plen && strncmp(path, rel, plen) == 0 && path[plen] == '/')
            m = 1;
        if (m)
            tt_pathset_add(out, path);
        free(pl);
    }
    tt_store_reader_free();
}

/* ==================== Stats ==================== */

int tt_scan_stats_dir(const char *store_dir, const uint8_t *key,
                      uint64_t *nrecords, uint64_t *nbytes,
                      uint64_t *first_ts, uint64_t *last_ts)
{
    uint64_t n = 0, b = 0, fts = 0, lts = 0;

    TtStoreReader *rd = tt_reader_open(store_dir);
    if (!rd)
        return -1;
    if (key)
        tt_reader_set_key(rd, key);

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;
        int rc = tt_reader_next(rd, &hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;
        n++;
        b += sizeof(TtDeltaHeader) + hdr.path_len + hdr.delta_size;
        if (fts == 0 || hdr.timestamp_ns < fts)
            fts = hdr.timestamp_ns;
        if (hdr.timestamp_ns > lts)
            lts = hdr.timestamp_ns;
        free(pl);
    }

    tt_reader_close(rd);

    if (nrecords)
        *nrecords = n;
    if (nbytes)
        *nbytes = b;
    if (first_ts)
        *first_ts = fts;
    if (last_ts)
        *last_ts = lts;
    return 0;
}
