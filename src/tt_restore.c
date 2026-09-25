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
#include "tt_types.h"
#include "tt_dedup.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>

extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps, uint8_t **pl, size_t *plsz);
extern void tt_store_reader_free(void);

extern int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *delta_data, size_t delta_size,
                           size_t expected_new_size,
                           uint8_t **new_out, size_t *new_size_out);

extern const uint8_t *tt_store_compat_peek_key(void);

typedef struct {
    TtDeltaHeader hdr;
    char path[TT_PATH_MAX];
    uint8_t *payload;
    size_t payload_size;
} TtRestoreRecord;

typedef struct {
    TtRestoreRecord *records;
    size_t count, cap;
} TtRestoreList;

static int restore_list_push(TtRestoreList *l,
                             const TtDeltaHeader *hdr,
                             const char *path,
                             uint8_t *payload,
                             size_t payload_size)
{
    if (l->count == l->cap) {
        size_t n = l->cap ? l->cap * 2 : 32;

        TtRestoreRecord *nr = realloc(l->records, n * sizeof(TtRestoreRecord));
        if (!nr)
            return -1;

        l->records = nr;
        l->cap = n;
    }

    TtRestoreRecord *r = &l->records[l->count++];

    r->hdr = *hdr;
    snprintf(r->path, sizeof r->path, "%s", path);
    r->payload = payload;
    r->payload_size = payload_size;

    return 0;
}

static void restore_list_free(TtRestoreList *l)
{
    if (!l)
        return;

    for (size_t i = 0; i < l->count; ++i)
        free(l->records[i].payload);

    free(l->records);

    memset(l, 0, sizeof *l);
}

static int restore_record_cmp(const void *a, const void *b)
{
    const TtRestoreRecord *ra = a, *rb = b;

    if (ra->hdr.timestamp_ns < rb->hdr.timestamp_ns)
        return -1;

    if (ra->hdr.timestamp_ns > rb->hdr.timestamp_ns)
        return 1;

    return 0;
}

static int load_records(const char *filter_path, TtRestoreList *out)
{
    memset(out, 0, sizeof *out);

    if (tt_store_reader_init() != 0)
        return -1;

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
            restore_list_free(out);
            return -1;
        }

        if (filter_path && filter_path[0] && strcmp(path, filter_path) != 0) {
            free(pl);
            continue;
        }

        if (restore_list_push(out, &hdr, path, pl, plsz) != 0) {
            free(pl);
            tt_store_reader_free();
            restore_list_free(out);
            return -1;
        }
    }

    tt_store_reader_free();

    if (out->count > 1)
        qsort(out->records, out->count, sizeof(TtRestoreRecord), restore_record_cmp);

    return 0;
}

/* Reconstruye el contenido de un fichero hasta target_ns.
   store_dir se necesita para resolver los bloques de los registros DEDUP. */
static int reconstruct_file(const char *store_dir,
                            const TtRestoreRecord *records,
                            size_t count,
                            uint64_t target_ns,
                            uint8_t **out_data,
                            size_t *out_size,
                            int *out_exists)
{
    *out_data = NULL;
    *out_size = 0;
    *out_exists = 0;

    uint8_t *state = NULL;
    size_t state_size = 0;
    int have = 0;

    for (size_t i = 0; i < count; ++i) {
        const TtRestoreRecord *rec = &records[i];

        if (rec->hdr.timestamp_ns > target_ns)
            break;

        if (rec->hdr.event_type == TT_EV_DELETE) {
            free(state);
            state = NULL;
            state_size = 0;
            have = 0;
        } else if (rec->hdr.event_type == TT_EV_CREATE) {
            free(state);
            state = NULL;
            state_size = 0;

            size_t s = rec->payload_size;

            state = malloc(s ? s : 1);
            if (!state)
                return -1;

            if (s > 0 && rec->payload)
                memcpy(state, rec->payload, s);

            state_size = s;
            have = 1;
        } else if (rec->hdr.event_type == TT_EV_CREATE_DEDUP) {
            free(state);
            state = NULL;
            state_size = 0;

            const uint8_t *dk = tt_store_compat_peek_key();

            if (tt_dedup_reconstruct(store_dir, rec->payload, rec->payload_size,
                                     &state, &state_size, dk) != 0) {
                return -1;   /* bloque faltante o corrupto */
            }

            if ((uint64_t)state_size != rec->hdr.file_size) {
                free(state);
                return -1;
            }

            have = 1;
        } else if (rec->hdr.event_type == TT_EV_MODIFY) {
            if (!have)
                return -1;

            if (rec->hdr.delta_size == 0) {
                free(state);

                state = malloc(1);
                if (!state)
                    return -1;

                state_size = 0;
                continue;
            }

            if (!rec->payload)
                return -1;

            uint8_t *ns = NULL;
            size_t nss = 0;

            if (tt_delta_decode(state, state_size,
                                rec->payload, rec->payload_size,
                                rec->hdr.file_size,
                                &ns, &nss) != 0) {
                free(state);
                return -1;
            }

            free(state);
            state = ns;
            state_size = nss;
        }
    }

    if (!have) {
        free(state);
        return 0;
    }

    if (!state) {
        state = malloc(1);
        if (!state)
            return -1;
    }

    *out_exists = 1;
    *out_data = state;
    *out_size = state_size;

    return 0;
}


static int write_file_with_parents(const char *path, const uint8_t *data, size_t size)
{
    if (!path || !path[0])
        return -1;

    if (!data && size > 0)
        return -1;

    char tmp[TT_PATH_MAX];

    snprintf(tmp, sizeof tmp, "%s", path);

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }

    struct stat orig_st;
    int have_orig = (stat(path, &orig_st) == 0);

    char tmppath[TT_PATH_MAX + 64];

    snprintf(tmppath, sizeof tmppath, "%s.tt_tmp_%d", path, (int)getpid());

    int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0)
        return -1;

    size_t off = 0;

    while (off < size) {
        ssize_t w = write(fd, data + off, size - off);

        if (w < 0) {
            if (errno == EINTR)
                continue;

            close(fd);
            unlink(tmppath);
            return -1;
        }

        off += (size_t)w;
    }

    fsync(fd);
    close(fd);

    if (have_orig)
        chmod(tmppath, orig_st.st_mode & 07777);

    if (rename(tmppath, path) != 0) {
        unlink(tmppath);
        return -1;
    }

    return 0;
}

/* ============================================================
 * Baseline support for undo dir --initial
 * ============================================================ */

#define TT_BASELINE_FILE "baseline.list"

static int repo_root_from_store_dir(const char *store_dir, char *out, size_t outsz)
{
    if (!store_dir || !out || outsz == 0)
        return -1;

    snprintf(out, outsz, "%s", store_dir);

    size_t len = strlen(out);
    while (len > 0 && out[len - 1] == '/')
        out[--len] = '\0';

    if (strcmp(out, ".timetravel") == 0) {
        snprintf(out, outsz, ".");
        return 0;
    }

    char *slash = strrchr(out, '/');
    if (slash && strcmp(slash + 1, ".timetravel") == 0) {
        *slash = '\0';
        return 0;
    }

    return -1;
}

static void normalize_rel_prefix(const char *in, char *out, size_t outsz)
{
    if (!in || outsz == 0) {
        if (out)
            out[0] = '\0';
        return;
    }

    snprintf(out, outsz, "%s", in);

    char *p = out;

    while (*p == '/')
        p++;

    while (p[0] == '.' && p[1] == '/')
        p += 2;

    if (p != out)
        memmove(out, p, strlen(p) + 1);

    size_t len = strlen(out);
    while (len > 0 && out[len - 1] == '/')
        out[--len] = '\0';
}

static int same_dir_path(const char *a, const char *b)
{
    if (!a || !b)
        return 0;

    char *ra = realpath(a, NULL);
    char *rb = realpath(b, NULL);

    int eq = 0;

    if (ra && rb)
        eq = (strcmp(ra, rb) == 0);
    else
        eq = (strcmp(a, b) == 0);

    free(ra);
    free(rb);

    return eq;
}

static int is_tt_excluded_component(const char *name)
{
    static const char *excluded[] = {
        ".timetravel",
        ".git",
        "node_modules",
        "__pycache__",
        "target",
        ".cache",
        NULL
    };

    if (!name)
        return 1;

    if (strncmp(name, ".tt_tmp_", 8) == 0)
        return 1;

    for (int i = 0; excluded[i]; ++i) {
        if (strcmp(name, excluded[i]) == 0)
            return 1;
    }

    return 0;
}

static void baseline_path(const char *store_dir, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s/%s", store_dir, TT_BASELINE_FILE);
}

static int baseline_scan_dir(const char *root, const char *rel, FILE *f, size_t *written)
{
    char full[TT_PATH_MAX];

    if (rel && rel[0])
        snprintf(full, sizeof(full), "%s/%s", root, rel);
    else
        snprintf(full, sizeof(full), "%s", root);

    DIR *d = opendir(full);
    if (!d)
        return 0;

    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        if (is_tt_excluded_component(de->d_name))
            continue;

        char child_rel[TT_PATH_MAX];

        if (rel && rel[0])
            snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, de->d_name);
        else
            snprintf(child_rel, sizeof(child_rel), "%s", de->d_name);

        char child_full[TT_PATH_MAX];
        int sn = snprintf(child_full, sizeof(child_full), "%s/%s", root, child_rel);

        if (sn < 0 || (size_t)sn >= sizeof(child_full))
            continue;

        struct stat st;
        if (lstat(child_full, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            baseline_scan_dir(root, child_rel, f, written);
        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            fprintf(f, "%s\n", child_rel);
            (*written)++;
        }
    }

    closedir(d);
    return 0;
}

/*
 * Genera .timetravel/baseline.list si no existe.
 *
 * Debe llamarse al adoptar/arrancar un repo, no en cada comando CLI.
 * Si baseline.list ya existe, NO se sobreescribe, para conservar el
 * punto inicial original.
 */
int tt_generate_baseline_from_store_dir(const char *store_dir)
{
    char repo_root[TT_PATH_MAX];
    char bpath[TT_PATH_MAX];
    char tmp[TT_PATH_MAX + 64];

    if (!store_dir)
        return -1;

    if (repo_root_from_store_dir(store_dir, repo_root, sizeof(repo_root)) != 0)
        return -1;

    baseline_path(store_dir, bpath, sizeof(bpath));

    struct stat st;
    if (stat(bpath, &st) == 0)
        return 0;

    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", bpath, (int)getpid());

    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;

    size_t written = 0;
    baseline_scan_dir(repo_root, "", f, &written);

    if (fclose(f) != 0) {
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, bpath) != 0) {
        unlink(tmp);
        return -1;
    }

    fprintf(stderr, "tt_restore: baseline written (%zu files)\n", written);
    return 0;
}

static int baseline_entry_cmp(const void *a, const void *b)
{
    const char *sa = *(const char * const *)a;
    const char *sb = *(const char * const *)b;
    return strcmp(sa, sb);
}

static char **read_baseline(const char *store_dir, size_t *out_count)
{
    char bpath[TT_PATH_MAX];
    baseline_path(store_dir, bpath, sizeof(bpath));

    FILE *f = fopen(bpath, "r");
    if (!f) {
        *out_count = 0;
        return NULL;
    }

    char **paths = NULL;
    size_t count = 0, cap = 0;
    char line[TT_PATH_MAX];

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (len == 0)
            continue;

        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            char **np = realloc(paths, ncap * sizeof(char *));
            if (!np) {
                for (size_t i = 0; i < count; ++i)
                    free(paths[i]);
                free(paths);
                fclose(f);
                *out_count = 0;
                return NULL;
            }
            paths = np;
            cap = ncap;
        }

        paths[count] = strdup(line);
        if (!paths[count]) {
            for (size_t i = 0; i < count; ++i)
                free(paths[i]);
            free(paths);
            fclose(f);
            *out_count = 0;
            return NULL;
        }

        count++;
    }

    fclose(f);

    if (count == 0) {
        paths = calloc(1, sizeof(char *));
        if (!paths) {
            *out_count = 0;
            return NULL;
        }
    } else if (count > 1) {
        qsort(paths, count, sizeof(char *), baseline_entry_cmp);
    }

    *out_count = count;
    return paths;
}

static void free_baseline(char **baseline, size_t count)
{
    if (!baseline)
        return;

    for (size_t i = 0; i < count; ++i)
        free(baseline[i]);

    free(baseline);
}

static int baseline_contains(char **baseline, size_t count, const char *rel)
{
    if (!baseline || count == 0 || !rel)
        return 0;

    const char *key = rel;

    return bsearch(&key, baseline, count, sizeof(char *), baseline_entry_cmp) != NULL;
}

static int prune_files_recursive(const char *base,
                                 const char *rel,
                                 const char *prefix,
                                 char **baseline,
                                 size_t bl_count,
                                 int *deleted,
                                 int *errors)
{
    char full[TT_PATH_MAX];

    if (rel && rel[0])
        snprintf(full, sizeof(full), "%s/%s", base, rel);
    else
        snprintf(full, sizeof(full), "%s", base);

    DIR *d = opendir(full);
    if (!d)
        return 0;

    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        if (is_tt_excluded_component(de->d_name))
            continue;

        char child_rel[TT_PATH_MAX];

        if (rel && rel[0])
            snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, de->d_name);
        else
            snprintf(child_rel, sizeof(child_rel), "%s", de->d_name);

        char child_full[TT_PATH_MAX];
        int sn = snprintf(child_full, sizeof(child_full), "%s/%s", base, child_rel);

        if (sn < 0 || (size_t)sn >= sizeof(child_full))
            continue;

        struct stat st;
        if (lstat(child_full, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            prune_files_recursive(base, child_rel, prefix, baseline, bl_count, deleted, errors);

            /*
             * Borra directorios que hayan quedado vacíos.
             * Si no quieres tocar directorios, comenta esta línea.
             */
            rmdir(child_full);
        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            char full_rel[TT_PATH_MAX];

            if (prefix && prefix[0])
                snprintf(full_rel, sizeof(full_rel), "%s/%s", prefix, child_rel);
            else
                snprintf(full_rel, sizeof(full_rel), "%s", child_rel);

            if (!baseline_contains(baseline, bl_count, full_rel)) {
                if (unlink(child_full) == 0)
                    (*deleted)++;
                else
                    (*errors)++;
            }
        }
    }

    closedir(d);
    return 0;
}

static int prune_files_not_in_baseline(const char *target_root,
                                       const char *prefix,
                                       char **baseline,
                                       size_t bl_count,
                                       int *deleted,
                                       int *errors)
{
    *deleted = 0;
    *errors = 0;

    return prune_files_recursive(target_root, "", prefix, baseline, bl_count, deleted, errors);
}

int tt_restore_file(const char *store_dir,
                    const char *file_path,
                    uint64_t target_ns,
                    const char *out_path)
{
    TtRestoreList list;

    if (load_records(file_path, &list) != 0)
        return -1;

    if (list.count == 0) {
        restore_list_free(&list);
        return 1;
    }

    uint8_t *content = NULL;
    size_t csz = 0;
    int exists = 0;

    int rc = reconstruct_file(store_dir, list.records, list.count,
                              target_ns, &content, &csz, &exists);

    restore_list_free(&list);

    if (rc != 0)
        return -1;

    if (!exists)
        return 1;

    if (out_path && write_file_with_parents(out_path, content, csz) != 0) {
        free(content);
        return -1;
    }

    fprintf(stderr, "tt_restore: restored %s -> %s (%zu bytes)\n",
            file_path, out_path ? out_path : "(null)", csz);

    free(content);

    return 0;
}

int tt_restore_dir(const char *store_dir,
                   const char *dir_prefix,
                   uint64_t target_ns,
                   const char *out_dir)
{
    TtRestoreList all;

    if (load_records(NULL, &all) != 0)
        return -1;

    if (all.count == 0) {
        restore_list_free(&all);
        return 1;
    }

    if (mkdir(out_dir, 0755) != 0 && errno != EEXIST) {
        restore_list_free(&all);
        return -1;
    }

    size_t plen = (dir_prefix && dir_prefix[0]) ? strlen(dir_prefix) : 0;

    char **upaths = NULL;
    size_t ucount = 0, ucap = 0;

    for (size_t i = 0; i < all.count; ++i) {
        const char *p = all.records[i].path;

        if (plen > 0 &&
            (strncmp(p, dir_prefix, plen) != 0 ||
             (p[plen] != '/' && p[plen] != '\0'))) {
            continue;
        }

        int found = 0;

        for (size_t u = 0; u < ucount; ++u) {
            if (strcmp(upaths[u], p) == 0) {
                found = 1;
                break;
            }
        }

        if (found)
            continue;

        if (ucount == ucap) {
            ucap = ucap ? ucap * 2 : 32;

            char **nu = realloc(upaths, ucap * sizeof(char *));
            if (!nu)
                break;

            upaths = nu;
        }

        upaths[ucount] = strdup(p);
        if (!upaths[ucount])
            break;

        ucount++;
    }

    int restored = 0, errors = 0;

    for (size_t u = 0; u < ucount; ++u) {
        const char *fp = upaths[u];

        size_t fc = 0;

        for (size_t i = 0; i < all.count; ++i) {
            if (strcmp(all.records[i].path, fp) == 0)
                fc++;
        }

        if (fc == 0)
            continue;

        TtRestoreRecord *fr = calloc(fc, sizeof(TtRestoreRecord));
        if (!fr) {
            errors++;
            continue;
        }

        size_t fi = 0;

        for (size_t i = 0; i < all.count; ++i) {
            if (strcmp(all.records[i].path, fp) == 0)
                fr[fi++] = all.records[i];
        }

        uint8_t *content = NULL;
        size_t csz = 0;
        int exists = 0;

        int rc = reconstruct_file(store_dir, fr, fc, target_ns,
                                  &content, &csz, &exists);

        free(fr);

        if (rc != 0) {
            errors++;
            continue;
        }

        if (!exists)
            continue;

        const char *rel = fp;

        if (plen > 0 && strncmp(fp, dir_prefix, plen) == 0) {
            rel = fp + plen;

            while (*rel == '/')
                rel++;
        }

        char out_file[TT_PATH_MAX * 2];

        snprintf(out_file, sizeof out_file, "%s/%s", out_dir, rel);

        if (write_file_with_parents(out_file, content, csz) == 0) {
            restored++;
            fprintf(stderr, "tt_restore:   %s (%zu bytes)\n", rel, csz);
        } else {
            errors++;
        }

        free(content);
    }

    for (size_t u = 0; u < ucount; ++u)
        free(upaths[u]);

    free(upaths);

    restore_list_free(&all);

    fprintf(stderr, "tt_restore: %d file(s) restored in %s\n", restored, out_dir);

    return errors == 0 ? 0 : -1;
}

int tt_restore_dir_per_file(const char *store_dir,
                            const char *dir_prefix,
                            const char *out_dir,
                            int mode)
{
    TtRestoreList all;

    if (load_records(NULL, &all) != 0)
        return -1;

    if (all.count == 0) {
        restore_list_free(&all);
        return 1;
    }

    if (mkdir(out_dir, 0755) != 0 && errno != EEXIST) {
        restore_list_free(&all);
        return -1;
    }

    size_t plen = (dir_prefix && dir_prefix[0]) ? strlen(dir_prefix) : 0;

    char **upaths = NULL;
    size_t ucount = 0, ucap = 0;

    for (size_t i = 0; i < all.count; ++i) {
        const char *p = all.records[i].path;

        if (plen > 0 &&
            (strncmp(p, dir_prefix, plen) != 0 ||
             (p[plen] != '/' && p[plen] != '\0'))) {
            continue;
        }

        int found = 0;
        for (size_t u = 0; u < ucount; ++u) {
            if (strcmp(upaths[u], p) == 0) {
                found = 1;
                break;
            }
        }

        if (found)
            continue;

        if (ucount == ucap) {
            ucap = ucap ? ucap * 2 : 32;
            char **nu = realloc(upaths, ucap * sizeof(char *));
            if (!nu)
                break;
            upaths = nu;
        }

        upaths[ucount] = strdup(p);
        if (!upaths[ucount])
            break;

        ucount++;
    }

    char prefix_norm[TT_PATH_MAX];
    normalize_rel_prefix(dir_prefix, prefix_norm, sizeof(prefix_norm));

    char **baseline = NULL;
    size_t bl_count = 0;
    int baseline_active = 0;
    int initial_inplace = 0;

    /*
     * Para undo dir --initial in-place, activamos baseline.
     *
     * Solo borramos ficheros si out_dir coincide con el directorio real
     * del repo. Así no tocamos exports/dumps fuera del árbol de trabajo.
     */
    if (mode != 0) {
        char repo_root[TT_PATH_MAX];

        if (repo_root_from_store_dir(store_dir, repo_root, sizeof(repo_root)) == 0) {
            char expected_target[TT_PATH_MAX];

            if (prefix_norm[0])
                snprintf(expected_target, sizeof(expected_target), "%s/%s", repo_root, prefix_norm);
            else
                snprintf(expected_target, sizeof(expected_target), "%s", repo_root);

            if (same_dir_path(out_dir, expected_target)) {
                initial_inplace = 1;
                baseline = read_baseline(store_dir, &bl_count);

                if (baseline)
                    baseline_active = 1;
            }
        }
    }

    int restored = 0, errors = 0, skipped = 0;

    for (size_t u = 0; u < ucount; ++u) {
        const char *fp = upaths[u];

        /*
         * Si estamos en undo --initial in-place y el fichero no estaba
         * en el baseline, no lo restauramos: luego será borrado.
         */
        if (baseline_active && !baseline_contains(baseline, bl_count, fp))
            continue;

        size_t fc = 0;

        for (size_t i = 0; i < all.count; ++i) {
            if (strcmp(all.records[i].path, fp) == 0)
                fc++;
        }

        if (fc == 0)
            continue;

        if (mode == 0 && fc < 2) {
            skipped++;
            continue;
        }

        TtRestoreRecord *fr = calloc(fc, sizeof(TtRestoreRecord));
        if (!fr) {
            errors++;
            continue;
        }

        size_t fi = 0;

        for (size_t i = 0; i < all.count; ++i) {
            if (strcmp(all.records[i].path, fp) == 0)
                fr[fi++] = all.records[i];
        }

        uint64_t target_ns = fr[mode == 0 ? fc - 2 : 0].hdr.timestamp_ns;

        uint8_t *content = NULL;
        size_t csz = 0;
        int exists = 0;

        int rc = reconstruct_file(store_dir, fr, fc, target_ns,
                                  &content, &csz, &exists);

        free(fr);

        if (rc != 0) {
            errors++;
            continue;
        }

        if (!exists)
            continue;

        const char *rel = fp;

        if (plen > 0 && strncmp(fp, dir_prefix, plen) == 0) {
            rel = fp + plen;
            while (*rel == '/')
                rel++;
        }

        char out_file[TT_PATH_MAX * 2];
        snprintf(out_file, sizeof(out_file), "%s/%s", out_dir, rel);

        if (write_file_with_parents(out_file, content, csz) == 0) {
            restored++;
            fprintf(stderr, "tt_restore:   %s (%zu bytes)\n", rel, csz);
        } else {
            errors++;
        }

        free(content);
    }

    for (size_t u = 0; u < ucount; ++u)
        free(upaths[u]);

    free(upaths);

    int deleted_initial = 0;
    int prune_errors = 0;

    if (baseline_active) {
        prune_files_not_in_baseline(out_dir, prefix_norm, baseline, bl_count,
                                    &deleted_initial, &prune_errors);

        errors += prune_errors;
        free_baseline(baseline, bl_count);
    } else if (initial_inplace) {
        fprintf(stderr,
                "tt_restore: baseline.list not found; "
                "undo --initial will not delete files added after startup\n");
    }

    restore_list_free(&all);

    if (baseline_active) {
        fprintf(stderr,
                "tt_restore: %d file(s) restored in %s "
                "(%d without previous version), %d deleted to match initial state\n",
                restored, out_dir, skipped, deleted_initial);
    } else {
        fprintf(stderr,
                "tt_restore: %d file(s) restored in %s "
                "(%d without previous version)\n",
                restored, out_dir, skipped);
    }

    return errors == 0 ? 0 : -1;
}

int tt_list_history(const char *store_dir, const char *file_path)
{
    (void)store_dir;

    TtRestoreList list;

    if (load_records(file_path, &list) != 0)
        return -1;

    if (list.count == 0) {
        printf("No history%s%s\n",
               (file_path && file_path[0]) ? " for: " : "",
               (file_path && file_path[0]) ? file_path : "");

        restore_list_free(&list);

        return 0;
    }

    if (file_path && file_path[0]) {
        printf("History of: %s (%zu events)\n", file_path, list.count);
    } else {
        printf("Full history (%zu events)\n", list.count);
    }

    for (size_t i = 0; i < list.count; ++i) {
        const TtRestoreRecord *r = &list.records[i];

        time_t s = (time_t)(r->hdr.timestamp_ns / 1000000000ULL);
        struct tm t;
        char ts[64];

        if (localtime_r(&s, &t))
            strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &t);
        else
            snprintf(ts, sizeof ts, "%llu", (unsigned long long)r->hdr.timestamp_ns);

        const char *ev =
            r->hdr.event_type == TT_EV_CREATE ? "CREATE" :
            r->hdr.event_type == TT_EV_MODIFY ? "MODIFY" :
            r->hdr.event_type == TT_EV_DELETE ? "DELETE" :
            r->hdr.event_type == TT_EV_CREATE_DEDUP ? "CREATE_D" : "???";

        printf("  %-20s  %-8s  delta=%10u  file=%10llu  %s\n",
               ts, ev, r->hdr.delta_size,
               (unsigned long long)r->hdr.file_size,
               r->path);
    }

    restore_list_free(&list);

    return 0;
}
