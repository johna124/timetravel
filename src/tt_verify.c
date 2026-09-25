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
tt_verify.c — verificación de integridad del store

Recorre TODOS los registros y valida:

CREATE       : payload_size coincide con file_size
CREATE_DEDUP : cada bloque referenciado existe, su tamaño cuadra
               y su re-hash BLAKE2b-256 coincide
MODIFY       : el delta decodifica contra el estado reconstruido
Cadena       : todo MODIFY tiene una base válida

Además verifica explícitamente el magic de todos los .ttd ANTES
de leer records, porque el reader puede skippear archivos con
magic corrupto y verify debe detectarlos.

Solo lectura: NUNCA escribe en el store.
============================================================ */

#include "tt_types.h"
#include "tt_dedup.h"
#include "tt_blake2b.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef TT_STORE_MAGIC
#define TT_STORE_MAGIC "TTDLTA01"
#endif

#ifndef TT_STORE_MAGIC_LEN
#define TT_STORE_MAGIC_LEN 8
#endif

extern const uint8_t *tt_store_compat_get_key(void);

extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps,
                                uint8_t **pl, size_t *plsz);
extern void tt_store_reader_free(void);

extern int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *delta_data, size_t delta_size,
                           size_t expected_new_size,
                           uint8_t **new_out, size_t *new_size_out);

typedef struct {
    TtDeltaHeader hdr;
    char path[TT_PATH_MAX];
    uint8_t *payload;
    size_t payload_size;
} TtVerifyRecord;

typedef struct {
    TtVerifyRecord *records;
    size_t count, cap;
} TtVerifyList;

/* ============================================================
 * Helpers: lista de records
 * ============================================================ */

static int verify_list_push(TtVerifyList *l,
                            const TtDeltaHeader *hdr,
                            const char *path,
                            uint8_t *payload,
                            size_t payload_size)
{
    if (l->count == l->cap) {
        size_t n = l->cap ? l->cap * 2 : 32;
        TtVerifyRecord *nr = realloc(l->records, n * sizeof(TtVerifyRecord));
        if (!nr)
            return -1;

        l->records = nr;
        l->cap = n;
    }

    TtVerifyRecord *r = &l->records[l->count++];
    r->hdr = *hdr;
    snprintf(r->path, sizeof(r->path), "%s", path);
    r->payload = payload;
    r->payload_size = payload_size;

    return 0;
}

static void verify_list_free(TtVerifyList *l)
{
    if (!l)
        return;

    for (size_t i = 0; i < l->count; ++i)
        free(l->records[i].payload);

    free(l->records);
    memset(l, 0, sizeof(*l));
}

static int verify_record_cmp(const void *a, const void *b)
{
    const TtVerifyRecord *ra = a;
    const TtVerifyRecord *rb = b;

    int c = strcmp(ra->path, rb->path);
    if (c != 0)
        return c;

    if (ra->hdr.timestamp_ns < rb->hdr.timestamp_ns)
        return -1;
    if (ra->hdr.timestamp_ns > rb->hdr.timestamp_ns)
        return 1;

    return 0;
}

/* ============================================================
 * Verificación de magic de archivos .ttd
 *
 * El reader puede ignorar archivos con magic inválido, así que
 * verify debe detectarlos explícitamente.
 * ============================================================ */

static int scan_bad_magic_in_dir(const char *dir, uint64_t *bad)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;

    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);

        if (len <= 4 || strcmp(de->d_name + len - 4, ".ttd") != 0)
            continue;

        char p[TT_PATH_MAX * 2];
        int sn = snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);

        if (sn < 0 || (size_t)sn >= sizeof(p))
            continue;

        struct stat st;
        if (stat(p, &st) != 0)
            continue;

        if (!S_ISREG(st.st_mode))
            continue;

        int fd = open(p, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "verify: CORRUPT file %s (cannot open)\n", p);
            (*bad)++;
            continue;
        }

        uint8_t hdr[TT_STORE_MAGIC_LEN + 4];
        ssize_t rd = read(fd, hdr, sizeof(hdr));
        close(fd);

        if (rd < (ssize_t)sizeof(hdr) ||
            memcmp(hdr, TT_STORE_MAGIC, TT_STORE_MAGIC_LEN) != 0) {
            fprintf(stderr, "verify: CORRUPT file %s (invalid magic)\n", p);
            (*bad)++;
        }
    }

    closedir(d);
    return 0;
}

static int verify_store_magic(const char *store_dir, uint64_t *bad)
{
    *bad = 0;

    if (!store_dir)
        return -1;

    /*
     * Escanea el directorio dado y también una posible carpeta
     * .timetravel, por si el caller pasa el repo completo.
     */
    scan_bad_magic_in_dir(store_dir, bad);

    char sub[TT_PATH_MAX * 2];
    int sn = snprintf(sub, sizeof(sub), "%s/.timetravel", store_dir);

    if (sn > 0 && (size_t)sn < sizeof(sub)) {
        struct stat st;
        if (stat(sub, &st) == 0 && S_ISDIR(st.st_mode)) {
            scan_bad_magic_in_dir(sub, bad);
        }
    }

    return 0;
}

/* ============================================================
 * Verificación / reconstrucción de CREATE_DEDUP
 * ============================================================ */

static int dedup_verify_and_build(const char *store_dir,
                                  const uint8_t *refs,
                                  size_t refs_size,
                                  uint64_t file_size,
                                  uint8_t **out,
                                  size_t *out_size)
{
    *out = NULL;
    *out_size = 0;

    if (refs_size % TT_DEDUP_HASH_LEN != 0)
        return -1;

    if (file_size > (uint64_t)SIZE_MAX)
        return -1;

    size_t fsz = (size_t)file_size;
    size_t nb = refs_size / TT_DEDUP_HASH_LEN;

    uint8_t *buf = NULL;

    if (fsz > 0) {
        buf = malloc(fsz);
        if (!buf)
            return -1;
    }

    size_t off = 0;

    for (size_t i = 0; i < nb; ++i) {
        const uint8_t *hash = refs + i * TT_DEDUP_HASH_LEN;

        size_t expect = TT_DEDUP_BLOCK_SIZE;
        if (off + expect > fsz)
            expect = fsz - off;

        size_t bsz = 0;
        uint8_t *blk = tt_dedup_get_block(store_dir, hash, &bsz,
                                          tt_store_compat_get_key());

        if (!blk) {
            free(buf);
            return -1;
        }

        if (bsz != expect) {
            free(blk);
            free(buf);
            return -1;
        }

        uint8_t rehash[TT_DEDUP_HASH_LEN];

        if (tt_blake2b(blk, bsz, rehash, TT_DEDUP_HASH_LEN) != 0) {
            free(blk);
            free(buf);
            return -1;
        }

        if (memcmp(rehash, hash, TT_DEDUP_HASH_LEN) != 0) {
            free(blk);
            free(buf);
            return -1;
        }

        if (buf)
            memcpy(buf + off, blk, bsz);

        off += bsz;
        free(blk);
    }

    if (off != fsz) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_size = off;

    return 0;
}

/* ============================================================
 * tt_verify_store
 * ============================================================ */

int tt_verify_store(const char *store_dir,
                    uint64_t *n_records,
                    uint64_t *n_paths,
                    uint64_t *n_corrupt_records,
                    uint64_t *n_corrupt_paths)
{
    if (n_records)
        *n_records = 0;
    if (n_paths)
        *n_paths = 0;
    if (n_corrupt_records)
        *n_corrupt_records = 0;
    if (n_corrupt_paths)
        *n_corrupt_paths = 0;

    if (!store_dir)
        return -1;

    /*
     * FIX 36.2:
     * Verificar magic de todos los .ttd ANTES de leer records.
     */
    uint64_t corrupt_magic_files = 0;

    if (verify_store_magic(store_dir, &corrupt_magic_files) != 0)
        return -1;

    if (tt_store_reader_init() != 0) {
        if (corrupt_magic_files > 0) {
            if (n_paths)
                *n_paths = corrupt_magic_files;
            if (n_corrupt_records)
                *n_corrupt_records = corrupt_magic_files;
            if (n_corrupt_paths)
                *n_corrupt_paths = corrupt_magic_files;
            return -1;
        }
        return -1;
    }

    TtVerifyList list;
    memset(&list, 0, sizeof(list));

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, path, sizeof(path), &pl, &plsz);

        if (rc == 0)
            break;

        if (rc < 0) {
            tt_store_reader_free();
            verify_list_free(&list);

            if (corrupt_magic_files > 0) {
                if (n_paths)
                    *n_paths = corrupt_magic_files;
                if (n_corrupt_records)
                    *n_corrupt_records = corrupt_magic_files;
                if (n_corrupt_paths)
                    *n_corrupt_paths = corrupt_magic_files;
            }

            return -1;
        }

        if (verify_list_push(&list, &hdr, path, pl, plsz) != 0) {
            free(pl);
            tt_store_reader_free();
            verify_list_free(&list);
            return -1;
        }
    }

    tt_store_reader_free();

    uint64_t total_records = list.count;

    if (list.count == 0) {
        verify_list_free(&list);

        if (n_records)
            *n_records = 0;
        if (n_paths)
            *n_paths = corrupt_magic_files;
        if (n_corrupt_records)
            *n_corrupt_records = corrupt_magic_files;
        if (n_corrupt_paths)
            *n_corrupt_paths = corrupt_magic_files;

        return corrupt_magic_files ? -1 : 0;
    }

    qsort(list.records, list.count, sizeof(TtVerifyRecord), verify_record_cmp);

    uint64_t paths = 0;
    uint64_t corrupt_records = 0;
    uint64_t corrupt_paths = 0;

    size_t i = 0;

    while (i < list.count) {
        const char *cur = list.records[i].path;

        paths++;

        uint8_t *state = NULL;
        size_t state_size = 0;

        int have = 0;
        int path_corrupt = 0;
        int chain_broken = 0;

        size_t j = i;

        while (j < list.count && strcmp(list.records[j].path, cur) == 0) {
            const TtVerifyRecord *rec = &list.records[j];

            if (!chain_broken) {
                if (rec->hdr.event_type == TT_EV_CREATE) {
                    if (rec->payload_size != (size_t)rec->hdr.file_size) {
                        fprintf(stderr,
                                "verify: CORRUPT CREATE %s @ %llu "
                                "(payload %zu != file_size %llu)\n",
                                cur,
                                (unsigned long long)rec->hdr.timestamp_ns,
                                rec->payload_size,
                                (unsigned long long)rec->hdr.file_size);

                        corrupt_records++;
                        path_corrupt = 1;
                        chain_broken = 1;
                    } else {
                        free(state);
                        state = NULL;
                        state_size = 0;

                        if (rec->payload_size > 0 && rec->payload) {
                            state = malloc(rec->payload_size);
                            if (!state) {
                                verify_list_free(&list);
                                return -1;
                            }

                            memcpy(state, rec->payload, rec->payload_size);
                            state_size = rec->payload_size;
                        }

                        have = 1;
                    }

                } else if (rec->hdr.event_type == TT_EV_CREATE_DEDUP) {
                    uint8_t *content = NULL;
                    size_t csz = 0;

                    if (dedup_verify_and_build(store_dir,
                                               rec->payload,
                                               rec->payload_size,
                                               rec->hdr.file_size,
                                               &content,
                                               &csz) != 0) {
                        fprintf(stderr,
                                "verify: CORRUPT CREATE_DEDUP %s @ %llu "
                                "(bloque ausente/corrupto)\n",
                                cur,
                                (unsigned long long)rec->hdr.timestamp_ns);

                        corrupt_records++;
                        path_corrupt = 1;
                        chain_broken = 1;
                    } else {
                        free(state);
                        state = content;
                        state_size = csz;
                        have = 1;
                    }

                } else if (rec->hdr.event_type == TT_EV_MODIFY) {
                    if (!have) {
                        fprintf(stderr,
                                "verify: CORRUPT MODIFY %s @ %llu "
                                "(no base version)\n",
                                cur,
                                (unsigned long long)rec->hdr.timestamp_ns);

                        corrupt_records++;
                        path_corrupt = 1;
                        chain_broken = 1;

                    } else if (rec->hdr.delta_size == 0) {
                        free(state);
                        state = NULL;
                        state_size = 0;

                    } else {
                        uint8_t *ns = NULL;
                        size_t nss = 0;

                        if (tt_delta_decode(state,
                                            state_size,
                                            rec->payload,
                                            rec->payload_size,
                                            (size_t)rec->hdr.file_size,
                                            &ns,
                                            &nss) != 0) {
                            fprintf(stderr,
                                    "verify: CORRUPT MODIFY %s @ %llu "
                                    "(delta decode failed)\n",
                                    cur,
                                    (unsigned long long)rec->hdr.timestamp_ns);

                            corrupt_records++;
                            path_corrupt = 1;
                            chain_broken = 1;

                        } else if (ns == NULL && nss != 0) {
                            fprintf(stderr,
                                    "verify: CORRUPT MODIFY %s @ %llu "
                                    "(delta decode returned NULL)\n",
                                    cur,
                                    (unsigned long long)rec->hdr.timestamp_ns);

                            corrupt_records++;
                            path_corrupt = 1;
                            chain_broken = 1;

                        } else if (nss != (size_t)rec->hdr.file_size) {
                            fprintf(stderr,
                                    "verify: CORRUPT MODIFY %s @ %llu "
                                    "(decoded size %zu != file_size %llu)\n",
                                    cur,
                                    (unsigned long long)rec->hdr.timestamp_ns,
                                    nss,
                                    (unsigned long long)rec->hdr.file_size);

                            free(ns);
                            corrupt_records++;
                            path_corrupt = 1;
                            chain_broken = 1;

                        } else {
                            free(state);
                            state = ns;
                            state_size = nss;
                        }
                    }

                } else if (rec->hdr.event_type == TT_EV_DELETE) {
                    free(state);
                    state = NULL;
                    state_size = 0;
                    have = 0;
                }
            }

            j++;
        }

        free(state);

        if (path_corrupt)
            corrupt_paths++;

        i = j;
    }

    verify_list_free(&list);

    uint64_t total_corrupt_records = corrupt_records + corrupt_magic_files;
    uint64_t total_corrupt_paths = corrupt_paths + corrupt_magic_files;

    if (n_records)
        *n_records = total_records;

    if (n_paths)
        *n_paths = paths + corrupt_magic_files;

    if (n_corrupt_records)
        *n_corrupt_records = total_corrupt_records;

    if (n_corrupt_paths)
        *n_corrupt_paths = total_corrupt_paths;

    if (total_corrupt_records > 0 || total_corrupt_paths > 0)
        return -1;

    return 0;
}
