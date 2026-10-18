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
   tt_dedup.c — dedup por bloques content-addressed

   Hash: BLAKE2b-256. Bloques de 64 KiB.
   Pool: <store>/blocks/<2hex>/<resto>.

   v1.4: si se pasa `key` (32 B), los bloques se cifran con
   XChaCha20-Poly1305 usando clave convergente por bloque.
============================================================ */

#include "tt_types.h"
#include "tt_dedup.h"
#include "tt_blake2b.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int tt_aead_encrypt(const uint8_t key[32],
                           const uint8_t nonce[24],
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *pt,
                           size_t pt_len,
                           uint8_t *ct,
                           uint8_t tag[16]);

extern int tt_aead_decrypt(const uint8_t key[32],
                           const uint8_t nonce[24],
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *ct,
                           size_t ct_len,
                           const uint8_t tag[16],
                           uint8_t *pt);

extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h,
                                char *p,
                                size_t ps,
                                uint8_t **pl,
                                size_t *plsz);
extern void tt_store_reader_free(void);

extern TtStoreReader *tt_reader_open(const char *store_dir);
extern int tt_reader_next(TtStoreReader *rd,
                          TtDeltaHeader *hdr,
                          char *path,
                          size_t path_size,
                          uint8_t **payload,
                          size_t *payload_size);
extern void tt_reader_close(TtStoreReader *rd);

/* ---------------- helpers ---------------- */

static void hash_to_hex(const uint8_t h[TT_DEDUP_HASH_LEN],
                        char out[2 * TT_DEDUP_HASH_LEN + 1])
{
    static const char *hx = "0123456789abcdef";

    for (int i = 0; i < TT_DEDUP_HASH_LEN; ++i) {
        out[i * 2]     = hx[h[i] >> 4];
        out[i * 2 + 1] = hx[h[i] & 0xF];
    }

    out[2 * TT_DEDUP_HASH_LEN] = '\0';
}

static int hex_to_hash(const char *hex, uint8_t out[TT_DEDUP_HASH_LEN])
{
    int want = 2 * TT_DEDUP_HASH_LEN;

    if (!hex || !out)
        return -1;

    if (strlen(hex) != (size_t)want)
        return -1;

    for (int i = 0; i < want; ++i) {
        char c = hex[i];
        int v;

        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;

        if (i % 2 == 0)
            out[i / 2] = (uint8_t)(v << 4);
        else
            out[i / 2] |= (uint8_t)v;
    }

    return 0;
}

static void block_path(const char *store_dir,
                       const char *hex,
                       char *out,
                       size_t outsz)
{
    snprintf(out, outsz, "%s/blocks/%.2s/%s", store_dir, hex, hex + 2);
}

static void block_dir_for(const char *store_dir,
                          const char *hex,
                          char *out,
                          size_t outsz)
{
    snprintf(out, outsz, "%s/blocks/%.2s", store_dir, hex);
}

static int mkdir_p_local(const char *path)
{
    char tmp[TT_PATH_MAX + 64];

    int n = snprintf(tmp, sizeof tmp, "%s", path);
    if (n < 0 || (size_t)n >= sizeof tmp)
        return -1;

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }

    if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
        return -1;

    return 0;
}

/* clave convergente por bloque = BLAKE2b(repo_key || hash_bloque) */
static int derive_block_key(const uint8_t *repo_key,
                            const uint8_t block_hash[TT_DEDUP_HASH_LEN],
                            uint8_t out[TT_DEDUP_HASH_LEN])
{
    uint8_t buf[2 * TT_DEDUP_HASH_LEN];

    if (!repo_key || !block_hash || !out)
        return -1;

    memcpy(buf, repo_key, TT_DEDUP_HASH_LEN);
    memcpy(buf + TT_DEDUP_HASH_LEN, block_hash, TT_DEDUP_HASH_LEN);

    return tt_blake2b(buf, sizeof buf, out, TT_DEDUP_HASH_LEN);
}

/* ---------------- escribir / leer un bloque ---------------- */

int tt_dedup_store_block(const char *store_dir,
                         const uint8_t *data,
                         size_t size,
                         uint8_t hash_out[TT_DEDUP_HASH_LEN],
                         const uint8_t *key)
{
    if (!store_dir || !store_dir[0] || !hash_out)
        return -1;

    if (!data && size > 0)
        return -1;

    if (size > SIZE_MAX - 16)
        return -1;

    const uint8_t *p = data ? data : (const uint8_t *)"";

    if (tt_blake2b(p, size, hash_out, TT_DEDUP_HASH_LEN) != 0)
        return -1;

    char hex[2 * TT_DEDUP_HASH_LEN + 1];
    hash_to_hex(hash_out, hex);

    char path[TT_PATH_MAX + 96];
    block_path(store_dir, hex, path, sizeof path);

    struct stat st;
    if (stat(path, &st) == 0)
        return 0; /* ya existe: dedup */

    char dir[TT_PATH_MAX + 64];
    block_dir_for(store_dir, hex, dir, sizeof dir);

    if (mkdir_p_local(dir) != 0)
        return -1;

    const uint8_t *to_write = p;
    size_t write_size = size;
    uint8_t *enc_buf = NULL;

    if (key) {
        uint8_t bkey[TT_DEDUP_HASH_LEN];

        if (derive_block_key(key, hash_out, bkey) != 0)
            return -1;

        enc_buf = malloc(size + 16);
        if (!enc_buf)
            return -1;

        uint8_t nonce[24];
        memset(nonce, 0, sizeof nonce); /* fijo: clave única por bloque */

        if (tt_aead_encrypt(bkey, nonce, NULL, 0,
                            p, size,
                            enc_buf, enc_buf + size) != 0) {
            free(enc_buf);
            return -1;
        }

        to_write = enc_buf;
        write_size = size + 16;
    }

    char tmpp[TT_PATH_MAX + 128];
    snprintf(tmpp, sizeof tmpp, "%s.tmp", path);

    int fd = open(tmpp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        free(enc_buf);
        return -1;
    }

    size_t off = 0;

    while (off < write_size) {
        ssize_t w = write(fd, to_write + off, write_size - off);

        if (w < 0) {
            if (errno == EINTR)
                continue;

            close(fd);
            unlink(tmpp);
            free(enc_buf);
            return -1;
        }

        off += (size_t)w;
    }

    close(fd);

    if (rename(tmpp, path) != 0) {
        unlink(tmpp);
        free(enc_buf);
        return -1;
    }

    free(enc_buf);
    return 0;
}

uint8_t *tt_dedup_get_block(const char *store_dir,
                            const uint8_t *hash,
                            size_t *out_size,
                            const uint8_t *key)
{
    if (out_size)
        *out_size = 0;

    if (!store_dir || !store_dir[0] || !hash)
        return NULL;

    char hex[2 * TT_DEDUP_HASH_LEN + 1];
    hash_to_hex(hash, hex);

    char path[TT_PATH_MAX + 96];
    block_path(store_dir, hex, path, sizeof path);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return NULL;
    }

    size_t sz = (size_t)st.st_size;

    uint8_t *buf = malloc(sz ? sz : 1);
    if (!buf) {
        close(fd);
        return NULL;
    }

    size_t off = 0;

    while (off < sz) {
        ssize_t r = read(fd, buf + off, sz - off);

        if (r < 0) {
            if (errno == EINTR)
                continue;

            free(buf);
            close(fd);
            return NULL;
        }

        if (r == 0)
            break;

        off += (size_t)r;
    }

    close(fd);

    if (!key) {
        if (out_size)
            *out_size = off;

        return buf;
    }

    if (off < 16) {
        free(buf);
        return NULL;
    }

    size_t ct_len = off - 16;

    uint8_t bkey[TT_DEDUP_HASH_LEN];

    if (derive_block_key(key, hash, bkey) != 0) {
        free(buf);
        return NULL;
    }

    uint8_t nonce[24];
    memset(nonce, 0, sizeof nonce);

    uint8_t *pt = malloc(ct_len ? ct_len : 1);
    if (!pt) {
        free(buf);
        return NULL;
    }

    if (tt_aead_decrypt(bkey, nonce, NULL, 0,
                        buf, ct_len,
                        buf + ct_len,
                        pt) != 0) {
        free(buf);
        free(pt);
        return NULL;
    }

    free(buf);

    if (out_size)
        *out_size = ct_len;

    return pt;
}

/* ---------------- partir / reensamblar ---------------- */

int tt_dedup_split(const char *store_dir,
                   const uint8_t *data,
                   size_t size,
                   uint8_t **hashes_out,
                   size_t *nblocks_out,
                   const uint8_t *key)
{
    if (!hashes_out || !nblocks_out)
        return -1;

    *hashes_out = NULL;
    *nblocks_out = 0;

    if (!store_dir || !store_dir[0])
        return -1;

    if (size == 0)
        return 0;

    if (!data)
        return -1;

    size_t block_size = (size_t)TT_DEDUP_BLOCK_SIZE;

    if (size > SIZE_MAX - block_size)
        return -1;

    size_t nb = (size + block_size - 1) / block_size;
    if (nb == 0)
        nb = 1;

    if (nb > SIZE_MAX / (size_t)TT_DEDUP_HASH_LEN)
        return -1;

    uint8_t *hashes = malloc(nb * (size_t)TT_DEDUP_HASH_LEN);
    if (!hashes)
        return -1;

    for (size_t i = 0; i < nb; ++i) {
        size_t off = i * block_size;
        size_t bsz = (off + block_size <= size) ? block_size : size - off;

        uint8_t h[TT_DEDUP_HASH_LEN];

        if (tt_dedup_store_block(store_dir, data + off, bsz, h, key) != 0) {
            free(hashes);
            return -1;
        }

        memcpy(hashes + i * TT_DEDUP_HASH_LEN, h, TT_DEDUP_HASH_LEN);
    }

    *hashes_out = hashes;
    *nblocks_out = nb;

    return 0;
}

int tt_dedup_reconstruct(const char *store_dir,
                         const uint8_t *payload,
                         size_t payload_size,
                         uint8_t **out,
                         size_t *out_size,
                         const uint8_t *key)
{
    if (out)
        *out = NULL;

    if (out_size)
        *out_size = 0;

    if (!store_dir || !store_dir[0] || !out || !out_size)
        return -1;

    if (payload_size == 0) {
        uint8_t *buf = malloc(1);
        if (!buf)
            return -1;

        *out = buf;
        *out_size = 0;
        return 0;
    }

    if (!payload || (payload_size % (size_t)TT_DEDUP_HASH_LEN) != 0)
        return -1;

    size_t nb = payload_size / (size_t)TT_DEDUP_HASH_LEN;
    size_t block_size = (size_t)TT_DEDUP_BLOCK_SIZE;

    if (nb > SIZE_MAX / block_size)
        return -1;

    size_t cap = nb * block_size;

    uint8_t *buf = malloc(cap ? cap : 1);
    if (!buf)
        return -1;

    size_t off = 0;

    for (size_t i = 0; i < nb; ++i) {
        size_t bsz = 0;

        uint8_t *blk = tt_dedup_get_block(store_dir,
                                          payload + i * TT_DEDUP_HASH_LEN,
                                          &bsz,
                                          key);

        if (!blk) {
            free(buf);
            return -1;
        }

        /* Un bloque dedup nunca debería ser mayor que 64 KiB */
        if (bsz > block_size) {
            free(blk);
            free(buf);
            return -1;
        }

        if (off > SIZE_MAX - bsz) {
            free(blk);
            free(buf);
            return -1;
        }

        if (off > cap || bsz > cap - off) {
            size_t ncap = off + bsz;

            uint8_t *nb2 = realloc(buf, ncap ? ncap : 1);
            if (!nb2) {
                free(blk);
                free(buf);
                return -1;
            }

            buf = nb2;
            cap = ncap;
        }

        if (bsz > 0)
            memcpy(buf + off, blk, bsz);

        off += bsz;
        free(blk);
    }

    *out = buf;
    *out_size = off;

    return 0;
}

/* ---------------- GC: borrar bloques huérfanos ---------------- */
/* HARDENED-GC-V3 */
extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps, uint8_t **pl, size_t *plsz);
extern void tt_store_reader_free(void);

typedef struct {
    uint8_t (*v)[TT_DEDUP_HASH_LEN];
    size_t n, cap;
} TtGcHashVec;

static int gc_hashvec_push(TtGcHashVec *s, const uint8_t h[TT_DEDUP_HASH_LEN]) {
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 64;

        if (ncap > SIZE_MAX / sizeof(*s->v))
            return -1;

        uint8_t (*nv)[TT_DEDUP_HASH_LEN] = realloc(s->v, ncap * sizeof(*nv));
        if (!nv)
            return -1;

        s->v = nv;
        s->cap = ncap;
    }

    memcpy(s->v[s->n], h, TT_DEDUP_HASH_LEN);
    s->n++;

    return 0;
}

static int gc_hashvec_cmp(const void *a, const void *b) {
    return memcmp(a, b, TT_DEDUP_HASH_LEN);
}

static void gc_hashvec_sort_unique(TtGcHashVec *s) {
    if (s->n < 2)
        return;

    qsort(s->v, s->n, sizeof(*s->v), gc_hashvec_cmp);

    size_t w = 1;

    for (size_t i = 1; i < s->n; ++i) {
        if (memcmp(s->v[i], s->v[w - 1], TT_DEDUP_HASH_LEN) != 0) {
            if (w != i)
                memcpy(s->v[w], s->v[i], TT_DEDUP_HASH_LEN);
            w++;
        }
    }

    s->n = w;
}

static int gc_hashvec_contains(const TtGcHashVec *s, const uint8_t h[TT_DEDUP_HASH_LEN]) {
    if (s->n == 0)
        return 0;

    return bsearch(h, s->v, s->n, sizeof(*s->v), gc_hashvec_cmp) != NULL;
}

int tt_dedup_gc(const char *store_dir) {
    if (!store_dir || !store_dir[0])
        return 0;

    TtGcHashVec ref;
    memset(&ref, 0, sizeof ref);

    /*
     * Fail-closed: si no podemos leer el historial, no borramos nada.
     */
    if (tt_store_reader_init() != 0) {
        free(ref.v);
        return 0;
    }

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);

        if (rc == 0)
            break;

        if (rc < 0) {
            free(pl);
            tt_store_reader_free();
            free(ref.v);
            return 0;
        }

        if (hdr.event_type == TT_EV_CREATE_DEDUP && plsz > 0) {
            if (!pl ||
                plsz < TT_DEDUP_HASH_LEN ||
                (plsz % TT_DEDUP_HASH_LEN) != 0) {
                free(pl);
                tt_store_reader_free();
                free(ref.v);
                return 0;
            }

            size_t nb = plsz / TT_DEDUP_HASH_LEN;

            for (size_t i = 0; i < nb; ++i) {
                if (gc_hashvec_push(&ref, pl + i * TT_DEDUP_HASH_LEN) != 0) {
                    free(pl);
                    tt_store_reader_free();
                    free(ref.v);
                    return 0;
                }
            }
        }

        free(pl);
    }

    tt_store_reader_free();

    gc_hashvec_sort_unique(&ref);

    int deleted = 0;

    char bdir[TT_PATH_MAX + 64];
    snprintf(bdir, sizeof bdir, "%s/blocks", store_dir);

    DIR *d1 = opendir(bdir);
    if (!d1) {
        free(ref.v);
        return 0;
    }

    struct dirent *e1;

    while ((e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.')
            continue;

        char sub[TT_PATH_MAX + 512];
        snprintf(sub, sizeof sub, "%s/%s", bdir, e1->d_name);

        struct stat st;

        /* Basura directa dentro de blocks/ */
        if (lstat(sub, &st) == 0 && !S_ISDIR(st.st_mode)) {
            if (unlink(sub) == 0)
                deleted++;
            continue;
        }

        DIR *d2 = opendir(sub);
        if (!d2)
            continue;

        struct dirent *e2;

        while ((e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.')
                continue;

            char fp[TT_PATH_MAX + 1024];
            snprintf(fp, sizeof fp, "%s/%s", sub, e2->d_name);

            struct stat st2;

            if (lstat(fp, &st2) == 0 && S_ISDIR(st2.st_mode))
                continue;

            int keep = 0;

            size_t dlen = strlen(e1->d_name);
            size_t flen = strlen(e2->d_name);

            if (dlen == 2 && flen == (size_t)(2 * TT_DEDUP_HASH_LEN - 2)) {
                char hex[2 * TT_DEDUP_HASH_LEN + 1];

                int hlen = snprintf(hex, sizeof hex, "%s%s",
                                    e1->d_name, e2->d_name);

                if (hlen == (int)(2 * TT_DEDUP_HASH_LEN)) {
                    uint8_t h[TT_DEDUP_HASH_LEN];

                    if (hex_to_hash(hex, h) == 0 &&
                        gc_hashvec_contains(&ref, h)) {
                        keep = 1;
                    }
                }
            }

            if (!keep) {
                if (unlink(fp) == 0)
                    deleted++;
            }
        }

        closedir(d2);
        rmdir(sub);
    }

    closedir(d1);
    free(ref.v);

    return deleted;
}
