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
#include "tt_crypto.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define TT_STORE_MAX_FILE_SIZE (64ULL * 1024ULL * 1024ULL)
#define TT_STORE_MAGIC         "TTDLTA01"
#define TT_STORE_MAGIC_LEN     8
#define TT_STORE_VERSION       1u

/* overhead por registro cifrado: nonce(24) + tag(16) */
#define TT_CRYPTO_OVERHEAD     (TT_NONCE_LEN + TT_TAG_LEN)

/* ============ escritor por contexto (1 por repo) ============ */

struct TtStore {
    char     store_dir[TT_PATH_MAX];
    int      current_fd;
    uint64_t current_size;
    int      encrypted;
    int      key_set;
    uint8_t  crypto_key[TT_KEY_LEN];
};

static int write_all(int fd, const void *data, size_t n)
{
    const uint8_t *p = data;

    while (n > 0) {
        ssize_t w = write(fd, p, n);

        if (w < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        p += w;
        n -= (size_t)w;
    }

    return 0;
}

/* AAD: cabecera serializada + path. Autentica metadatos y ruta,
   impidiendo intercambiar ciphertexts entre registros. */
static size_t build_aad(const TtDeltaHeader *hdr, const char *path, uint32_t path_len,
                        uint8_t *aad, size_t aad_cap)
{
    size_t off = 0;

    for (int i = 0; i < 8; ++i)
        aad[off++] = (uint8_t)((hdr->timestamp_ns >> (8 * i)) & 0xFF);

    aad[off++] = hdr->event_type;

    for (int i = 0; i < 4; ++i)
        aad[off++] = (uint8_t)((path_len >> (8 * i)) & 0xFF);

    for (int i = 0; i < 4; ++i)
        aad[off++] = (uint8_t)((hdr->delta_size >> (8 * i)) & 0xFF);

    for (int i = 0; i < 8; ++i)
        aad[off++] = (uint8_t)((hdr->file_size >> (8 * i)) & 0xFF);

    if (path && path_len > 0 && off + path_len <= aad_cap) {
        memcpy(aad + off, path, path_len);
        off += path_len;
    }

    return off;
}

static int store_find_latest_c(const TtStore *s, char *out, size_t outsz)
{
    DIR *d = opendir(s->store_dir);
    if (!d)
        return -1;

    uint64_t best = 0;
    int found = 0;

    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        size_t ln = strlen(de->d_name);

        if (ln <= 4 || strcmp(de->d_name + ln - 4, ".ttd") != 0)
            continue;

        char *end = NULL;
        unsigned long long v = strtoull(de->d_name, &end, 10);

        if (end == de->d_name || *end != '.')
            continue;

        if (!found || v > best) {
            best = v;
            found = 1;
        }
    }

    closedir(d);

    if (!found)
        return -1;

    snprintf(out, outsz, "%s/%020llu.ttd", s->store_dir, (unsigned long long)best);

    return 0;
}

static int store_try_continue_c(TtStore *s)
{
    char fpath[TT_PATH_MAX + 32];

    if (store_find_latest_c(s, fpath, sizeof fpath) != 0)
        return -1;

    int fd = open(fpath, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }

    struct stat st;

    if (fstat(fd, &st) != 0)
        goto fail;

    if ((uint64_t)st.st_size < (TT_STORE_MAGIC_LEN + 4))
        goto fail;

    if ((uint64_t)st.st_size >= TT_STORE_MAX_FILE_SIZE)
        goto fail;

    uint8_t mhdr[TT_STORE_MAGIC_LEN + 4];

    if (pread(fd, mhdr, sizeof mhdr, 0) != (ssize_t)sizeof mhdr)
        goto fail;

    if (memcmp(mhdr, TT_STORE_MAGIC, TT_STORE_MAGIC_LEN) != 0)
        goto fail;

    s->current_fd = fd;
    s->current_size = (uint64_t)st.st_size;

    return 0;

fail:
    close(fd);
    return -1;
}

TtStore *tt_store_open(const char *store_dir, int continue_last)
{
    if (!store_dir || !store_dir[0])
        return NULL;

    TtStore *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;

    s->current_fd = -1;
    s->key_set = 0;

    snprintf(s->store_dir, sizeof s->store_dir, "%s", store_dir);

    s->encrypted = tt_crypto_is_encrypted(store_dir);

    if (mkdir(store_dir, 0700) != 0 && errno != EEXIST) {
        free(s);
        return NULL;
    }
    
        /* v1.4.1: create baseline.list on first repo adoption/start */
{
    extern int tt_generate_baseline_from_store_dir(const char *store_dir);
    tt_generate_baseline_from_store_dir(store_dir);
}


    if (continue_last)
        store_try_continue_c(s);

    return s;
}

void tt_store_close(TtStore *s)
{
    if (!s)
        return;

    if (s->current_fd >= 0) {
        fsync(s->current_fd);
        close(s->current_fd);
    }

    memset(s->crypto_key, 0, sizeof s->crypto_key);

    free(s);
}

void tt_store_set_key(TtStore *s, const uint8_t key[TT_KEY_LEN])
{
    if (!s || !key)
        return;

    memcpy(s->crypto_key, key, TT_KEY_LEN);
    s->key_set = 1;
}

void tt_store_set_encrypted(TtStore *s, int enc)
{
    if (s)
        s->encrypted = enc;
}

void tt_store_force_encrypted(TtStore *s)
{
    if (s)
        s->encrypted = 1;
}

const uint8_t *tt_store_get_key(const TtStore *s)
{
    if (!s || !s->encrypted || !s->key_set)
        return NULL;

    return s->crypto_key;
}

int tt_store_write_ctx(TtStore *s, const TtDeltaHeader *hdr,
                       const char *path, const uint8_t *delta_payload)
{
    if (!s || !hdr || !path)
        return -1;

    uint32_t path_len = (uint32_t)strlen(path);

    if (path_len >= TT_PATH_MAX)
        return -1;

    /* --- cifrado: payload -> nonce || ciphertext || tag --- */
    TtDeltaHeader out_hdr = *hdr;
    uint8_t *final_payload = (uint8_t *)delta_payload;
    uint8_t *enc_buf = NULL;

    if (s->encrypted) {
        if (!s->key_set)
            return -1;

        size_t ct_len = out_hdr.delta_size;

        if (ct_len > 0 && !delta_payload)
            return -1;

        if (ct_len > SIZE_MAX - TT_CRYPTO_OVERHEAD)
            return -1;

        size_t stored_len = TT_CRYPTO_OVERHEAD + ct_len;

        enc_buf = malloc(stored_len ? stored_len : 1);
        if (!enc_buf)
            return -1;

        int urfd = open("/dev/urandom", O_RDONLY);
        if (urfd < 0) {
            free(enc_buf);
            return -1;
        }

        if (read(urfd, enc_buf, TT_NONCE_LEN) != (ssize_t)TT_NONCE_LEN) {
            close(urfd);
            free(enc_buf);
            return -1;
        }

        close(urfd);

        out_hdr.delta_size = (uint32_t)stored_len;   /* tamaño en disco */

        uint8_t aad[sizeof(TtDeltaHeader) + TT_PATH_MAX];
        size_t aad_len = build_aad(&out_hdr, path, path_len, aad, sizeof aad);

        uint8_t *ct  = enc_buf + TT_NONCE_LEN;
        uint8_t *tag = enc_buf + TT_NONCE_LEN + ct_len;

        const uint8_t *pt = delta_payload ? delta_payload : (const uint8_t *)"";

        if (tt_aead_encrypt(s->crypto_key, enc_buf, aad, aad_len,
                            pt, ct_len, ct, tag) != 0) {
            free(enc_buf);
            return -1;
        }

        final_payload = enc_buf;
    } else {
        if (out_hdr.delta_size > 0 && !delta_payload)
            return -1;
    }

    size_t record_size = sizeof(TtDeltaHeader) + path_len + out_hdr.delta_size;

    if (s->current_fd < 0 ||
        s->current_size + record_size > TT_STORE_MAX_FILE_SIZE) {

        if (s->current_fd >= 0) {
            fsync(s->current_fd);
            close(s->current_fd);
            s->current_fd = -1;
        }

        char fpath[TT_PATH_MAX + 32];

        snprintf(fpath, sizeof fpath, "%s/%020llu.ttd",
                 s->store_dir, (unsigned long long)tt_now_ns());

        int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (enc_buf)
                free(enc_buf);

            return -1;
        }

        uint8_t mhdr[TT_STORE_MAGIC_LEN + 4];

        memcpy(mhdr, TT_STORE_MAGIC, TT_STORE_MAGIC_LEN);

        uint32_t ver = TT_STORE_VERSION;

        for (int i = 0; i < 4; ++i)
            mhdr[TT_STORE_MAGIC_LEN + i] = (uint8_t)((ver >> (8 * i)) & 0xFF);

        if (write_all(fd, mhdr, sizeof mhdr) != 0) {
            close(fd);

            if (enc_buf)
                free(enc_buf);

            return -1;
        }

        s->current_fd = fd;
        s->current_size = sizeof mhdr;
    }

    uint8_t hdr_buf[sizeof(TtDeltaHeader)];
    size_t off = 0;

    for (int i = 0; i < 8; ++i)
        hdr_buf[off++] = (uint8_t)((out_hdr.timestamp_ns >> (8 * i)) & 0xFF);

    hdr_buf[off++] = out_hdr.event_type;

    for (int i = 0; i < 4; ++i)
        hdr_buf[off++] = (uint8_t)((path_len >> (8 * i)) & 0xFF);

    for (int i = 0; i < 4; ++i)
        hdr_buf[off++] = (uint8_t)((out_hdr.delta_size >> (8 * i)) & 0xFF);

    for (int i = 0; i < 8; ++i)
        hdr_buf[off++] = (uint8_t)((out_hdr.file_size >> (8 * i)) & 0xFF);

    if (write_all(s->current_fd, hdr_buf, sizeof hdr_buf) != 0) {
        if (enc_buf)
            free(enc_buf);

        return -1;
    }

    if (path_len > 0 && write_all(s->current_fd, path, path_len) != 0) {
        if (enc_buf)
            free(enc_buf);

        return -1;
    }

    if (out_hdr.delta_size > 0 && final_payload &&
        write_all(s->current_fd, final_payload, out_hdr.delta_size) != 0) {
        if (enc_buf)
            free(enc_buf);

        return -1;
    }

    s->current_size += record_size;

    if (enc_buf)
        free(enc_buf);

    return 0;
}

/* ============ lector por contexto ============ */

struct TtStoreReaderCtx {
    char     dir_path[TT_PATH_MAX];
    int      file_fd;
    uint64_t file_size, file_pos;
    uint64_t *ids;
    size_t   id_count, id_index, cap;
    int      encrypted;
    uint8_t  crypto_key[TT_KEY_LEN];
};

static int id_cmp(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;

    if (va < vb)
        return -1;

    if (va > vb)
        return 1;

    return 0;
}

TtStoreReader *tt_reader_open(const char *store_dir)
{
    if (!store_dir || !store_dir[0])
        return NULL;

    TtStoreReader *rd = calloc(1, sizeof *rd);
    if (!rd)
        return NULL;

    rd->file_fd = -1;

    snprintf(rd->dir_path, sizeof rd->dir_path, "%s", store_dir);

    rd->encrypted = tt_crypto_is_encrypted(store_dir);

    DIR *d = opendir(rd->dir_path);
    if (!d) {
        free(rd);
        return NULL;
    }

    rd->cap = 16;
    rd->ids = malloc(rd->cap * sizeof(uint64_t));

    if (!rd->ids) {
        closedir(d);
        free(rd);
        return NULL;
    }

    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        size_t ln = strlen(de->d_name);

        if (ln <= 4 || strcmp(de->d_name + ln - 4, ".ttd") != 0)
            continue;

        char *end = NULL;
        unsigned long long v = strtoull(de->d_name, &end, 10);

        if (end == de->d_name || *end != '.')
            continue;

        if (rd->id_count == rd->cap) {
            rd->cap *= 2;

            uint64_t *ni = realloc(rd->ids, rd->cap * sizeof(uint64_t));
            if (!ni)
                break;

            rd->ids = ni;
        }

        rd->ids[rd->id_count++] = (uint64_t)v;
    }

    closedir(d);

    if (rd->id_count > 1)
        qsort(rd->ids, rd->id_count, sizeof(uint64_t), id_cmp);

    return rd;
}

void tt_reader_set_key(TtStoreReader *rd, const uint8_t key[TT_KEY_LEN])
{
    if (rd)
        memcpy(rd->crypto_key, key, TT_KEY_LEN);
}

static int reader_open_next_file(TtStoreReader *rd)
{
    if (rd->file_fd >= 0) {
        close(rd->file_fd);
        rd->file_fd = -1;
    }

    while (rd->id_index < rd->id_count) {
        char path[TT_PATH_MAX + 32];

        snprintf(path, sizeof path, "%s/%020llu.ttd",
                 rd->dir_path, (unsigned long long)rd->ids[rd->id_index++]);

        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;

        struct stat st;

        if (fstat(fd, &st) != 0 || st.st_size < (off_t)(TT_STORE_MAGIC_LEN + 4)) {
            close(fd);
            continue;
        }

        uint8_t hdr[TT_STORE_MAGIC_LEN + 4];

        if (read(fd, hdr, sizeof hdr) != (ssize_t)sizeof hdr ||
            memcmp(hdr, TT_STORE_MAGIC, TT_STORE_MAGIC_LEN) != 0) {
            close(fd);
            continue;
        }

        rd->file_fd = fd;
        rd->file_size = (uint64_t)st.st_size;
        rd->file_pos = TT_STORE_MAGIC_LEN + 4;

        return 0;
    }

    return -1;
}

int tt_reader_next(TtStoreReader *rd, TtDeltaHeader *out_hdr,
                   char *out_path, size_t out_path_size,
                   uint8_t **out_payload, size_t *out_payload_size)
{
    if (!rd)
        return 0;

    if (out_payload)
        *out_payload = NULL;

    if (out_payload_size)
        *out_payload_size = 0;

    for (;;) {
        if (rd->file_fd < 0) {
            if (reader_open_next_file(rd) != 0)
                return 0;
        }

        if (rd->file_pos + sizeof(TtDeltaHeader) > rd->file_size) {
            close(rd->file_fd);
            rd->file_fd = -1;
            continue;
        }

        uint8_t hdr_buf[sizeof(TtDeltaHeader)];

        if (pread(rd->file_fd, hdr_buf, sizeof hdr_buf, (off_t)rd->file_pos)
            != (ssize_t)sizeof hdr_buf) {
            close(rd->file_fd);
            rd->file_fd = -1;
            continue;
        }

        size_t off = 0;
        uint64_t ts = 0;

        for (int i = 0; i < 8; ++i)
            ts |= (uint64_t)hdr_buf[off++] << (8 * i);

        uint8_t ev = hdr_buf[off++];

        uint32_t pl = 0;
        for (int i = 0; i < 4; ++i)
            pl |= (uint32_t)hdr_buf[off++] << (8 * i);

        uint32_t ds = 0;
        for (int i = 0; i < 4; ++i)
            ds |= (uint32_t)hdr_buf[off++] << (8 * i);

        uint64_t fs = 0;
        for (int i = 0; i < 8; ++i)
            fs |= (uint64_t)hdr_buf[off++] << (8 * i);

        if (pl == 0 || pl >= out_path_size ||
            rd->file_pos + sizeof(hdr_buf) + pl + ds > rd->file_size) {
            close(rd->file_fd);
            rd->file_fd = -1;
            continue;
        }

        if (rd->encrypted && ds > 0 && ds < TT_CRYPTO_OVERHEAD) {
            close(rd->file_fd);
            rd->file_fd = -1;
            return -1;
        }

        if (pread(rd->file_fd, out_path, pl, (off_t)(rd->file_pos + sizeof(hdr_buf)))
            != (ssize_t)pl) {
            close(rd->file_fd);
            rd->file_fd = -1;
            continue;
        }

        out_path[pl] = '\0';

        uint8_t *final_pl = NULL;
        size_t final_pl_size = 0;
        uint32_t reported_ds = ds;

        if (ds > 0) {
            uint8_t *buf = malloc(ds);
            if (!buf)
                return -1;

            if (pread(rd->file_fd, buf, ds,
                      (off_t)(rd->file_pos + sizeof(hdr_buf) + pl)) != (ssize_t)ds) {
                free(buf);
                close(rd->file_fd);
                rd->file_fd = -1;
                continue;
            }

            final_pl = buf;
            final_pl_size = ds;

            /* --- descifrado --- */
            if (rd->encrypted && ds >= TT_CRYPTO_OVERHEAD) {
                size_t ct_len = ds - TT_CRYPTO_OVERHEAD;

                uint8_t *nonce = buf;
                uint8_t *ct    = buf + TT_NONCE_LEN;
                uint8_t *tag   = buf + TT_NONCE_LEN + ct_len;

                TtDeltaHeader disk_hdr;

                disk_hdr.timestamp_ns = ts;
                disk_hdr.event_type = ev;
                disk_hdr.path_len = pl;
                disk_hdr.delta_size = ds;
                disk_hdr.file_size = fs;

                uint8_t aad[sizeof(TtDeltaHeader) + TT_PATH_MAX];
                size_t aad_len = build_aad(&disk_hdr, out_path, pl, aad, sizeof aad);

                uint8_t *pt = malloc(ct_len ? ct_len : 1);
                if (!pt) {
                    free(buf);
                    return -1;
                }

                if (tt_aead_decrypt(rd->crypto_key, nonce, aad, aad_len,
                                    ct, ct_len, tag, pt) != 0) {
                    free(pt);
                    free(buf);
                    close(rd->file_fd);
                    rd->file_fd = -1;
                    return -1;   /* tag inválido: manipulado o clave errónea */
                }

                free(buf);

                final_pl = pt;
                final_pl_size = ct_len;
                reported_ds = (uint32_t)ct_len;
            }
        }

        if (out_payload && out_payload_size) {
            *out_payload = final_pl;
            *out_payload_size = final_pl_size;
        } else if (final_pl) {
            free(final_pl);
        }

        if (out_hdr) {
            out_hdr->timestamp_ns = ts;
            out_hdr->event_type = ev;
            out_hdr->path_len = pl;
            out_hdr->delta_size = reported_ds;
            out_hdr->file_size = fs;
        }

        rd->file_pos += sizeof(hdr_buf) + pl + ds;   /* ds = tamaño EN DISCO */

        return 1;
    }
}

void tt_reader_close(TtStoreReader *rd)
{
    if (!rd)
        return;

    if (rd->file_fd >= 0)
        close(rd->file_fd);

    free(rd->ids);

    memset(rd->crypto_key, 0, sizeof rd->crypto_key);

    free(rd);
}

/* ============ API global v1.2 (compat) ============ */

static TtStore g_store_compat;
static int     g_store_compat_open = 0;
static TtStoreReader *g_reader_compat = NULL;

int tt_store_init(const char *store_dir)
{
    if (!store_dir || !store_dir[0])
        return -1;

    if (g_store_compat_open && g_store_compat.current_fd >= 0) {
        fsync(g_store_compat.current_fd);
        close(g_store_compat.current_fd);
    }

    memset(&g_store_compat, 0, sizeof g_store_compat);

    g_store_compat.current_fd = -1;

    snprintf(g_store_compat.store_dir, sizeof g_store_compat.store_dir, "%s", store_dir);

    g_store_compat.encrypted = tt_crypto_is_encrypted(store_dir);
    g_store_compat.key_set = 0;

    if (mkdir(store_dir, 0700) != 0 && errno != EEXIST)
        return -1;

    g_store_compat_open = 1;

    return 0;
}

void tt_store_compat_set_key(const uint8_t key[TT_KEY_LEN])
{
    memcpy(g_store_compat.crypto_key, key, TT_KEY_LEN);
    g_store_compat.key_set = 1;
}

/* HARDENED-COMPAT-GET-KEY */
const uint8_t *tt_store_compat_get_key(void)
{
    if (!g_store_compat_open || !g_store_compat.encrypted || !g_store_compat.key_set)
        return NULL;

    return g_store_compat.crypto_key;
}


const uint8_t *tt_store_compat_peek_key(void)
{
    if (!g_store_compat_open || !g_store_compat.encrypted || !g_store_compat.key_set)
        return NULL;

    return g_store_compat.crypto_key;
}

int tt_store_compat_copy_key(uint8_t out[TT_KEY_LEN])
{
    if (!g_store_compat_open || !g_store_compat.encrypted || !g_store_compat.key_set || !out)
        return -1;

    memcpy(out, g_store_compat.crypto_key, TT_KEY_LEN);

    return 0;
}

void tt_store_free(void)
{
    if (g_reader_compat) {
        tt_reader_close(g_reader_compat);
        g_reader_compat = NULL;
    }

    if (g_store_compat_open && g_store_compat.current_fd >= 0) {
        fsync(g_store_compat.current_fd);
        close(g_store_compat.current_fd);
    }

    memset(&g_store_compat, 0, sizeof g_store_compat);

    g_store_compat.current_fd = -1;
    g_store_compat_open = 0;
}

int tt_store_write(const TtDeltaHeader *hdr, const char *path, const uint8_t *payload)
{
    if (!g_store_compat_open)
        return -1;

    return tt_store_write_ctx(&g_store_compat, hdr, path, payload);
}

int tt_store_reader_init(void)
{
    if (!g_store_compat_open || !g_store_compat.store_dir[0])
        return -1;

    if (g_reader_compat) {
        tt_reader_close(g_reader_compat);
        g_reader_compat = NULL;
    }

    g_reader_compat = tt_reader_open(g_store_compat.store_dir);
    if (!g_reader_compat)
        return -1;

    /* hereda estado cripto del store de compat */
    g_reader_compat->encrypted = g_store_compat.encrypted;
    memcpy(g_reader_compat->crypto_key, g_store_compat.crypto_key, TT_KEY_LEN);

    return 0;
}

int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps, uint8_t **pl, size_t *plsz)
{
    return g_reader_compat ? tt_reader_next(g_reader_compat, h, p, ps, pl, plsz) : 0;
}

void tt_store_reader_free(void)
{
    if (g_reader_compat) {
        tt_reader_close(g_reader_compat);
        g_reader_compat = NULL;
    }
}

int tt_store_scan_stats(uint64_t *nrecords, uint64_t *nbytes,
                        uint64_t *first_ts, uint64_t *last_ts)
{
    uint64_t n = 0, b = 0, fts = 0, lts = 0;

    if (tt_store_reader_init() != 0)
        return -1;

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);

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

    tt_store_reader_free();

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

static int store_try_continue_compat(void)
{
    TtStore tmp = g_store_compat;

    tmp.current_fd = -1;
    tmp.current_size = 0;

    if (store_try_continue_c(&tmp) != 0)
        return -1;

    g_store_compat.current_fd = tmp.current_fd;
    g_store_compat.current_size = tmp.current_size;

    return 0;
}

int tt_store_init_writer(const char *store_dir, int continue_last)
{
    if (tt_store_init(store_dir) != 0)
        return -1;

    if (continue_last)
        store_try_continue_compat();

    return 0;
}
