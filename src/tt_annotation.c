/* ============================================================
   Time-Travel v1.5 — tt_annotation.c
   Persistencia de anotaciones (autotags) por record.
   Cifrado transparente: annotations.enc (AEAD).
   Retrocompatible: lee annotations.tsv legacy si no hay .enc.
   ============================================================ */
#include "tt_annotation.h"
#include "tt_types.h"
#include "tt_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TT_ANNOTATIONS_ENC "annotations.enc"
#define TT_ANNOTATIONS_TSV "annotations.tsv"   /* legacy */

/* ---------- helpers de path ---------- */

static void annotations_enc_path(const char *store_dir, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s/%s", store_dir, TT_ANNOTATIONS_ENC);
}

static void annotations_tsv_path(const char *store_dir, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s/%s", store_dir, TT_ANNOTATIONS_TSV);
}

/* ---------- leer contenido descifrado ---------- */

static int read_annotations(const char *store_dir, char **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;

    char enc_path[TT_PATH_MAX + 64];
    annotations_enc_path(store_dir, enc_path, sizeof enc_path);

    if (access(enc_path, F_OK) == 0) {
        /* Existe annotations.enc → descifrar */
        uint8_t key[TT_KEY_LEN];
        if (tt_repo_get_key(store_dir, key) != 0)
            return -1;

        char tmp_path[] = "/tmp/tt_annot_XXXXXX";
        int tmp_fd = mkstemp(tmp_path);
        if (tmp_fd < 0)
            return -1;
        close(tmp_fd);

        if (tt_crypto_decrypt_file(enc_path, tmp_path, key) != 0) {
            unlink(tmp_path);
            return -1;
        }

        FILE *f = fopen(tmp_path, "r");
        unlink(tmp_path);
        if (!f)
            return -1;

        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (size <= 0) {
            fclose(f);
            *out = calloc(1, 1);
            *out_len = 0;
            return *out ? 0 : -1;
        }

        *out = malloc((size_t)size + 1);
        if (!*out) {
            fclose(f);
            return -1;
        }

        size_t rd = fread(*out, 1, (size_t)size, f);
        fclose(f);
        (*out)[rd] = '\0';
        *out_len = rd;
        return 0;
    }

    /* No hay .enc → intentar legacy annotations.tsv */
    char tsv_path[TT_PATH_MAX + 64];
    annotations_tsv_path(store_dir, tsv_path, sizeof tsv_path);

    FILE *f = fopen(tsv_path, "r");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        *out = calloc(1, 1);
        *out_len = 0;
        return *out ? 0 : -1;
    }

    *out = malloc((size_t)size + 1);
    if (!*out) {
        fclose(f);
        return -1;
    }

    size_t rd = fread(*out, 1, (size_t)size, f);
    fclose(f);
    (*out)[rd] = '\0';
    *out_len = rd;
    return 0;
}

/* ---------- escribir contenido cifrado ---------- */

static int write_annotations(const char *store_dir, const char *content, size_t content_len)
{
    char enc_path[TT_PATH_MAX + 64];
    annotations_enc_path(store_dir, enc_path, sizeof enc_path);

    uint8_t key[TT_KEY_LEN];
    if (tt_repo_get_key(store_dir, key) != 0)
        return -1;

    /* Escribir plaintext a temporal */
    char tmp_plain[] = "/tmp/tt_annot_p_XXXXXX";
    int fd1 = mkstemp(tmp_plain);
    if (fd1 < 0)
        return -1;

    if (content_len > 0) {
        if (write(fd1, content, content_len) != (ssize_t)content_len) {
            close(fd1);
            unlink(tmp_plain);
            return -1;
        }
    }
    close(fd1);

    /* Cifrar a otro temporal */
    char tmp_enc[] = "/tmp/tt_annot_e_XXXXXX";
    int fd2 = mkstemp(tmp_enc);
    if (fd2 < 0) {
        unlink(tmp_plain);
        return -1;
    }
    close(fd2);

    if (tt_crypto_encrypt_file(tmp_plain, tmp_enc, key) != 0) {
        unlink(tmp_plain);
        unlink(tmp_enc);
        return -1;
    }
    unlink(tmp_plain);

    /* Mover atómicamente */
    if (rename(tmp_enc, enc_path) != 0) {
        unlink(tmp_enc);
        return -1;
    }

    return 0;
}

/* ---------- API pública ---------- */

int tt_annotation_write(const char *store_dir, const char *rel,
                        uint64_t ts, const char *summary)
{
    if (!store_dir || !rel || !summary || !summary[0])
        return -1;

    /* Leer contenido existente */
    char *existing = NULL;
    size_t existing_len = 0;
    read_annotations(store_dir, &existing, &existing_len);

    /* Nueva línea */
    char new_line[TT_PATH_MAX + 512];
    int line_len = snprintf(new_line, sizeof new_line, "%llu\t%s\t%s\n",
                            (unsigned long long)ts, rel, summary);
    if (line_len < 0) {
        free(existing);
        return -1;
    }

    /* Concatenar */
    size_t total_len = existing_len + (size_t)line_len;
    char *new_content = malloc(total_len + 1);
    if (!new_content) {
        free(existing);
        return -1;
    }

    if (existing_len > 0)
        memcpy(new_content, existing, existing_len);
    memcpy(new_content + existing_len, new_line, (size_t)line_len);
    new_content[total_len] = '\0';
    free(existing);

    /* Escribir cifrado */
    int rc = write_annotations(store_dir, new_content, total_len);
    free(new_content);
    return rc;
}

int tt_annotation_lookup(const char *store_dir, const char *rel,
                         uint64_t ts, char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return -1;
    out[0] = '\0';

    if (!store_dir || !rel)
        return -1;

    char *content = NULL;
    size_t content_len = 0;
    if (read_annotations(store_dir, &content, &content_len) != 0)
        return -1;

    if (!content || content_len == 0) {
        free(content);
        return -1;
    }

    char ts_str[32];
    snprintf(ts_str, sizeof ts_str, "%llu", (unsigned long long)ts);

    char *line = content;
    while (line && *line) {
        char *next = strchr(line, '\n');
        size_t line_len = next ? (size_t)(next - line) : strlen(line);

        char line_copy[TT_PATH_MAX + 512];
        size_t copy_len = line_len < sizeof line_copy - 1 ? line_len : sizeof line_copy - 1;
        memcpy(line_copy, line, copy_len);
        line_copy[copy_len] = '\0';

        char *tab1 = strchr(line_copy, '\t');
        if (tab1) {
            *tab1 = '\0';
            char *tab2 = strchr(tab1 + 1, '\t');
            if (tab2) {
                *tab2 = '\0';
                if (strcmp(line_copy, ts_str) == 0 &&
                    strcmp(tab1 + 1, rel) == 0) {
                    snprintf(out, outsz, "%s", tab2 + 1);
                    free(content);
                    return 0;
                }
            }
        }

        line = next ? next + 1 : NULL;
    }

    free(content);
    return -1;
}
