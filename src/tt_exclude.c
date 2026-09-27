/* ============================================================
   Time-Travel v1.5 — tt_exclude.c
   Lista de exclusiones por repositorio (configurable por usuario).
   ============================================================ */
#include "tt_exclude.h"

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tt_crypto.h"

/* ==================== utilidades internas ==================== */

static void tt_exclude_file_path(char *out, size_t n, const char *store_dir)
{
    snprintf(out, n, "%s/exclude.enc", store_dir);
}

/*
 * Matching de un patrón contra un path relativo.
 *
 * Reglas:
 * 1. Coincidencia exacta con el path completo.
 * 2. Coincidencia como prefijo de directorio:
 *    "build" matchea "build/foo.txt" y "build".
 * 3. Coincidencia de componente en cualquier profundidad:
 *    ".venv" matchea "sub/.venv/x.txt".
 * 4. Glob fnmatch sobre el path completo.
 * 5. Glob fnmatch sobre el basename.
 */
static int tt_exclude_match_single(const char *rel, const char *pattern)
{
    if (!rel || !rel[0] || !pattern || !pattern[0])
        return 0;

    size_t plen = strlen(pattern);

    /* 1. coincidencia exacta */
    if (strcmp(rel, pattern) == 0)
        return 1;

    /* 2. prefijo de directorio: "build" -> "build/..." */
    if (strncmp(rel, pattern, plen) == 0 &&
        (rel[plen] == '/' || rel[plen] == '\0'))
        return 1;

    /* 3. componente en cualquier profundidad */
    const char *p = rel;
    while (*p) {
        if (p == rel || *(p - 1) == '/') {
            if (strncmp(p, pattern, plen) == 0 &&
                (p[plen] == '/' || p[plen] == '\0'))
                return 1;
        }
        const char *slash = strchr(p, '/');
        if (!slash)
            break;
        p = slash + 1;
    }

    /* 4. glob sobre path completo */
    if (fnmatch(pattern, rel, 0) == 0)
        return 1;

    /* 5. glob sobre basename */
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    if (fnmatch(pattern, base, 0) == 0)
        return 1;

    return 0;
}

/* ==================== API pública ==================== */

void tt_exclude_init(TtExcludeList *list)
{
    if (!list)
        return;
    memset(list, 0, sizeof *list);
}

void tt_exclude_free(TtExcludeList *list)
{
    if (!list)
        return;
    for (size_t i = 0; i < list->count; ++i)
        free(list->patterns[i]);
    free(list->patterns);
    memset(list, 0, sizeof *list);
}

int tt_exclude_add(TtExcludeList *list, const char *pattern)
{
    if (!list || !pattern || !pattern[0])
        return -1;

    /* evitar duplicados */
    for (size_t i = 0; i < list->count; ++i)
        if (strcmp(list->patterns[i], pattern) == 0)
            return 0;

    if (list->count == list->cap) {
        size_t ncap = list->cap ? list->cap * 2 : 16;
        char **np = realloc(list->patterns, ncap * sizeof(char *));
        if (!np)
            return -1;
        list->patterns = np;
        list->cap = ncap;
    }

    list->patterns[list->count] = strdup(pattern);
    if (!list->patterns[list->count])
        return -1;
    list->count++;
    return 0;
}

int tt_exclude_remove(TtExcludeList *list, const char *pattern)
{
    if (!list || !pattern)
        return -1;

    for (size_t i = 0; i < list->count; ++i) {
        if (strcmp(list->patterns[i], pattern) == 0) {
            free(list->patterns[i]);
            for (size_t j = i; j < list->count - 1; ++j)
                list->patterns[j] = list->patterns[j + 1];
            list->count--;
            return 0;
        }
    }
    return -1; /* no encontrado */
}

int tt_exclude_match(const TtExcludeList *list, const char *rel)
{
    if (!list || list->count == 0)
        return 0;
    if (!rel || !rel[0])
        return 0;

    for (size_t i = 0; i < list->count; ++i) {
        if (tt_exclude_match_single(rel, list->patterns[i]))
            return 1;
    }
    return 0;
}

/* ==================== persistencia ==================== */

int tt_exclude_load(const char *store_dir, TtExcludeList *list)
{
    if (!list)
        return -1;

    tt_exclude_init(list);

    char path[TT_PATH_MAX + 64];
    tt_exclude_file_path(path, sizeof path, store_dir);

    /* v1.5: intentar descifrar exclude.enc primero */
    char tmp_dec[TT_PATH_MAX + 64];
    snprintf(tmp_dec, sizeof(tmp_dec), "/tmp/tt_exclude_%d", (int)getpid());

    uint8_t key[TT_KEY_LEN];
    FILE *f = NULL;

    if (tt_repo_get_key(store_dir, key) == 0) {
        if (tt_crypto_decrypt_file(path, tmp_dec, key) == 0) {
            f = fopen(tmp_dec, "r");
            unlink(tmp_dec);
        }
    }

    /* Fallback: legacy exclude.list en texto plano */
    if (!f) {
        char legacy_path[TT_PATH_MAX + 64];
        snprintf(legacy_path, sizeof(legacy_path), "%s/exclude.list", store_dir);
        f = fopen(legacy_path, "r");
    }

    if (!f)
        return 0; /* no hay exclude → lista vacía */

    char line[TT_PATH_MAX];
    while (fgets(line, sizeof line, f)) {
        /* quitar trailing whitespace */
        size_t len = strlen(line);
        while (len > 0 &&
               (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                line[len - 1] == ' '  || line[len - 1] == '\t'))
            line[--len] = '\0';

        /* saltar vacías y comentarios */
        if (len == 0 || line[0] == '#')
            continue;

        tt_exclude_add(list, line);
    }

    fclose(f);
    return 0;
}

int tt_exclude_save(const char *store_dir, const TtExcludeList *list)
{
    char path[TT_PATH_MAX + 64];
    tt_exclude_file_path(path, sizeof path, store_dir);

    char tmp[TT_PATH_MAX + 96];
    snprintf(tmp, sizeof tmp, "%s.tmp.%d", path, (int)getpid());

    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;

    fprintf(f, "# Time-Travel exclude list (v1.5)\n");
    fprintf(f, "# One pattern per line. '#' = comment.\n");

    if (list) {
        for (size_t i = 0; i < list->count; ++i)
            fprintf(f, "%s\n", list->patterns[i]);
    }

    fclose(f);

    /* v1.5: cifrar el temporal → exclude.enc */
    uint8_t key[TT_KEY_LEN];
    if (tt_repo_get_key(store_dir, key) != 0) {
        unlink(tmp);
        return -1;
    }
    if (tt_crypto_encrypt_file(tmp, path, key) != 0) {
        unlink(tmp);
        return -1;
    }
    unlink(tmp);
    return 0;
}

/* ==================== pending excludes (--exclude en start/add) ==================== */

static const char *g_pending_excludes[64];
static int g_n_pending_excludes = 0;

void tt_set_pending_excludes(const char **patterns, int n)
{
    g_n_pending_excludes = 0;
    for (int i = 0; i < n && i < 64; ++i)
        g_pending_excludes[g_n_pending_excludes++] = patterns[i];
}

void tt_apply_pending_excludes(TtLocalRepo *r)
{
    if (g_n_pending_excludes <= 0 || !r)
        return;
    for (int i = 0; i < g_n_pending_excludes; ++i)
        tt_exclude_add(&r->excludes, g_pending_excludes[i]);
    tt_exclude_save(r->store_dir, &r->excludes);
    g_n_pending_excludes = 0;
}
