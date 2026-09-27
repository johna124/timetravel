/* ============================================================
   Time-Travel v1.5 — tt_cache.c
   Cache de estado de ficheros (por repo).
   Sin dependencias internas (solo tt_types.h).
   ============================================================ */
#include "tt_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void tt_cache_init(TtStateCache *c)
{
    memset(c, 0, sizeof *c);
}

void tt_cache_free(TtStateCache *c)
{
    if (!c)
        return;
    for (size_t i = 0; i < c->count; ++i)
        if (c->entries[i].active)
            free(c->entries[i].data);
    free(c->entries);
    memset(c, 0, sizeof *c);
}

TtStateEntry *tt_cache_find(TtStateCache *c, const char *path)
{
    for (size_t i = 0; i < c->count; ++i)
        if (c->entries[i].active && strcmp(c->entries[i].path, path) == 0)
            return &c->entries[i];
    return NULL;
}

void tt_cache_remove(TtStateCache *c, const char *path)
{
    TtStateEntry *e = tt_cache_find(c, path);
    if (!e)
        return;
    free(e->data);
    memset(e, 0, sizeof *e);
    if (c->active_count > 0)
        c->active_count--;
}

int tt_cache_put(TtStateCache *c, const char *path,
                 const uint8_t *data, size_t size,
                 int anchored, int baseline_pending)
{
    TtStateEntry *e = tt_cache_find(c, path);

    if (!e) {
        size_t slot = c->count;
        for (size_t i = 0; i < c->count; ++i)
            if (!c->entries[i].active) { slot = i; break; }

        if (slot == c->count) {
            if (c->count == c->cap) {
                size_t ncap = c->cap ? c->cap * 2 : 64;
                TtStateEntry *ne = realloc(c->entries, ncap * sizeof(TtStateEntry));
                if (!ne)
                    return -1;
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
        if (!e->data)
            return -1;
        memcpy(e->data, data, size);
    }

    e->size = size;
    e->anchored = anchored;
    e->baseline_pending = baseline_pending;
    return 0;
}
