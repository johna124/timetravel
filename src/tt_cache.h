/* ============================================================
   Time-Travel v1.5 — tt_cache.h
   Cache de estado de ficheros (por repo).
   ============================================================ */
#ifndef TT_CACHE_H
#define TT_CACHE_H

#include "tt_types.h"
#include <stddef.h>
#include <stdint.h>

void           tt_cache_init(TtStateCache *c);
void           tt_cache_free(TtStateCache *c);
TtStateEntry  *tt_cache_find(TtStateCache *c, const char *path);
void           tt_cache_remove(TtStateCache *c, const char *path);
int            tt_cache_put(TtStateCache *c, const char *path,
                            const uint8_t *data, size_t size,
                            int anchored, int baseline_pending);

#endif /* TT_CACHE_H */
