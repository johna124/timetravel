/* ============================================================
   Time-Travel v1.5 — tt_exclude.h
   Lista de exclusiones por repositorio (configurable por usuario).
   ============================================================ */
#ifndef TT_EXCLUDE_H
#define TT_EXCLUDE_H

#include "tt_types.h"
#include <stddef.h>

/* ---------------- tipos ---------------- */

/* ---------------- API ---------------- */
void tt_exclude_init(TtExcludeList *list);
void tt_exclude_free(TtExcludeList *list);
int  tt_exclude_add(TtExcludeList *list, const char *pattern);
int  tt_exclude_remove(TtExcludeList *list, const char *pattern);
int  tt_exclude_match(const TtExcludeList *list, const char *rel);

/* ---------------- persistencia ---------------- */
int  tt_exclude_load(const char *store_dir, TtExcludeList *list);
int  tt_exclude_save(const char *store_dir, const TtExcludeList *list);

/* ---------------- pending excludes (para --exclude en start/add) ---------------- */
void tt_set_pending_excludes(const char **patterns, int n);
void tt_apply_pending_excludes(TtLocalRepo *r);

#endif /* TT_EXCLUDE_H */
