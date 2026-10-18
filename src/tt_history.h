/* ============================================================
   Time-Travel v1.5 — tt_history.h
   Consultas de historial, tags, pathsets y resolución de targets.
   ============================================================ */
#ifndef TT_HISTORY_H
#define TT_HISTORY_H

#include "tt_types.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ---------------- PathSet ---------------- */
typedef struct { char **v; size_t n, cap; } TtPathSet;

int  tt_pathset_has(TtPathSet *s, const char *p);
void tt_pathset_add(TtPathSet *s, const char *p);
void tt_pathset_free(TtPathSet *s);

/* ---------------- Tags ---------------- */
int tt_tag_add(const char *store_dir, const char *name, uint64_t ts);
int tt_tag_lookup(const char *store_dir, const char *name, uint64_t *out_ts);
int tt_tag_list(const char *store_dir);

/* ---------------- History queries ---------------- */
int tt_load_version_content(const char *store_dir, const char *rel_path,
                            uint64_t target_ns, uint8_t **out,
                            size_t *out_size, int *exists);

int tt_find_last_two_ts(const char *rel_path,
                        uint64_t *prev_ts, uint64_t *last_ts);

int tt_scan_timestamps(const char *rel, int prefix_mode,
                       uint64_t **out_ts, size_t *out_n);

int tt_resolve_file_target_ns(const char *store_dir, const char *rel,
                              const char *expr, uint64_t *out,
                              char *desc, size_t descsz);

/* ---------------- Store collection ---------------- */
void tt_store_collect_paths_ctx(const char *store_dir, TtPathSet *out);
void tt_store_collect_matching(TtPathSet *out, const char *rel);

/* ---------------- Stats ---------------- */
int tt_scan_stats_dir(const char *store_dir, const uint8_t *key,
                      uint64_t *nrecords, uint64_t *nbytes,
                      uint64_t *first_ts, uint64_t *last_ts);

#endif /* TT_HISTORY_H */
