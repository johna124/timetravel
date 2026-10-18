/* ============================================================
   Time-Travel v1.5 — tt_annotation.h
   Persistencia de anotaciones (autotags) por record.
   ============================================================ */
#ifndef TT_ANNOTATION_H
#define TT_ANNOTATION_H

#include <stdint.h>
#include <stddef.h>

/* Escribe una anotación en .timetravel/annotations.tsv */
int tt_annotation_write(const char *store_dir, const char *rel,
                        uint64_t ts, const char *summary);

/* Busca la anotación de un (ts, path). Devuelve 0 si la encuentra. */
int tt_annotation_lookup(const char *store_dir, const char *rel,
                         uint64_t ts, char *out, size_t outsz);

#endif /* TT_ANNOTATION_H */
