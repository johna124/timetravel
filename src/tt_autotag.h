/* ============================================================
   Time-Travel v1.5 — tt_autotag.h
   Generación automática de tags semánticos a partir de deltas.
   ============================================================ */
#ifndef TT_AUTOTAG_H
#define TT_AUTOTAG_H

#include <stdint.h>
#include <stddef.h>

/*
 * Genera el resumen completo de un delta:
 *   cantidad + rango de líneas + tags semánticos
 *
 * Ejemplos de salida:
 *   "+3/-1 lines 500-503 #futex_lock #worker"
 *   "~80B 12-15 #max_retries #timeout_ms"
 *   "+0/-12 lines 100-112 #shutdown #cleanup"
 */
void tt_delta_full_summary(const uint8_t *old, size_t old_sz,
                           const uint8_t *new, size_t new_sz,
                           char *out, size_t outsz);

/*
 * Genera solo los tags semánticos:
 *   "#futex_lock #worker #pthread"
 */
void tt_generate_autotag(const uint8_t *old, size_t old_sz,
                         const uint8_t *new, size_t new_sz,
                         char *out, size_t outsz);

#endif /* TT_AUTOTAG_H */
