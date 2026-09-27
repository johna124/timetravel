/* ============================================================
   Time-Travel v1.5 — tt_reconstruct.h
   Motor unificado de reconstrucción de estado (point-in-time).
   ============================================================ */
#ifndef TT_RECONSTRUCT_H
#define TT_RECONSTRUCT_H

#include "tt_types.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Reconstruye el contenido de un fichero en un punto en el tiempo.
 *
 * - target_ns = 0  -> reconstruye hasta el último record disponible.
 * - target_ns > 0  -> reconstruye hasta ese timestamp (inclusive).
 *
 * Retorna:
 *   0  = éxito (out_data puede ser NULL si el fichero estaba vacío).
 *  -1  = error de I/O o memoria.
 *
 * Si el fichero no existía o fue borrado antes de target_ns:
 *   *out_exists = 0, *out_data = NULL, *out_size = 0.
 */
int tt_reconstruct_file(const char *store_dir, const char *rel_path,
                        uint64_t target_ns,
                        uint8_t **out_data, size_t *out_size, int *out_exists);

#endif /* TT_RECONSTRUCT_H */
