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
#include <stdlib.h>
#include <string.h>
#include "xdelta3.h"

int tt_delta_encode(const uint8_t *old_data, size_t old_size,
                    const uint8_t *new_data, size_t new_size,
                    uint8_t **delta_out, size_t *delta_size_out) {
    if (!delta_out || !delta_size_out) return -1;
    *delta_out = NULL; *delta_size_out = 0;
    if (!new_data || new_size == 0) return 0;
    size_t out_cap = new_size + (new_size / 8) + 64;
    uint8_t *out = malloc(out_cap);
    if (!out) return -1;
    size_t out_size = out_cap;
    if (xd3_encode_memory(new_data, new_size, old_data, old_size,
                          out, &out_size, out_cap, 0) != 0) { free(out); return -1; }
    *delta_out = out; *delta_size_out = out_size;
    return 0;
}

int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                    const uint8_t *delta_data, size_t delta_size,
                    size_t expected_new_size,
                    uint8_t **new_out, size_t *new_size_out) {
    if (!new_out || !new_size_out) return -1;
    *new_out = NULL; *new_size_out = 0;
    if (expected_new_size == 0) return 0;
    if (!delta_data || delta_size == 0) return -1;
    uint8_t *out = malloc(expected_new_size);
    if (!out) return -1;
    size_t out_size = expected_new_size;
    if (xd3_decode_memory(delta_data, delta_size, old_data, old_size,
                          out, &out_size, expected_new_size, 0) != 0 ||
        out_size != expected_new_size) { free(out); return -1; }
    *new_out = out; *new_size_out = out_size;
    return 0;
}
