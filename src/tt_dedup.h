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
#ifndef TT_DEDUP_H
#define TT_DEDUP_H

#include <stddef.h>
#include <stdint.h>

#ifndef TT_DEDUP_HASH_LEN
#define TT_DEDUP_HASH_LEN    32
#endif

int tt_dedup_store_block(const char *store_dir, const uint8_t *data, size_t size,
                         uint8_t hash_out[TT_DEDUP_HASH_LEN], const uint8_t *key);
uint8_t *tt_dedup_get_block(const char *store_dir, const uint8_t *hash, size_t *out_size,
                            const uint8_t *key);
int tt_dedup_split(const char *store_dir, const uint8_t *data, size_t size,
                   uint8_t **hashes_out, size_t *nblocks_out, const uint8_t *key);
int tt_dedup_reconstruct(const char *store_dir, const uint8_t *payload, size_t payload_size,
                         uint8_t **out, size_t *out_size, const uint8_t *key);
int tt_dedup_gc(const char *store_dir);

#endif
