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
/* tt_blake2b.h */
#ifndef TT_BLAKE2B_H
#define TT_BLAKE2B_H
#include <stddef.h>
#include <stdint.h>
#define TT_BLAKE2B_256_LEN 32
#define TT_BLAKE2B_MAX_LEN 64
int tt_blake2b(const void *in, size_t inlen, void *out, size_t outlen);
int tt_blake2b_selftest(void);
#endif
