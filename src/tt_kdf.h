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
#ifndef TT_KDF_H
#define TT_KDF_H

#include <stddef.h>
#include <stdint.h>

#define TT_KDF_SALT_LEN    16
#define TT_KDF_KEY_LEN     32
/* Iteraciones por defecto. Calibrar para ~0.5-1 s en el hardware objetivo
 * (a mas iteraciones, mas lento el ataque de fuerza bruta). */
#define TT_KDF_ITERATIONS  100000u

/* PBKDF2-HMAC-BLAKE2b. Deriva `outlen` bytes (max 64) en `out`.
 * Devuelve 0 en exito, -1 en error. */
int tt_kdf_pbkdf2(const uint8_t *password, size_t passlen,
                  const uint8_t *salt, size_t saltlen,
                  uint32_t iterations,
                  uint8_t *out, size_t outlen);

int tt_kdf_selftest(void);

#endif
