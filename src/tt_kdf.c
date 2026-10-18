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
/* ============================================================
 * tt_kdf.c — PBKDF2-HMAC-BLAKE2b (passphrase -> clave)
 * HMAC segun RFC 2104 sobre BLAKE2b (block size 128).
 * ============================================================ */
#include "tt_kdf.h"
#include "tt_blake2b.h"
#include <stdlib.h>
#include <string.h>

/* HMAC-BLAKE2b. Salida fija de 64 bytes. */
static int hmac_blake2b(const uint8_t *key, size_t keylen,
                        const uint8_t *msg, size_t msglen,
                        uint8_t out[64]) {
    uint8_t k[128];
    memset(k, 0, sizeof k);
    if (keylen > 128) {                       /* clave larga: se hashea primero */
        uint8_t kh[64];
        if (tt_blake2b(key, keylen, kh, 64) != 0) return -1;
        memcpy(k, kh, 64);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }
    /* inner = BLAKE2b((k ^ ipad) || msg) */
    uint8_t *inner_in = malloc(128 + (msglen ? msglen : 1));
    if (!inner_in) return -1;
    for (int i = 0; i < 128; ++i) inner_in[i] = k[i] ^ 0x36;
    if (msglen) memcpy(inner_in + 128, msg, msglen);
    uint8_t inner[64];
    int rc = tt_blake2b(inner_in, 128 + msglen, inner, 64);
    free(inner_in);
    if (rc != 0) return -1;
    /* outer = BLAKE2b((k ^ opad) || inner) */
    uint8_t outer_in[128 + 64];
    for (int i = 0; i < 128; ++i) outer_in[i] = k[i] ^ 0x5c;
    memcpy(outer_in + 128, inner, 64);
    return tt_blake2b(outer_in, 128 + 64, out, 64);
}

int tt_kdf_pbkdf2(const uint8_t *password, size_t passlen,
                  const uint8_t *salt, size_t saltlen,
                  uint32_t iterations,
                  uint8_t *out, size_t outlen) {
    if (!out || outlen == 0 || outlen > 64) return -1;
    if (iterations == 0) return -1;
    if (!password && passlen > 0) return -1;
    if (!salt && saltlen > 0) return -1;
    if (saltlen > SIZE_MAX - 4) return -1;
    const size_t hlen = 64;
    size_t blocks = (outlen + hlen - 1) / hlen;
    uint8_t *salt_i = malloc(saltlen + 4);
    if (!salt_i) return -1;
    memcpy(salt_i, salt, saltlen);
    for (size_t b = 1; b <= blocks; ++b) {
        salt_i[saltlen + 0] = (uint8_t)(b >> 24);   /* INT32 big-endian */
        salt_i[saltlen + 1] = (uint8_t)(b >> 16);
        salt_i[saltlen + 2] = (uint8_t)(b >> 8);
        salt_i[saltlen + 3] = (uint8_t)(b);
        uint8_t U[64], T[64];
        if (hmac_blake2b(password, passlen, salt_i, saltlen + 4, U) != 0) {
            free(salt_i); return -1;
        }
        memcpy(T, U, 64);
        for (uint32_t i = 1; i < iterations; ++i) {
            if (hmac_blake2b(password, passlen, U, 64, U) != 0) { free(salt_i); return -1; }
            for (int j = 0; j < 64; ++j) T[j] ^= U[j];
        }
        size_t off = (b - 1) * hlen;
        size_t take = outlen - off;
        if (take > hlen) take = hlen;
        memcpy(out + off, T, take);
    }
    free(salt_i);
    return 0;
}

int tt_kdf_selftest(void) {
    uint8_t salt[16];
    for (int i = 0; i < 16; ++i) salt[i] = (uint8_t)i;
    const char *pw  = "correct horse battery staple";
    const char *pw2 = "correct horse battery staplz";
    uint8_t k1[32], k2[32], k3[32];
    /* determinismo: misma entrada -> misma clave */
    if (tt_kdf_pbkdf2((const uint8_t *)pw, strlen(pw), salt, 16, 1000, k1, 32) != 0) return -1;
    if (tt_kdf_pbkdf2((const uint8_t *)pw, strlen(pw), salt, 16, 1000, k2, 32) != 0) return -1;
    if (memcmp(k1, k2, 32) != 0) return -1;
    /* sensibilidad a la contrasena */
    if (tt_kdf_pbkdf2((const uint8_t *)pw2, strlen(pw2), salt, 16, 1000, k3, 32) != 0) return -1;
    if (memcmp(k1, k3, 32) == 0) return -1;
    /* sensibilidad al salt */
    uint8_t salt2[16]; memcpy(salt2, salt, 16); salt2[0] ^= 1;
    if (tt_kdf_pbkdf2((const uint8_t *)pw, strlen(pw), salt2, 16, 1000, k3, 32) != 0) return -1;
    if (memcmp(k1, k3, 32) == 0) return -1;
    /* sensibilidad a las iteraciones */
    if (tt_kdf_pbkdf2((const uint8_t *)pw, strlen(pw), salt, 16, 1001, k3, 32) != 0) return -1;
    if (memcmp(k1, k3, 32) == 0) return -1;
    return 0;
}
