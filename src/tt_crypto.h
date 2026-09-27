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
#ifndef TT_CRYPTO_H
#define TT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define TT_KEY_LEN    32   /* clave simétrica */
#define TT_NONCE_LEN  24   /* nonce extendido XChaCha20 */
#define TT_TAG_LEN    16   /* tag Poly1305 */

int tt_crypto_is_encrypted(const char *store_dir);
int tt_crypto_setup_repo(const char *store_dir, const uint8_t *pass, size_t passlen);
int tt_crypto_unlock_repo(const char *store_dir, const uint8_t *pass, size_t passlen, uint8_t key_out[32]);

/* XChaCha20-Poly1305 AEAD (RFC 8439 + draft-arciszewski-xchacha).
 * Cifra pt_len bytes de pt en ct (mismo tamaño) y genera el tag.
 * aad/aad_len: datos asociados autenticados pero NO cifrados (metadatos).
 * Devuelve 0 en éxito. */
int tt_aead_encrypt(const uint8_t key[TT_KEY_LEN], const uint8_t nonce[TT_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[TT_TAG_LEN]);

/* Descifra y autentica. Devuelve 0 si el tag es válido; -1 si falla la
 * autenticación (ct pudo ser manipulado; el contenido de pt no es fiable). */
int tt_aead_decrypt(const uint8_t key[TT_KEY_LEN], const uint8_t nonce[TT_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[TT_TAG_LEN],
                    uint8_t *pt);

/* Self-test: vectores oficiales (RFC 8439) + round-trip + tamper.
 * Devuelve 0 si todo es correcto, -1 si algo falla. */
int tt_crypto_selftest(void);


/* Cifra un path (rel) con la clave del repo.
nonce: derivado de path_index + timestamp (evita nonces repetidos).
aad: timestamp_ns || event_type (autentica el contexto).
Devuelve 0 en éxito. ct debe tener al menos pt_len bytes. */
int tt_encrypt_path(const uint8_t key[TT_KEY_LEN],
                  uint64_t path_index, uint64_t timestamp_ns,
                  uint8_t event_type,
                  const char *path, size_t path_len,
                  uint8_t *ct, uint8_t tag[TT_TAG_LEN]);

/* Descifra un path cifrado. Devuelve 0 si autenticación OK, -1 si falla. */
int tt_decrypt_path(const uint8_t key[TT_KEY_LEN],
                    uint64_t path_index, uint64_t timestamp_ns,
                    uint8_t event_type,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[TT_TAG_LEN],
                    char *path_out, size_t path_out_sz);

/* Deriva un nonce de 24 bytes a partir de un path_index y timestamp.
Usa BLAKE2b para asegurar que nunca se repite. */
void tt_path_nonce(uint64_t path_index, uint64_t timestamp_ns,
                   uint8_t nonce[TT_NONCE_LEN]);


/* Clave de repo: genera o lee .timetravel/repo.key (32 bytes aleatorios).
Transparente: se crea automáticamente al primer uso. Permisos 0600. */
int tt_repo_get_key(const char *store_dir, uint8_t key_out[TT_KEY_LEN]);

/* Cifra un archivo completo con AEAD.
Formato de salida: "TTENC01" || nonce(24) || tag(16) || ciphertext. */
int tt_crypto_encrypt_file(const char *plaintext_path,
                           const char *encrypted_path,
                           const uint8_t key[TT_KEY_LEN]);

/* Descifra un archivo cifrado con tt_crypto_encrypt_file.
Devuelve 0 en éxito, -1 si falla la autenticación. */
int tt_crypto_decrypt_file(const char *encrypted_path,
                           const char *plaintext_path,
                           const uint8_t key[TT_KEY_LEN]);

#endif
