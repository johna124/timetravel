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
 * tt_crypto.c — XChaCha20-Poly1305 AEAD, C11 puro, sin dependencias
 *   ChaCha20 / HChaCha20 : RFC 8439 / draft-arciszewski-xchacha
 *   Poly1305             : RFC 8439 (radix 2^26, 32-bit safe)
 * ============================================================ */
#include "tt_crypto.h"
#include <stdint.h>
#include <string.h>
#include "tt_types.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include "tt_kdf.h"
#include "tt_blake2b.h"

/* ---------- helpers little-endian ---------- */
static uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0])       | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void store64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define QR(a,b,c,d) do { a+=b; d^=a; d=rotl32(d,16); c+=d; b^=c; b=rotl32(b,12); \
                         a+=b; d^=a; d=rotl32(d,8);  c+=d; b^=c; b=rotl32(b,7); } while (0)

/* ---------- ChaCha20 core ---------- */
static void chacha20_setup(uint32_t x[16], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) x[4 + i] = load32_le(key + i * 4);
    x[12] = counter;
    for (int i = 0; i < 3; ++i) x[13 + i] = load32_le(nonce + i * 4);
}
static void chacha20_core(uint32_t x[16]) {
    for (int i = 0; i < 10; ++i) {           /* 20 rondas = 10 dobles-rondas */
        QR(x[0],x[4],x[8], x[12]); QR(x[1],x[5],x[9], x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8], x[13]); QR(x[3],x[4],x[9], x[14]);
    }
}
/* bloque de keystream (counter, nonce de 12 bytes) */
static void chacha20_block(uint8_t out[64], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
    uint32_t x[16], orig[16];
    chacha20_setup(x, key, counter, nonce);
    memcpy(orig, x, sizeof orig);
    chacha20_core(x);
    for (int i = 0; i < 16; ++i) store32_le(out + i * 4, x[i] + orig[i]);
}
/* keystream XOR (cifra y descifra por igual) */
static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12]) {
    uint8_t block[64];
    size_t off = 0;
    while (off < len) {
        chacha20_block(block, key, counter++, nonce);
        size_t take = len - off;
        if (take > 64) take = 64;
        for (size_t i = 0; i < take; ++i) out[off + i] = in[off + i] ^ block[i];
        off += take;
    }
    memset(block, 0, sizeof block);
}

/* ---------- HChaCha20 (deriva subclave con nonce de 16 bytes) ---------- */
static void hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t n16[16]) {
    uint32_t x[16];
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) x[4 + i] = load32_le(key + i * 4);
    for (int i = 0; i < 4; ++i) x[12 + i] = load32_le(n16 + i * 4);
    chacha20_core(x);                       /* SIN sumar el estado original */
    for (int i = 0; i < 4; ++i) store32_le(out + i * 4, x[i]);
    for (int i = 0; i < 4; ++i) store32_le(out + 16 + i * 4, x[12 + i]);
}

/* ---------- Poly1305 (radix 2^26) ---------- */
typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buffer[16];
    size_t   leftover;
} TtPoly1305;

static void poly1305_init(TtPoly1305 *p, const uint8_t key[32]) {
    /* r = key[0..15] con clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
    uint32_t r0 = load32_le(key + 0)  & 0x0fffffff;
    uint32_t r1 = load32_le(key + 4)  & 0x0ffffffc;
    uint32_t r2 = load32_le(key + 8)  & 0x0ffffffc;
    uint32_t r3 = load32_le(key + 12) & 0x0ffffffc;
    p->r[0] = r0 & 0x3ffffff;
    p->r[1] = ((r0 >> 26) | (r1 << 6))  & 0x3ffffff;
    p->r[2] = ((r1 >> 20) | (r2 << 12)) & 0x3ffffff;
    p->r[3] = ((r2 >> 14) | (r3 << 18)) & 0x3ffffff;
    p->r[4] = (r3 >> 8);
    p->pad[0] = load32_le(key + 16); p->pad[1] = load32_le(key + 20);
    p->pad[2] = load32_le(key + 24); p->pad[3] = load32_le(key + 28);
    p->h[0] = p->h[1] = p->h[2] = p->h[3] = p->h[4] = 0;
    p->leftover = 0;
}
static void poly1305_blocks(TtPoly1305 *p, const uint8_t *m, size_t n, uint32_t hibit) {
    uint32_t r0=p->r[0], r1=p->r[1], r2=p->r[2], r3=p->r[3], r4=p->r[4];
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint32_t h0=p->h[0], h1=p->h[1], h2=p->h[2], h3=p->h[3], h4=p->h[4];
    while (n >= 16) {
        uint32_t t0 = load32_le(m + 0),  t1 = load32_le(m + 4);
        uint32_t t2 = load32_le(m + 8),  t3 = load32_le(m + 12);
        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 << 6))  & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += 16; n -= 16;
    }
    p->h[0]=h0; p->h[1]=h1; p->h[2]=h2; p->h[3]=h3; p->h[4]=h4;
}
static void poly1305_update(TtPoly1305 *p, const uint8_t *m, size_t n) {
    if (p->leftover) {
        size_t want = 16 - p->leftover;
        if (want > n) want = n;
        memcpy(p->buffer + p->leftover, m, want);
        p->leftover += want; m += want; n -= want;
        if (p->leftover < 16) return;
        poly1305_blocks(p, p->buffer, 16, (1u << 24));
        p->leftover = 0;
    }
    if (n >= 16) {
        size_t full = n & ~(size_t)15;
        poly1305_blocks(p, m, full, (1u << 24));
        m += full; n -= full;
    }
    if (n) { memcpy(p->buffer + p->leftover, m, n); p->leftover += n; }
}
static void poly1305_finish(TtPoly1305 *p, uint8_t tag[16]) {
    if (p->leftover) {                     /* bloque final parcial + 0x01 */
        size_t i = p->leftover;
        p->buffer[i++] = 0x01;
        memset(p->buffer + i, 0, 16 - i);
        poly1305_blocks(p, p->buffer, 16, 0);
    }
    uint32_t h0=p->h[0], h1=p->h[1], h2=p->h[2], h3=p->h[3], h4=p->h[4], c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    /* elegir h o h - (2^130 - 5) */
    uint32_t g0=h0+5; c=g0>>26; g0&=0x3ffffff;
    uint32_t g1=h1+c; c=g1>>26; g1&=0x3ffffff;
    uint32_t g2=h2+c; c=g2>>26; g2&=0x3ffffff;
    uint32_t g3=h3+c; c=g3>>26; g3&=0x3ffffff;
    uint32_t g4=h4+c-(1u<<26);
    uint32_t mask = (g4 >> 31) - 1;
    g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
    mask = ~mask;
    h0=(h0&mask)|g0; h1=(h1&mask)|g1; h2=(h2&mask)|g2; h3=(h3&mask)|g3; h4=(h4&mask)|g4;
    /* h mod 2^128 -> 4 palabras, y sumar pad */
    h0 = ((h0)       | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6)  | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8))  & 0xffffffff;
    uint64_t f;
    f = (uint64_t)h0 + p->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + p->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + p->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + p->pad[3] + (f >> 32); h3 = (uint32_t)f;
    store32_le(tag + 0, h0); store32_le(tag + 4, h1);
    store32_le(tag + 8, h2); store32_le(tag + 12, h3);
    memset(p, 0, sizeof *p);
}

/* ---------- AEAD: datos MAC (aad || pad || ct || pad || lens) ---------- */
static void aead_mac_data(TtPoly1305 *p, const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct, size_t ct_len) {
    static const uint8_t zeros[16] = {0};
    uint8_t lenbuf[8];
    if (aad_len) poly1305_update(p, aad, aad_len);
    if (aad_len & 15) poly1305_update(p, zeros, 16 - (aad_len & 15));
    if (ct_len) poly1305_update(p, ct, ct_len);
    if (ct_len & 15) poly1305_update(p, zeros, 16 - (ct_len & 15));
    store64_le(lenbuf, (uint64_t)aad_len); poly1305_update(p, lenbuf, 8);
    store64_le(lenbuf, (uint64_t)ct_len);  poly1305_update(p, lenbuf, 8);
}
static void aead_setup(uint8_t subkey[32], uint8_t cn[12],
                       const uint8_t key[32], const uint8_t nonce[24]) {
    hchacha20(subkey, key, nonce);        /* nonce[0..15] */
    memset(cn, 0, 4);                     /* nonce ChaCha20: 0000 || nonce[16..23] */
    memcpy(cn + 4, nonce + 16, 8);
}

int tt_aead_encrypt(const uint8_t key[TT_KEY_LEN], const uint8_t nonce[TT_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[TT_TAG_LEN]) {
    uint8_t subkey[32], cn[12], poly_key[64];
    aead_setup(subkey, cn, key, nonce);
    chacha20_block(poly_key, subkey, 0, cn);      /* clave Poly1305 de un solo uso */
    chacha20_xor(ct, pt, pt_len, subkey, 1, cn);  /* cifra con counter desde 1 */
    TtPoly1305 p;
    poly1305_init(&p, poly_key);
    aead_mac_data(&p, aad, aad_len, ct, pt_len);
    poly1305_finish(&p, tag);
    memset(subkey, 0, sizeof subkey); memset(poly_key, 0, sizeof poly_key);
    return 0;
}

int tt_aead_decrypt(const uint8_t key[TT_KEY_LEN], const uint8_t nonce[TT_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[TT_TAG_LEN],
                    uint8_t *pt) {
    uint8_t subkey[32], cn[12], poly_key[64];
    aead_setup(subkey, cn, key, nonce);
    chacha20_block(poly_key, subkey, 0, cn);
    TtPoly1305 p;
    poly1305_init(&p, poly_key);
    aead_mac_data(&p, aad, aad_len, ct, ct_len);
    uint8_t calc[TT_TAG_LEN];
    poly1305_finish(&p, calc);
    uint8_t diff = 0;                     /* comparación en tiempo constante */
    for (int i = 0; i < TT_TAG_LEN; ++i) diff |= calc[i] ^ tag[i];
    if (diff != 0) {                       /* autenticación fallida: no descifrar */
        memset(subkey, 0, sizeof subkey); memset(poly_key, 0, sizeof poly_key);
        return -1;
    }
    chacha20_xor(pt, ct, ct_len, subkey, 1, cn);
    memset(subkey, 0, sizeof subkey); memset(poly_key, 0, sizeof poly_key);
    return 0;
}

/* ---------- self-test ---------- */
/* Poly1305 KAT — RFC 8439 §2.5.2 */
static int test_poly1305_kat(void) {
    static const uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33, 0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd, 0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
    static const uint8_t msg[34] = "Cryptographic Forum Research Group";
    static const uint8_t expect[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6, 0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9 };
    TtPoly1305 p;
    uint8_t tag[16];
    poly1305_init(&p, key);
    poly1305_update(&p, msg, 34);
    poly1305_finish(&p, tag);
    return memcmp(tag, expect, 16) == 0 ? 0 : -1;
}
/* ChaCha20 KAT — RFC 8439 §2.4.2 (verificar bytes contra el RFC si falla) */
static int test_chacha20_kat(void) {
    static const uint8_t key[32] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                                     16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
    static const uint8_t nonce[12] = {0,0,0,0,0,0,0,0x4a,0,0,0,0};
    static const char *pt =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one "
        "tip for the future, sunscreen would be it.";
    size_t pt_len = strlen(pt);            /* 114 */
    static const uint8_t expect[114] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
        0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
        0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
        0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,
        0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
        0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
        0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
        0x87,0x4d };
    uint8_t ct[114];
    if (pt_len != 114) return -1;
    chacha20_xor(ct, (const uint8_t *)pt, pt_len, key, 1, nonce);
    return memcmp(ct, expect, 114) == 0 ? 0 : -1;
}
/* Round-trip + tamper del AEAD completo */
static int test_aead_roundtrip(void) {
    uint8_t key[32], nonce[24], ct[64], tag[16], pt[64];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 24; ++i) nonce[i] = (uint8_t)(i + 100);
    static const char *msg = "The quick brown fox jumps over the lazy dog";
    static const char *aad = "tt-meta";
    size_t msg_len = strlen(msg), aad_len = strlen(aad);
    if (tt_aead_encrypt(key, nonce, (const uint8_t *)aad, aad_len,
                        (const uint8_t *)msg, msg_len, ct, tag) != 0) return -1;
    if (tt_aead_decrypt(key, nonce, (const uint8_t *)aad, aad_len,
                        ct, msg_len, tag, pt) != 0) return -1;
    if (memcmp(pt, msg, msg_len) != 0) return -1;
    ct[0] ^= 0x01;                          /* ciphertext manipulado → debe fallar */
    if (tt_aead_decrypt(key, nonce, (const uint8_t *)aad, aad_len,
                        ct, msg_len, tag, pt) == 0) return -1;
    ct[0] ^= 0x01;
    tag[0] ^= 0x01;                         /* tag manipulado → debe fallar */
    if (tt_aead_decrypt(key, nonce, (const uint8_t *)aad, aad_len,
                        ct, msg_len, tag, pt) == 0) return -1;
    return 0;
}
int tt_crypto_selftest(void) {
    if (test_poly1305_kat() != 0) return -1;
    if (test_chacha20_kat() != 0) return -1;
    if (test_aead_roundtrip() != 0) return -1;
    return 0;
}

#define TT_CRYPTO_MAGIC "TTCRYPT01"
#define TT_CRYPTO_MAGIC_LEN 9
#define TT_CRYPTO_META_FILE "crypto.meta"

int tt_crypto_is_encrypted(const char *store_dir) {
    char path[TT_PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", store_dir, TT_CRYPTO_META_FILE);
    struct stat st;
    return (stat(path, &st) == 0);
}

/* Crea crypto.meta con un salt aleatorio y el verificador de la clave */
int tt_crypto_setup_repo(const char *store_dir, const uint8_t *pass, size_t passlen) {
    char path[TT_PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", store_dir, TT_CRYPTO_META_FILE);
    uint8_t salt[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    if (read(fd, salt, 16) != 16) { close(fd); return -1; }
    close(fd);

    uint8_t key[32];
    if (tt_kdf_pbkdf2(pass, passlen, salt, 16, TT_KDF_ITERATIONS, key, 32) != 0) return -1;

    uint8_t verifier[32];
    if (tt_blake2b(key, 32, verifier, 32) != 0) return -1;

    uint8_t buf[9 + 16 + 4 + 32];
    memcpy(buf, TT_CRYPTO_MAGIC, 9);
    memcpy(buf + 9, salt, 16);
    uint32_t iters = TT_KDF_ITERATIONS;
    buf[25] = (uint8_t)iters; buf[26] = (uint8_t)(iters>>8);
    buf[27] = (uint8_t)(iters>>16); buf[28] = (uint8_t)(iters>>24);
    memcpy(buf + 29, verifier, 32);

    int wfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (wfd < 0) return -1;
    if (write(wfd, buf, sizeof buf) != sizeof buf) { close(wfd); return -1; }
    close(wfd);
    return 0;
}

/* Lee crypto.meta, deriva la clave y comprueba el verificador */
int tt_crypto_unlock_repo(const char *store_dir, const uint8_t *pass, size_t passlen, uint8_t key_out[32]) {
    char path[TT_PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", store_dir, TT_CRYPTO_META_FILE);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t buf[9 + 16 + 4 + 32];
    if (read(fd, buf, sizeof buf) != sizeof buf) { close(fd); return -1; }
    close(fd);
    if (memcmp(buf, TT_CRYPTO_MAGIC, 9) != 0) return -1;

    uint8_t *salt = buf + 9;
    uint32_t iters = (uint32_t)buf[25] | ((uint32_t)buf[26]<<8) | ((uint32_t)buf[27]<<16) | ((uint32_t)buf[28]<<24);
    if (iters < 10000u || iters > 10000000u) return -1;
    uint8_t *verifier = buf + 29;

    uint8_t key[32];
    if (tt_kdf_pbkdf2(pass, passlen, salt, 16, iters, key, 32) != 0) return -1;

    uint8_t calc_verifier[32];
    if (tt_blake2b(key, 32, calc_verifier, 32) != 0) return -1;

    { uint8_t diff = 0;
        for (int i = 0; i < 32; ++i) diff |= calc_verifier[i] ^ verifier[i];
        if (diff != 0) return -1; } /* comparación constante */

    memcpy(key_out, key, 32);
    return 0;
}
