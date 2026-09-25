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
#ifndef TT_TYPES_H
#define TT_TYPES_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define TT_PATH_MAX          4096
#define TT_DEBOUNCE_MS       200
#define TT_TICK_MS           50
#define TT_RESCAN_MS         10000
/* TT_COMPACT_HOUR eliminado en v1.3: la compactacion solo es manual. */
#define TT_COMPACT_THRESHOLD 15
/* v1.3: era 4096 global. Ahora es POR REPO y en heap; 512 rutas
   pendientes simultaneas por repo es holgado (ventana de 200 ms). */
#define TT_MAX_PENDING       512
#define TT_MAX_CAPTURE_SIZE  (64ULL * 1024ULL * 1024ULL)

/* ===================== v1.4: DEDUP ===================== */
#define TT_DEDUP_BLOCK_SIZE  (64ULL * 1024ULL)      /* 64 KiB por bloque */
#define TT_DEDUP_MIN_SIZE    (1ULL * 1024ULL * 1024ULL) /* dedup desde 1 MiB */
#define TT_DEDUP_HASH_LEN    32                       /* BLAKE2b-256 */

/* ===================== v1.3: MULTI-REPO ===================== */
#define TT_MAX_REPOS         16    /* limite estricto anti-OOM */
#define TT_IPC_SOCK_NAME     "timetravel.ipc"

typedef enum {
    TT_EV_CREATE = 1, TT_EV_MODIFY = 2, TT_EV_DELETE = 3, TT_EV_RENAME = 4,
    TT_EV_CREATE_DEDUP = 5   /* v1.4: contenido como referencias de bloques dedup */
} TtEventType;

/* Formato de disco: NO TOCAR (packed = 25 bytes, compatible con v1.2).
   Con cifrado activo, delta_size guarda el tamano ALMACENADO
   (payload cifrado + nonce + tag); el lector lo restaura al descifrar. */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_ns;
    uint8_t  event_type;
    uint32_t path_len;
    uint32_t delta_size;
    uint64_t file_size;
} TtDeltaHeader;

typedef struct {
    char     path[TT_PATH_MAX];
    uint64_t last_event_ns;
    uint8_t  event_type;
    int      pending_close;
    int      active;
} TtPendingEntry;

typedef struct {
    TtPendingEntry entries[TT_MAX_PENDING];
    size_t count;
} TtDebounce;

typedef struct { int wd; int repo_id; char path[TT_PATH_MAX]; } TtWatchEntry;

typedef struct {
    TtWatchEntry *entries;
    size_t count, cap;
} TtWatchMap;

typedef struct {
    char    path[TT_PATH_MAX];
    uint8_t *data;
    size_t  size;
    int     active;
    int     anchored;          /* el ultimo estado del almacen == cache */
    int     baseline_pending;  /* sin historial: el 1er cambio guarda el original */
} TtStateEntry;

typedef struct {
    TtStateEntry *entries;
    size_t count, cap, active_count;
} TtStateCache;

/* Contextos por repo de tt_store.c (opacos aqui) */
typedef struct TtStore TtStore;
typedef struct TtStoreReaderCtx TtStoreReader;

/* Repositorio autonomo: 1 carpeta + 1 .timetravel + 1 cache + 1 cola */
typedef struct {
    int      active;
    int      repo_id;
    char     root[TT_PATH_MAX];       /* dir vigilada, absoluta (realpath) */
    char     store_dir[TT_PATH_MAX];  /* <root>/.timetravel */
    int      root_wd;
    int      root_lost;
    uint64_t start_ns;
    uint64_t deltas_written;
    uint64_t bytes_stored;
    TtStateCache cache;
    TtDebounce  *debounce;    /* heap: ~2 MB, solo si el repo existe */
    TtStore     *store;       /* escritor .ttd propio, sin globales */
} TtLocalRepo;

/* Administrador global del enjambre */
typedef struct TtDaemon {
    int running;
    int inotify_fd;                  /* UNICO fd para todos los repos */
    int timer_fd;
    int ipc_fd;                      /* socket pasivo (3er pollfd) */
    char ipc_path[TT_PATH_MAX];
    uint64_t start_ns;
    int repo_count;
    TtLocalRepo repos[TT_MAX_REPOS];
    TtWatchMap wmap;                 /* wd -> repo_id (enjambre completo) */
    int rescan_needed;
    uint64_t rescan_accum_ms;
    int      has_crypto_key;
    uint8_t  crypto_key[32];
} TtDaemon;

typedef void (*TtProcessCb)(TtDaemon *d, const char *full_path, uint8_t event_type, void *user);

static inline uint64_t tt_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif
