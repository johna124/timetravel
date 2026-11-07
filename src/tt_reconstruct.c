/* ============================================================
   Time-Travel v1.5 — tt_reconstruct.c
   Motor unificado de reconstrucción de estado (point-in-time).
   ============================================================ */
#include "tt_reconstruct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- externs ---------------- */
extern int tt_store_reader_init(void);
extern int tt_store_reader_next(TtDeltaHeader *h, char *p, size_t ps,
                                uint8_t **pl, size_t *plsz);
extern void tt_store_reader_free(void);

extern int tt_delta_decode(const uint8_t *old_data, size_t old_size,
                           const uint8_t *delta_data, size_t delta_size,
                           size_t expected_new_size,
                           uint8_t **new_out, size_t *new_size_out);

extern int tt_dedup_reconstruct(const char *store_dir,
                                const uint8_t *payload, size_t payload_size,
                                uint8_t **out, size_t *out_size,
                                const uint8_t *key);

extern const uint8_t *tt_store_compat_get_key(void);

/* ==================== implementación ==================== */

int tt_reconstruct_file(const char *store_dir, const char *rel_path,
                        uint64_t target_ns,
                        uint8_t **out_data, size_t *out_size, int *out_exists)
{
    if (out_data) *out_data = NULL;
    if (out_size) *out_size = 0;
    if (out_exists) *out_exists = 0;

    if (!store_dir || !rel_path)
        return -1;

    if (tt_store_reader_init() != 0)
        return -1;

    uint8_t *state = NULL;
    size_t state_size = 0;
    int have = 0;

    for (;;) {
        TtDeltaHeader hdr;
        char path[TT_PATH_MAX];
        uint8_t *pl = NULL;
        size_t plsz = 0;

        int rc = tt_store_reader_next(&hdr, path, sizeof path, &pl, &plsz);
        if (rc <= 0)
            break;

        /* filtrar por path */
        if (strcmp(path, rel_path) != 0) {
            free(pl);
            continue;
        }

        /* filtrar por tiempo (si target_ns > 0) */
        if (target_ns > 0 && hdr.timestamp_ns > target_ns) {
            free(pl);
            continue;
        }

        /* --- máquina de estados --- */

        if (hdr.event_type == TT_EV_DELETE) {
            free(state);
            state = NULL;
            state_size = 0;
            have = 0;

        } else if (hdr.event_type == TT_EV_CREATE) {
            free(state);
            state = NULL;
            state_size = 0;

            if (plsz > 0 && pl) {
                state = malloc(plsz);
                if (!state) {
                    free(pl);
                    tt_store_reader_free();
                    return -1;
                }
                memcpy(state, pl, plsz);
                state_size = plsz;
            }
            have = 1;

        } else if (hdr.event_type == TT_EV_CREATE_DEDUP) {
            free(state);
            state = NULL;
            state_size = 0;

            uint8_t *rec = NULL;
            size_t rec_sz = 0;

            if (pl && plsz > 0 &&
                tt_dedup_reconstruct(store_dir, pl, plsz,
                                     &rec, &rec_sz,
                                     tt_store_compat_get_key()) == 0) {
                state = rec;
                state_size = rec_sz;
                have = 1;
            } else {
                free(rec);
                tt_store_reader_free();
                return -1;   /* bloque faltante o corrupto */
            }

        } else if (hdr.event_type == TT_EV_MODIFY) {
            if (plsz > 0) {
                int changed = 0;

                /* caso normal: delta sobre el estado anterior */
                if (have) {
                    uint8_t *ns = NULL;
                    size_t nss = 0;
                    if (tt_delta_decode(state, state_size,
                                        pl, plsz,
                                        hdr.file_size,
                                        &ns, &nss) == 0) {
                        free(state);
                        state = ns;
                        state_size = nss;
                        changed = 1;
                    }
                }

                /* fallback: algunos MODIFY antiguos guardan el contenido completo */
                if (!changed && plsz == hdr.file_size) {
                    free(state);
                    state = malloc(plsz);
                    if (state) {
                        memcpy(state, pl, plsz);
                        state_size = plsz;
                        have = 1;
                    }
                }
            }
        }

        free(pl);
    }

    tt_store_reader_free();

    if (!have) {
        free(state);
        return 0; /* no existía en ese punto */
    }

    if (out_exists) *out_exists = 1;
    if (out_data) *out_data = state;
    else free(state); /* si el caller no quiere los datos, los liberamos */
    if (out_size) *out_size = state_size;

    return 0;
}
