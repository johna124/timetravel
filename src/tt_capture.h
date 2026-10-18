/* ============================================================
   Time-Travel v1.5 — tt_capture.h
   Pipeline de captura: CREATE/MODIFY/DELETE, walks y rescans.
   ============================================================ */
#ifndef TT_CAPTURE_H
#define TT_CAPTURE_H

#include "tt_types.h"
#include "tt_history.h"

#include <stddef.h>
#include <stdint.h>

/* ---------------- escritura de records ---------------- */
int tt_write_create_record_ts(TtLocalRepo *r, const char *rel,
                              const uint8_t *data, size_t size,
                              uint64_t ts);

int tt_write_create_record(TtLocalRepo *r, const char *rel,
                           const uint8_t *data, size_t size);

int tt_write_version_record(TtLocalRepo *r, const char *rel,
                            const uint8_t *old, size_t old_size,
                            const uint8_t *newd, size_t new_size);

/* ---------------- captura ---------------- */
int tt_capture_path(TtDaemon *d, TtLocalRepo *r, const char *rel, int quiet);

/* ---------------- builds / rescans ---------------- */
void tt_capture_build_walk_repo(TtDaemon *d, TtLocalRepo *r, TtPathSet *hist,
                                const char *dir_full, const char *rel_prefix,
                                size_t *n_files);

void tt_capture_build_initial_repo(TtDaemon *d, TtLocalRepo *r);

void tt_capture_rescan_walk_repo(TtDaemon *d, TtLocalRepo *r,
                                 const char *dir_full, const char *rel_prefix,
                                 int *written);

void tt_capture_rescan_and_sync_repo(TtDaemon *d, TtLocalRepo *r);

/* ---------------- debounce callback ---------------- */
void tt_capture_on_debounced(TtDaemon *d, const char *full_path,
                             uint8_t event_type, void *user);

#endif /* TT_CAPTURE_H */
