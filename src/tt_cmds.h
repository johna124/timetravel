/* ============================================================
   Time-Travel v1.5 — tt_cmds.h
   Comandos CLI: verify, watch, stop, undo, status, log, etc.
   ============================================================ */
#ifndef TT_CMDS_H
#define TT_CMDS_H

#include "tt_types.h"

#include <stdint.h>

/* ---------------- undo mode ---------------- */
typedef enum {
    UNDO_MODE_TIME,
    UNDO_MODE_LAST,
    UNDO_MODE_INITIAL,
    UNDO_MODE_TAG
} TtUndoMode;

/* ---------------- crypto helpers ---------------- */
int tt_read_passphrase(const char *prompt, char *buf, size_t bufsz, int confirm);
int tt_store_has_records(const char *store_dir);
int tt_unlock_store_key(const char *store_dir, uint8_t key_out[32]);
int tt_unlock_compat_store(const char *store_dir);

/* ---------------- commands ---------------- */
int tt_cmd_verify(const char *repo_dir);
int tt_cmd_watch(const char *dir, int fg, int encrypt);
int tt_cmd_add(const char *dir);
int tt_cmd_stop(const char *repo_dir);
int tt_cmd_undo(const char *path, const char *time_expr, const char *repo_dir,
                TtUndoMode mode, const char *tag_name, int force);
int tt_cmd_status_global(void);
int tt_cmd_status(const char *repo_dir);
int tt_cmd_log(const char *path, const char *repo_dir, const char *since_expr);
int tt_cmd_compact(const char *repo_dir);
int tt_cmd_tag(const char *name, const char *repo_dir);
int tt_cmd_diff(const char *path, const char *repo_dir, const char *time_expr);
int tt_cmd_dump(const char *path, const char *repo_dir, const char *outdir, int with_diff);

/* ---------------- exclusion commands ---------------- */
int tt_cmd_exclude(const char *action, const char *pattern, const char *repo);

#endif /* TT_CMDS_H */
