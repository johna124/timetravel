/* ============================================================
   Time-Travel v1.5 — tt_repo.h
   Ciclo de vida de repos: adopción, PID, status, salud de raíz.
   ============================================================ */
#ifndef TT_REPO_H
#define TT_REPO_H

#include "tt_types.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* ---------------- PID ---------------- */
void  tt_pid_file_path(char *out, size_t n, const char *store_dir);
int   tt_write_pid_file(const char *store_dir);
pid_t tt_read_pid_file(const char *store_dir, uint64_t *start_ns);
pid_t tt_find_running_daemon(const char *store_dir, uint64_t *start_ns);

/* ---------------- Status ---------------- */
typedef struct {
    int valid;
    pid_t pid;
    uint64_t start_ns, deltas, bytes, pending, updated_ns;
    char watch_dir[TT_PATH_MAX];
    int repo_count;
    struct {
        char root[TT_PATH_MAX];
        uint64_t deltas, bytes, files;
        int lost;
    } repos[TT_MAX_REPOS];
} TtStatusFile;

void tt_status_file_path(char *out, size_t n, const char *store_dir);
void tt_status_write_content(TtDaemon *d, FILE *f,
                             uint64_t td, uint64_t tb, uint64_t tp);
void tt_status_write(TtDaemon *d);
int  tt_status_read_file(const char *path, TtStatusFile *sf);
int  tt_status_read(const char *store_dir, TtStatusFile *sf);

/* ---------------- Root health ---------------- */
void tt_handle_root_health_repo(TtDaemon *d, TtLocalRepo *r);

/* ---------------- Repo lifecycle ---------------- */
void tt_repo_list_path(char *out, size_t n, const char *store_dir);
void tt_repo_list_sync(TtDaemon *d);
int  tt_repo_overlaps(TtDaemon *d, const char *abs);
int  tt_repo_adopt_base(TtDaemon *d, const char *abs_dir,
                         char *err, size_t errsz);
void tt_repo_finish_watch(TtDaemon *d, int repo_id);
void tt_repo_list_load(TtDaemon *d);
void tt_repo_release(TtDaemon *d, int idx);

#endif /* TT_REPO_H */
