/* ============================================================
   Time-Travel v1.5 — tt_util.h
   Utilidades puras: paths, tiempo, I/O, procesos, formato.
   Sin dependencias internas (solo tt_types.h + sistema).
   ============================================================ */
#ifndef TT_UTIL_H
#define TT_UTIL_H

#include "tt_types.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* ---------------- logging ---------------- */
void tt_log(const char *fmt, ...);

/* ---------------- timestamp ---------------- */
uint64_t tt_next_ts(void);

/* ---------------- file I/O ---------------- */
int read_file_all(const char *full, uint8_t **out, size_t *out_size);
int write_file_all(const char *path, const uint8_t *data, size_t size);
int mkdir_p(const char *path);

/* ---------------- path sanitization ---------------- */
void sanitize_component(const char *in, char *out, size_t outsz);

/* ---------------- external diff ---------------- */
int run_diff_file(const char *a, const char *b, const char *out);

/* ---------------- process info ---------------- */
int    proc_alive(pid_t pid);
long   proc_rss_kb(pid_t pid);
int    proc_stat_fields(pid_t pid, unsigned long *utime,
                        unsigned long *stime, unsigned long long *starttime);
double proc_cpu_total_sec(pid_t pid);
double proc_cpu_percent(pid_t pid);

/* ---------------- parsing ---------------- */
int is_integer(const char *s, long long *out);

/* ---------------- time expressions ---------------- */
uint64_t parse_time_expr(const char *expr, int *ok);

/* ---------------- formatting ---------------- */
void format_timestamp(uint64_t ns, char *out, size_t sz);
void format_bytes(uint64_t b, char *out, size_t sz);
void format_ns_duration(uint64_t ns, char *out, size_t sz);

/* ---------------- path resolution ---------------- */
int find_repo_dir(const char *path, char *out, size_t out_size);
int normalize_dir(const char *in, char *out, size_t outsz);
int resolve_repo_arg(const char *repo_dir, const char *fallback_path,
                     char *wd, size_t wdsz);
int make_rel_from_arg(const char *wd, const char *path,
                      char *rel, size_t relsz);

/* ---------------- multi-dir helpers ---------------- */
int normalize_dir_arg(const char *in, char *out, size_t outsz);
int dir_is_inside(const char *parent, const char *child);
int check_start_overlaps(char dirs[][TT_PATH_MAX], int n);

#endif /* TT_UTIL_H */
