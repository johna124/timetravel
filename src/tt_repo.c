/* ============================================================
   Time-Travel v1.5 — tt_repo.c
   Ciclo de vida de repos: adopción, PID, status, salud de raíz.
   ============================================================ */
#include "tt_repo.h"
#include "tt_util.h"
#include "tt_cache.h"
#include "tt_capture.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tt_exclude.h"

/* ---------------- externs ---------------- */
extern TtStore *tt_store_open(const char *, int);
extern void     tt_store_close(TtStore *);
extern void     tt_store_set_key(TtStore *, const uint8_t key[32]);

extern int  tt_watcher_add_repo(TtDaemon *, int);
extern int  tt_watcher_remove_repo(TtDaemon *, int);
extern int  tt_watcher_rebuild_repo(TtDaemon *, int);

extern void tt_debounce_init(TtDebounce *);
extern void tt_debounce_free(TtDebounce *);

extern void tt_ipc_global_status_path(char *, size_t);

/* ==================== PID ==================== */

void tt_pid_file_path(char *out, size_t n, const char *store_dir)
{
    snprintf(out, n, "%s/timetravel.pid", store_dir);
}

int tt_write_pid_file(const char *store_dir)
{
    char pf[TT_PATH_MAX + 64];
    tt_pid_file_path(pf, sizeof pf, store_dir);

    int fd = open(pf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    char buf[64];
    int n = snprintf(buf, sizeof buf, "%d %llu\n",
                     (int)getpid(),
                     (unsigned long long)tt_now_ns());
    if (write(fd, buf, (size_t)n) != n) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

pid_t tt_read_pid_file(const char *store_dir, uint64_t *start_ns)
{
    char pf[TT_PATH_MAX + 64];
    tt_pid_file_path(pf, sizeof pf, store_dir);

    FILE *f = fopen(pf, "r");
    if (!f)
        return -1;

    pid_t pid = -1;
    unsigned long long sns = 0;
    if (fscanf(f, "%d %llu", &pid, &sns) < 1)
        pid = -1;
    fclose(f);

    if (start_ns)
        *start_ns = (uint64_t)sns;
    return pid;
}

pid_t tt_find_running_daemon(const char *store_dir, uint64_t *start_ns)
{
    pid_t pid = tt_read_pid_file(store_dir, start_ns);
    if (pid > 0 && kill(pid, 0) == 0)
        return pid;
    return -1;
}

/* ==================== Status ==================== */

void tt_status_file_path(char *out, size_t n, const char *store_dir)
{
    snprintf(out, n, "%s/timetravel.status", store_dir);
}

void tt_status_write_content(TtDaemon *d, FILE *f,
                             uint64_t td, uint64_t tb, uint64_t tp)
{
    fprintf(f, "pid=%d\nstart_ns=%llu\ndeltas=%llu\nbytes=%llu\npending=%llu\nrepos=%d\nwatch_dir=%s\n",
            (int)getpid(), (unsigned long long)d->start_ns,
            (unsigned long long)td, (unsigned long long)tb, (unsigned long long)tp,
            d->repo_count, d->repos[0].root);

    for (int j = 0; j < d->repo_count; ++j) {
        TtLocalRepo *r = &d->repos[j];
        if (!r->active)
            continue;
        fprintf(f, "repo.%d=%s|%llu|%llu|%zu|%d\n", j, r->root,
                (unsigned long long)r->deltas_written,
                (unsigned long long)r->bytes_stored,
                r->cache.active_count, r->root_lost);
    }
    fprintf(f, "updated_ns=%llu\n", (unsigned long long)tt_now_ns());
}

void tt_status_write(TtDaemon *d)
{
    if (!d || d->repo_count < 1)
        return;

    uint64_t td = 0, tb = 0, tp = 0;
    for (int i = 0; i < d->repo_count; ++i) {
        TtLocalRepo *r = &d->repos[i];
        if (!r->active)
            continue;
        td += r->deltas_written;
        tb += r->bytes_stored;
        if (r->debounce)
            tp += r->debounce->count;
    }
        for (int i = 0; i < d->repo_count; ++i) {
        char fin[TT_PATH_MAX + 64], tmp[TT_PATH_MAX + 64 + 8];
        tt_status_file_path(fin, sizeof fin, d->repos[i].store_dir);
        snprintf(tmp, sizeof tmp, "%s.tmp", fin);


        FILE *f = fopen(tmp, "w");
        if (!f)
            continue;
        tt_status_write_content(d, f, td, tb, tp);
        fclose(f);
        if (rename(tmp, fin) != 0)
            unlink(tmp);
    }

    char gfin[TT_PATH_MAX], gtmp[TT_PATH_MAX + 40];
    tt_ipc_global_status_path(gfin, sizeof gfin);
    snprintf(gtmp, sizeof gtmp, "%s.tmp.%d", gfin, (int)getpid());

    FILE *gf = fopen(gtmp, "w");
    if (gf) {
        tt_status_write_content(d, gf, td, tb, tp);
        fclose(gf);
        if (rename(gtmp, gfin) != 0)
            unlink(gtmp);
    }
}

int tt_status_read_file(const char *path, TtStatusFile *sf)
{
    memset(sf, 0, sizeof *sf);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[TT_PATH_MAX + 128];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';

        if (!strncmp(line, "pid=", 4))
            sf->pid = (pid_t)atol(line + 4);
        else if (!strncmp(line, "start_ns=", 9))
            sf->start_ns = strtoull(line + 9, NULL, 10);
        else if (!strncmp(line, "deltas=", 7))
            sf->deltas = strtoull(line + 7, NULL, 10);
        else if (!strncmp(line, "bytes=", 6))
            sf->bytes = strtoull(line + 6, NULL, 10);
        else if (!strncmp(line, "pending=", 8))
            sf->pending = strtoull(line + 8, NULL, 10);
        else if (!strncmp(line, "updated_ns=", 11))
            sf->updated_ns = strtoull(line + 11, NULL, 10);
        else if (!strncmp(line, "watch_dir=", 10))
            snprintf(sf->watch_dir, sizeof sf->watch_dir, "%.*s", (int)(sizeof(sf->watch_dir) - 1), line + 10);
        else if (!strncmp(line, "repo.", 5) && sf->repo_count < TT_MAX_REPOS) {
            char *eq = strchr(line, '=');
            if (eq) {
                int idx = sf->repo_count;
                char *p = eq + 1;
                char *bar = strchr(p, '|');
                size_t rl = bar ? (size_t)(bar - p) : strlen(p);
                if (rl >= sizeof sf->repos[idx].root)
                    rl = sizeof sf->repos[idx].root - 1;
                memcpy(sf->repos[idx].root, p, rl);
                sf->repos[idx].root[rl] = '\0';

                unsigned long long dd = 0, bb = 0, ff = 0;
                int lo = 0;
                if (bar && sscanf(bar + 1, "%llu|%llu|%llu|%d", &dd, &bb, &ff, &lo) >= 3) {
                    sf->repos[idx].deltas = dd;
                    sf->repos[idx].bytes = bb;
                    sf->repos[idx].files = ff;
                    sf->repos[idx].lost = lo;
                }
                sf->repo_count++;
            }
        }
    }
    fclose(f);

    sf->valid = (sf->pid > 0);
    return sf->valid ? 0 : -1;
}

int tt_status_read(const char *store_dir, TtStatusFile *sf)
{
    char path[TT_PATH_MAX + 64];
    tt_status_file_path(path, sizeof path, store_dir);
    return tt_status_read_file(path, sf);
}

/* ==================== Root health ==================== */

void tt_handle_root_health_repo(TtDaemon *d, TtLocalRepo *r)
{
    struct stat st;
    int exists = (stat(r->root, &st) == 0 && S_ISDIR(st.st_mode));

    if (!exists) {
        if (!r->root_lost) {
            r->root_lost = 1;
            tt_log("WARNING: watched directory '%s' deleted; waiting for recovery...\n", r->root);
        }
        return;
    }

    if (!r->root_lost)
        return;

    tt_log("[%s] recovered; reindexing...\n", r->root);

    if (r->store)
        tt_store_close(r->store);

    r->store = tt_store_open(r->store_dir, 1);
    if (!r->store)
        return;

    if (d->has_crypto_key)
        tt_store_set_key(r->store, d->crypto_key);

    tt_cache_free(&r->cache);
    tt_cache_init(&r->cache);

    r->start_ns = tt_now_ns();
    tt_capture_build_initial_repo(d, r);
    tt_watcher_rebuild_repo(d, r->repo_id);

    r->root_lost = 0;
}

/* ==================== Repo lifecycle ==================== */

void tt_repo_list_path(char *out, size_t n, const char *store_dir)
{
    snprintf(out, n, "%s/repos.list", store_dir);
}

void tt_repo_list_sync(TtDaemon *d)
{
    for (int i = 0; i < d->repo_count; ++i) {
        char lp[TT_PATH_MAX + 64], lpt[TT_PATH_MAX + 96];
        tt_repo_list_path(lp, sizeof lp, d->repos[i].store_dir);
        snprintf(lpt, sizeof lpt, "%s.tmp", lp);

        FILE *f = fopen(lpt, "w");
        if (!f)
            continue;
        for (int j = 1; j < d->repo_count; ++j)
            fprintf(f, "%s\n", d->repos[j].root);
        fclose(f);
        if (rename(lpt, lp) != 0)
            unlink(lpt);
    }
}

int tt_repo_overlaps(TtDaemon *d, const char *abs)
{
    for (int i = 0; i < d->repo_count; ++i) {
        if (!d->repos[i].active)
            continue;

        const char *a = d->repos[i].root, *b = abs;
        size_t la = strlen(a), lb = strlen(b);

        if ((strncmp(a, b, lb) == 0 && (a[lb] == '/' || a[lb] == '\0')) ||
            (strncmp(b, a, la) == 0 && (b[la] == '/' || b[la] == '\0')))
            return 1;
    }
    return 0;
}

int tt_repo_adopt_base(TtDaemon *d, const char *abs_dir,
                       char *err, size_t errsz)
{
    for (int i = 0; i < d->repo_count; ++i)
        if (d->repos[i].active && strcmp(d->repos[i].root, abs_dir) == 0)
            return 1;

    if (d->repo_count >= TT_MAX_REPOS) {
        snprintf(err, errsz, "ERR full: maximum %d repos\n", TT_MAX_REPOS);
        return -1;
    }

    struct stat st;
    if (stat(abs_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        snprintf(err, errsz, "ERR not a real directory: %s\n", abs_dir);
        return -1;
    }

    if (tt_repo_overlaps(d, abs_dir)) {
        snprintf(err, errsz, "ERR overlaps an already-watched repo\n");
        return -1;
    }

    TtLocalRepo *r = &d->repos[d->repo_count];
    memset(r, 0, sizeof *r);

    r->repo_id = d->repo_count;
    r->root_wd = -1;
    snprintf(r->root, sizeof r->root, "%s", abs_dir);
    snprintf(r->store_dir, sizeof r->store_dir, "%s/.timetravel", abs_dir);

    mkdir(r->store_dir, 0700);

    r->store = tt_store_open(r->store_dir, 1);
    if (!r->store) {
        snprintf(err, errsz, "ERR cannot open store in %s\n", r->store_dir);
        return -1;
    }

    if (d->has_crypto_key)
        tt_store_set_key(r->store, d->crypto_key);

    tt_cache_init(&r->cache);

    r->debounce = calloc(1, sizeof(TtDebounce));
    if (!r->debounce) {
        tt_store_close(r->store);
        snprintf(err, errsz, "ERR out of memory\n");
        return -1;
    }
    tt_debounce_init(r->debounce);
    tt_exclude_load(r->store_dir, &r->excludes);

    r->start_ns = tt_now_ns();
    r->active = 1;
    d->repo_count++;

    tt_log("ADOPT   %s (repo #%d)\n", abs_dir, r->repo_id);
    return 0;
}

void tt_repo_finish_watch(TtDaemon *d, int repo_id)
{
    if (!d || repo_id < 0 || repo_id >= d->repo_count)
        return;

    tt_watcher_add_repo(d, repo_id);
    tt_capture_build_initial_repo(d, &d->repos[repo_id]);
    tt_write_pid_file(d->repos[repo_id].store_dir);
}

void tt_repo_list_load(TtDaemon *d)
{
    if (!d || d->repo_count < 1)
        return;

    char lp[TT_PATH_MAX + 64];
    tt_repo_list_path(lp, sizeof lp, d->repos[0].store_dir);

    FILE *f = fopen(lp, "r");
    if (!f)
        return;

    char line[TT_PATH_MAX];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0])
            continue;

        struct stat st;
        if (stat(line, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        char err[256] = "";
        if (tt_repo_adopt_base(d, line, err, sizeof err) == 0)
            tt_log("re-adopted from repos.list: %s\n", line);
    }
    fclose(f);
}

void tt_repo_release(TtDaemon *d, int idx)
{
    TtLocalRepo *r = &d->repos[idx];
    if (!r->active)
        return;

    tt_watcher_remove_repo(d, r->repo_id);

    if (r->store)
        tt_store_close(r->store);

    tt_cache_free(&r->cache);

    if (r->debounce) {
        tt_debounce_free(r->debounce);
        free(r->debounce);
    }

    char pf[TT_PATH_MAX + 64], sf[TT_PATH_MAX + 64];
    tt_pid_file_path(pf, sizeof pf, r->store_dir);
    unlink(pf);
    tt_status_file_path(sf, sizeof sf, r->store_dir);
    unlink(sf);

    memset(r, 0, sizeof *r);

    for (int i = idx; i < d->repo_count - 1; ++i) {
        d->repos[i] = d->repos[i + 1];
        d->repos[i].repo_id = i;
    }
    d->repo_count--;

    for (size_t w = 0; w < d->wmap.count; ++w)
        if (d->wmap.entries[w].repo_id > idx)
            d->wmap.entries[w].repo_id--;
}
