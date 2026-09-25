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
#include "tt_types.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>

extern int tt_is_excluded(const char *path);
extern void tt_debounce_add(TtDebounce *d, const char *path, uint8_t event_type);
extern void tt_debounce_mark_close(TtDebounce *d, const char *path);
extern void tt_debounce_mark_delete(TtDebounce *d, const char *path);

#define TT_INOTIFY_MASK (IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | \
                         IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB |           \
                         IN_DELETE_SELF | IN_MOVE_SELF)

static int watch_map_add(TtWatchMap *m, int wd, int repo_id, const char *path) {
    if (m->count == m->cap) {
        size_t ncap = m->cap ? m->cap * 2 : 256;
        TtWatchEntry *p = realloc(m->entries, ncap * sizeof(TtWatchEntry));
        if (!p) return -1;
        m->entries = p; m->cap = ncap;
    }
    m->entries[m->count].wd = wd;
    m->entries[m->count].repo_id = repo_id;
    snprintf(m->entries[m->count].path, TT_PATH_MAX, "%s", path);
    m->count++;
    return 0;
}

static TtWatchEntry *watch_map_lookup(TtWatchMap *m, int wd) {
    for (size_t i = 0; i < m->count; ++i)
        if (m->entries[i].wd == wd) return &m->entries[i];
    return NULL;
}

static void watch_map_remove(TtWatchMap *m, int wd) {
    for (size_t i = 0; i < m->count; ++i)
        if (m->entries[i].wd == wd) {
            m->entries[i] = m->entries[m->count - 1];
            m->count--;
            return;
        }
}

static void watch_map_clear(TtWatchMap *m) {
    free(m->entries);
    m->entries = NULL;
    m->count = m->cap = 0;
}

static TtLocalRepo *repo_of(TtDaemon *d, int repo_id) {
    if (!d || repo_id < 0 || repo_id >= d->repo_count) return NULL;
    TtLocalRepo *r = &d->repos[repo_id];
    return r->active ? r : NULL;
}

static int add_watch_recursive(TtDaemon *d, int repo_id, const char *dir) {
    if (tt_is_excluded(dir)) return 0;
    struct stat dst;
    if (lstat(dir, &dst) != 0 || !S_ISDIR(dst.st_mode)) return 0;
    int wd = inotify_add_watch(d->inotify_fd, dir, TT_INOTIFY_MASK);
    if (wd < 0) return (errno == EACCES || errno == ENOENT || errno == ENOTDIR) ? 0 : -1;
    if (!watch_map_lookup(&d->wmap, wd)) {
        if (watch_map_add(&d->wmap, wd, repo_id, dir) != 0) {
            inotify_rm_watch(d->inotify_fd, wd);
            return -1;
        }
    }
    TtLocalRepo *r = repo_of(d, repo_id);
    if (r && strcmp(dir, r->root) == 0) r->root_wd = wd;

    DIR *dp = opendir(dir);
    if (!dp) return 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char full[TT_PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) add_watch_recursive(d, repo_id, full);
    }
    closedir(dp);
    return 0;
}

int tt_watcher_init(TtDaemon *d) {
    if (!d) return -1;
    memset(&d->wmap, 0, sizeof d->wmap);
    d->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (d->inotify_fd < 0) return -1;
    d->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (d->timer_fd < 0) { close(d->inotify_fd); d->inotify_fd = -1; return -1; }
    struct itimerspec its = {
        .it_interval = { .tv_nsec = TT_TICK_MS * 1000000L },
        .it_value    = { .tv_nsec = TT_TICK_MS * 1000000L }
    };
    if (timerfd_settime(d->timer_fd, 0, &its, NULL) != 0) {
        close(d->timer_fd); close(d->inotify_fd);
        d->timer_fd = d->inotify_fd = -1;
        return -1;
    }
    return 0;
}

void tt_watcher_free(TtDaemon *d) {
    if (!d) return;
    if (d->inotify_fd >= 0) close(d->inotify_fd);
    if (d->timer_fd >= 0) close(d->timer_fd);
    d->inotify_fd = d->timer_fd = -1;
    watch_map_clear(&d->wmap);
}

int tt_watcher_add_repo(TtDaemon *d, int repo_id) {
    if (!d || d->inotify_fd < 0) return -1;
    TtLocalRepo *r = repo_of(d, repo_id);
    if (!r) return -1;
    r->root_wd = -1;
    return add_watch_recursive(d, repo_id, r->root);
}

int tt_watcher_rebuild_repo(TtDaemon *d, int repo_id) {
    if (!d || d->inotify_fd < 0) return -1;
    size_t i = 0;
    while (i < d->wmap.count) {
        if (d->wmap.entries[i].repo_id == repo_id) {
            inotify_rm_watch(d->inotify_fd, d->wmap.entries[i].wd);
            d->wmap.entries[i] = d->wmap.entries[d->wmap.count - 1];
            d->wmap.count--;
        } else i++;
    }
    return tt_watcher_add_repo(d, repo_id);
}

int tt_watcher_rebuild_all(TtDaemon *d) {
    if (!d || d->inotify_fd < 0) return -1;
    for (size_t i = 0; i < d->wmap.count; ++i)
        inotify_rm_watch(d->inotify_fd, d->wmap.entries[i].wd);
    watch_map_clear(&d->wmap);
    for (int i = 0; i < d->repo_count; ++i)
        if (d->repos[i].active) tt_watcher_add_repo(d, i);
    return 0;
}

int tt_watcher_remove_repo(TtDaemon *d, int repo_id) {
    if (!d || d->inotify_fd < 0) return -1;
    size_t i = 0;
    while (i < d->wmap.count) {
        if (d->wmap.entries[i].repo_id == repo_id) {
            inotify_rm_watch(d->inotify_fd, d->wmap.entries[i].wd);
            d->wmap.entries[i] = d->wmap.entries[d->wmap.count - 1];
            d->wmap.count--;
        } else i++;
    }
    return 0;
}

void tt_watcher_process_events(TtDaemon *d) {
    if (!d || d->inotify_fd < 0) return;
    char buf[8192] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t len;
    while ((len = read(d->inotify_fd, buf, sizeof buf)) > 0) {
        char *ptr = buf;
        while (ptr < buf + len) {
            struct inotify_event *ev = (struct inotify_event *)ptr;
            ptr += sizeof(struct inotify_event) + ev->len;

            if (ev->mask & IN_Q_OVERFLOW) {
                tt_watcher_rebuild_all(d);
                d->rescan_needed = 1;
                continue;
            }
            if (ev->mask & IN_IGNORED) {
                TtWatchEntry *we = watch_map_lookup(&d->wmap, ev->wd);
                if (we) {
                    TtLocalRepo *r = repo_of(d, we->repo_id);
                    if (r && ev->wd == r->root_wd) r->root_wd = -1;
                }
                watch_map_remove(&d->wmap, ev->wd);
                continue;
            }

            TtWatchEntry *we = watch_map_lookup(&d->wmap, ev->wd);
            if (!we) continue;
            TtLocalRepo *repo = repo_of(d, we->repo_id);
            if (!repo || !repo->debounce) continue;

            if (ev->wd == repo->root_wd && (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF))) {
                repo->root_lost = 1;
                continue;
            }
            if (ev->len == 0) continue;

            char full[TT_PATH_MAX * 2];
            snprintf(full, sizeof full, "%s/%s", we->path, ev->name);
            if (tt_is_excluded(full)) continue;

            if (ev->mask & IN_ISDIR) {
                if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                    add_watch_recursive(d, repo->repo_id, full);
                    d->rescan_needed = 1;
                } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                    d->rescan_needed = 1;
                }
                continue;
            }

            /* enrutamiento: cada evento acaba en la cola LOCAL de su repo */
            if (ev->mask & (IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_ATTRIB))
                tt_debounce_add(repo->debounce, full, TT_EV_MODIFY);
            if (ev->mask & IN_CLOSE_WRITE)
                tt_debounce_mark_close(repo->debounce, full);
            if (ev->mask & (IN_DELETE | IN_MOVED_FROM))
                tt_debounce_mark_delete(repo->debounce, full);
        }
    }
}
