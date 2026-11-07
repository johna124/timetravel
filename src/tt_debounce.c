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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tt_debounce_init(TtDebounce *d) { if (d) memset(d, 0, sizeof *d); }
void tt_debounce_free(TtDebounce *d) { if (d) memset(d, 0, sizeof *d); }

static int debounce_find(const TtDebounce *d, const char *path) {
    for (size_t i = 0; i < TT_MAX_PENDING; ++i)
        if (d->entries[i].active && strcmp(d->entries[i].path, path) == 0) return (int)i;
    return -1;
}

static size_t debounce_find_slot(TtDebounce *d) {
    for (size_t i = 0; i < TT_MAX_PENDING; ++i)
        if (!d->entries[i].active) return i;
    size_t oldest = 0;
    uint64_t oldest_ts = d->entries[0].last_event_ns;
    for (size_t i = 1; i < TT_MAX_PENDING; ++i)
        if (d->entries[i].last_event_ns < oldest_ts) { oldest_ts = d->entries[i].last_event_ns; oldest = i; }
    return oldest;
}

void tt_debounce_add(TtDebounce *d, const char *path, uint8_t event_type) {
    if (!d || !path || !path[0]) return;
    uint64_t now = tt_now_ns();
    int idx = debounce_find(d, path);
    if (idx >= 0) {
        d->entries[idx].last_event_ns = now;
        if (event_type != TT_EV_DELETE) d->entries[idx].event_type = event_type;
        return;
    }
    size_t slot = debounce_find_slot(d);
    TtPendingEntry *e = &d->entries[slot];
    if (!e->active) d->count++;
    e->active = 1;
    snprintf(e->path, sizeof e->path, "%s", path);
    e->last_event_ns = now;
    e->pending_close = 0;
    e->event_type = event_type;
}

void tt_debounce_mark_close(TtDebounce *d, const char *path) {
    int idx = debounce_find(d, path);
    if (idx >= 0) { d->entries[idx].pending_close = 1; d->entries[idx].last_event_ns = 0; }
}

void tt_debounce_mark_delete(TtDebounce *d, const char *path) {
    int idx = debounce_find(d, path);
    if (idx >= 0) {
        d->entries[idx].event_type = TT_EV_DELETE;
        d->entries[idx].pending_close = 1;
        d->entries[idx].last_event_ns = 0;
        return;
    }
    size_t slot = debounce_find_slot(d);
    TtPendingEntry *e = &d->entries[slot];
    if (!e->active) d->count++;
    e->active = 1;
    snprintf(e->path, sizeof e->path, "%s", path);
    e->last_event_ns = 0;
    e->pending_close = 1;
    e->event_type = TT_EV_DELETE;
}

/* v1.3: la cola ya no sale del daemon, se pasa explicitamente (por repo) */
int tt_debounce_process(TtDaemon *daemon, TtDebounce *d, TtProcessCb cb, void *user) {
    if (!daemon || !d || !cb) return 0;
    uint64_t now = tt_now_ns();
    uint64_t threshold = (uint64_t)TT_DEBOUNCE_MS * 1000000ULL;
    int processed = 0;
    for (size_t i = 0; i < TT_MAX_PENDING; ++i) {
        TtPendingEntry *e = &d->entries[i];
        if (!e->active) continue;
        int ready = e->pending_close ||
                    (e->last_event_ns != 0 && (now - e->last_event_ns) >= threshold);
        if (ready) {
            cb(daemon, e->path, e->event_type, user);
            e->active = 0;
            if (d->count > 0) d->count--;
            processed++;
        }
    }
    return processed;
}
