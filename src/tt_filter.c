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
#include <fnmatch.h>
#include <string.h>

static int path_has_component(const char *path, const char *comp) {
    size_t clen = strlen(comp);
    const char *p = path;
    while ((p = strstr(p, comp)) != NULL) {
        int before_ok = (p == path) || (p[-1] == '/');
        int after_ok  = (p[clen] == '\0') || (p[clen] == '/');
        if (before_ok && after_ok) return 1;
        p += clen;
    }
    return 0;
}

int tt_is_excluded(const char *path) {
    if (!path || !path[0]) return 1;

    static const char *excluded_dirs[] = {
        ".git", "node_modules", "__pycache__", "target", ".cache", ".timetravel", NULL
    };
    for (int i = 0; excluded_dirs[i]; ++i)
        if (path_has_component(path, excluded_dirs[i])) return 1;

    if (strstr(path, ".tt_tmp_") != NULL) return 1;

    static const char *file_patterns[] = {
        "*.o", "*.obj", "*.pyc", "*.pyo", "*.swp", "*.swo", "*~",
        "*.tmp", "*.part", "*.download", "*.ttd",
        ".DS_Store", "Thumbs.db", "timetravel.log", "timetravel.pid",
        /* ---- v1.3: temporales de editores/frameworks ---- */
        ".goutputstream-*",   /* GLib/GIO: gedit y cualquier app GTK */
        ".~lock.*",           /* LibreOffice */
        ".#*",                /* lock de emacs */
        "#*#",                /* autosave de emacs */
        "*.bak", "*.orig", "*.rej",
        ".nfs*",              /* silly-rename de NFS */
        NULL
    };
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (int i = 0; file_patterns[i]; ++i)
        if (fnmatch(file_patterns[i], base, FNM_PERIOD) == 0) return 1;
    return 0;
}
