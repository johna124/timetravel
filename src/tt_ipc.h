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
#ifndef TT_IPC_H
#define TT_IPC_H

#include "tt_types.h"
#include <sys/types.h>

int  tt_boot_lock_acquire(void);
void tt_boot_lock_release(void);
void tt_ipc_global_status_path(char *out, size_t n);

/* Lado daemon (integrado en el poll; cero hilos, cero CPU en reposo) */
int  tt_ipc_listen(TtDaemon *d);
void tt_ipc_close(TtDaemon *d);
void tt_ipc_accept_all(TtDaemon *d);      /* llamar solo con POLLIN */

/* Lado cliente ligero */
int  tt_ipc_discover(char *sockpath, size_t n, pid_t *pid_out);
int  tt_ipc_client(const char *sockpath, const char *line, char *resp, size_t respsz);

/* Despachador; los handlers viven en tt_main.c */
void tt_ipc_dispatch(TtDaemon *d, const char *line, char *resp, size_t respsz);
extern int tt_core_ipc_add(TtDaemon *d, const char *path, char *resp, size_t respsz);
extern int tt_core_ipc_list(TtDaemon *d, char *resp, size_t respsz);

extern int tt_core_ipc_remove(TtDaemon *d, const char *path, char *resp, size_t respsz);
#endif
