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
#include "tt_ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/file.h>

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

/* Descubrimiento global por usuario:
   /tmp/timetravel-<uid>/ipc.path  →  linea 1: ruta del socket
                                      linea 2: pid del daemon */
static void ipc_global_dir(char *out, size_t n)
{
    snprintf(out, n, "/tmp/timetravel-%d", (int)getuid());
}

static void ipc_global_file(char *out, size_t n)
{
    char d[TT_PATH_MAX];
    ipc_global_dir(d, sizeof d);
    snprintf(out, n, "%s/ipc.path", d);
}

static int ipc_sockaddr(const char *path, struct sockaddr_un *sa)
{
    memset(sa, 0, sizeof *sa);
    sa->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa->sun_path) return -1;  /* limite sun_path */
    snprintf(sa->sun_path, sizeof sa->sun_path, "%s", path);
    return 0;
}

static ssize_t write_fd_all(int fd, const char *s, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, s + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)w;
    }
    return (ssize_t)off;
}

int tt_ipc_listen(TtDaemon *d)
{
    if (!d || d->repo_count < 1) return -1;

    /* socket en el .timetravel del repo primario; si la ruta no cabe en
       sun_path (~108), fallback bajo /tmp/timetravel-<uid>/ */
    char sockpath[TT_PATH_MAX];
    snprintf(sockpath, sizeof sockpath, "%s/%s",
             d->repos[0].store_dir, TT_IPC_SOCK_NAME);
    struct sockaddr_un sa;
    if (ipc_sockaddr(sockpath, &sa) != 0) {
        char gd[TT_PATH_MAX];
        ipc_global_dir(gd, sizeof gd);
        mkdir(gd, 0700);
        snprintf(sockpath, sizeof sockpath, "%s/main.sock", gd);
        if (ipc_sockaddr(sockpath, &sa) != 0) return -1;
    }

    unlink(sockpath);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fcntl(fd, F_SETFL, O_NONBLOCK);       /* obligatorio: accept hasta EAGAIN */
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    chmod(sockpath, 0600);
    if (listen(fd, 8) != 0) { close(fd); unlink(sockpath); return -1; }

    d->ipc_fd = fd;
    snprintf(d->ipc_path, sizeof d->ipc_path, "%s", sockpath);

        char gd[TT_PATH_MAX], gf[TT_PATH_MAX], gft[TT_PATH_MAX + 40];
    ipc_global_dir(gd, sizeof gd);
    mkdir(gd, 0700);
    ipc_global_file(gf, sizeof gf);
    snprintf(gft, sizeof gft, "%s.tmp.%d", gf, (int)getpid());
    FILE *f = fopen(gft, "w");
    if (f) {
        fprintf(f, "%s\n%d\n", sockpath, (int)getpid());
        fclose(f);
        chmod(gft, 0600);
        if (rename(gft, gf) != 0) unlink(gft);
    }
    return 0;
}

void tt_ipc_close(TtDaemon *d)
{
    if (!d) return;
    if (d->ipc_fd >= 0) { close(d->ipc_fd); d->ipc_fd = -1; }
    if (d->ipc_path[0]) unlink(d->ipc_path);

    /* borrar el puntero global solo si somos nosotros */

            char gf[TT_PATH_MAX], gs[TT_PATH_MAX], line[TT_PATH_MAX];
    ipc_global_file(gf, sizeof gf);
    tt_ipc_global_status_path(gs, sizeof gs);
    FILE *f = fopen(gf, "r");
    if (!f) return;
    pid_t pid = -1;
    if (fgets(line, sizeof line, f) && fscanf(f, "%d", &pid) == 1 && pid == getpid()) {
        fclose(f);
        unlink(gf);
        unlink(gs);
        return;
    }
    fclose(f);
}

void tt_ipc_accept_all(TtDaemon *d)
{
    for (;;) {
        int c = accept(d->ipc_fd, NULL, NULL);
        if (c < 0) break;                    /* EAGAIN: no hay mas clientes */
        fcntl(c, F_SETFD, FD_CLOEXEC);
        struct timeval tv = { 60, 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        char buf[TT_PATH_MAX + 16];
        ssize_t n = read(c, buf, sizeof buf - 1);
        if (n > 0) {
            buf[n] = '\0';
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
            char resp[TT_PATH_MAX + 96];
            tt_ipc_dispatch(d, buf, resp, sizeof resp);
            write_fd_all(c, resp, strlen(resp));
        }
        close(c);                            /* cliente ligero: 1 request */
    }
}

void tt_ipc_dispatch(TtDaemon *d, const char *line, char *resp, size_t respsz)
{
    if (!strncmp(line, "ADD ", 4)) { tt_core_ipc_add(d, line + 4, resp, respsz); return; }
    if (!strcmp(line, "LIST"))     { tt_core_ipc_list(d, resp, respsz); return; }
    if (!strncmp(line, "REMOVE ", 7)) { tt_core_ipc_remove(d, line + 7, resp, respsz); return; }
    if (!strcmp(line, "PING")) {
        snprintf(resp, respsz, "OK pong pid=%d repos=%d\n", (int)getpid(), d->repo_count);
        return;
    }
    snprintf(resp, respsz, "ERR unknown command\n");
}

int tt_ipc_discover(char *sockpath, size_t n, pid_t *pid_out)
{
    char gf[TT_PATH_MAX], line[TT_PATH_MAX];
    ipc_global_file(gf, sizeof gf);
    FILE *f = fopen(gf, "r");
    if (!f) return -1;
    if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
    line[strcspn(line, "\r\n")] = '\0';
    pid_t pid = -1;
    if (fscanf(f, "%d", &pid) == 1 && pid_out) *pid_out = pid;
    fclose(f);
    if (!line[0]) return -1;
    snprintf(sockpath, n, "%s", line);
    return 0;
}

int tt_ipc_client(const char *sockpath, const char *line, char *resp, size_t respsz)
{
    struct sockaddr_un sa;
    if (ipc_sockaddr(sockpath, &sa) != 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }

    char buf[TT_PATH_MAX + 16];
    int m = snprintf(buf, sizeof buf, "%s\n", line);
    if (m > 0 && write_fd_all(fd, buf, (size_t)m) < 0) { close(fd); return -1; }

    size_t off = 0;
    while (off + 1 < respsz) {
        ssize_t r = read(fd, resp + off, respsz - 1 - off);
        if (r <= 0) break;
        off += (size_t)r;
        if (memchr(resp, '\n', off)) break;
    }
    resp[off] = '\0';
    close(fd);
    return off > 0 ? 0 : -1;
}

/* ---------- cerrojo de arranque (anti-stampede) ---------- */
static int g_boot_lock_fd = -1;

int tt_boot_lock_acquire(void)
{
    char gd[TT_PATH_MAX], lp[TT_PATH_MAX];
    ipc_global_dir(gd, sizeof gd);
    if (mkdir(gd, 0700) != 0 && errno != EEXIST) return -1;
    snprintf(lp, sizeof lp, "%s/boot.lock", gd);
    g_boot_lock_fd = open(lp, O_RDWR | O_CREAT, 0600);
    if (g_boot_lock_fd < 0) return -1;
    if (flock(g_boot_lock_fd, LOCK_EX) != 0) {
        close(g_boot_lock_fd);
        g_boot_lock_fd = -1;
        return -1;
    }
    return 0;
}

void tt_boot_lock_release(void)
{
    if (g_boot_lock_fd >= 0) {
        flock(g_boot_lock_fd, LOCK_UN);
        close(g_boot_lock_fd);
        g_boot_lock_fd = -1;
    }
}

void tt_ipc_global_status_path(char *out, size_t n)
{
    char gd[TT_PATH_MAX];
    ipc_global_dir(gd, sizeof gd);
    mkdir(gd, 0700);
    snprintf(out, n, "%s/status", gd);
}
