/* ============================================================
   Time-Travel v1.5 — tt_util.c
   Utilidades puras: paths, tiempo, I/O, procesos, formato.
   Sin dependencias internas (solo tt_types.h + sistema).
   ============================================================ */
#include "tt_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---------------- logging ---------------- */

void tt_log(const char *fmt, ...)
{
    char tsbuf[32];
    time_t t = time(NULL);
    struct tm tmv;
    if (localtime_r(&t, &tmv))
        strftime(tsbuf, sizeof tsbuf, "%Y-%m-%d %H:%M:%S", &tmv);
    else
        snprintf(tsbuf, sizeof tsbuf, "?");
    fprintf(stderr, "[%s] ", tsbuf);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

/* ---------------- timestamp ---------------- */

uint64_t tt_next_ts(void)
{
    static uint64_t last_ts = 0;
    uint64_t now = tt_now_ns();
    if (now <= last_ts)
        now = last_ts + 1;
    last_ts = now;
    return now;
}

/* ---------------- file I/O ---------------- */

int read_file_all(const char *full, uint8_t **out, size_t *out_size)
{
    *out = NULL;
    *out_size = 0;

    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return -1;
    }

    size_t sz = (size_t)st.st_size;
    if (sz == 0) {
        close(fd);
        return 0;
    }

    uint8_t *buf = malloc(sz);
    if (!buf) {
        close(fd);
        return -1;
    }

    size_t off = 0;
    while (off < sz) {
        ssize_t r = read(fd, buf + off, sz - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0)
            break;
        off += (size_t)r;
    }

    close(fd);
    *out = buf;
    *out_size = off;
    return 0;
}

int write_file_all(const char *path, const uint8_t *data, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (size > 0 && fwrite(data, 1, size, f) != size) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int mkdir_p(const char *path)
{
    char tmp[TT_PATH_MAX * 2];
    int n = snprintf(tmp, sizeof tmp, "%s", path);
    if (n < 0 || (size_t)n >= sizeof tmp)
        return -1;

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* ---------------- path sanitization ---------------- */

void sanitize_component(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    if (!in || !in[0])
        in = "root";
    for (const char *p = in; *p && o + 1 < outsz; ++p) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ' ')
            out[o++] = (char)c;
        else
            out[o++] = ' ';
    }
    out[o] = '\0';
}

/* ---------------- external diff ---------------- */

int run_diff_file(const char *a, const char *b, const char *out)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2)
                close(fd);
        }
        execlp("diff", "diff", "-u", a, b, (char *)NULL);
        _exit(127);
    }

    int st = 0;
    if (waitpid(pid, &st, 0) != pid)
        return -1;
    if (!WIFEXITED(st))
        return -1;
    int code = WEXITSTATUS(st);
    return (code == 0 || code == 1) ? 0 : -1;
}

/* ---------------- process info ---------------- */

int proc_alive(pid_t pid)
{
    if (pid <= 0)
        return 0;
    if (kill(pid, 0) == 0)
        return 1;
    return errno == EPERM;
}

long proc_rss_kb(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/status", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld kB", &rss) == 1)
            break;
    fclose(f);
    return rss;
}

int proc_stat_fields(pid_t pid, unsigned long *utime,
                     unsigned long *stime, unsigned long long *starttime)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char buf[4096];
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char *rp = strrchr(buf, ')');
    if (!rp)
        return -1;
    rp += 2;

    int field = 3;
    char *save = NULL;
    char *tok = strtok_r(rp, " ", &save);
    unsigned long u = 0, s = 0;
    unsigned long long st = 0;

    while (tok) {
        if (field == 14)
            u = strtoul(tok, NULL, 10);
        else if (field == 15)
            s = strtoul(tok, NULL, 10);
        else if (field == 22)
            st = strtoull(tok, NULL, 10);
        field++;
        tok = strtok_r(NULL, " ", &save);
    }

    if (utime)
        *utime = u;
    if (stime)
        *stime = s;
    if (starttime)
        *starttime = st;
    return 0;
}

static double proc_cpu_total_sec_internal(pid_t pid)
{
    unsigned long u = 0, s = 0;
    if (proc_stat_fields(pid, &u, &s, NULL) != 0)
        return -1.0;
    static long hz = 0;
    if (!hz)
        hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0)
        hz = 100;
    return (double)(u + s) / (double)hz;
}

double proc_cpu_total_sec(pid_t pid)
{
    return proc_cpu_total_sec_internal(pid);
}

double proc_cpu_percent(pid_t pid)
{
    double c1 = proc_cpu_total_sec_internal(pid);
    if (c1 < 0.0)
        return -1.0;

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    usleep(200 * 1000);

    double c2 = proc_cpu_total_sec_internal(pid);
    if (c2 < 0.0)
        return -1.0;

    struct timespec t2;
    clock_gettime(CLOCK_MONOTONIC, &t2);

    double wall = (double)(t2.tv_sec - t1.tv_sec) +
                  (double)(t2.tv_nsec - t1.tv_nsec) / 1e9;
    if (wall <= 0.0001)
        return 0.0;

    double pct = (c2 - c1) / wall * 100.0;
    if (pct < 0.0)
        pct = 0.0;
    return pct;
}

/* ---------------- parsing ---------------- */

int is_integer(const char *s, long long *out)
{
    if (!s || !s[0])
        return 0;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return 0;
    *out = v;
    return 1;
}

/* ---------------- time expressions ---------------- */

uint64_t parse_time_expr(const char *expr, int *ok)
{
    if (ok)
        *ok = 1;
    if (!expr || !expr[0] || strcmp(expr, "now") == 0)
        return tt_now_ns();

    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    if (strptime(expr, "%Y-%m-%d %H:%M:%S", &tm) != NULL) {
        time_t t = mktime(&tm);
        if (t != (time_t)-1)
            return (uint64_t)t * 1000000000ULL;
    }

    long long val = 0;
    char unit[32] = {0}, extra[32] = {0};
    int n = sscanf(expr, "%lld %31s %31s", &val, unit, extra);
    if (n >= 2) {
        long long sec = 0;
        if (strncmp(unit, "sec", 3) == 0)
            sec = val;
        else if (strncmp(unit, "min", 3) == 0)
            sec = val * 60;
        else if (strncmp(unit, "hour", 4) == 0)
            sec = val * 3600;
        else if (strncmp(unit, "day", 3) == 0)
            sec = val * 86400;
        else if (strncmp(unit, "week", 4) == 0)
            sec = val * 604800;
        else {
            if (ok)
                *ok = 0;
            return 0;
        }
        if (sec < 0)
            sec = -sec;
        uint64_t delta = (uint64_t)sec * 1000000000ULL;
        uint64_t now = tt_now_ns();
        return (delta >= now) ? 0 : (now - delta);
    }

    if (ok)
        *ok = 0;
    return 0;
}

/* ---------------- formatting ---------------- */

void format_timestamp(uint64_t ns, char *out, size_t sz)
{
    time_t s = (time_t)(ns / 1000000000ULL);
    struct tm t;
    if (localtime_r(&s, &t))
        strftime(out, sz, "%Y-%m-%d %H:%M:%S", &t);
    else
        snprintf(out, sz, "%llu", (unsigned long long)ns);
}

void format_bytes(uint64_t b, char *out, size_t sz)
{
    if (b < 1024ULL)
        snprintf(out, sz, "%llu B", (unsigned long long)b);
    else if (b < 1024ULL * 1024ULL)
        snprintf(out, sz, "%.1f KiB", (double)b / 1024.0);
    else if (b < 1024ULL * 1024ULL * 1024ULL)
        snprintf(out, sz, "%.1f MiB", (double)b / (1024.0 * 1024.0));
    else
        snprintf(out, sz, "%.2f GiB", (double)b / (1024.0 * 1024.0 * 1024.0));
}

void format_ns_duration(uint64_t ns, char *out, size_t sz)
{
    uint64_t s = ns / 1000000000ULL;
    uint64_t d = s / 86400ULL; s %= 86400ULL;
    uint64_t h = s / 3600ULL;  s %= 3600ULL;
    uint64_t m = s / 60ULL;    s %= 60ULL;

    if (d)
        snprintf(out, sz, "%llud %lluh %llum %llus",
                 (unsigned long long)d, (unsigned long long)h,
                 (unsigned long long)m, (unsigned long long)s);
    else if (h)
        snprintf(out, sz, "%lluh %llum %llus",
                 (unsigned long long)h, (unsigned long long)m,
                 (unsigned long long)s);
    else if (m)
        snprintf(out, sz, "%llum %llus",
                 (unsigned long long)m, (unsigned long long)s);
    else
        snprintf(out, sz, "%llus", (unsigned long long)s);
}

/* ---------------- path resolution ---------------- */

int find_repo_dir(const char *path, char *out, size_t out_size)
{
    char tmp[TT_PATH_MAX * 2];
    struct stat st;

    if (!path || !path[0])
        path = ".";

    char *rp = realpath(path, NULL);
    if (rp) {
        snprintf(tmp, sizeof(tmp), "%s", rp);
        free(rp);
    } else {
        if (path[0] == '/') {
            snprintf(tmp, sizeof(tmp), "%s", path);
        } else {
            char cwd[TT_PATH_MAX];
            if (!getcwd(cwd, sizeof(cwd)))
                return -1;
            if (strcmp(cwd, "/") == 0)
                snprintf(tmp, sizeof(tmp), "/%s", path);
            else
                snprintf(tmp, sizeof(tmp), "%s/%s", cwd, path);
        }
    }

    if (stat(tmp, &st) == 0 && S_ISREG(st.st_mode)) {
        char *s = strrchr(tmp, '/');
        if (s == tmp)
            tmp[1] = '\0';
        else if (s)
            *s = '\0';
    }

    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';

    while (tmp[0] != '\0') {
        char cand[TT_PATH_MAX * 2 + 32];
        if (strcmp(tmp, "/") == 0)
            snprintf(cand, sizeof(cand), "/.timetravel");
        else
            snprintf(cand, sizeof(cand), "%s/.timetravel", tmp);

        if (stat(cand, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(out, out_size, "%s", tmp);
            return 0;
        }

        if (strcmp(tmp, "/") == 0)
            break;

        char *s = strrchr(tmp, '/');
        if (!s)
            break;
        if (s == tmp)
            tmp[1] = '\0';
        else
            *s = '\0';
    }

    return -1;
}

int normalize_dir(const char *in, char *out, size_t outsz)
{
    if (!in || !in[0])
        return -1;
    char *rp = realpath(in, NULL);
    if (!rp)
        return -1;
    snprintf(out, outsz, "%s", rp);
    free(rp);
    return 0;
}

int resolve_repo_arg(const char *repo_dir, const char *fallback_path,
                     char *wd, size_t wdsz)
{
    char raw[TT_PATH_MAX];
    if (repo_dir && repo_dir[0]) {
        snprintf(raw, sizeof raw, "%s", repo_dir);
    } else {
        const char *p = (fallback_path && fallback_path[0]) ? fallback_path : ".";
        if (find_repo_dir(p, raw, sizeof raw) != 0)
            return -1;
    }
    if (normalize_dir(raw, wd, wdsz) == 0)
        return 0;
    snprintf(wd, wdsz, "%s", raw);
    return 0;
}

int make_rel_from_arg(const char *wd, const char *path,
                      char *rel, size_t relsz)
{
    if (!path || !path[0] || strcmp(path, ".") == 0) {
        rel[0] = '\0';
        return 0;
    }

    char abs[TT_PATH_MAX * 2];
    if (path[0] == '/')
        snprintf(abs, sizeof abs, "%s", path);
    else {
        char cwd[TT_PATH_MAX];
        if (!getcwd(cwd, sizeof cwd))
            return -1;
        snprintf(abs, sizeof abs, "%s/%s", cwd, path);
    }

    char *rp = realpath(abs, NULL);
    if (rp) {
        snprintf(abs, sizeof abs, "%s", rp);
        free(rp);
    }

    size_t wlen = strlen(wd);
    if (strncmp(abs, wd, wlen) == 0 &&
        (abs[wlen] == '\0' || abs[wlen] == '/')) {
        const char *r = abs + wlen;
        while (*r == '/')
            r++;
        snprintf(rel, relsz, "%s", r);
        return 0;
    }

    snprintf(rel, relsz, "%s", path);
    return 0;
}

/* ---------------- multi-dir helpers ---------------- */

int normalize_dir_arg(const char *in, char *out, size_t outsz)
{
    if (!in || !in[0])
        in = ".";

    char *rp = realpath(in, NULL);
    if (!rp) {
        fprintf(stderr, "error: cannot resolve directory '%s': %s\n",
                in, strerror(errno));
        return -1;
    }

    struct stat st;
    if (stat(rp, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: '%s' is not a directory\n", in);
        free(rp);
        return -1;
    }

    snprintf(out, outsz, "%s", rp);
    free(rp);
    return 0;
}

int dir_is_inside(const char *parent, const char *child)
{
    if (strcmp(parent, "/") == 0)
        return 1;
    size_t plen = strlen(parent);
    if (strncmp(child, parent, plen) != 0)
        return 0;
    return child[plen] == '\0' || child[plen] == '/';
}

int check_start_overlaps(char dirs[][TT_PATH_MAX], int n)
{
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            if (i == j)
                continue;
            if (strcmp(dirs[i], dirs[j]) == 0) {
                fprintf(stderr, "error: duplicate directory '%s'\n", dirs[i]);
                return -1;
            }
            if (dir_is_inside(dirs[i], dirs[j])) {
                fprintf(stderr,
                        "error: '%s' is inside '%s' (overlapping repositories)\n",
                        dirs[j], dirs[i]);
                return -1;
            }
        }
    }
    return 0;
}
