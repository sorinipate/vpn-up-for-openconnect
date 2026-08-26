/*
 * proc.c — process identity, and privileged process hygiene.
 *
 * Identity exists so that a recorded pid can be trusted before it is signalled
 * as root. Pids recycle; `sudo kill "$pid"` with a pid from a user-writable file
 * (what core.sh does today) will happily signal whatever happens to hold that
 * number now. Matching the executable path AND a start token closes that.
 */

#define _GNU_SOURCE

#include "vu_state.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __APPLE__
#  include <libproc.h>
#  include <sys/proc_info.h>
#endif

/* --------------------------------------------------------------- identity */

#ifdef __APPLE__

bool vu_proc_identity(pid_t pid, vu_proc *out, vu_err *e)
{
    if (!out) { vu_err_set(e, "proc: null argument"); return false; }
    memset(out, 0, sizeof *out);

    char path[PROC_PIDPATHINFO_MAXSIZE];
    int n = proc_pidpath(pid, path, sizeof path);
    if (n <= 0) {
        vu_err_set(e, "proc: pid %ld is not running", (long)pid);
        return false;
    }
    if ((size_t)n >= sizeof out->exe) { vu_err_set(e, "proc: executable path too long"); return false; }
    memcpy(out->exe, path, (size_t)n + 1);

    struct proc_bsdinfo bi;
    int got = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi);
    if (got != (int)sizeof bi) {
        vu_err_set(e, "proc: cannot read start time for pid %ld", (long)pid);
        return false;
    }
    /* Seconds and microseconds of process start, combined. Compared for
     * equality only — never treated as a wall-clock value. */
    out->start_token = (uint64_t)bi.pbi_start_tvsec * 1000000u + (uint64_t)bi.pbi_start_tvusec;
    out->pid = pid;
    return true;
}

#elif defined(__linux__)

bool vu_proc_identity(pid_t pid, vu_proc *out, vu_err *e)
{
    if (!out) { vu_err_set(e, "proc: null argument"); return false; }
    memset(out, 0, sizeof *out);

    char link[64];
    snprintf(link, sizeof link, "/proc/%ld/exe", (long)pid);
    ssize_t n = readlink(link, out->exe, sizeof out->exe - 1);
    if (n < 0) {
        vu_err_set(e, "proc: pid %ld is not running", (long)pid);
        return false;
    }
    out->exe[n] = '\0';

    char statpath[64];
    snprintf(statpath, sizeof statpath, "/proc/%ld/stat", (long)pid);
    int fd = open(statpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { vu_err_set(e, "proc: cannot read %s", statpath); return false; }
    char buf[4096];
    ssize_t r = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (r <= 0) { vu_err_set(e, "proc: cannot read %s", statpath); return false; }
    buf[r] = '\0';

    /*
     * Field 22 is the start time. Fields cannot simply be split on spaces: the
     * comm field (2) is parenthesised and may itself contain spaces and
     * parentheses, so scan from the LAST ')' — the standard way to parse this
     * file without being fooled by a process named "evil ) 1 2 3".
     */
    char *close_paren = strrchr(buf, ')');
    if (!close_paren) { vu_err_set(e, "proc: malformed stat for pid %ld", (long)pid); return false; }
    char *p = close_paren + 1;
    /* After comm comes state (field 3); start time is field 22, i.e. the 20th
     * whitespace-separated token from here. */
    int field = 2;
    unsigned long long start = 0;
    bool found = false;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        field++;
        char *tok = p;
        while (*p && *p != ' ') p++;
        char saved = *p;
        *p = '\0';
        if (field == 22) {
            errno = 0;
            char *end = NULL;
            start = strtoull(tok, &end, 10);
            if (errno == 0 && end && *end == '\0') found = true;
            *p = saved;
            break;
        }
        *p = saved;
    }
    if (!found) { vu_err_set(e, "proc: no start time in stat for pid %ld", (long)pid); return false; }

    out->start_token = (uint64_t)start;
    out->pid = pid;
    return true;
}

#else
#  error "vu_proc_identity needs a platform backend"
#endif

/* ---------------------------------------------------------------- hygiene */

bool vu_harden_process(int keep_fd, vu_err *e)
{
    umask(077);

    if (chdir("/") != 0) {
        /*
         * Not cosmetic. The shipped vpnc-script does PATH=/sbin:/usr/sbin:$PATH,
         * so an empty inherited PATH becomes "/sbin:/usr/sbin:" — a trailing
         * colon means the CURRENT DIRECTORY. Leaving root in a caller-chosen cwd
         * turns that into a root-exec path arriving through a variable nobody
         * set. Refuse to continue rather than run from an unknown directory.
         */
        vu_err_set(e, "harden: cannot chdir to /: %s", strerror(errno));
        return false;
    }

    /* This process holds the session cookie; a core dump would write it to disk. */
    struct rlimit rl = { 0, 0 };
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        vu_err_set(e, "harden: cannot disable core dumps: %s", strerror(errno));
        return false;
    }

    /*
     * Close every descriptor above stderr except the lock. Inherited fds are not
     * a privilege problem in themselves (the caller opened them, so they name
     * only what the caller could already reach) but OpenConnect has no business
     * inheriting them, and the lock fd must be the only survivor so its lifetime
     * means what we say it means.
     */
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) max_fd = 65536;
    for (int fd = 3; fd < (int)max_fd; ++fd) {
        if (fd == keep_fd) continue;
        (void)close(fd);            /* EBADF is the common, uninteresting case */
    }
    return true;
}

char **vu_clean_env(void)
{
    /*
     * Built, never inherited. Nothing from the caller's environment survives:
     * no IFS, no LD_ or DYLD_ interposition, no BASH_ENV, no CDPATH, no PS4.
     * PATH is explicit and deliberately non-empty (see vu_harden_process).
     */
    static char path_var[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    static char *env[] = { path_var, NULL };
    return env;
}
