/* state.c — state paths, safe directory creation, locking, record/verify. */

#define _GNU_SOURCE

#include "vu_state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#  include <libproc.h>
#endif
#ifdef __linux__
#  include <grp.h>
#endif

/* ------------------------------------------------------------- caller's uid */

bool vu_sudo_uid(uid_t *out, vu_err *e)
{
    const char *s = getenv("SUDO_UID");
    if (!s || !*s) {
        /* No default. Falling back to anything would merge two users' state, and
         * a helper invoked without sudo is not a situation to paper over. */
        vu_err_set(e, "SUDO_UID is not set - the helper must be invoked through sudo");
        return false;
    }
    /* Reuse the strict integer parse: no sign, no leading zero, no trailing
     * garbage. A uid is not a place to be relaxed about "12x" or " 12". */
    int32_t v;
    if (!vu_parse_i32(s, 1, 2147483647, &v, e)) {
        vu_err_set(e, "SUDO_UID is not a plausible uid");
        return false;
    }
    if (out) *out = (uid_t)v;
    return true;
}

/* --------------------------------------------------------------- path layout */

bool vu_state_paths_in(const char *root, uid_t uid, const char *profile_id,
                       vu_state_paths *out, vu_err *e)
{
    if (!root || !profile_id || !out) { vu_err_set(e, "state: null argument"); return false; }
    if (!*profile_id) { vu_err_set(e, "state: empty profile id"); return false; }

    /* The caller is expected to have canonicalised the id already. Refuse the
     * shapes that would escape the directory even so, because a path built from
     * an uncanonicalised id is the kind of mistake that must fail loudly rather
     * than land somewhere surprising. */
    if (strchr(profile_id, '/') || strcmp(profile_id, ".") == 0 || strcmp(profile_id, "..") == 0) {
        vu_err_set(e, "state: profile id is not canonical");
        return false;
    }

    memset(out, 0, sizeof *out);
    if (snprintf(out->root, sizeof out->root, "%s", root) >= (int)sizeof out->root) {
        vu_err_set(e, "state: root path too long"); return false;
    }
    if (snprintf(out->uid_dir, sizeof out->uid_dir, "%s/%lu",
                 root, (unsigned long)uid) >= (int)sizeof out->uid_dir) {
        vu_err_set(e, "state: uid path too long"); return false;
    }
    if (snprintf(out->profile_dir, sizeof out->profile_dir, "%s/%s",
                 out->uid_dir, profile_id) >= (int)sizeof out->profile_dir) {
        vu_err_set(e, "state: profile path too long"); return false;
    }

    struct { char *dst; size_t cap; const char *leaf; } f[] = {
        { out->lock,     sizeof out->lock,     "lock"     },
        { out->pid,      sizeof out->pid,      "pid"      },
        { out->started,  sizeof out->started,  "started"  },
        { out->endpoint, sizeof out->endpoint, "endpoint" },
    };
    for (size_t i = 0; i < sizeof f / sizeof *f; ++i) {
        if (snprintf(f[i].dst, f[i].cap, "%s/%s", out->profile_dir, f[i].leaf) >= (int)f[i].cap) {
            vu_err_set(e, "state: %s path too long", f[i].leaf);
            return false;
        }
    }
    return true;
}

bool vu_state_paths_for(uid_t uid, const char *profile_id, vu_state_paths *out, vu_err *e)
{
    return vu_state_paths_in(VU_STATE_ROOT, uid, profile_id, out, e);
}

/* ------------------------------------------------------- safe directory work */

/*
 * Create (if absent) and verify ONE directory. The parent must already exist.
 *
 * The parent chain is opened normally, following symlinks; the leaf is opened
 * with O_NOFOLLOW and then fully verified. That split is deliberate and was
 * forced by reality rather than chosen for convenience:
 *
 *   revision 3 §11.4 says "every component opened with O_NOFOLLOW". That cannot
 *   work. On macOS /var IS a symlink (-> private/var), so a no-follow walk over
 *   the system prefix refuses /var/run/vpn-up before it starts — BSD returns
 *   ENOTDIR rather than ELOOP for O_NOFOLLOW|O_DIRECTORY on a link, which is
 *   how this surfaced. The system prefix is root-owned system infrastructure; if
 *   it is subverted, nothing we do here helps. What must not be followable is
 *   any component WE own, and each of those is a leaf of one of these calls.
 *
 * So callers build the chain explicitly — root, then uid dir, then profile dir —
 * and every directory we own is verified as a leaf, inductively covering the
 * whole path below the state root. That is also more auditable than a recursive
 * walk: the set of directories this program will create is visible at the call
 * site.
 */
bool vu_dir_ensure(const char *path, uid_t expect_uid, mode_t mode, vu_err *e)
{
    if (!path || path[0] != '/') { vu_err_set(e, "state: path must be absolute"); return false; }
    size_t n = strlen(path);
    while (n > 1 && path[n - 1] == '/') n--;          /* tolerate a trailing slash */
    if (n <= 1) { vu_err_set(e, "state: refusing to manage '/'"); return false; }
    if (n >= VU_PATH_MAX) { vu_err_set(e, "state: path too long"); return false; }

    /* Split into parent and leaf, collapsing any run of slashes between them. */
    size_t cut = n;
    while (cut > 0 && path[cut - 1] != '/') cut--;
    if (cut == 0) { vu_err_set(e, "state: malformed path"); return false; }
    size_t leaf_len = n - cut;
    if (leaf_len == 0) { vu_err_set(e, "state: empty final component"); return false; }

    size_t parent_len = cut - 1;                       /* drop the separator */
    while (parent_len > 1 && path[parent_len - 1] == '/') parent_len--;
    char parent_path[VU_PATH_MAX];
    if (parent_len == 0) { parent_path[0] = '/'; parent_path[1] = '\0'; }
    else { memcpy(parent_path, path, parent_len); parent_path[parent_len] = '\0'; }

    char leaf[VU_PATH_MAX];
    memcpy(leaf, path + cut, leaf_len);
    leaf[leaf_len] = '\0';
    if (strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0) {
        vu_err_set(e, "state: '%s' is not a directory name", leaf);
        return false;
    }

    int parent = open(parent_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent < 0) {
        vu_err_set(e, "state: parent '%s' unavailable: %s", parent_path, strerror(errno));
        return false;
    }

    int fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        if (mkdirat(parent, leaf, mode) != 0 && errno != EEXIST) {
            vu_err_set(e, "state: cannot create '%s': %s", path, strerror(errno));
            close(parent);
            return false;
        }
        fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    close(parent);

    if (fd < 0) {
        /* ELOOP on Linux, ENOTDIR on BSD: the leaf exists but is a symlink, and
         * O_NOFOLLOW refused to traverse it. Either way it is not ours. */
        bool linkish = (errno == ELOOP || errno == ENOTDIR);
        vu_err_set(e, "state: cannot open '%s': %s%s", path, strerror(errno),
                   linkish ? " (symlink or non-directory refused)" : "");
        return false;
    }

    struct stat st;
    bool ok = true;
    if (fstat(fd, &st) != 0) {
        vu_err_set(e, "state: cannot stat '%s': %s", path, strerror(errno));
        ok = false;
    } else if (!S_ISDIR(st.st_mode)) {
        vu_err_set(e, "state: '%s' is not a directory", path);
        ok = false;
    } else if (st.st_uid != expect_uid) {
        vu_err_set(e, "state: '%s' is owned by uid %lu, expected %lu", path,
                   (unsigned long)st.st_uid, (unsigned long)expect_uid);
        ok = false;
    } else if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        vu_err_set(e, "state: '%s' grants group or other access (mode %04o)", path,
                   (unsigned)(st.st_mode & 07777));
        ok = false;
    }
    close(fd);
    return ok;
}

bool vu_writable_by(const char *path, uid_t as_uid, bool *writable, vu_err *e)
{
    if (!path || !writable) { vu_err_set(e, "writable: null argument"); return false; }
    *writable = false;

    /* Only meaningful as root — dropping privilege is the whole mechanism. When
     * not root (under test, or in prompt mode) report the honest answer rather
     * than a misleading one. */
    if (geteuid() != 0) {
        if (as_uid != geteuid()) {
            vu_err_set(e, "writable: probing another uid requires root");
            return false;
        }
        *writable = access(path, W_OK) == 0;
        return true;
    }

    pid_t child = fork();
    if (child < 0) { vu_err_set(e, "writable: fork failed: %s", strerror(errno)); return false; }
    if (child == 0) {
        /* Order matters: supplementary groups and gid must go before uid, since
         * dropping uid first would remove the privilege needed to drop the rest. */
        if (setgroups(0, NULL) != 0) _exit(70);
        if (setgid((gid_t)as_uid) != 0) _exit(71);
        if (setuid(as_uid) != 0)        _exit(72);
        if (setuid(0) == 0)             _exit(73);   /* must not be able to get back */
        _exit(access(path, W_OK) == 0 ? 0 : 1);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        vu_err_set(e, "writable: waitpid failed: %s", strerror(errno));
        return false;
    }
    if (!WIFEXITED(status)) { vu_err_set(e, "writable: probe did not exit normally"); return false; }
    int code = WEXITSTATUS(status);
    if (code == 0) { *writable = true;  return true; }
    if (code == 1) { *writable = false; return true; }
    vu_err_set(e, "writable: probe failed to drop privilege (code %d)", code);
    return false;
}

/* ------------------------------------------------------------------ locking */

bool vu_lock_acquire(const vu_state_paths *p, uid_t expect_uid, int *out_fd, vu_err *e)
{
    if (!p || !out_fd) { vu_err_set(e, "lock: null argument"); return false; }
    *out_fd = -1;

    /* Build the chain one owned directory at a time (see vu_dir_ensure). Each is
     * root-owned 0700 in production; the test corpus passes its own uid. Doing
     * this explicitly keeps the full set of directories this program will ever
     * create visible in one place. */
    if (!vu_dir_ensure(p->root,        expect_uid, 0700, e)) return false;
    if (!vu_dir_ensure(p->uid_dir,     expect_uid, 0700, e)) return false;
    if (!vu_dir_ensure(p->profile_dir, expect_uid, 0700, e)) return false;

    int fd = open(p->lock, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        vu_err_set(e, "lock: cannot open lock file: %s%s", strerror(errno),
                   errno == ELOOP ? " (symlinked lock refused)" : "");
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != expect_uid) {
        vu_err_set(e, "lock: lock file is not a regular file owned by uid %lu",
                   (unsigned long)expect_uid);
        close(fd);
        return false;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK)
            vu_err_set(e, "lock: this profile already has a tunnel running");
        else
            vu_err_set(e, "lock: cannot lock: %s", strerror(errno));
        close(fd);
        return false;
    }

    /*
     * Clear FD_CLOEXEC so the lock survives the execve into OpenConnect and the
     * kernel drops it when OpenConnect exits. Opened with O_CLOEXEC above so
     * that a failure between open and here cannot leak the descriptor.
     */
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
        vu_err_set(e, "lock: cannot clear FD_CLOEXEC: %s", strerror(errno));
        close(fd);
        return false;
    }

    *out_fd = fd;
    return true;
}

void vu_lock_release(int fd)
{
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
}

/* -------------------------------------------------------------- record/verify */

/* Write one small file atomically: temp in the same directory, then rename.
 * Same reasoning as the secrets vault — a half-written pid file read by the
 * next `stop` is worse than no pid file at all. */
static bool write_small(const char *path, const char *text, vu_err *e)
{
    char tmp[VU_PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        vu_err_set(e, "state: temp path too long"); return false;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { vu_err_set(e, "state: cannot write %s: %s", path, strerror(errno)); return false; }

    size_t len = strlen(text);
    ssize_t w = write(fd, text, len);
    if (w < 0 || (size_t)w != len) {
        vu_err_set(e, "state: short write to %s", path);
        close(fd); unlink(tmp);
        return false;
    }
    (void)fsync(fd);            /* best effort; tmpfs may not implement it */
    if (close(fd) != 0) {
        vu_err_set(e, "state: cannot close %s: %s", tmp, strerror(errno));
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        vu_err_set(e, "state: cannot install %s: %s", path, strerror(errno));
        unlink(tmp);
        return false;
    }
    return true;
}

static bool read_small(const char *path, char *out, size_t cap, vu_err *e)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT) vu_err_set(e, "state: cannot read %s: %s", path, strerror(errno));
        return false;
    }
    ssize_t r = read(fd, out, cap - 1);
    close(fd);
    if (r < 0) { vu_err_set(e, "state: cannot read %s: %s", path, strerror(errno)); return false; }
    out[r] = '\0';
    /* Trim exactly one trailing newline; anything else stays, so junk is visible
     * to the parser rather than silently tolerated. */
    size_t n = strlen(out);
    if (n && out[n - 1] == '\n') out[n - 1] = '\0';
    return true;
}

bool vu_state_record(const vu_state_paths *p, const vu_proc *self,
                     const char *endpoint, vu_err *e)
{
    if (!p || !self) { vu_err_set(e, "state: null argument"); return false; }
    char buf[64];

    snprintf(buf, sizeof buf, "%ld\n", (long)self->pid);
    if (!write_small(p->pid, buf, e)) return false;

    snprintf(buf, sizeof buf, "%llu\n", (unsigned long long)self->start_token);
    if (!write_small(p->started, buf, e)) return false;

    if (endpoint && *endpoint) {
        char line[VU_ORIGIN_MAX + 2];
        snprintf(line, sizeof line, "%s\n", endpoint);
        if (!write_small(p->endpoint, line, e)) return false;
    }
    return true;
}

bool vu_state_check(const vu_state_paths *p, const char *expect_exe,
                    vu_state_status *status, vu_proc *found, vu_err *e)
{
    if (!p || !status) { vu_err_set(e, "state: null argument"); return false; }
    *status = VU_STATE_ABSENT;

    char pid_text[64], started_text[64];
    if (!read_small(p->pid, pid_text, sizeof pid_text, e)) {
        /* No record is a normal state, not an error. */
        return e->msg[0] == '\0';
    }
    int32_t pid_val;
    vu_err scratch; vu_err_clear(&scratch);
    if (!vu_parse_i32(pid_text, 1, 2147483647, &pid_val, &scratch)) {
        /* Garbage in the pid file is stale by definition — never signalled. */
        *status = VU_STATE_STALE;
        return true;
    }

    uint64_t want_token = 0;
    bool have_token = read_small(p->started, started_text, sizeof started_text, &scratch);
    if (have_token) {
        errno = 0;
        char *end = NULL;
        unsigned long long v = strtoull(started_text, &end, 10);
        if (errno != 0 || !end || *end != '\0') have_token = false;
        else want_token = (uint64_t)v;
    }

    vu_proc live;
    vu_err_clear(&scratch);
    if (!vu_proc_identity((pid_t)pid_val, &live, &scratch)) {
        *status = VU_STATE_STALE;          /* nothing running with that pid */
        return true;
    }

    /*
     * A live pid is not enough. Pids recycle, so a recorded number can name an
     * unrelated process by the time `stop` runs — and signalling that as root is
     * precisely the hole that `sudo kill "$pid"` leaves open today. Require the
     * executable path AND the start token to match.
     */
    if (expect_exe && *expect_exe && strcmp(live.exe, expect_exe) != 0) {
        *status = VU_STATE_STALE;
        return true;
    }
    if (have_token && live.start_token != want_token) {
        *status = VU_STATE_STALE;          /* same pid number, different process */
        return true;
    }
    if (!have_token) {
        /* Without a token we cannot rule out recycling, so refuse to call it
         * live rather than guess. */
        *status = VU_STATE_STALE;
        return true;
    }

    *status = VU_STATE_LIVE;
    if (found) *found = live;
    return true;
}

bool vu_state_prune(const vu_state_paths *p, vu_err *e)
{
    if (!p) { vu_err_set(e, "state: null argument"); return false; }
    const char *files[] = { p->pid, p->started, p->endpoint };
    for (size_t i = 0; i < sizeof files / sizeof *files; ++i) {
        if (unlink(files[i]) != 0 && errno != ENOENT) {
            vu_err_set(e, "state: cannot remove %s: %s", files[i], strerror(errno));
            return false;
        }
    }
    return true;
}
