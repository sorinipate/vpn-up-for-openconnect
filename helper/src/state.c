/* state.c — state paths, safe directory creation, locking, record/verify. */

/* Feature-test macros come from the Makefile (see FEATURE there), so a new
 * translation unit cannot forget them. */

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
        { out->session,  sizeof out->session,  "session"  },
        { out->status,   sizeof out->status,   "status"   },
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
static bool dir_check(const char *path, uid_t expect_uid, mode_t mode, bool create,
                      bool *absent, vu_err *e)
{
    if (absent) *absent = false;
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
        if (!create && errno == ENOENT) {
            if (absent) *absent = true;
            return false;
        }
        vu_err_set(e, "state: parent '%s' unavailable: %s", parent_path, strerror(errno));
        return false;
    }

    int fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        if (!create) {
            /* Verify-only callers (stop) must not bring the directory into
             * existence: "there is no state" is a legitimate answer, and
             * creating the tree to discover that would leave root-owned
             * directories behind on every failed teardown. */
            close(parent);
            if (absent) *absent = true;
            return false;
        }
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

bool vu_dir_ensure(const char *path, uid_t expect_uid, mode_t mode, vu_err *e)
{
    return dir_check(path, expect_uid, mode, true, NULL, e);
}

/*
 * Verify without creating — added in step 9, after the adversarial corpus found
 * that `stop` trusted the state tree without ever checking it.
 *
 * `connect` builds the tree through vu_dir_ensure, so every directory it uses
 * has been verified as root-owned and 0700. `stop` did not: it went straight to
 * reading the pid file. On Linux that is academic, because /run is writable only
 * by root. On macOS it is not: /var/run is drwxrwxr-x root:daemon, so a process
 * in group daemon can create /var/run/vpn-up itself, plant a pid and a start
 * token, and have root signal a process of its choosing. The exe-path and
 * start-token checks narrow that to processes whose executable is the pinned
 * OpenConnect, which is a real constraint but not a boundary — both values are
 * readable from the process table by anyone.
 */
bool vu_dir_verify(const char *path, uid_t expect_uid, bool *absent, vu_err *e)
{
    return dir_check(path, expect_uid, 0, false, absent, e);
}

bool vu_writable_by(const char *path, uid_t as_uid, bool *writable, vu_err *e)
{
    if (!path || !writable) { vu_err_set(e, "writable: null argument"); return false; }
    *writable = false;

    /*
     * Probing uid 0 is not a question with an answer: root can write anything, so
     * "can uid 0 write this" is always yes and tells you nothing about whether an
     * ACL grants the CALLER access, which is the only thing §11.5 is about.
     *
     * Refused loudly rather than attempted, because attempting it produced one of
     * the more confusing failures in this project's history. The child below drops
     * to as_uid and then asserts it cannot get back to root; asked to drop to
     * ROOT, it "succeeds", regains root trivially, and exits with the
     * could-not-drop-privilege code. The report reads as a broken sandbox or a
     * missing capability, and the actual mistake is a caller passing the wrong
     * uid. See the step 11 amendment in §11.5.
     */
    if (as_uid == 0) {
        vu_err_set(e, "writable: refusing to probe uid 0 - root can write anything, "
                      "so the caller's uid (SUDO_UID) is what this must be asked about");
        return false;
    }

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

/*
 * Read one small state file, refusing anything that is not a regular file owned
 * by expect_uid with no group or other access.
 *
 * The ownership check is step 9's other correction. It was absent because the
 * containing directory is created 0700 and owned by root, which makes the check
 * redundant — right up to the moment some other path reaches these files
 * without having verified the directory, which is exactly what `stop` did. A
 * file whose contents decide which pid root signals is worth checking twice;
 * this mirrors read_record() in registry.c, which has checked ownership from
 * the start.
 */
static bool read_small(const char *path, uid_t expect_uid, char *out, size_t cap, vu_err *e)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT) vu_err_set(e, "state: cannot read %s: %s", path, strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        vu_err_set(e, "state: cannot stat %s: %s", path, strerror(errno));
        close(fd);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        vu_err_set(e, "state: %s is not a regular file", path);
        close(fd);
        return false;
    }
    if (st.st_uid != expect_uid) {
        vu_err_set(e, "state: %s is owned by uid %lu, expected %lu", path,
                   (unsigned long)st.st_uid, (unsigned long)expect_uid);
        close(fd);
        return false;
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        vu_err_set(e, "state: %s grants group or other access (mode %04o)", path,
                   (unsigned)(st.st_mode & 07777));
        close(fd);
        return false;
    }
    ssize_t r = read(fd, out, cap - 1);
    close(fd);
    if (r < 0) { vu_err_set(e, "state: cannot read %s: %s", path, strerror(errno)); return false; }
    out[(size_t)r] = '\0';   /* explicit: GCC's -Wsign-conversion flags ssize_t indices */
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

bool vu_state_verify(const vu_state_paths *p, uid_t expect_uid, bool *present, vu_err *e)
{
    if (!p || !present) { vu_err_set(e, "state: null argument"); return false; }
    *present = false;

    const char *dirs[] = { p->root, p->uid_dir, p->profile_dir };
    for (size_t i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
        bool absent = false;
        if (!vu_dir_verify(dirs[i], expect_uid, &absent, e)) {
            /* Absent is a normal answer: nothing has connected for this profile
             * (or at all) since boot. A directory that EXISTS but is not ours is
             * a refusal, and the caller must not fall back to reading anything
             * inside it. */
            if (absent) return true;
            return false;
        }
    }
    *present = true;
    return true;
}

bool vu_state_check(const vu_state_paths *p, const char *expect_exe, uid_t expect_uid,
                    vu_state_status *status, vu_proc *found, vu_err *e)
{
    if (!p || !status) { vu_err_set(e, "state: null argument"); return false; }
    *status = VU_STATE_ABSENT;

    char pid_text[64], started_text[64];
    if (!read_small(p->pid, expect_uid, pid_text, sizeof pid_text, e)) {
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
    bool have_token = read_small(p->started, expect_uid, started_text,
                                 sizeof started_text, &scratch);
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
    /* session/status are deliberately NOT in this list — see vu_state.h's
     * struct comment. They are telemetry, replaced only by the next
     * connect's fresh write, never pruned here. */
    const char *files[] = { p->pid, p->started, p->endpoint };
    for (size_t i = 0; i < sizeof files / sizeof *files; ++i) {
        if (unlink(files[i]) != 0 && errno != ENOENT) {
            vu_err_set(e, "state: cannot remove %s: %s", files[i], strerror(errno));
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------ telemetry */

bool vu_generate_hex_id(char out[VU_HEXID_MAX], vu_err *e)
{
    if (!out) { vu_err_set(e, "hexid: null argument"); return false; }
    unsigned char raw[VU_HEXID_LEN / 2];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { vu_err_set(e, "hexid: cannot open /dev/urandom: %s", strerror(errno)); return false; }
    size_t got = 0;
    while (got < sizeof raw) {
        ssize_t r = read(fd, raw + got, sizeof raw - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            vu_err_set(e, "hexid: cannot read /dev/urandom: %s", strerror(errno));
            close(fd);
            return false;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != sizeof raw) { vu_err_set(e, "hexid: short read from /dev/urandom"); return false; }

    static const char hexch[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof raw; ++i) {
        out[i * 2]     = hexch[(raw[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexch[raw[i] & 0x0F];
    }
    out[VU_HEXID_LEN] = '\0';
    return true;
}

bool vu_state_write_fresh_telemetry(const vu_state_paths *p, const char *session_id,
                                    const char *request_id, vu_err *e)
{
    if (!p || !session_id || !request_id) { vu_err_set(e, "state: null argument"); return false; }

    char line[VU_HEXID_MAX + 1];
    if (snprintf(line, sizeof line, "%s\n", session_id) >= (int)sizeof line) {
        vu_err_set(e, "state: session id too long"); return false;
    }
    if (!write_small(p->session, line, e)) return false;

    char status[256];
    int n = snprintf(status, sizeof status,
                     "version=1\n"
                     "session=%s\n"
                     "request_id=%s\n"
                     "last_connected_epoch=0\n"
                     "current_verified=0\n"
                     "last_reason=\n"
                     "last_event_epoch=0\n",
                     session_id, request_id);
    if (n < 0 || (size_t)n >= sizeof status) {
        vu_err_set(e, "state: status record too long"); return false;
    }
    return write_small(p->status, status, e);
}

bool vu_state_read_session(const vu_state_paths *p, uid_t expect_uid,
                           char out[VU_HEXID_MAX], bool *present, vu_err *e)
{
    if (!p || !out || !present) { vu_err_set(e, "state: null argument"); return false; }
    *present = false;
    char buf[VU_HEXID_MAX + 1];
    vu_err scratch; vu_err_clear(&scratch);
    if (!read_small(p->session, expect_uid, buf, sizeof buf, &scratch)) {
        if (scratch.msg[0] == '\0') return true;   /* absent: a normal answer */
        *e = scratch;
        return false;
    }
    if (strlen(buf) != VU_HEXID_LEN) return true;  /* malformed: read as absent */
    memcpy(out, buf, VU_HEXID_LEN + 1);
    *present = true;
    return true;
}

/* One key=value line, in the exact position `vu_state_write_fresh_telemetry`
 * and the vpnc-script wrapper both always write it. Strict on purpose (see
 * the header comment on vu_state_read_status): this program controls both
 * writers, so there is no reason to tolerate a shape neither of them ever
 * produces. */
static bool status_line(const char *line, const char *key, const char **value_out)
{
    size_t klen = strlen(key);
    if (strncmp(line, key, klen) != 0 || line[klen] != '=') return false;
    *value_out = line + klen + 1;
    return true;
}

bool vu_state_read_status(const vu_state_paths *p, uid_t expect_uid,
                          const char *want_session, vu_telemetry *out,
                          bool *present, vu_err *e)
{
    if (!p || !want_session || !out || !present) { vu_err_set(e, "state: null argument"); return false; }
    *present = false;
    memset(out, 0, sizeof *out);

    char buf[256];
    vu_err scratch; vu_err_clear(&scratch);
    if (!read_small(p->status, expect_uid, buf, sizeof buf, &scratch)) {
        if (scratch.msg[0] == '\0') return true;   /* absent: a normal answer */
        *e = scratch;
        return false;
    }

    /*
     * Split into exactly the seven expected lines, in order. Any deviation —
     * a missing line, extra content, an eighth line — is treated as absent
     * rather than partially parsed. read_small already trimmed exactly one
     * trailing newline, so the seventh (last) line legitimately has none of
     * its own; a bare strchr scan handles that correctly by simply finding
     * none for the final segment.
     */
    char *lines[7];
    size_t n = 0;
    char *cursor = buf;
    bool malformed = false;
    for (;;) {
        if (n >= 7) { malformed = true; break; }
        char *nl = strchr(cursor, '\n');
        if (!nl) { lines[n++] = cursor; break; }
        *nl = '\0';
        lines[n++] = cursor;
        cursor = nl + 1;
    }
    if (malformed || n != 7) return true;          /* malformed: read as absent */

    const char *v;
    if (!status_line(lines[0], "version", &v) || strcmp(v, "1") != 0) return true;
    if (!status_line(lines[1], "session", &v) || strcmp(v, want_session) != 0) return true;
    if (!status_line(lines[2], "request_id", &v) || strlen(v) != VU_HEXID_LEN) return true;
    memcpy(out->request_id, v, VU_HEXID_LEN + 1);

    if (!status_line(lines[3], "last_connected_epoch", &v)) return true;
    if (!vu_parse_i32(v, 0, 2147483647, &out->last_connected_epoch, &scratch)) return true;

    if (!status_line(lines[4], "current_verified", &v)) return true;
    if (strcmp(v, "0") == 0) out->current_verified = false;
    else if (strcmp(v, "1") == 0) out->current_verified = true;
    else return true;

    if (!status_line(lines[5], "last_reason", &v)) return true;
    if (v[0] != '\0' && strcmp(v, "connect") != 0 && strcmp(v, "reconnect") != 0 &&
        strcmp(v, "attempt-reconnect") != 0 && strcmp(v, "disconnect") != 0) {
        return true;
    }
    if (strlen(v) >= sizeof out->last_reason) return true;
    memcpy(out->last_reason, v, strlen(v) + 1);

    if (!status_line(lines[6], "last_event_epoch", &v)) return true;
    if (!vu_parse_i32(v, 0, 2147483647, &out->last_event_epoch, &scratch)) return true;

    *present = true;
    return true;
}

bool vu_state_read_pid(const vu_state_paths *p, uid_t expect_uid,
                       int32_t *pid_out, bool *present, vu_err *e)
{
    if (!p || !pid_out || !present) { vu_err_set(e, "state: null argument"); return false; }
    *present = false;
    char buf[64];
    vu_err scratch; vu_err_clear(&scratch);
    if (!read_small(p->pid, expect_uid, buf, sizeof buf, &scratch)) {
        if (scratch.msg[0] == '\0') return true;   /* absent: a normal answer */
        *e = scratch;
        return false;
    }
    if (!vu_parse_i32(buf, 1, 2147483647, pid_out, &scratch)) return true; /* garbage: read as absent */
    *present = true;
    return true;
}

/* ------------------------------------------------- pinned-path verification */

/* Verify one component of an already-resolved pinned path. Nothing here is ever
 * created: these paths belong to the system or the installer, and the only
 * question is whether we are willing to trust them. */
static bool trusted_component(const char *whole, size_t len, uid_t owner,
                              bool is_leaf, bool leaf_is_dir, bool want_exec, vu_err *e)
{
    char path[VU_PATH_MAX];
    if (len + 1 > sizeof path) { vu_err_set(e, "trust: path too long"); return false; }
    memcpy(path, whole, len);
    path[len] = '\0';

    struct stat st;
    if (lstat(path, &st) != 0) {
        vu_err_set(e, "trust: cannot stat '%s': %s", path, strerror(errno));
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        /* Cannot happen after realpath(); if it does, something changed under
         * us and refusing is the only safe answer. */
        vu_err_set(e, "trust: '%s' became a symlink during checking", path);
        return false;
    }
    if (is_leaf && !leaf_is_dir) {
        if (!S_ISREG(st.st_mode)) {
            vu_err_set(e, "trust: '%s' is not a regular file", path);
            return false;
        }
        if (want_exec && !(st.st_mode & S_IXUSR)) {
            vu_err_set(e, "trust: '%s' is not executable", path);
            return false;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        vu_err_set(e, "trust: '%s' is not a directory", path);
        return false;
    }
    /*
     * Root, or the nominated owner. In production `owner` IS 0, so this reduces
     * to "must be root" and grants nothing extra. It reads as a special case
     * only under test, where the fixture necessarily sits beneath root-owned
     * system directories (/, /private, /var/folders ...) that the test user
     * cannot own — and a root-owned component is exactly the thing a non-root
     * attacker cannot subvert, which is the whole property being checked. A
     * component owned by some OTHER unprivileged uid is still refused.
     */
    if (st.st_uid != owner && st.st_uid != 0) {
        vu_err_set(e, "trust: '%s' is owned by uid %lu, expected %lu or root", path,
                   (unsigned long)st.st_uid, (unsigned long)owner);
        return false;
    }
    /* Write access is the question, not read: anyone who can write the binary,
     * or any directory above it, chooses what root runs. */
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        vu_err_set(e, "trust: '%s' is group- or world-writable (mode %04o)", path,
                   (unsigned)(st.st_mode & 07777));
        return false;
    }
    return true;
}

/*
 * RESOLVE, then verify the resolved chain — rather than refusing symlinks.
 *
 * An earlier draft refused a symlink at any component. That is unworkable and,
 * more importantly, checks the wrong thing:
 *
 *   - unworkable, for the same reason as §11.4: /var is a symlink on macOS, so
 *     any path under /var/... is refused before the interesting checks run;
 *   - wrong, because what actually matters is whether a non-root user can
 *     influence what gets executed. A root-owned link inside root-owned
 *     directories is harmless; a link whose TARGET sits in a user-writable
 *     directory is not, and blanket refusal conflates the two.
 *
 * Resolving first and then verifying every component of the real path is
 * strictly stronger against the case that motivated the rule. Homebrew's
 * /opt/homebrew/bin/openconnect is a link into ../Cellar: refusing the link
 * catches it, but so does resolving it and finding that the Cellar chain is
 * owned by the installing user. The second answer is the true one, and it does
 * not break /var.
 *
 * TOCTOU is bounded rather than eliminated: between this check and execve, only
 * root can alter a chain in which every component is root-owned and not
 * group-writable. Same honest caveat as §11.5.
 */
static bool trusted_walk(const char *path, uid_t owner, bool leaf_is_dir,
                         bool want_exec, vu_err *e)
{
    if (!path || path[0] != '/') { vu_err_set(e, "trust: path must be absolute"); return false; }
    size_t n = strlen(path);
    if (n < 2 || n >= VU_PATH_MAX) { vu_err_set(e, "trust: implausible path length"); return false; }
    if (path[n - 1] == '/') { vu_err_set(e, "trust: path must not end in '/'"); return false; }
    if (strstr(path, "/../") || strstr(path, "/./")) {
        /* Refuse rather than normalise: a pinned path is written once, by hand,
         * and should say plainly what it means. */
        vu_err_set(e, "trust: path must be canonical");
        return false;
    }

    /* NULL lets realpath allocate: passing a buffer smaller than PATH_MAX is a
     * documented overflow hazard, and PATH_MAX differs between platforms. */
    char *real = realpath(path, NULL);
    if (!real) {
        vu_err_set(e, "trust: cannot resolve '%s': %s", path, strerror(errno));
        return false;
    }
    size_t rn = strlen(real);
    if (rn < 2 || rn >= VU_PATH_MAX) {
        vu_err_set(e, "trust: resolved path has implausible length");
        free(real);
        return false;
    }

    /* Walk left to right, so an error about /opt being writable is reported
     * before one about the binary inside it. */
    bool ok = true;
    for (size_t i = 1; i <= rn && ok; ++i) {
        if (i == rn || real[i] == '/') {
            ok = trusted_component(real, i, owner, i == rn, leaf_is_dir, want_exec, e);
        }
    }
    free(real);
    return ok;
}

bool vu_path_trusted(const char *path, uid_t owner, bool want_exec, vu_err *e)
{
    return trusted_walk(path, owner, false, want_exec, e);
}

bool vu_dir_trusted(const char *path, uid_t owner, vu_err *e)
{
    return trusted_walk(path, owner, true, false, e);
}
