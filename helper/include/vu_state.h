/*
 * vu_state.h — root-owned state, locking, process identity, and privileged
 * process hygiene for vpn-up-helper.
 *
 * Step 5 of PRIVILEGED-HELPER-DESIGN.md §16. This is the first code that deals
 * with privileged paths, but it still performs no privilege *transition*: there
 * is no execve and no setuid here beyond the deliberately scoped
 * effective-writability probe. The trusted execution closure walk is step 10;
 * the approval registry is step 6.
 *
 * Two decisions in this header are load-bearing and easy to get wrong later:
 *
 *  1. The state root is a COMPILE-TIME constant, never an environment variable.
 *     A privileged binary that lets its caller choose where root writes has
 *     handed the caller a root-owned file anywhere it likes. Tests reach the
 *     same logic through the *_in() variants, which take the root as an
 *     argument, so testability never becomes a runtime override.
 *
 *  2. Ownership is a parameter, not an assumption. Production requires uid 0;
 *     the tests pass their own uid so the identical checking code is what runs
 *     under test, rather than a weakened copy of it.
 */
#ifndef VU_STATE_H
#define VU_STATE_H

#include "vu.h"

#include <sys/types.h>

/*
 * Per-platform state root (§6). /run is the modern Linux tmpfs; macOS has no
 * /run, and /var/run is a root-owned symlink into /private/var/run.
 * Overridable at build time for packaging, never at run time.
 */
#ifndef VU_STATE_ROOT
#  if defined(__APPLE__)
#    define VU_STATE_ROOT "/var/run/vpn-up"
#  else
#    define VU_STATE_ROOT "/run/vpn-up"
#  endif
#endif

#define VU_PATH_MAX 1024

typedef struct {
    char root[VU_PATH_MAX];         /* <root>                  */
    char uid_dir[VU_PATH_MAX];      /* <root>/<uid>            */
    char profile_dir[VU_PATH_MAX];  /* <root>/<uid>/<profile>  */
    char lock[VU_PATH_MAX];         /* .../lock                */
    char pid[VU_PATH_MAX];          /* .../pid                 */
    char started[VU_PATH_MAX];      /* .../started             */
    char endpoint[VU_PATH_MAX];     /* .../endpoint            */
} vu_state_paths;

/* ------------------------------------------------------------- caller's uid */

/*
 * The invoking user's real uid, from SUDO_UID.
 *
 * Trustworthy only because `Defaults env_reset` holds: sudo strips the caller's
 * copy of SUDO_UID and sets its own from the real invoking uid. Absent or
 * unparseable is a hard refusal — never a default, because a default would
 * silently merge two users' state (§6). uid 0 is refused too: a root caller has
 * no need of this path and would collide with the namespace root.
 */
bool vu_sudo_uid(uid_t *out, vu_err *e);

/* --------------------------------------------------------------- path layout */

/* profile_id must already be canonical (vu_canon_profile_id): this function
 * does not sanitise it, it only refuses to build an over-long path. Callers
 * that skip canonicalisation are the bug. */
bool vu_state_paths_for(uid_t uid, const char *profile_id, vu_state_paths *out, vu_err *e);
bool vu_state_paths_in(const char *root, uid_t uid, const char *profile_id,
                       vu_state_paths *out, vu_err *e);

/* ------------------------------------------------------- safe directory work */

/*
 * Create (if absent) and verify ONE directory; the parent must already exist.
 * Refuses anything that is not exactly what we expect:
 *   - the leaf is opened with O_NOFOLLOW, so a symlink there is a failure
 *     rather than a redirection;
 *   - owner must equal expect_uid;
 *   - no group or other permission bits at all;
 *   - must be a directory, not a file or a device.
 *
 * The parent chain is opened following symlinks, which corrects revision 3
 * §11.4's "every component opened with O_NOFOLLOW": on macOS /var is itself a
 * symlink, so a blanket no-follow walk cannot create /var/run/vpn-up at all.
 * Callers therefore build the chain one owned directory at a time, so every
 * directory this program creates is verified as a leaf.
 *
 * expect_uid is explicit so the same code runs under test as in production.
 */
bool vu_dir_ensure(const char *path, uid_t expect_uid, mode_t mode, vu_err *e);

/*
 * Ownership and mode bits do not prove non-writability, because both platforms
 * support ACLs: a path can be root:wheel 0755 while an ACL grants the caller
 * write access. For a FIXED, TRUSTED path, fork a child, drop supplementary
 * groups, gid and uid to `as_uid`, and test effective write access there.
 *
 * Honest limitation: this is a TOCTOU check, so it is defence-in-depth
 * detection, not enforcement. Root-owned parent directories remain the primary
 * protection. Never call this on a caller-supplied path — the whole reason it
 * is safe is that the path set is fixed and small (§11.5).
 */
bool vu_writable_by(const char *path, uid_t as_uid, bool *writable, vu_err *e);

/* ------------------------------------------------------------------ locking */

/*
 * Take the exclusive per-(uid, profile) lock.
 *
 * Returns an fd with FD_CLOEXEC CLEARED, so the lock survives the execve into
 * OpenConnect and the kernel releases it when OpenConnect exits. That is what
 * makes "one tunnel per profile" hold without a process-table race, and what
 * makes stale state self-healing: the next connect takes the lock, then
 * validates or prunes whatever the previous one left behind.
 *
 * Non-blocking: a second connect for the same profile fails immediately rather
 * than queueing behind a live tunnel.
 */
bool vu_lock_acquire(const vu_state_paths *p, uid_t expect_uid, int *out_fd, vu_err *e);
void vu_lock_release(int fd);

/* --------------------------------------------------------- process identity */

/*
 * Identify a running process well enough to be sure a recorded pid still refers
 * to the same one. A pid alone is not enough: pids recycle, and signalling a
 * recycled pid as root is exactly the hole `sudo kill "$pid"` leaves open today.
 *
 * start_token is a monotonic-ish process start stamp (Linux: field 22 of
 * /proc/<pid>/stat, in clock ticks since boot; macOS: pbi_start_tvsec). It is
 * compared for equality only — never interpreted as a wall-clock time.
 */
typedef struct {
    pid_t    pid;
    char     exe[VU_PATH_MAX];
    uint64_t start_token;
} vu_proc;

bool vu_proc_identity(pid_t pid, vu_proc *out, vu_err *e);

/* Write pid, start token and endpoint into the (already locked) profile dir.
 * Called BEFORE execve, with getpid(): execve replaces the image rather than
 * forking, so the pid recorded here is exactly the OpenConnect pid. */
bool vu_state_record(const vu_state_paths *p, const vu_proc *self,
                     const char *endpoint, vu_err *e);

/*
 * Read back the recorded state and confirm the process is still the one we
 * started: same pid, same executable path, same start token. Any mismatch means
 * stale state, so the caller prunes rather than signalling.
 */
typedef enum {
    VU_STATE_LIVE,      /* recorded process is still running and matches */
    VU_STATE_STALE,     /* nothing running, or a different process now   */
    VU_STATE_ABSENT     /* no record at all                              */
} vu_state_status;

bool vu_state_check(const vu_state_paths *p, const char *expect_exe,
                    vu_state_status *status, vu_proc *found, vu_err *e);

bool vu_state_prune(const vu_state_paths *p, vu_err *e);

/* ------------------------------------------------- privileged process hygiene */

/*
 * Requirements, not optional hardening (§11.3):
 *   umask(077); chdir("/"); RLIMIT_CORE = 0; every fd > 2 closed except keep_fd.
 *
 * chdir("/") is mandatory for a specific verified reason: the shipped
 * vpnc-script does `PATH=/sbin:/usr/sbin:$PATH`, so an EMPTY inherited PATH
 * becomes "/sbin:/usr/sbin:" — and a trailing colon means the current
 * directory. Leaving the privileged process in a caller-controlled cwd turns
 * that into a root-exec path arriving through a variable nobody set. Disabling
 * core dumps matters because this process holds the session cookie.
 */
bool vu_harden_process(int keep_fd, vu_err *e);

/*
 * A minimal, explicitly constructed environment for the exec'd child. Nothing
 * is inherited: no IFS, no LD_ or DYLD_ variables, no BASH_ENV, no CDPATH. PATH
 * is set explicitly and is never empty, for the reason above.
 *
 * Returns a NULL-terminated array owned by the callee; valid until the next
 * call. Not thread-safe, and does not need to be.
 */
char **vu_clean_env(void);

#endif /* VU_STATE_H */
