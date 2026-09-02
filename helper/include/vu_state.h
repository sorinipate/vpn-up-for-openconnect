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

/* VU_HEXID_LEN / VU_HEXID_MAX (32 lowercase hex characters, the shared format
 * for `session` and `request_id`) now live in vu.h, so that vu_request can
 * carry an optional request_id field without a circular include. Fixed and
 * non-guessable (see vu_generate_hex_id) — not for secrecy, since only root
 * ever writes any of these paths, but so a stale or not-yet-rotated record
 * can never coincide with a new one by construction. */

typedef struct {
    char root[VU_PATH_MAX];         /* <root>                  */
    char uid_dir[VU_PATH_MAX];      /* <root>/<uid>            */
    char profile_dir[VU_PATH_MAX];  /* <root>/<uid>/<profile>  */
    char lock[VU_PATH_MAX];         /* .../lock                */
    char pid[VU_PATH_MAX];          /* .../pid                 */
    char started[VU_PATH_MAX];      /* .../started             */
    char endpoint[VU_PATH_MAX];     /* .../endpoint            */
    /*
     * session/status are TELEMETRY, not runtime process state, and that
     * distinction is load-bearing: vu_state_prune() below deliberately never
     * touches either of them (connection-state design plan, round 2/round 4).
     * An ordinary `stop` prunes pid/started/endpoint the moment the process
     * is confirmed gone; if session/status were pruned the same way, the
     * evidence a concurrently-running `start` is about to read synchronously
     * (via the event-status verb) would already be gone on the single most
     * common shutdown path there is. Telemetry is only ever REPLACED, by the
     * next connect's fresh write, never explicitly deleted; it ages out
     * naturally at reboot since VU_STATE_ROOT is /run or /var/run.
     */
    char session[VU_PATH_MAX];      /* .../session — authoritative generation id, diagnostic only */
    char status[VU_PATH_MAX];       /* .../status  — wrapper-written tunnel-event telemetry */
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
 * The same verification, WITHOUT creating anything: *absent is set when the
 * directory (or its parent) simply does not exist yet, which is a normal answer
 * rather than a failure.
 *
 * Added in step 9. `connect` builds the state tree through vu_dir_ensure, so
 * every directory it touches has been verified; `stop` did not, and went
 * straight to reading the pid file. On Linux /run is root-only so that was
 * academic, but macOS /var/run is drwxrwxr-x root:daemon, meaning a process in
 * group daemon could create /var/run/vpn-up, plant a pid and start token, and
 * have root signal a process of its choosing.
 */
bool vu_dir_verify(const char *path, uid_t expect_uid, bool *absent, vu_err *e);

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

/*
 * Verify that a FIXED, pinned path is one we are willing to hand root to.
 *
 * Resolves the path with realpath(), then checks the resolved file and every
 * parent directory: owned by `owner` (or by root, which in production is the
 * same thing since owner is 0), no group or other write bit, a regular file,
 * and executable when want_exec.
 *
 * Resolving rather than refusing symlinks is deliberate. Blanket refusal cannot
 * work (/var is a symlink on macOS) and checks the wrong thing: what matters is
 * whether a non-root user can influence what gets executed. Homebrew's
 * bin/openconnect is a link into a user-owned Cellar, and resolving it catches
 * that on the ownership of the real chain — a truer answer than refusing the
 * link. See the comment on the implementation.
 *
 * SCOPE, and this matters: this is the file-level part of the trusted execution
 * closure (§11.4), which is all step 7 implements. It does NOT yet cover the
 * dynamic library closure, the sourced hooks under /etc/vpnc, or the PATH entries
 * vpnc-script resolves through. Those are step 10 on Linux and step 14 on
 * macOS (both now implemented — closure.c). Never call
 * this on a caller-supplied path: its safety comes from the path set being
 * fixed and small.
 */
bool vu_path_trusted(const char *path, uid_t owner, bool want_exec, vu_err *e);

/*
 * The same walk, for a path whose leaf must be a DIRECTORY. Step 10 needs this
 * for the sourced-hooks directory under /etc/vpnc and for every entry in the
 * PATH the helper constructs — both are part of the closure and neither is a
 * file. Also lets a caller ask "is this chain trustworthy at all?" before
 * relying on it.
 */
bool vu_dir_trusted(const char *path, uid_t owner, vu_err *e);

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

/*
 * Is THIS executable running from a path we are willing to hand root to?
 *
 * Design §11.1: "the load-bearing part is not the path but the check", and each
 * binary repeats the walk on its own path. Resolves the running image (Linux
 * /proc/self/exe, macOS proc_pidpath) and runs it through vu_path_trusted with
 * owner 0, so a root-owned binary sitting under a directory the caller can write
 * is refused before it does any privileged work.
 *
 * SCOPE, and this is easy to overclaim: it prevents a LEGITIMATE binary being
 * run as root from an untrusted path. It says nothing about a malicious binary
 * that is already installed as root on a trusted path — code cannot attest to
 * its own provenance, and the install-time trust assumption in SECURITY.md is
 * where that is dealt with instead.
 *
 * Called after the root gate in both binaries, NOT at the top of main(): the
 * diagnostic commands (`version`, and vpn-up-admin's unprivileged
 * `verify-closure`) deliberately run from anywhere, because their job is to
 * answer questions about a machine that may not have an installation yet. §11.1
 * records that exemption.
 */
bool vu_self_trusted(vu_err *e);

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

/*
 * Verify the whole state chain for this profile before anything inside it is
 * believed. *present is false when no directory exists yet (nothing has
 * connected); a false RETURN means a directory exists and is not ours, and the
 * caller must then read nothing from it.
 */
bool vu_state_verify(const vu_state_paths *p, uid_t expect_uid, bool *present, vu_err *e);

/*
 * expect_uid is the uid that must own the pid and start-token files — 0 in
 * production, the caller's own under test. A state file with any other owner,
 * or with group or other access, is refused rather than parsed: its contents
 * decide which pid root signals.
 */
bool vu_state_check(const vu_state_paths *p, const char *expect_exe, uid_t expect_uid,
                    vu_state_status *status, vu_proc *found, vu_err *e);

bool vu_state_prune(const vu_state_paths *p, vu_err *e);

/* ------------------------------------------------------------------ telemetry */
/*
 * session/status: connection-state design plan §2. Deliberately separate
 * from pid/started/endpoint above — see vu_state_paths's struct comment for
 * why vu_state_prune() never touches them.
 */

/* A cryptographically-uninteresting but non-guessable per-generation
 * identifier: 32 lowercase hex characters read from /dev/urandom. Used both
 * for the helper-generated, authoritative `session` id and, when a caller
 * omits --request-id, an internally generated fallback request id — the
 * one thing this design needs from either is that two generations never
 * collide, not secrecy. */
bool vu_generate_hex_id(char out[VU_HEXID_MAX], vu_err *e);

/*
 * Called once per `connect`, after the profile lock is held and BEFORE
 * execve: writes the authoritative `session` leaf and a FRESHLY ZEROED
 * `status` telemetry record for this brand-new generation. Never called
 * again for this generation by this program — every later update to
 * `status` comes from the vpnc-script wrapper's own read-modify-write.
 *
 * Writing a zeroed record here (rather than leaving whatever a previous
 * generation left in `status`) is what stops the wrapper from ever
 * inheriting a stale generation's last_connected_epoch, even before its own
 * defensive request-id check runs.
 */
bool vu_state_write_fresh_telemetry(const vu_state_paths *p, const char *session_id,
                                    const char *request_id, vu_err *e);

/* Parsed contents of the `status` telemetry leaf. */
typedef struct {
    char request_id[VU_HEXID_MAX];
    int32_t last_connected_epoch;
    bool current_verified;
    char last_reason[24];      /* "", "connect", "reconnect", "attempt-reconnect", "disconnect" */
    int32_t last_event_epoch;
} vu_telemetry;

/*
 * Read the `session` leaf alone — present=false is the normal, valid answer
 * for a profile that has never connected, not an error. An ownership
 * violation (wrong uid, group/other access) is a hard refusal, like every
 * other state read in this file.
 */
bool vu_state_read_session(const vu_state_paths *p, uid_t expect_uid,
                           char out[VU_HEXID_MAX], bool *present, vu_err *e);

/*
 * Read and strictly parse the `status` telemetry leaf, but ONLY if its own
 * `session` field equals `want_session` (the value vu_state_read_session
 * just returned) — a mismatch is treated exactly like an absent record
 * (present=false, never an error, never partially-populated output), per
 * the connection-state design plan's session-consistency check. Strict
 * parsing: an unrecognised `version`, a malformed epoch, a `current_verified`
 * outside {0,1}, or an undocumented `last_reason` are ALL treated as absent
 * — never partially trusted, never surfaced as verified evidence.
 *
 * Deliberately does not call vu_state_check/vu_proc_identity or
 * vu_state_prune: this must answer correctly even after OpenConnect has
 * already exited, which is exactly when its most important caller (a
 * connect's own mandatory final synchronous read) needs it.
 */
bool vu_state_read_status(const vu_state_paths *p, uid_t expect_uid,
                          const char *want_session, vu_telemetry *out,
                          bool *present, vu_err *e);

/*
 * Read the raw recorded pid, with no liveness check at all — the caller
 * (event-status) hands this to an unprivileged poller purely so it can
 * populate its OWN pid file for `vpn-up status`'s existing, unmodified
 * `is_openconnect_pid` predicate to find and independently re-verify.
 * Garbage or unparseable content reads as absent, never as an error.
 */
bool vu_state_read_pid(const vu_state_paths *p, uid_t expect_uid,
                       int32_t *pid_out, bool *present, vu_err *e);

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
 * Guarantee that descriptors 0, 1 and 2 are open, pointing any that are not at
 * /dev/null. Must run before this program opens ANYTHING.
 *
 * Not hygiene — a correctness requirement, and step 9's most concrete finding.
 * A caller may invoke the helper with stdin closed (`sudo vpn-up-helper connect
 * ... 0<&-`), and the kernel then hands the lowest free descriptor to the next
 * open() — which is the LOCK FILE. The helper execve's OpenConnect with
 * --cookie-on-stdin, so OpenConnect would read the lock file as the session
 * cookie. Verified: with stdin closed, vu_lock_acquire returns fd 0.
 *
 * The same shape with stderr closed points the process's own diagnostics at a
 * root-owned state file. Neither is a privilege escalation, but both make a
 * privileged program's behaviour depend on how its caller arranged its
 * descriptors, which is a property no privileged program should have.
 */
bool vu_ensure_std_fds(vu_err *e);

/*
 * The PATH the privileged child receives.
 *
 * Defined here, and used by BOTH vu_clean_env (which sets it) and the closure
 * check (which verifies every entry is a trusted directory). One definition
 * because two would drift, and a PATH entry nobody checked is a directory root
 * resolves tools through — vpnc-script looks up route, ifconfig, ip and
 * resolvconf by name.
 *
 * Never empty: vpnc-script does PATH=/sbin:/usr/sbin:$PATH, so an empty value
 * becomes a trailing colon, and a trailing colon means the current directory.
 */
#ifndef VU_HELPER_PATH
#  define VU_HELPER_PATH "/usr/sbin:/usr/bin:/sbin:/bin"
#endif

/*
 * A minimal, explicitly constructed environment for the exec'd child. Nothing
 * is inherited: no IFS, no LD_ or DYLD_ variables, no BASH_ENV, no CDPATH. PATH
 * is set explicitly and is never empty, for the reason above.
 *
 * Also carries the four variables the vpnc-script wrapper needs to find and
 * validate its own telemetry leaf (connection-state design plan §2):
 * VUP_STATE_UID, VUP_PROFILE_ID, VUP_SESSION_ID, VUP_REQUEST_ID. profile_id
 * must already be canonical; session_id and request_id must already be
 * VU_HEXID_LEN hex characters — this function does not validate them, it only
 * formats what the caller already validated.
 *
 * Returns a NULL-terminated array owned by the callee; valid until the next
 * call. Not thread-safe, and does not need to be.
 */
char **vu_clean_env(uid_t uid, const char *profile_id,
                    const char *session_id, const char *request_id);

#endif /* VU_STATE_H */
