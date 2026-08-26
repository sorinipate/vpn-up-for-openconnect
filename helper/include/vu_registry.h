/*
 * vu_registry.h — the Model B approval registry (§7, §16 step 6).
 *
 * An approval records that a specific privileged VPN capability was authorised
 * once, interactively, by a human who typed their sudo password. The helper
 * checks a connect request against it; nothing else in the system can add one.
 *
 * Three properties this file exists to guarantee:
 *
 *  1. PERSISTENT, not volatile. The registry deliberately does NOT live under
 *     the state root: /run and /var/run are cleared at boot, so approvals kept
 *     there would be silently revoked every restart, and a login service would
 *     stop working for reasons nobody could see. Approvals are policy and
 *     belong with policy.
 *
 *  2. WRITTEN ONLY BY vpn-up-admin. vpn-up-helper links this code to READ the
 *     registry and must never be given a path that writes it. A NOPASSWD binary
 *     that can approve endpoints is a NOPASSWD binary that can approve anything
 *     (§5), which is the whole reason there are two executables.
 *
 *  3. ONE RECORD PER FILE. Revoke is an unlink, approve is an atomic rename,
 *     list is a readdir, and two profiles can never contend over one file or be
 *     corrupted together by a partial write.
 */
#ifndef VU_REGISTRY_H
#define VU_REGISTRY_H

#include "vu.h"
#include "vu_state.h"

#include <sys/types.h>

/*
 * Persistent registry root. /etc is root-owned on both platforms and survives
 * reboots and OS updates; on macOS it is a symlink to /private/etc, which the
 * leaf-only no-follow policy (§11.4, as amended) handles correctly.
 * Overridable at build time for packaging, never at run time — same reasoning
 * as VU_STATE_ROOT.
 */
#ifndef VU_REGISTRY_ROOT
#  define VU_REGISTRY_ROOT "/etc/vpn-up"
#endif

#define VU_APPROVALS_DIR "approvals"

/* Bumped only if the on-disk record format changes incompatibly. A record with
 * an unrecognised version is refused, never guessed at. */
#define VU_APPROVAL_VERSION 1

/* A generous ceiling for `list`; approvals are per-user VPN profiles, not a
 * data set. Exceeding it is reported rather than silently truncated. */
#define VU_APPROVAL_LIST_MAX 256

typedef struct {
    char approvals[VU_PATH_MAX];   /* <root>/approvals          */
    char uid_dir[VU_PATH_MAX];     /* <root>/approvals/<uid>    */
    char record[VU_PATH_MAX];      /* <root>/approvals/<uid>/<profile-id> */
} vu_registry_paths;

/* profile_id must already be canonical (vu_canon_profile_id). */
bool vu_registry_paths_in(const char *root, uid_t uid, const char *profile_id,
                          vu_registry_paths *out, vu_err *e);
bool vu_registry_paths_for(uid_t uid, const char *profile_id,
                           vu_registry_paths *out, vu_err *e);

/* ------------------------------------------------------------ serialisation */

/*
 * Canonical `key=value` lines, fixed key set, single spelling per record, so
 * writing the same approval twice produces byte-identical files.
 *
 * Parsing is as strict as the phase-one decoder and for the same reason: the
 * fact that root wrote this file is not a licence to trust its contents. A
 * hand-edited or truncated record must fail loudly rather than yield a
 * half-populated approval that then authorises something.
 */
bool vu_approval_serialise(const vu_approval *a, char *out, size_t cap, vu_err *e);
bool vu_approval_parse(const char *text, vu_approval *out, vu_err *e);

/* --------------------------------------------------------------- operations */

/*
 * `owner` is the uid every registry directory and record must belong to: 0 in
 * production, the caller's own uid under test. Explicit for the same reason as
 * vu_dir_ensure's expect_uid — the corpus exercises the real ownership checks
 * rather than a weakened copy.
 */
bool vu_registry_put(const char *root, uid_t owner, uid_t uid,
                     const vu_approval *a, vu_err *e);

/* found=false with a true return means "no such approval", which is a normal
 * answer rather than an error. */
bool vu_registry_get(const char *root, uid_t owner, uid_t uid, const char *profile_id,
                     vu_approval *out, bool *found, vu_err *e);

bool vu_registry_delete(const char *root, uid_t owner, uid_t uid, const char *profile_id,
                        bool *removed, vu_err *e);

bool vu_registry_list(const char *root, uid_t owner, uid_t uid,
                      vu_approval *out, size_t cap, size_t *count, vu_err *e);

/* ------------------------------------------------------------------ vpn-up-admin */

/*
 * vpn-up-admin must be reached through an interactive `sudo`, so every approval
 * costs a real password prompt. The enforcement lives in sudoers — this binary
 * cannot tell an interactive sudo from a passwordless one, and pretending
 * otherwise would be security theatre. What it CAN do is refuse to run without
 * privilege at all, so a mistaken unprivileged invocation fails clearly instead
 * of writing somewhere unexpected.
 */
bool vu_admin_require_root(vu_err *e);

#endif /* VU_REGISTRY_H */
