/*
 * helper_main.c — vpn-up-helper: connect | stop | version.
 *
 * The ONLY binary that belongs in the NOPASSWD sudoers rule (§5). Everything it
 * will do for any input is establish or tear down a tunnel that has already
 * been approved for the calling user.
 *
 * The connect sequence, in order, because the order is the design:
 *
 *   0. confirm fds 0,1,2 are open                -- before ANY open() in this
 *                                                   process; see below
 *   1. parse argv against the closed schema      -- no pass-through, ever
 *                                                   (vu_request_from_argv)
 *   2. resolve SUDO_UID                          -- refuse if absent
 *   3. look up the approval                      -- refuse if absent
 *   4. policy check                              -- protocol/origin/proxy/resolve
 *   5. verify the pinned executables             -- file-level closure (partial)
 *   6. take the per-(uid, profile) lock          -- survives execve
 *   7. harden the process                        -- umask, chdir, fds, core
 *   8. record pid + start token                  -- getpid() IS the future
 *                                                   OpenConnect pid
 *   9. execve                                    -- one call, no fork
 *
 * `stop` verifies the state tree it is about to read (step 9 of §16 found that
 * it did not), then re-verifies the process identity before every signal.
 *
 * Step 0 is not hygiene. A caller who closes stdin gets the lowest free
 * descriptor handed to the next open() — which is the lock file — and
 * OpenConnect, run with --cookie-on-stdin, would read the lock file as the
 * session cookie. Verified, not theoretical.
 *
 * stdin is never read HERE. The cookie flows through untouched to
 * `openconnect --cookie-on-stdin`; reading it to validate it would consume the
 * bytes OpenConnect needs, and there is nothing for validation to protect since
 * the helper never interprets it.
 *
 * The argv schema itself lives in src/request.c, not in this file: main()
 * refuses to run as anything but root before it looks at argv, so a parser in
 * here could not be attacked by an unprivileged test at all.
 */

#include "vu_exec.h"
#include "vu_state.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void usage(void)
{
    fputs(
        "usage: vpn-up-helper <command>\n"
        "\n"
        "  connect --profile-id ID --protocol P --connect-url URL\n"
        "          [--resolve HOST:IP] [--proxy URL] [--useragent S]\n"
        "          [--tunable K=V ...] [--quiet] [--request-id ID]\n"
        "  stop    --profile-id ID\n"
        "  event-status --profile-id ID\n"
        "  version\n"
        "\n"
        "The cookie is read from stdin by OpenConnect; this program does not\n"
        "read it. The server fingerprint comes from the approval registry, not\n"
        "from the command line: use vpn-up-admin to approve an endpoint.\n",
        stderr);
}

static int cmd_connect(int argc, char **argv, uid_t uid)
{
    vu_err e; vu_err_clear(&e);
    vu_request req;

    if (!vu_request_from_argv(argc, argv, &req, &e)) goto bad;

    /* The approval, and the fingerprint that comes with it. A missing record is
     * the common case for a first run, so say what to do about it. */
    vu_approval appr;
    bool found = false;
    if (!vu_registry_get(VU_REGISTRY_ROOT, 0, uid, req.profile_id, &appr, &found, &e)) goto bad;
    if (!found) {
        fprintf(stderr, "vpn-up-helper: profile %s is not approved for this user.\n"
                        "Approve it first: sudo vpn-up-admin approve --profile-id %s ...\n",
                req.profile_id, req.profile_id);
        return 1;
    }
    memcpy(req.fingerprint, appr.fingerprint, sizeof req.fingerprint);

    /* Model B. Refuses a substituted protocol, endpoint, proxy, or a --resolve
     * naming an unapproved host. */
    if (!vu_policy_check(&req, &appr, &e)) goto bad;

    /*
     * The whole trusted execution closure, checked immediately before use rather
     * than at startup: the window matters less than the fact that this is the
     * last look. The failing rows are printed, because a closure failure is
     * something the operator has to fix on the machine and "refused" alone would
     * not tell them what.
     *
     * Two objects now, not one (connection-state design plan §2): the REAL
     * vpnc-script gets the full §11.4 walk (hooks, PATH, library closure) via
     * vu_exec_precheck, exactly as before this design landed. The wrapper
     * OpenConnect actually invokes (VU_VPNC_SCRIPT) gets only the lighter-weight
     * vu_wrapper_precheck: file ownership/permissions and its own shebang
     * interpreter. Walking the wrapper through the full check too would just
     * duplicate report rows for objects (hooks, PATH, libraries) that belong to
     * the real script, not to whichever thin wrapper happens to name it.
     */
    static vu_closure_report closure;
    if (!vu_exec_precheck(VU_OPENCONNECT, VU_VPNC_SCRIPT_REAL, 0, uid, &closure, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        vu_closure_print(&closure, stderr);
        fprintf(stderr, "vpn-up-helper: helper mode needs a root-owned OpenConnect whose "
                        "whole execution closure is outside your write control; a Homebrew "
                        "install cannot be used (see SECURITY.md).\n");
        return 1;
    }

    static vu_closure_report wrapper_closure;
    vu_err werr; vu_err_clear(&werr);
    if (!vu_wrapper_precheck(VU_VPNC_SCRIPT, 0, &wrapper_closure, &werr)) {
        fprintf(stderr, "vpn-up-helper: %s\n", werr.msg);
        vu_closure_print(&wrapper_closure, stderr);
        fprintf(stderr, "vpn-up-helper: helper mode needs a root-owned vpnc-script "
                        "wrapper whose ownership and interpreter are outside your write "
                        "control; reinstall with 'vpn-up install-helper' (see "
                        "SECURITY.md).\n");
        return 1;
    }

    /* VU_VPNC_SCRIPT (the wrapper), not VU_VPNC_SCRIPT_REAL: this is the value
     * OpenConnect's --script must actually receive, so its own telemetry
     * recording runs on every connect/disconnect/reconnect event. */
    static vu_argv cmd;
    if (!vu_build_argv(&req, &appr, VU_OPENCONNECT, VU_VPNC_SCRIPT, &cmd, &e)) goto bad;

    vu_state_paths paths;
    if (!vu_state_paths_for(uid, req.profile_id, &paths, &e)) goto bad;

    int lock_fd = -1;
    if (!vu_lock_acquire(&paths, 0, &lock_fd, &e)) goto bad;

    /*
     * Stale state from a previous run is pruned only after the lock is held, so
     * two connects cannot race over it. A live tunnel would have kept the lock,
     * so reaching here means nothing is running for this profile.
     */
    vu_state_status status;
    vu_err scratch; vu_err_clear(&scratch);
    if (vu_state_check(&paths, VU_OPENCONNECT, 0, &status, NULL, &scratch) &&
        status == VU_STATE_STALE) {
        (void)vu_state_prune(&paths, &scratch);
    }

    /*
     * A fresh generation, connection-state design plan §2: the authoritative
     * session id and the request id (the caller's own, when it supplied one and
     * knows to look for it via event-status; otherwise generated here purely for
     * this program's own bookkeeping, since a request id is required either way
     * to write a well-formed telemetry record). Both are generated, and the
     * telemetry leaf is written fresh and zeroed, while the lock is held and
     * BEFORE execve — the wrapper's very first invocation must already find a
     * record belonging to THIS generation, never a stale one left by whatever
     * ran here before.
     */
    char session_id[VU_HEXID_MAX];
    if (!vu_generate_hex_id(session_id, &e)) goto bad;

    const char *request_id = req.request_id;
    char generated_request_id[VU_HEXID_MAX];
    if (!req.has_request_id) {
        if (!vu_generate_hex_id(generated_request_id, &e)) goto bad;
        request_id = generated_request_id;
    }

    if (!vu_state_write_fresh_telemetry(&paths, session_id, request_id, &e)) goto bad;

    if (!vu_harden_process(lock_fd, &e)) goto bad;

    /*
     * getpid() now IS the OpenConnect pid: execve replaces this image rather
     * than forking, so the recorded pid is exact with no --pid-file and no
     * scanning the process table.
     */
    vu_proc self;
    if (!vu_proc_identity(getpid(), &self, &e)) goto bad;
    if (!vu_state_record(&paths, &self, appr.origin, &e)) goto bad;

    execve(VU_OPENCONNECT, cmd.argv,
          vu_clean_env(uid, req.profile_id, session_id, request_id));

    /* Only reachable if execve failed, which means nothing was started. Drop the
     * state we just wrote so `stop` is not left pointing at this process. */
    vu_err_clear(&scratch);
    (void)vu_state_prune(&paths, &scratch);
    fprintf(stderr, "vpn-up-helper: cannot execute %s: %s\n",
            VU_OPENCONNECT, strerror(errno));
    return 1;

bad:
    fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
    return 1;
}

static int cmd_stop(int argc, char **argv, uid_t uid)
{
    vu_err e; vu_err_clear(&e);

    /* stop's schema is one flag, so it is scanned here rather than through
     * vu_request_from_argv. Same rules: no pass-through, no repeats, and never a
     * pid on argv. */
    const char *raw_id = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--profile-id") == 0) {
            if (raw_id) {
                fprintf(stderr, "vpn-up-helper: --profile-id was given more than once\n");
                return 2;
            }
            if (i + 1 >= argc) {
                fprintf(stderr, "vpn-up-helper: --profile-id needs a value\n");
                return 2;
            }
            raw_id = argv[++i];
            if (raw_id[0] == '-') {
                fprintf(stderr, "vpn-up-helper: --profile-id was given '%s', "
                                "which looks like a flag\n", raw_id);
                return 2;
            }
        } else {
            fprintf(stderr, "vpn-up-helper: unrecognised argument '%s'\n", argv[i]);
            return 2;
        }
    }
    if (!raw_id) { fprintf(stderr, "vpn-up-helper: stop needs --profile-id\n"); return 2; }

    char id[VU_UUID_MAX];
    if (!vu_canon_profile_id(raw_id, id, sizeof id, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }

    vu_state_paths paths;
    if (!vu_state_paths_for(uid, id, &paths, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }

    /*
     * Verify the state tree BEFORE reading anything out of it. connect builds it
     * with vu_dir_ensure, so it arrives verified; stop used to walk straight to
     * the pid file, which meant that on any platform where the state root's
     * parent is not root-only (macOS /var/run is drwxrwxr-x root:daemon) another
     * user could plant the pid that root then signals.
     */
    bool state_present = false;
    if (!vu_state_verify(&paths, 0, &state_present, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        fprintf(stderr, "vpn-up-helper: refusing to act on state this program does not own\n");
        return 1;
    }
    if (!state_present) {
        printf("no tunnel recorded for %s\n", id);
        return 0;
    }

    /*
     * No pid is ever accepted on argv. The pid comes from root-owned state and
     * is only signalled if the executable path AND the start token still match,
     * so a recycled pid is never touched. That is the hole `sudo kill "$pid"`
     * leaves open in core.sh today.
     */
    vu_state_status status;
    vu_proc found;
    if (!vu_state_check(&paths, VU_OPENCONNECT, 0, &status, &found, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }

    if (status == VU_STATE_ABSENT) {
        printf("no tunnel recorded for %s\n", id);
        return 0;
    }
    if (status == VU_STATE_STALE) {
        /* Nothing to signal, and the record is misleading, so remove it. */
        vu_err_clear(&e);
        if (!vu_state_prune(&paths, &e)) {
            fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
            return 1;
        }
        printf("no tunnel running for %s (cleared stale state)\n", id);
        return 0;
    }

    if (kill(found.pid, SIGTERM) != 0 && errno != ESRCH) {
        fprintf(stderr, "vpn-up-helper: cannot signal pid %ld: %s\n",
                (long)found.pid, strerror(errno));
        return 1;
    }

    /* Give it a few seconds, re-verifying identity each time so a pid recycled
     * during the wait is never escalated to SIGKILL. */
    for (int i = 0; i < 50; ++i) {
        struct timespec ts = { 0, 100 * 1000 * 1000 };   /* 100ms */
        (void)nanosleep(&ts, NULL);
        vu_err_clear(&e);
        if (!vu_state_check(&paths, VU_OPENCONNECT, 0, &status, NULL, &e) ||
            status != VU_STATE_LIVE) {
            vu_err_clear(&e);
            (void)vu_state_prune(&paths, &e);
            printf("stopped %s\n", id);
            return 0;
        }
    }

    vu_err_clear(&e);
    if (vu_state_check(&paths, VU_OPENCONNECT, 0, &status, &found, &e) && status == VU_STATE_LIVE) {
        if (kill(found.pid, SIGKILL) != 0 && errno != ESRCH) {
            fprintf(stderr, "vpn-up-helper: cannot kill pid %ld: %s\n",
                    (long)found.pid, strerror(errno));
            return 1;
        }
    }
    vu_err_clear(&e);
    (void)vu_state_prune(&paths, &e);
    printf("stopped %s (did not exit on SIGTERM)\n", id);
    return 0;
}

/*
 * event-status --profile-id ID — read-only, connection-state design plan §2.
 *
 * Deliberately does NOT call vu_state_verify/vu_state_check/vu_proc_identity or
 * vu_state_prune: unlike connect/stop this must answer correctly even after
 * OpenConnect has already exited, which is exactly when its most important
 * caller — a connect invocation's own mandatory final synchronous read — needs
 * it. Telemetry is never pruned regardless (see vu_state_paths's struct
 * comment), so there is nothing here for a liveness check to protect.
 *
 * No server-side request-id filtering: that is not an authority question, so
 * the unprivileged caller (which already knows its own request id) does that
 * comparison itself against this verb's output.
 */
static int cmd_event_status(int argc, char **argv, uid_t uid)
{
    vu_err e; vu_err_clear(&e);

    /* Same one-flag schema as stop: scanned inline rather than through
     * vu_request_from_argv, which is connect's schema. */
    const char *raw_id = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--profile-id") == 0) {
            if (raw_id) {
                fprintf(stderr, "vpn-up-helper: --profile-id was given more than once\n");
                return 2;
            }
            if (i + 1 >= argc) {
                fprintf(stderr, "vpn-up-helper: --profile-id needs a value\n");
                return 2;
            }
            raw_id = argv[++i];
            if (raw_id[0] == '-') {
                fprintf(stderr, "vpn-up-helper: --profile-id was given '%s', "
                                "which looks like a flag\n", raw_id);
                return 2;
            }
        } else {
            fprintf(stderr, "vpn-up-helper: unrecognised argument '%s'\n", argv[i]);
            return 2;
        }
    }
    if (!raw_id) { fprintf(stderr, "vpn-up-helper: event-status needs --profile-id\n"); return 2; }

    char id[VU_UUID_MAX];
    if (!vu_canon_profile_id(raw_id, id, sizeof id, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }

    vu_state_paths paths;
    if (!vu_state_paths_for(uid, id, &paths, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }

    /* present=false ("never connected") is a normal answer, not an error;
     * an ownership violation (wrong uid, group/other access) is a hard
     * refusal, like every other state read. */
    bool present = false;
    char session[VU_HEXID_MAX];
    if (!vu_state_read_session(&paths, 0, session, &present, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }
    if (!present) {
        printf("no telemetry for %s\n", id);
        return 0;
    }

    /*
     * The session-consistency check (distinct from the client-side request-id
     * check the caller performs on this output) happens inside
     * vu_state_read_status: a status record whose OWN session field does not
     * match the authoritative leaf just read is treated exactly like an
     * absent record. This is also why the record below prints the
     * authoritative `session` read above, and not a second copy from inside
     * `tel` — vu_telemetry has no session field at all, precisely so this
     * cannot regress into the round-4 duplicate-session-field bug.
     */
    vu_telemetry tel;
    bool tel_present = false;
    if (!vu_state_read_status(&paths, 0, session, &tel, &tel_present, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }
    if (!tel_present) {
        printf("no telemetry for %s\n", id);
        return 0;
    }

    /*
     * The recorded pid, with no liveness check at all (round-4 item 1): this is
     * what lets the unprivileged poller populate its OWN pid file for
     * `vpn-up status`'s existing, unmodified predicate to find and
     * independently re-verify. 0 is not a valid pid (vu_state_read_pid never
     * returns one below 1) and is printed here as the explicit absent
     * sentinel, so a caller can tell "no pid recorded" from a real value by
     * strict parsing alone, with no separate presence field to get out of sync.
     */
    int32_t pid_out = 0;
    bool pid_present = false;
    vu_err perr; vu_err_clear(&perr);
    if (!vu_state_read_pid(&paths, 0, &pid_out, &pid_present, &perr)) {
        fprintf(stderr, "vpn-up-helper: %s\n", perr.msg);
        return 1;
    }

    printf("session=%s\n", session);
    printf("request_id=%s\n", tel.request_id);
    printf("last_connected_epoch=%d\n", (int)tel.last_connected_epoch);
    printf("current_verified=%d\n", tel.current_verified ? 1 : 0);
    printf("last_reason=%s\n", tel.last_reason);
    printf("last_event_epoch=%d\n", (int)tel.last_event_epoch);
    printf("pid=%d\n", pid_present ? (int)pid_out : 0);
    return 0;
}

int main(int argc, char **argv)
{
    /*
     * FIRST, before any open() in this process: a caller who closes stdin gets
     * the lock file on descriptor 0, and OpenConnect then reads the lock file as
     * the --cookie-on-stdin cookie. See vu_ensure_std_fds.
     */
    {
        vu_err fds; vu_err_clear(&fds);
        if (!vu_ensure_std_fds(&fds)) {
            fprintf(stderr, "vpn-up-helper: %s\n", fds.msg);
            return 1;
        }
    }

    if (argc < 2) { usage(); return 2; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "version") == 0) {
        printf("vpn-up-helper (policy engine %d)\n", VU_APPROVAL_VERSION);
        printf("  openconnect     %s\n", VU_OPENCONNECT);
        printf("  vpnc-script     %s (wrapper)\n", VU_VPNC_SCRIPT);
        printf("  vpnc-script.real %s\n", VU_VPNC_SCRIPT_REAL);
        printf("  registry root   %s\n", VU_REGISTRY_ROOT);
        printf("  state root      %s\n", VU_STATE_ROOT);
        /*
         * Unprivileged, grep-able capability marker (connection-state design
         * plan, round 3 item 7 / round 4 item 6): callers must decide "does
         * this helper support event-status/request-id telemetry" from THIS
         * line, checked before any credential is spent, never from whether a
         * later PRIVILEGED event-status call happens to fail — a failure
         * there can mean many things besides "old helper" (an expired sudo
         * credential, corrupted state, a real bug), and conflating them would
         * hide real problems behind a silent, wrong "must be old" fallback.
         */
        printf("  features        event-status-v1\n");
        return 0;
    }

    vu_err e; vu_err_clear(&e);
    if (geteuid() != 0) {
        fprintf(stderr, "vpn-up-helper: must run as root (via sudo)\n");
        return 1;
    }

    uid_t uid;
    if (!vu_sudo_uid(&uid, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        return 1;
    }

    /*
     * §11.1: this binary re-walks its own install path before doing privileged
     * work. A root-owned helper under a directory the caller can write is not a
     * boundary — the caller replaces the file and waits for the next connect.
     * After the root gate so that `version` stays runnable from a build tree.
     */
    if (!vu_self_trusted(&e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        fprintf(stderr, "vpn-up-helper: refusing to run as root from an untrusted path; "
                        "install with 'vpn-up install-helper'\n");
        return 1;
    }

    if (strcmp(cmd, "connect")      == 0) return cmd_connect(argc - 2, argv + 2, uid);
    if (strcmp(cmd, "stop")         == 0) return cmd_stop(argc - 2, argv + 2, uid);
    if (strcmp(cmd, "event-status") == 0) return cmd_event_status(argc - 2, argv + 2, uid);

    fprintf(stderr, "vpn-up-helper: unknown command '%s'\n", cmd);
    usage();
    return 2;
}
