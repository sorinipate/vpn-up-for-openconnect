/*
 * helper_main.c — vpn-up-helper: connect | stop | version.
 *
 * The ONLY binary that belongs in the NOPASSWD sudoers rule (§5). Everything it
 * will do for any input is establish or tear down a tunnel that has already
 * been approved for the calling user.
 *
 * The connect sequence, in order, because the order is the design:
 *
 *   1. parse argv against the closed schema      -- no pass-through, ever
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
 * stdin is never read. The cookie flows through untouched to
 * `openconnect --cookie-on-stdin`; reading it here to validate it would consume
 * the bytes OpenConnect needs, and there is nothing for validation to protect
 * since the helper never interprets it.
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
        "          [--tunable K=V ...] [--quiet]\n"
        "  stop    --profile-id ID\n"
        "  version\n"
        "\n"
        "The cookie is read from stdin by OpenConnect; this program does not\n"
        "read it. The server fingerprint comes from the approval registry, not\n"
        "from the command line: use vpn-up-admin to approve an endpoint.\n",
        stderr);
}

static const char *next_value(int argc, char **argv, int *i, const char *flag)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "vpn-up-helper: %s needs a value\n", flag);
        return NULL;
    }
    const char *v = argv[++(*i)];
    if (v[0] == '-') {
        fprintf(stderr, "vpn-up-helper: %s was given '%s', which looks like a flag\n", flag, v);
        return NULL;
    }
    return v;
}

/* Parse and validate the closed schema (§8). Every field goes through the
 * policy engine; nothing is copied across unchecked. */
static bool parse_connect(int argc, char **argv, vu_request *req, vu_err *e)
{
    memset(req, 0, sizeof *req);

    const char *raw_id = NULL, *raw_proto = NULL, *raw_url = NULL;
    const char *raw_resolve = NULL, *raw_proxy = NULL, *raw_ua = NULL;
    const char *raw_tunables[VU_TUNABLE_MAX];
    size_t n_tun = 0;

    for (int i = 0; i < argc; ++i) {
        const char *a = argv[i];
        if      (strcmp(a, "--profile-id")  == 0) { if (!(raw_id      = next_value(argc, argv, &i, a))) return false; }
        else if (strcmp(a, "--protocol")    == 0) { if (!(raw_proto   = next_value(argc, argv, &i, a))) return false; }
        else if (strcmp(a, "--connect-url") == 0) { if (!(raw_url     = next_value(argc, argv, &i, a))) return false; }
        else if (strcmp(a, "--resolve")     == 0) { if (!(raw_resolve = next_value(argc, argv, &i, a))) return false; }
        else if (strcmp(a, "--proxy")       == 0) { if (!(raw_proxy   = next_value(argc, argv, &i, a))) return false; }
        else if (strcmp(a, "--useragent")   == 0) { if (!(raw_ua      = next_value(argc, argv, &i, a))) return false; }
        else if (strcmp(a, "--quiet")       == 0) { req->quiet = true; }
        else if (strcmp(a, "--tunable")     == 0) {
            const char *v = next_value(argc, argv, &i, a);
            if (!v) return false;
            if (n_tun >= VU_TUNABLE_MAX) {
                vu_err_set(e, "at most %d tunables", VU_TUNABLE_MAX);
                return false;
            }
            raw_tunables[n_tun++] = v;
        } else {
            /* No pass-through. An argument we do not understand is a mistake,
             * and forwarding it is exactly how the old extraArgs hole worked. */
            vu_err_set(e, "unrecognised argument '%s'", a);
            return false;
        }
    }

    if (!raw_id || !raw_proto || !raw_url) {
        vu_err_set(e, "connect needs --profile-id, --protocol and --connect-url");
        return false;
    }

    if (!vu_canon_profile_id(raw_id, req->profile_id, sizeof req->profile_id, e)) return false;
    if (!vu_valid_protocol(raw_proto, e)) return false;
    if (strlen(raw_proto) + 1 > sizeof req->protocol) {
        vu_err_set(e, "protocol: too long"); return false;
    }
    memcpy(req->protocol, raw_proto, strlen(raw_proto) + 1);

    if (!vu_parse_url(raw_url, &req->url, e)) return false;

    if (raw_resolve) {
        if (!vu_canon_resolve(raw_resolve, &req->resolve, e)) return false;
        req->has_resolve = true;
    }
    if (raw_proxy) {
        if (!vu_canon_proxy(raw_proxy, req->proxy, sizeof req->proxy, e)) return false;
    }
    if (raw_ua) {
        if (!vu_valid_useragent(raw_ua, e)) return false;
        if (strlen(raw_ua) + 1 > sizeof req->useragent) {
            vu_err_set(e, "useragent: too long"); return false;
        }
        memcpy(req->useragent, raw_ua, strlen(raw_ua) + 1);
    }
    for (size_t i = 0; i < n_tun; ++i) {
        if (!vu_render_tunable(raw_tunables[i], req->tunables[i],
                               VU_TUNABLE_LEN, e)) return false;
    }
    req->n_tunables = n_tun;
    return true;
}

static int cmd_connect(int argc, char **argv, uid_t uid)
{
    vu_err e; vu_err_clear(&e);
    vu_request req;

    if (!parse_connect(argc, argv, &req, &e)) goto bad;

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

    /* Pinned executables, checked immediately before use rather than at startup:
     * the window matters less than the fact that this is the last look. */
    if (!vu_exec_precheck(VU_OPENCONNECT, VU_VPNC_SCRIPT, 0, &e)) {
        fprintf(stderr, "vpn-up-helper: %s\n", e.msg);
        fprintf(stderr, "vpn-up-helper: helper mode needs a root-owned OpenConnect; "
                        "a Homebrew install cannot be used (see SECURITY.md).\n");
        return 1;
    }

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
    if (vu_state_check(&paths, VU_OPENCONNECT, &status, NULL, &scratch) &&
        status == VU_STATE_STALE) {
        (void)vu_state_prune(&paths, &scratch);
    }

    if (!vu_harden_process(lock_fd, &e)) goto bad;

    /*
     * getpid() now IS the OpenConnect pid: execve replaces this image rather
     * than forking, so the recorded pid is exact with no --pid-file and no
     * scanning the process table.
     */
    vu_proc self;
    if (!vu_proc_identity(getpid(), &self, &e)) goto bad;
    if (!vu_state_record(&paths, &self, appr.origin, &e)) goto bad;

    execve(VU_OPENCONNECT, cmd.argv, vu_clean_env());

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

    const char *raw_id = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--profile-id") == 0) {
            if (!(raw_id = next_value(argc, argv, &i, argv[i]))) return 2;
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
     * No pid is ever accepted on argv. The pid comes from root-owned state and
     * is only signalled if the executable path AND the start token still match,
     * so a recycled pid is never touched. That is the hole `sudo kill "$pid"`
     * leaves open in core.sh today.
     */
    vu_state_status status;
    vu_proc found;
    if (!vu_state_check(&paths, VU_OPENCONNECT, &status, &found, &e)) {
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
        if (!vu_state_check(&paths, VU_OPENCONNECT, &status, NULL, &e) ||
            status != VU_STATE_LIVE) {
            vu_err_clear(&e);
            (void)vu_state_prune(&paths, &e);
            printf("stopped %s\n", id);
            return 0;
        }
    }

    vu_err_clear(&e);
    if (vu_state_check(&paths, VU_OPENCONNECT, &status, &found, &e) && status == VU_STATE_LIVE) {
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

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 2; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "version") == 0) {
        printf("vpn-up-helper (policy engine %d)\n", VU_APPROVAL_VERSION);
        printf("  openconnect   %s\n", VU_OPENCONNECT);
        printf("  vpnc-script   %s\n", VU_VPNC_SCRIPT);
        printf("  registry root %s\n", VU_REGISTRY_ROOT);
        printf("  state root    %s\n", VU_STATE_ROOT);
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

    if (strcmp(cmd, "connect") == 0) return cmd_connect(argc - 2, argv + 2, uid);
    if (strcmp(cmd, "stop")    == 0) return cmd_stop(argc - 2, argv + 2, uid);

    fprintf(stderr, "vpn-up-helper: unknown command '%s'\n", cmd);
    usage();
    return 2;
}
