/*
 * admin_main.c — vpn-up-admin: approve | revoke | list | version.
 *
 * The second of the two privileged binaries (§5). This one is NEVER in the
 * NOPASSWD sudoers rule, so every approval costs a real password prompt:
 *
 *     vpn-up-helper   connect | stop | version     <- the ONLY NOPASSWD binary
 *     vpn-up-admin    approve | revoke | list      <- NEVER NOPASSWD
 *
 * That separation is what makes Model B mean anything. If the passwordless
 * binary could also approve endpoints, an attacker holding the passwordless
 * grant could approve whatever it wanted and then "legitimately" connect there.
 *
 * Enforcement of the interactive requirement lives in sudoers, not here: this
 * process cannot distinguish an interactive sudo from a passwordless one, and
 * pretending otherwise would be theatre. What it does enforce is that every
 * value reaching the registry has been through the policy engine first, so a
 * malformed origin or a truncated fingerprint cannot be approved at all.
 */

#include "vu_closure.h"
#include "vu_exec.h"
#include "vu_registry.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void usage(void)
{
    fputs(
        "usage: vpn-up-admin <command>\n"
        "\n"
        "  approve --profile-id ID --protocol P --endpoint URL --fingerprint F\n"
        "          (--proxy URL | --no-proxy)\n"
        "  revoke  --profile-id ID\n"
        "  list\n"
        "  verify-closure\n"
        "  version\n"
        "\n"
        "Approvals are per-user and are keyed by the invoking user's SUDO_UID.\n"
        "--endpoint accepts a full URL; only its origin (scheme, host, port) is\n"
        "recorded, because a post-authentication URL carries session data.\n"
        "One of --proxy/--no-proxy is required: approving a proxy by omission\n"
        "is not something that should be possible to do by accident.\n",
        stderr);
}

/* Fetch the value that follows a flag, refusing a missing or flag-shaped one.
 * A flag-shaped value is nearly always a forgotten argument. */
static const char *next_value(int argc, char **argv, int *i, const char *flag)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "vpn-up-admin: %s needs a value\n", flag);
        return NULL;
    }
    const char *v = argv[++(*i)];
    if (v[0] == '-') {
        fprintf(stderr, "vpn-up-admin: %s was given '%s', which looks like a flag\n", flag, v);
        return NULL;
    }
    return v;
}

/* Refuse a repeated flag rather than letting the last one win. An approval is
 * written once and then trusted indefinitely, so a command line whose meaning
 * differs from its reading is worse here than anywhere else. */
static bool once(const char *slot, const char *flag)
{
    if (slot) {
        fprintf(stderr, "vpn-up-admin: %s was given more than once\n", flag);
        return false;
    }
    return true;
}

static int cmd_approve(int argc, char **argv, uid_t uid)
{
    const char *raw_id = NULL, *raw_proto = NULL, *raw_endpoint = NULL;
    const char *raw_fpr = NULL, *raw_proxy = NULL;
    bool no_proxy = false;

    for (int i = 0; i < argc; ++i) {
        const char *a = argv[i];
        if      (strcmp(a, "--profile-id")  == 0) { if (!once(raw_id, a)) return 2; if (!(raw_id = next_value(argc, argv, &i, a))) return 2; }
        else if (strcmp(a, "--protocol")    == 0) { if (!once(raw_proto, a)) return 2; if (!(raw_proto = next_value(argc, argv, &i, a))) return 2; }
        else if (strcmp(a, "--endpoint")    == 0) { if (!once(raw_endpoint, a)) return 2; if (!(raw_endpoint = next_value(argc, argv, &i, a))) return 2; }
        else if (strcmp(a, "--fingerprint") == 0) { if (!once(raw_fpr, a)) return 2; if (!(raw_fpr = next_value(argc, argv, &i, a))) return 2; }
        else if (strcmp(a, "--proxy")       == 0) { if (!once(raw_proxy, a)) return 2; if (!(raw_proxy = next_value(argc, argv, &i, a))) return 2; }
        else if (strcmp(a, "--no-proxy")    == 0) {
            if (no_proxy) { fprintf(stderr, "vpn-up-admin: --no-proxy was given more than once\n"); return 2; }
            no_proxy = true;
        }
        else {
            /* No pass-through, here or anywhere: an argument we do not
             * understand is a mistake, not something to forward. */
            fprintf(stderr, "vpn-up-admin: unrecognised argument '%s'\n", a);
            return 2;
        }
    }

    if (!raw_id || !raw_proto || !raw_endpoint || !raw_fpr) {
        fprintf(stderr, "vpn-up-admin: approve needs --profile-id, --protocol, "
                        "--endpoint and --fingerprint\n");
        return 2;
    }
    if (raw_proxy && no_proxy) {
        fprintf(stderr, "vpn-up-admin: --proxy and --no-proxy are mutually exclusive\n");
        return 2;
    }
    if (!raw_proxy && !no_proxy) {
        fprintf(stderr, "vpn-up-admin: pass --no-proxy to approve without a proxy, "
                        "or --proxy URL to approve one\n");
        return 2;
    }

    vu_approval a;
    memset(&a, 0, sizeof a);
    vu_err e; vu_err_clear(&e);

    if (!vu_canon_profile_id(raw_id, a.profile_id, sizeof a.profile_id, &e)) goto bad;
    if (!vu_valid_protocol(raw_proto, &e)) goto bad;
    if (strlen(raw_proto) + 1 > sizeof a.protocol) {
        vu_err_set(&e, "protocol: too long"); goto bad;
    }
    memcpy(a.protocol, raw_proto, strlen(raw_proto) + 1);

    /* Accept a full URL and keep only the origin. Recording the whole URL would
     * bind session data, so a later connect with a different path would be
     * refused for no good reason (§7). */
    {
        vu_url u;
        if (!vu_parse_url(raw_endpoint, &u, &e)) goto bad;
        if (strlen(u.origin) + 1 > sizeof a.origin) {
            vu_err_set(&e, "endpoint: origin too long"); goto bad;
        }
        memcpy(a.origin, u.origin, strlen(u.origin) + 1);
        if (u.path[0] || u.query[0]) {
            fprintf(stderr, "vpn-up-admin: note: recording origin %s "
                            "(path and query are session data and are not approved)\n",
                    a.origin);
        }
    }

    if (!vu_canon_fingerprint(raw_fpr, a.fingerprint, sizeof a.fingerprint, &e)) goto bad;

    if (raw_proxy) {
        if (!vu_canon_proxy(raw_proxy, a.proxy, sizeof a.proxy, &e)) goto bad;
    } else {
        a.proxy[0] = '\0';
    }

    if (!vu_registry_put(VU_REGISTRY_ROOT, 0, uid, &a, &e)) goto bad;

    printf("approved %s\n", a.profile_id);
    printf("  protocol    %s\n", a.protocol);
    printf("  endpoint    %s\n", a.origin);
    printf("  fingerprint %s\n", a.fingerprint);
    printf("  proxy       %s\n", a.proxy[0] ? a.proxy : "none");
    return 0;

bad:
    fprintf(stderr, "vpn-up-admin: %s\n", e.msg);
    return 1;
}

static int cmd_revoke(int argc, char **argv, uid_t uid)
{
    const char *raw_id = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--profile-id") == 0) {
            if (!once(raw_id, argv[i])) return 2;
            if (!(raw_id = next_value(argc, argv, &i, argv[i]))) return 2;
        } else {
            fprintf(stderr, "vpn-up-admin: unrecognised argument '%s'\n", argv[i]);
            return 2;
        }
    }
    if (!raw_id) { fprintf(stderr, "vpn-up-admin: revoke needs --profile-id\n"); return 2; }

    vu_err e; vu_err_clear(&e);
    char id[VU_UUID_MAX];
    if (!vu_canon_profile_id(raw_id, id, sizeof id, &e)) {
        fprintf(stderr, "vpn-up-admin: %s\n", e.msg);
        return 1;
    }

    bool removed = false;
    if (!vu_registry_delete(VU_REGISTRY_ROOT, 0, uid, id, &removed, &e)) {
        fprintf(stderr, "vpn-up-admin: %s\n", e.msg);
        return 1;
    }
    /* Revoking something that was not approved is reported, not treated as an
     * error: the end state the user asked for is the state they now have. */
    printf(removed ? "revoked %s\n" : "no approval for %s\n", id);
    return 0;
}

/*
 * Report the trusted execution closure (§11.4, §11.6).
 *
 * It lives HERE and not in vpn-up-helper on purpose. The helper is the
 * passwordless binary, and every subcommand it gains is something an attacker
 * holding that grant can run; a diagnostic belongs with the tool that already
 * costs a password. The helper runs the same check itself before every execve —
 * this just shows you the result before you rely on it.
 *
 * Deliberately usable when the answer is "no": it prints every row and exits
 * non-zero, rather than stopping at the first failure, because a machine that
 * fails the closure usually fails several rows for one underlying reason (a
 * user-owned prefix) and seeing them together is what identifies it.
 */
static int cmd_verify_closure(void)
{
    vu_closure_spec spec;
    vu_closure_spec_default(&spec, VU_OPENCONNECT, VU_VPNC_SCRIPT, 0);
    spec.probe = (geteuid() == 0);
    spec.probe_uid = 0;

    static vu_closure_report report;
    vu_err e; vu_err_clear(&e);
    bool ok = vu_closure_check(&spec, &report, &e);

    printf("trusted execution closure\n");
    printf("  openconnect   %s\n", VU_OPENCONNECT);
    printf("  vpnc-script   %s\n", VU_VPNC_SCRIPT);
    printf("  PATH          %s\n\n", VU_HELPER_PATH);
    vu_closure_print(&report, stdout);

    if (ok) {
        printf("\nhelper mode: the closure is trustworthy on this machine\n");
        return 0;
    }
    printf("\n%s\n", e.msg);
    printf("helper mode is unavailable until every object above is root-owned and\n"
           "outside your write control. The usual cause on macOS is a Homebrew\n"
           "OpenConnect: its prefix belongs to the installing user, so handing root\n"
           "to it would accomplish nothing (see SECURITY.md and design section 11.6).\n");
    return 1;
}

static int cmd_list(uid_t uid)
{
    static vu_approval items[VU_APPROVAL_LIST_MAX];
    size_t n = 0;
    vu_err e; vu_err_clear(&e);

    bool ok = vu_registry_list(VU_REGISTRY_ROOT, 0, uid, items, VU_APPROVAL_LIST_MAX, &n, &e);

    if (n == 0) printf("no approved profiles for uid %lu\n", (unsigned long)uid);
    for (size_t i = 0; i < n; ++i) {
        printf("%s\n", items[i].profile_id);
        printf("  protocol    %s\n", items[i].protocol);
        printf("  endpoint    %s\n", items[i].origin);
        printf("  fingerprint %s\n", items[i].fingerprint);
        printf("  proxy       %s\n", items[i].proxy[0] ? items[i].proxy : "none");
    }
    if (!ok) {
        /* Partial output plus a non-zero exit: the records we could read are
         * still worth showing, but the caller must not believe the list is
         * complete. */
        fprintf(stderr, "vpn-up-admin: %s\n", e.msg);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    /* Before any open() in this process — see vu_ensure_std_fds. This binary
     * writes root-owned policy files, so a caller-closed descriptor must not be
     * able to land on one of them. */
    {
        vu_err fds; vu_err_clear(&fds);
        if (!vu_ensure_std_fds(&fds)) {
            fprintf(stderr, "vpn-up-admin: %s\n", fds.msg);
            return 1;
        }
    }

    if (argc < 2) { usage(); return 2; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "version") == 0) {
        printf("vpn-up-admin (policy engine %d)\n", VU_APPROVAL_VERSION);
        printf("  registry root %s\n", VU_REGISTRY_ROOT);
        printf("  state root    %s\n", VU_STATE_ROOT);
        return 0;
    }

    /*
     * verify-closure sits ABOVE the root gate deliberately. It writes nothing and
     * reads only ownership and mode bits, which are world-readable — so requiring
     * a password to ask "is this machine eligible for helper mode?" would buy
     * nothing and would keep `vpn-up doctor` from reporting it. The ACL probe
     * inside it is the one part that needs privilege, and it is skipped rather
     * than faked when absent (see cmd_verify_closure).
     */
    if (strcmp(cmd, "verify-closure") == 0) {
        if (argc > 2) { fprintf(stderr, "vpn-up-admin: verify-closure takes no arguments\n"); return 2; }
        return cmd_verify_closure();
    }

    vu_err e; vu_err_clear(&e);
    if (!vu_admin_require_root(&e)) {
        fprintf(stderr, "vpn-up-admin: %s\n", e.msg);
        return 1;
    }

    /* Approvals are per-user, keyed by whoever invoked sudo. Refusing when
     * SUDO_UID is absent keeps one user's approvals from being written into
     * another's namespace, or into a default that belongs to nobody. */
    uid_t uid;
    if (!vu_sudo_uid(&uid, &e)) {
        fprintf(stderr, "vpn-up-admin: %s\n", e.msg);
        return 1;
    }

    if (strcmp(cmd, "approve") == 0) return cmd_approve(argc - 2, argv + 2, uid);
    if (strcmp(cmd, "revoke")  == 0) return cmd_revoke(argc - 2, argv + 2, uid);
    if (strcmp(cmd, "list")    == 0) {
        if (argc > 2) { fprintf(stderr, "vpn-up-admin: list takes no arguments\n"); return 2; }
        return cmd_list(uid);
    }

    fprintf(stderr, "vpn-up-admin: unknown command '%s'\n", cmd);
    usage();
    return 2;
}
