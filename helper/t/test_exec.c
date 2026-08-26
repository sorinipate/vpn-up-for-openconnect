/*
 * test_exec.c — element-by-element assertions on the phase-two invocation
 * (§16 step 7, §18).
 *
 * This is the corpus that matters most. Every other test protects a validator;
 * these protect what root actually executes. So they assert the exact argv,
 * not just that a build succeeded, and they assert the absences as hard as the
 * presences — a flag that must never appear is a security property, and
 * "we didn't add it" is not a test.
 */

#include "vu_exec.h"
#include "vu_state.h"
#include "harness.h"

#include <stdio.h>
#include <stdlib.h>      /* mkdtemp, getenv */
#include <string.h>
#include <sys/stat.h>    /* chmod, mkdir */
#include <unistd.h>      /* symlink */

#define OC     "/opt/vpn-up/sbin/openconnect"
#define SCRIPT "/opt/vpn-up/etc/vpnc-script"

static const char *ID   = "a7d1bb99-538c-4db4-b357-0123456789ab";
static const char *FPR  = "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42";

/* Index of an argv element, or -1. */
static int idx_of(const vu_argv *a, const char *want)
{
    for (size_t i = 0; i < a->n; ++i)
        if (strcmp(a->argv[i], want) == 0) return (int)i;
    return -1;
}

static bool has(const vu_argv *a, const char *want) { return idx_of(a, want) >= 0; }

/* Any element beginning with prefix — for asserting a flag is absent in every
 * spelling, not just the one we happened to think of. */
static bool has_prefix(const vu_argv *a, const char *prefix)
{
    size_t n = strlen(prefix);
    for (size_t i = 0; i < a->n; ++i)
        if (strncmp(a->argv[i], prefix, n) == 0) return true;
    return false;
}

static void base_request(vu_request *req, vu_approval *appr, const char *url)
{
    vu_err e; vu_err_clear(&e);
    memset(req, 0, sizeof *req);
    memset(appr, 0, sizeof *appr);

    vu_canon_profile_id(ID, req->profile_id, sizeof req->profile_id, &e);
    snprintf(req->protocol, sizeof req->protocol, "anyconnect");
    vu_parse_url(url, &req->url, &e);
    vu_canon_fingerprint(FPR, req->fingerprint, sizeof req->fingerprint, &e);

    memcpy(appr->profile_id, req->profile_id, sizeof appr->profile_id);
    memcpy(appr->protocol,   req->protocol,   sizeof appr->protocol);
    snprintf(appr->origin, sizeof appr->origin, "%s", req->url.origin);
    memcpy(appr->fingerprint, req->fingerprint, sizeof appr->fingerprint);
    appr->proxy[0] = '\0';
}

/* ------------------------------------------------------- the baseline shape */

static void test_baseline(void)
{
    vu_request req; vu_approval appr; vu_err e;
    static vu_argv a;

    base_request(&req, &appr, "https://vpn.example.com/portal?session=xyz");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "baseline builds: %s", e.msg);

    /* Exact vector, in order. Written out in full deliberately: this is the one
     * place where reading the test tells you what root will run. */
    const char *want[] = {
        OC,
        "--cookie-on-stdin",
        "--non-inter",
        "--protocol=anyconnect",
        "--servercert=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42",
        ("--script=" SCRIPT),
        "--no-proxy",
        "https://vpn.example.com:443/portal?session=xyz",
    };
    size_t want_n = sizeof want / sizeof *want;

    CHECK(a.n == want_n, "argv has %zu elements, expected %zu", a.n, want_n);
    for (size_t i = 0; i < want_n && i < a.n; ++i)
        CHECK(strcmp(a.argv[i], want[i]) == 0,
              "argv[%zu] is '%s', expected '%s'", i, a.argv[i], want[i]);
    CHECK(a.argv[a.n] == NULL, "vector is NULL-terminated");

    /* argv[0] is the pinned absolute path: execve does no PATH search, and ps
     * should not claim something else is running. */
    CHECK(strcmp(a.argv[0], OC) == 0, "argv[0] is the pinned path");
}

/* ------------------------------------------------- absences are the contract */

static void test_forbidden_flags(void)
{
    vu_request req; vu_approval appr; vu_err e;
    static vu_argv a;

    /* Ask for everything a caller might try to smuggle through, then assert
     * none of it appears. The request fields these would come from do not
     * exist, which is the point — but a future field could reintroduce one, and
     * this test is what would catch it. */
    base_request(&req, &appr, "https://vpn.example.com/x");
    req.has_resolve = true;
    vu_err_clear(&e);
    CHECK(vu_canon_resolve("vpn.example.com:10.0.0.1", &req.resolve, &e), "resolve parses");
    snprintf(req.useragent, sizeof req.useragent, "AnyConnect Windows 4.10.06079");
    req.quiet = true;
    snprintf(req.tunables[0], VU_TUNABLE_LEN, "--no-dtls");
    snprintf(req.tunables[1], VU_TUNABLE_LEN, "--mtu=1400");
    req.n_tunables = 2;

    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "full request builds: %s", e.msg);

    /* Every flag that hands root an executable, or that daemonises. */
    const char *forbidden[] = {
        "--script",           /* only ever as --script=<pinned>, checked below */
        "--script-tun", "-S",
        "--csd-wrapper", "--csd-user",
        "--config", "--xmlconfig", "-x",
        "--external-browser",
        "--background", "-b",
        "--pid-file",
        "--cookie",           /* the cookie must never reach argv */
        "-C",
        "--passwd-on-stdin",  /* phase one's business, not ours */
        "--user", "--authgroup", "--certificate", "-c", "--sslkey", "-k",
        "--key-password", "--token-mode", "--token-secret",
        "--os",
    };
    for (size_t i = 0; i < sizeof forbidden / sizeof *forbidden; ++i) {
        /* Exact match, and the --flag=value spelling too. */
        char eq[64];
        snprintf(eq, sizeof eq, "%s=", forbidden[i]);
        bool bare = has(&a, forbidden[i]);
        bool valued = has_prefix(&a, eq);
        if (strcmp(forbidden[i], "--script") == 0) {
            /* --script is present, but ONLY as the pinned path. */
            CHECK(!bare, "--script never appears as a separate element");
            CHECK(has(&a, ("--script=" SCRIPT)), "--script is the pinned path");
            continue;
        }
        CHECK(!bare && !valued, "%s must not appear in phase two", forbidden[i]);
    }

    /* -s is --script's short form; it must not appear at all. */
    CHECK(!has(&a, "-s"), "-s must not appear");

    /* The three unconditional elements survive a full request. */
    CHECK(has(&a, "--cookie-on-stdin"), "--cookie-on-stdin always present");
    CHECK(has(&a, "--non-inter"), "--non-inter always present");
    CHECK(has_prefix(&a, "--servercert="), "--servercert always present");

    /* And the optional ones landed. */
    CHECK(has(&a, "--resolve=vpn.example.com:10.0.0.1"), "resolve rendered");
    CHECK(has(&a, "--useragent=AnyConnect Windows 4.10.06079"), "useragent rendered");
    CHECK(has(&a, "-q"), "quiet rendered");
    CHECK(has(&a, "--no-dtls") && has(&a, "--mtu=1400"), "tunables rendered");
}

/* ------------------------------------------------- the fingerprint's origin */

static void test_fingerprint_comes_from_the_registry(void)
{
    vu_request req; vu_approval appr; vu_err e;
    static vu_argv a;

    base_request(&req, &appr, "https://vpn.example.com/x");

    /* A caller that manages to set a different fingerprint on the request must
     * not get it into argv. vu_policy_check refuses the mismatch outright,
     * which is the stronger outcome: not "the registry wins" but "the request
     * is rejected". */
    vu_err_clear(&e);
    vu_canon_fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                         req.fingerprint, sizeof req.fingerprint, &e);
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e),
          "a request whose fingerprint differs from the record is refused");
    CHECK(strstr(e.msg, "re-approve") != NULL, "and says to re-approve: '%s'", e.msg);

    /* With them in agreement, the value emitted is the record's. */
    base_request(&req, &appr, "https://vpn.example.com/x");
    snprintf(appr.fingerprint, sizeof appr.fingerprint,
             "sha256:%s", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    memcpy(req.fingerprint, appr.fingerprint, sizeof req.fingerprint);
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "builds: %s", e.msg);
    CHECK(has(&a, "--servercert=sha256:0123456789abcdef0123456789abcdef"
                  "0123456789abcdef0123456789abcdef"),
          "the emitted fingerprint is the record's");
}

/* --------------------------------------------------------------- the proxy */

static void test_proxy(void)
{
    vu_request req; vu_approval appr; vu_err e;
    static vu_argv a;

    /* Approved WITH a proxy: emitted, and --no-proxy absent. */
    base_request(&req, &appr, "https://vpn.example.com/x");
    snprintf(appr.proxy, sizeof appr.proxy, "socks5://127.0.0.1:1080");
    snprintf(req.proxy,  sizeof req.proxy,  "socks5://127.0.0.1:1080");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "proxy builds: %s", e.msg);
    CHECK(has(&a, "--proxy=socks5://127.0.0.1:1080"), "approved proxy emitted");
    CHECK(!has(&a, "--no-proxy"), "--no-proxy not emitted alongside a proxy");

    /* Approved WITHOUT one: --no-proxy is emitted explicitly rather than
     * --proxy merely being omitted, so environment-driven proxy discovery
     * cannot quietly insert one. */
    base_request(&req, &appr, "https://vpn.example.com/x");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "no-proxy builds: %s", e.msg);
    CHECK(has(&a, "--no-proxy"), "--no-proxy emitted explicitly");
    CHECK(!has_prefix(&a, "--proxy="), "no --proxy");
    CHECK(!has(&a, "--proxy-auth") && !has_prefix(&a, "--proxy-auth="),
          "--proxy-auth is never emitted");
}

/* --------------------------------------------------- URL rebuilt canonically */

static void test_url_canonicalisation(void)
{
    vu_request req; vu_approval appr; vu_err e;
    static vu_argv a;

    /* The URL handed to OpenConnect is rebuilt from validated parts, so an
     * implicit port becomes explicit. Equivalent, and it means what OpenConnect
     * receives is exactly what was matched against the record. */
    base_request(&req, &appr, "https://vpn.example.com/portal");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "builds: %s", e.msg);
    CHECK(strcmp(a.argv[a.n - 1], "https://vpn.example.com:443/portal") == 0,
          "URL is last and canonical, got '%s'", a.argv[a.n - 1]);

    /* No path at all. */
    base_request(&req, &appr, "https://vpn.example.com");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "builds: %s", e.msg);
    CHECK(strcmp(a.argv[a.n - 1], "https://vpn.example.com:443") == 0,
          "bare origin, got '%s'", a.argv[a.n - 1]);

    /* Bracketed IPv6 survives intact. */
    base_request(&req, &appr, "https://[2001:db8::42]:8443/gw");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "builds: %s", e.msg);
    CHECK(strcmp(a.argv[a.n - 1], "https://[2001:db8::42]:8443/gw") == 0,
          "IPv6 authority preserved, got '%s'", a.argv[a.n - 1]);

    /* A differing path is authorised (session data), a differing host is not. */
    base_request(&req, &appr, "https://vpn.example.com/one");
    snprintf(appr.origin, sizeof appr.origin, "https://vpn.example.com:443");
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "path differs, still builds");
    base_request(&req, &appr, "https://vpn.example.com/one");
    snprintf(appr.origin, sizeof appr.origin, "https://other.example.com:443");
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "host differs, refused");
}

/* ----------------------------------------------- unapproved requests refused */

static void test_policy_gate_is_not_bypassable(void)
{
    vu_request req; vu_approval appr; vu_err e;
    static vu_argv a;

    /* The builder runs the policy check itself, so there is no way to reach an
     * argv for an unauthorised request even by calling the builder directly. */
    base_request(&req, &appr, "https://vpn.example.com/x");
    snprintf(req.protocol, sizeof req.protocol, "gp");
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e), "protocol substitution refused");
    CHECK(a.n == 0, "nothing was built");

    base_request(&req, &appr, "https://vpn.example.com/x");
    req.has_resolve = true;
    vu_err_clear(&e);
    CHECK(vu_canon_resolve("attacker.example.com:10.0.0.1", &req.resolve, &e), "parses");
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, OC, SCRIPT, &a, &e),
          "--resolve naming an unapproved host refused");

    vu_err_clear(&e);
    CHECK(!vu_build_argv(NULL, &appr, OC, SCRIPT, &a, &e), "null request refused");
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, NULL, SCRIPT, &a, &e), "null binary path refused");
}

/* ------------------------------------------------ pinned-path trust checking */

static void test_trusted_paths(void)
{
    vu_err e;
    uid_t me = geteuid();
    char root[VU_PATH_MAX], bin[VU_PATH_MAX], sub[VU_PATH_MAX];

    /*
     * The fixture has to live somewhere whose parent chain is ALREADY trusted,
     * because vu_path_trusted judges the whole absolute path and there is
     * deliberately no way to tell it "start checking here".
     *
     * That rules out /tmp, which is 1777 on Linux — and TMPDIR is unset on the
     * Linux runners, so the fallback lands exactly there. The refusal is correct
     * (anyone can write /tmp, so nothing under it is a fit home for a
     * root-executed binary) and the sticky bit does not change that judgement
     * for this purpose, so the fixture moves rather than the rule.
     *
     * $HOME works on both: 0755 under a root-owned /home or /Users. TMPDIR is
     * tried second because it is a per-user 0700 directory on macOS.
     */
    char base[VU_PATH_MAX];
    bool have_base = false;
    {
        const char *cands[3];
        size_t nc = 0;
        const char *home = getenv("HOME");
        const char *tmp  = getenv("TMPDIR");
        if (home && *home) cands[nc++] = home;
        if (tmp  && *tmp)  cands[nc++] = tmp;
        cands[nc++] = "/tmp";

        for (size_t i = 0; i < nc && !have_base; ++i) {
            vu_path(base, sizeof base, "%s", cands[i]);
            size_t bn = strlen(base);
            while (bn > 1 && base[bn - 1] == '/') base[--bn] = '\0';
            vu_err probe; vu_err_clear(&probe);
            if (vu_dir_trusted(base, me, &probe)) have_base = true;
        }
    }
    if (!have_base) {
        /* Nowhere writable has a trustworthy chain. Say so rather than silently
         * dropping the positive assertions. */
        CHECK(false, "no fixture base with a trusted parent chain (checked HOME, TMPDIR, /tmp)");
        return;
    }

    vu_path(root, sizeof root, "%s/vu-exec-test-XXXXXX", base);
    if (!mkdtemp(root)) { CHECK(false, "cannot create temp root"); return; }
    chmod(root, 0755);

    vu_path(sub, sizeof sub, "%s/sbin", root);
    CHECK(mkdir(sub, 0755) == 0, "made bin dir");
    vu_path(bin, sizeof bin, "%s/openconnect", sub);
    FILE *f = fopen(bin, "w");
    CHECK(f != NULL, "made fake binary");
    if (f) { fputs("#!/bin/sh\n", f); fclose(f); }
    CHECK(chmod(bin, 0755) == 0, "made it executable");

    vu_err_clear(&e);
    CHECK(vu_path_trusted(bin, me, true, &e), "our own 0755 binary is trusted: %s", e.msg);

    /* Group-writable anywhere above it is disqualifying: whoever can write the
     * directory can replace what root executes. */
    CHECK(chmod(sub, 0775) == 0, "loosen the parent");
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(bin, me, true, &e), "group-writable parent refused");
    CHECK(strstr(e.msg, "writable") != NULL, "refusal names the reason: '%s'", e.msg);
    CHECK(chmod(sub, 0755) == 0, "restore");

    CHECK(chmod(bin, 0775) == 0, "loosen the binary");
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(bin, me, true, &e), "group-writable binary refused");
    CHECK(chmod(bin, 0755) == 0, "restore");

    /* Not executable. */
    CHECK(chmod(bin, 0644) == 0, "drop the x bit");
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(bin, me, true, &e), "non-executable refused");
    CHECK(chmod(bin, 0755) == 0, "restore");

    /* Wrong owner. */
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(bin, me + 1, true, &e), "wrong owner refused");

    /*
     * Symlinks resolve, and the RESOLVED chain is what gets judged. A link whose
     * target sits in a trusted chain is fine; a link into a user-writable chain
     * is not. The second case is the Homebrew shape —
     * /opt/homebrew/bin/openconnect is a link into ../Cellar, owned by the
     * installing user — and catching it on the target's ownership is a truer
     * answer than refusing all links, which would also make every path under
     * macOS's /var unusable.
     */
    char link[VU_PATH_MAX];
    vu_path(link, sizeof link, "%s/oc-link", sub);
    CHECK(symlink(bin, link) == 0, "made symlink to a trusted binary");
    vu_err_clear(&e);
    CHECK(vu_path_trusted(link, me, true, &e),
          "a link resolving into a trusted chain is accepted: %s", e.msg);

    /* The Homebrew shape: a link in a clean directory pointing into a
     * group-writable one. Must be refused, on the target's chain. */
    char cellar[VU_PATH_MAX], target[VU_PATH_MAX], hb[VU_PATH_MAX];
    vu_path(cellar, sizeof cellar, "%s/cellar", root);
    /* mkdir's mode is masked by umask (022 here), so 0775 would land as 0755
     * and the fixture would prove nothing. chmod is not masked. */
    CHECK(mkdir(cellar, 0755) == 0, "made target dir");
    CHECK(chmod(cellar, 0775) == 0, "made it genuinely group-writable");
    vu_path(target, sizeof target, "%s/openconnect", cellar);
    FILE *tf = fopen(target, "w");
    CHECK(tf != NULL, "made target binary");
    if (tf) { fputs("#!/bin/sh\n", tf); fclose(tf); }
    CHECK(chmod(target, 0755) == 0, "made target executable");
    vu_path(hb, sizeof hb, "%s/brew-link", sub);
    CHECK(symlink(target, hb) == 0, "made the Homebrew-shaped link");
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(hb, me, true, &e),
          "a link into a group-writable chain is refused");
    CHECK(strstr(e.msg, "writable") != NULL, "refused on writability: '%s'", e.msg);

    /* World-writable anywhere above the binary is disqualifying too — this is
     * what /tmp actually looks like, asserted deterministically instead of
     * depending on how the runner sets TMPDIR. */
    {
        char open_dir[VU_PATH_MAX], open_bin[VU_PATH_MAX];
        vu_path(open_dir, sizeof open_dir, "%s/wideopen", root);
        CHECK(mkdir(open_dir, 0755) == 0, "made dir");
        CHECK(chmod(open_dir, 0777) == 0, "made it world-writable");
        vu_path(open_bin, sizeof open_bin, "%s/openconnect", open_dir);
        FILE *of = fopen(open_bin, "w");
        CHECK(of != NULL, "made binary");
        if (of) { fputs("#!/bin/sh\n", of); fclose(of); }
        CHECK(chmod(open_bin, 0755) == 0, "made it executable");
        vu_err_clear(&e);
        CHECK(!vu_path_trusted(open_bin, me, true, &e),
              "a binary under a world-writable directory is refused");
        CHECK(strstr(e.msg, "writable") != NULL, "refused on writability: '%s'", e.msg);
    }

    /* And the same question asked of a directory, which is what step 10 will do
     * for /etc/vpnc and each PATH entry. */
    vu_err_clear(&e);
    CHECK(vu_dir_trusted(sub, me, &e), "a trusted directory passes: %s", e.msg);
    vu_err_clear(&e);
    CHECK(!vu_dir_trusted(bin, me, &e), "a file is not a trusted directory");

    /* Non-canonical and relative paths. */
    char dotted[VU_PATH_MAX];
    vu_path(dotted, sizeof dotted, "%s/sbin/../sbin/openconnect", root);
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(dotted, me, true, &e), "non-canonical path refused");
    vu_err_clear(&e);
    CHECK(!vu_path_trusted("sbin/openconnect", me, true, &e), "relative path refused");
    vu_err_clear(&e);
    CHECK(!vu_path_trusted(sub, me, true, &e), "a directory is not an executable");

    vu_rm_rf(root);
}

void vu_test_exec(void)
{
    test_baseline();
    test_forbidden_flags();
    test_fingerprint_comes_from_the_registry();
    test_proxy();
    test_url_canonicalisation();
    test_policy_gate_is_not_bypassable();
    test_trusted_paths();
}
