/*
 * test_adversarial.c — step 9 of PRIVILEGED-HELPER-DESIGN.md §16.
 *
 * Steps 4 to 8 built the boundary and tested that each piece does what it says.
 * This corpus tries to get through it. The distinction matters: the earlier
 * files are organised by module, this one by ATTACK, and several of its cases
 * were written against the implementation as it stood and failed. What they
 * found is recorded next to each test, because a test whose history is invisible
 * looks like paranoia rather than evidence.
 *
 * Everything here is unprivileged, as in every earlier step: the state and
 * registry roots are parameters, and the expected owner is a parameter, so the
 * code under test is byte-for-byte the code that runs as root.
 *
 * What is deliberately NOT here, because it belongs to a later step:
 *   - the dynamic library closure, /etc/vpnc sourced hooks, PATH entries (§10)
 *   - lock survival across execve, cookie passthrough on a real tunnel (§11)
 * Both need either a root-owned fixture tree or a real OpenConnect.
 */

#include "harness.h"
#include "vu.h"
#include "vu_exec.h"
#include "vu_registry.h"
#include "vu_state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define ID_A "11111111-2222-3333-4444-555555555555"
#define ID_B "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
#define FPR_A "sha256:1111111111111111111111111111111111111111111111111111111111111111"
#define FPR_B "sha256:2222222222222222222222222222222222222222222222222222222222222222"

/* Fixtures live under $HOME, not /tmp: /tmp is 1777 on both platforms, and the
 * trusted-path walk correctly refuses a world-writable component. Learned the
 * hard way in step 7 — see t/README. */
static char g_base[VU_PATH_MAX];

static void make_base(const char *tag)
{
    vu_path(g_base, sizeof g_base, "%s/.vpn-up-test-%s-%ld",
            vu_test_base(), tag, (long)getpid());
    vu_rm_rf(g_base);
    CHECK(mkdir(g_base, 0700) == 0, "cannot create fixture base %s: %s", g_base, strerror(errno));
}

static void drop_base(void) { vu_rm_rf(g_base); }

/* ------------------------------------------------------------------------- */
/* The closed argv schema, attacked directly.                                */
/*                                                                           */
/* This is only reachable because step 9 moved the parser out of              */
/* helper_main.c: main() refuses non-root before it looks at argv, so while   */
/* the grammar lived there it could not be attacked at all from a test.       */
/* ------------------------------------------------------------------------- */

/*
 * Build a real argv and hand it to the parser.
 *
 * The arguments are COPIED into writable storage rather than passed as pointers
 * to string literals: argv is `char **` because a process may write to it, and
 * -Wcast-qual is right to object to casting the const away. This is also a
 * closer imitation of what execve delivers.
 *
 * VEND, not a bare NULL, terminates the list: NULL in a variadic position is
 * not guaranteed to be pointer-sized.
 */
#define VEND ((const char *)NULL)
#define VARGV_MAX  24
#define VARGV_ITEM 512

static bool parse_argv(vu_request *req, vu_err *e, const char *a0, ...)
{
    static char store[VARGV_MAX][VARGV_ITEM];
    char *argv[VARGV_MAX];
    int n = 0;

    va_list ap;
    va_start(ap, a0);
    for (const char *s = a0; s != NULL && n < VARGV_MAX; ) {
        size_t len = strlen(s);
        if (len + 1 > VARGV_ITEM) { va_end(ap); CHECK(false, "fixture argument too long"); return false; }
        memcpy(store[n], s, len + 1);
        argv[n] = store[n];
        n++;
        s = va_arg(ap, const char *);
    }
    va_end(ap);

    vu_err_clear(e);
    return vu_request_from_argv(n, argv, req, e);
}

static void test_schema_attacks(void)
{
    vu_request req;
    vu_err e;

    /* The shape a legitimate caller sends. */
    CHECK(parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                     "--connect-url", "https://vpn.example.com/portal", VEND),
          "the baseline request must parse: %s", e.msg);
    CHECK(strcmp(req.url.origin, "https://vpn.example.com:443") == 0,
          "origin should be explicit, got %s", req.url.origin);

    /*
     * A repeated flag. Last-wins was the behaviour before step 9, and it is the
     * shape an injection takes when the attacker can APPEND to a command line
     * but not rewrite it: the operator reads --connect-url pointing at the real
     * gateway, the program uses the second one. Model B would still have caught
     * the substitution at the policy check — the origin has to match the
     * approval — but "a later gate catches it" is not a reason for the parser to
     * accept a request whose meaning cannot be read off the request.
     */
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--profile-id", ID_B,
                      "--protocol", "anyconnect", "--connect-url", "https://vpn.example.com/", VEND),
          "a repeated --profile-id must be refused");
    CHECK(strstr(e.msg, "more than once") != NULL, "say what was repeated: %s", e.msg);
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/",
                      "--connect-url", "https://evil.example.net/", VEND),
          "a repeated --connect-url must be refused");
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--protocol", "gp", "--connect-url", "https://vpn.example.com/", VEND),
          "a repeated --protocol must be refused");
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/", "--quiet", "--quiet", VEND),
          "a repeated --quiet must be refused");

    /*
     * Two spellings of one tunable. Both are individually valid, so nothing
     * downstream objects; the argv reaching OpenConnect was
     * "--mtu=1400 --mtu=1500" and which one took effect was OpenConnect's
     * business rather than ours.
     */
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/",
                      "--tunable", "mtu=1400", "--tunable", "mtu=1500", VEND),
          "the same tunable twice must be refused");
    CHECK(strstr(e.msg, "more than once") != NULL, "name the duplicate tunable: %s", e.msg);
    /* "no-dtls" and "no-dtls=true" are one knob spelled two ways, and the check
     * compares the RENDERED flag so they collide as they should. */
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/",
                      "--tunable", "no-dtls", "--tunable", "no-dtls=true", VEND),
          "two spellings of one boolean tunable must collide");
    /* Different knobs are fine. */
    CHECK(parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                     "--connect-url", "https://vpn.example.com/",
                     "--tunable", "mtu=1400", "--tunable", "no-dtls", VEND),
          "distinct tunables must still be accepted: %s", e.msg);

    /* Nothing is forwarded. Every flag the design deleted from the schema, and
     * every flag that can name a program, must land in "unrecognised". */
    static const char *forbidden[] = {
        "--script", "--script-tun", "--csd-wrapper", "--csd-user", "--config",
        "--xmlconfig", "--external-browser", "--background", "--pid-file",
        "--cookie", "--cookie-on-stdin", "--servercert", "--no-system-trust",
        "--certificate", "--sslkey", "--key-password", "--token-secret",
        "--token-mode", "--authenticate", "--route", "--interface", "--syslog",
        "-b", "-S", "-x", "-C", "-c", "-q", "--help", "--version", "",
    };
    for (size_t i = 0; i < sizeof forbidden / sizeof *forbidden; ++i) {
        CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                          "--connect-url", "https://vpn.example.com/",
                          forbidden[i], "x", VEND),
              "'%s' must not be accepted by the connect schema", forbidden[i]);
    }

    /* A flag-shaped value is a forgotten argument, not a value. */
    CHECK(!parse_argv(&req, &e, "--profile-id", "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/", VEND),
          "--profile-id must not swallow the next flag as its value");
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--connect-url", VEND),
          "a trailing flag with no value must be refused");

    /* Missing required fields. */
    CHECK(!parse_argv(&req, &e, "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/", VEND),
          "--profile-id is required");
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A,
                      "--connect-url", "https://vpn.example.com/", VEND),
          "--protocol is required");
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect", VEND),
          "--connect-url is required");
    {
        vu_err ee; vu_err_clear(&ee);
        CHECK(!vu_request_from_argv(0, NULL, &req, &ee), "an empty argv must be refused");
    }

    /* Nine tunables exceeds VU_TUNABLE_MAX; the table only has seven entries, so
     * this can only be reached by repeating, which is refused first. Assert the
     * bound anyway: it is the one place a caller controls a count. */
    CHECK(!parse_argv(&req, &e, "--profile-id", ID_A, "--protocol", "anyconnect",
                      "--connect-url", "https://vpn.example.com/",
                      "--tunable", "mtu=1400", "--tunable", "base-mtu=1400",
                      "--tunable", "no-dtls", "--tunable", "disable-ipv6",
                      "--tunable", "no-http-keepalive", "--tunable", "force-dpd=30",
                      "--tunable", "reconnect-timeout=30", "--tunable", "mtu=1500",
                      "--tunable", "mtu=1600", VEND),
          "more tunables than the schema allows must be refused");

    /* Every refusal must carry a reason. Before step 9 the parser printed to
     * stderr and returned false without touching the error struct, so the
     * caller's "vpn-up-helper: %s" printed an empty line. */
    CHECK(!parse_argv(&req, &e, "--nonsense", VEND), "unknown flag refused");
    CHECK(e.msg[0] != '\0', "a refusal must set an error message");
}

/* ------------------------------------------------------------------------- */
/* Origin confusion: values that look like the approved endpoint.            */
/* ------------------------------------------------------------------------- */

static void fill(vu_request *req, vu_approval *appr, const char *url)
{
    vu_err e; vu_err_clear(&e);
    memset(req, 0, sizeof *req);
    memset(appr, 0, sizeof *appr);
    CHECK(vu_canon_profile_id(ID_A, req->profile_id, sizeof req->profile_id, &e),
          "fixture profile id: %s", e.msg);
    memcpy(req->protocol, "anyconnect", sizeof "anyconnect");
    CHECK(vu_parse_url(url, &req->url, &e), "fixture url %s: %s", url, e.msg);
    memcpy(req->fingerprint, FPR_A, sizeof FPR_A);

    memcpy(appr->profile_id, req->profile_id, sizeof appr->profile_id);
    memcpy(appr->protocol, "anyconnect", sizeof "anyconnect");
    memcpy(appr->origin, "https://vpn.example.com:443", sizeof "https://vpn.example.com:443");
    memcpy(appr->fingerprint, FPR_A, sizeof FPR_A);
}

static void test_origin_confusion(void)
{
    vu_err e;

    /*
     * Each of these is an attempt to name a different host while looking like
     * the approved one. The interesting property is not that they are refused —
     * it is WHERE: the ones that are syntactically invalid never reach the
     * policy check, and the ones that are valid URLs are refused by Model B.
     * Both are required; neither alone is sufficient.
     */
    static const char *bad_urls[] = {
        "https://vpn.example.com:443.evil.net/",   /* port that is a hostname */
        "https://vpn.example.com@evil.net/",       /* userinfo */
        "https://user:pw@vpn.example.com/",        /* userinfo with a password */
        "https://vpn.example.com#@evil.net/",      /* fragment */
        "https://vpn.example.com\t/",              /* control byte */
        "https://vpn.example.com /",               /* raw space */
        "https://vpn.example.com:0/",              /* port 0 */
        "https://vpn.example.com:65536/",          /* port out of range */
        "https://vpn.example.com:0443/",           /* non-canonical port */
        "https://vpn.example.com:+443/",           /* signed port */
        "https://vpn.example.com:44 3/",           /* space inside the port */
        "https:///portal",                         /* empty authority */
        "http://vpn.example.com/",                 /* wrong scheme */
        "ftp://vpn.example.com/",
        "//vpn.example.com/",
        "https://vpn.example.com:/",               /* empty port */
        "https://[::1/",                           /* unterminated literal */
        "https://[::1]junk/",                      /* junk after the literal */
        "https://2001:db8::1/",                    /* unbracketed v6 */
        "https://999.999.999.999/",                /* numeric final label */
        "https://vpn.example.com%00.evil.net/",    /* percent-encoded NUL */
        "https://.example.com/",                   /* empty leading label */
        "https://vpn..example.com/",               /* empty inner label */
        "https://-vpn.example.com/",               /* label starts with a dash */
        "https://vpn.example.com../",              /* two trailing dots */
        "https://xn--e1afmkfd.xn--p1ai/",          /* punycode: valid ASCII labels */
    };
    for (size_t i = 0; i < sizeof bad_urls / sizeof *bad_urls; ++i) {
        vu_url u;
        vu_err_clear(&e);
        bool ok = vu_parse_url(bad_urls[i], &u, &e);
        if (i == sizeof bad_urls / sizeof *bad_urls - 1) {
            /* Punycode is ASCII and legal; IDNA is out of scope for v1, so an
             * already-encoded name is accepted and is simply not the approved
             * origin. Listed here so the boundary is explicit rather than
             * accidental. */
            CHECK(ok, "an already-punycoded host is valid ASCII and must parse: %s", e.msg);
            continue;
        }
        CHECK(!ok, "'%s' must not parse as a connect URL", bad_urls[i]);
        CHECK(e.msg[0] != '\0', "'%s' was refused without a reason", bad_urls[i]);
    }

    /* Well-formed URLs for the wrong endpoint: refused by policy, not grammar. */
    static const char *wrong_endpoint[] = {
        "https://evil.example.net/",
        "https://vpn.example.com.evil.net/",
        "https://vpn.example.com:8443/",           /* right host, wrong port */
        "https://VPN.EXAMPLE.COM.evil.net/",
        "https://xn--vpn-example.com/",
        "https://1.2.3.4/",
    };
    for (size_t i = 0; i < sizeof wrong_endpoint / sizeof *wrong_endpoint; ++i) {
        vu_request req; vu_approval appr;
        fill(&req, &appr, wrong_endpoint[i]);
        vu_err_clear(&e);
        CHECK(!vu_policy_check(&req, &appr, &e),
              "'%s' must not satisfy the approved origin", wrong_endpoint[i]);
        CHECK(strstr(e.msg, "not approved") != NULL, "say it was not approved: %s", e.msg);
    }

    /* Spellings of the SAME endpoint must all be accepted, or approval becomes
     * unusable in practice: a gateway that returns a differently-cased or
     * dotted host would look like an attack. */
    static const char *same_endpoint[] = {
        "https://vpn.example.com/",
        "https://vpn.example.com:443/",
        "https://VPN.Example.COM/",
        "https://vpn.example.com./",               /* one trailing dot */
        "https://vpn.example.com/other/path",
        "https://vpn.example.com/portal?session=abc&x=1",
        "HTTPS://vpn.example.com/",                /* scheme is case-insensitive */
    };
    for (size_t i = 0; i < sizeof same_endpoint / sizeof *same_endpoint; ++i) {
        vu_request req; vu_approval appr;
        fill(&req, &appr, same_endpoint[i]);
        vu_err_clear(&e);
        CHECK(vu_policy_check(&req, &appr, &e),
              "'%s' is the approved endpoint and must be accepted: %s", same_endpoint[i], e.msg);
    }

    /* Path and query are session data: forwarded, never part of the decision. */
    {
        vu_request req; vu_approval appr;
        fill(&req, &appr, "https://vpn.example.com/a/b?c=d&e=%20f");
        static vu_argv cmd;
        vu_err_clear(&e);
        CHECK(vu_build_argv(&req, &appr, "/bin/sh", "/etc/vpnc/vpnc-script", &cmd, &e),
              "a session path and query must be forwarded: %s", e.msg);
        CHECK(strcmp(cmd.argv[cmd.n - 1], "https://vpn.example.com:443/a/b?c=d&e=%20f") == 0,
              "the URL must be rebuilt from canonical parts, got %s", cmd.argv[cmd.n - 1]);
    }
}

/* ------------------------------------------------------------------------- */
/* --resolve, which is bound semantically and not merely syntactically.      */
/* ------------------------------------------------------------------------- */

static void test_resolve_binding(void)
{
    vu_err e;
    vu_request req; vu_approval appr;

    /* A well-formed --resolve naming somewhere else is the whole point of the
     * binding: it would tell OpenConnect to send the approved host's traffic to
     * an address of the caller's choosing. */
    fill(&req, &appr, "https://vpn.example.com/");
    vu_err_clear(&e);
    CHECK(vu_canon_resolve("evil.example.net:203.0.113.9", &req.resolve, &e),
          "the fixture must be syntactically valid: %s", e.msg);
    req.has_resolve = true;
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "--resolve for another host must be refused");
    CHECK(strstr(e.msg, "not the approved host") != NULL, "explain the binding: %s", e.msg);

    /* The address half is free to change: DNS moves, and the fingerprint is what
     * carries identity. */
    static const char *ok_addresses[] = { "1.2.3.4", "203.0.113.9", "2001:db8::1", "[2001:db8::1]" };
    for (size_t i = 0; i < sizeof ok_addresses / sizeof *ok_addresses; ++i) {
        char spec[128];
        vu_path(spec, sizeof spec, "vpn.example.com:%s", ok_addresses[i]);
        fill(&req, &appr, "https://vpn.example.com/");
        vu_err_clear(&e);
        CHECK(vu_canon_resolve(spec, &req.resolve, &e), "'%s': %s", spec, e.msg);
        req.has_resolve = true;
        vu_err_clear(&e);
        CHECK(vu_policy_check(&req, &appr, &e),
              "a changed address for the approved host must be accepted: %s", e.msg);
    }

    /* A hostname on the address side defeats the purpose. */
    static const char *bad_resolve[] = {
        "vpn.example.com:evil.example.net",
        "vpn.example.com:not-an-ip",
        "vpn.example.com:",
        "vpn.example.com",
        ":1.2.3.4",
        "vpn.example.com:1.2.3.4.5",
        "vpn.example.com:999.999.999.999",
        "vpn.example.com:1.2.3.4/24",
        "vpn.example.com:0x01020304",
    };
    for (size_t i = 0; i < sizeof bad_resolve / sizeof *bad_resolve; ++i) {
        vu_resolve r;
        vu_err_clear(&e);
        CHECK(!vu_canon_resolve(bad_resolve[i], &r, &e), "'%s' must be refused", bad_resolve[i]);
    }

    /* IPv6: the origin host is bracketed, so the resolve host must compare
     * bracketed too, or the binding would reject a legitimate v6 endpoint. */
    {
        memset(&req, 0, sizeof req); memset(&appr, 0, sizeof appr);
        vu_err_clear(&e);
        CHECK(vu_canon_profile_id(ID_A, req.profile_id, sizeof req.profile_id, &e), "id: %s", e.msg);
        memcpy(req.protocol, "anyconnect", sizeof "anyconnect");
        CHECK(vu_parse_url("https://[2001:db8::1]/", &req.url, &e), "v6 url: %s", e.msg);
        memcpy(req.fingerprint, FPR_A, sizeof FPR_A);
        memcpy(appr.profile_id, req.profile_id, sizeof appr.profile_id);
        memcpy(appr.protocol, "anyconnect", sizeof "anyconnect");
        memcpy(appr.origin, req.url.origin, sizeof appr.origin);
        memcpy(appr.fingerprint, FPR_A, sizeof FPR_A);
        CHECK(vu_canon_resolve("[2001:db8::1]:2001:db8::1", &req.resolve, &e), "v6 resolve: %s", e.msg);
        req.has_resolve = true;
        vu_err_clear(&e);
        CHECK(vu_policy_check(&req, &appr, &e), "a v6 endpoint must bind: %s", e.msg);
    }
}

/* ------------------------------------------------------------------------- */
/* Model B substitutions.                                                    */
/* ------------------------------------------------------------------------- */

static void test_model_b_substitution(void)
{
    vu_err e;
    vu_request req; vu_approval appr;

    /* Protocol. Approving anyconnect must not authorise gp: a different
     * protocol is a different conversation with a different server. */
    fill(&req, &appr, "https://vpn.example.com/");
    memcpy(req.protocol, "gp", sizeof "gp");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "a substituted protocol must be refused");
    CHECK(strstr(e.msg, "protocol") != NULL, "say it was the protocol: %s", e.msg);

    /* Proxy, in both directions. NONE-to-proxy would route the tunnel through a
     * host of the caller's choosing; proxy-to-NONE would take it out of a proxy
     * the operator deliberately required. */
    fill(&req, &appr, "https://vpn.example.com/");
    memcpy(req.proxy, "http://127.0.0.1:8080", sizeof "http://127.0.0.1:8080");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "adding a proxy must be refused");
    CHECK(strstr(e.msg, "without a proxy") != NULL, "explain: %s", e.msg);

    fill(&req, &appr, "https://vpn.example.com/");
    memcpy(appr.proxy, "http://proxy.example.com:3128", sizeof "http://proxy.example.com:3128");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "dropping the approved proxy must be refused");
    CHECK(strstr(e.msg, "with a proxy") != NULL, "explain: %s", e.msg);

    fill(&req, &appr, "https://vpn.example.com/");
    memcpy(appr.proxy, "http://proxy.example.com:3128", sizeof "http://proxy.example.com:3128");
    memcpy(req.proxy, "http://evil.example.net:3128", sizeof "http://evil.example.net:3128");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "a substituted proxy must be refused");

    /* Fingerprint. The request's copy comes from the registry, so a mismatch
     * means either a caller tried to override it or the record is inconsistent.
     * Rotation is re-approval, never a silent update. */
    fill(&req, &appr, "https://vpn.example.com/");
    memcpy(appr.fingerprint, FPR_B, sizeof FPR_B);
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "a rotated fingerprint must be refused");
    CHECK(strstr(e.msg, "re-approve") != NULL, "tell the user to re-approve: %s", e.msg);

    /* Profile id. */
    fill(&req, &appr, "https://vpn.example.com/");
    vu_err_clear(&e);
    CHECK(vu_canon_profile_id(ID_B, appr.profile_id, sizeof appr.profile_id, &e), "id: %s", e.msg);
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "another profile's approval must not apply");

    /*
     * The argv builder runs the policy check itself, so there is no way to reach
     * execve past a refused request even if a future caller forgets to check.
     * This is the assertion that keeps that property from rotting.
     */
    fill(&req, &appr, "https://evil.example.net/");
    static vu_argv cmd;
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, "/bin/sh", "/etc/vpnc/vpnc-script", &cmd, &e),
          "the argv builder must refuse an unapproved request");
    CHECK(cmd.n == 0 && cmd.argv[0] == NULL, "a refused build must leave no argv behind");
}

/* ------------------------------------------------------------------------- */
/* Fingerprints: the partial-match hazard, and one canonical spelling.       */
/* ------------------------------------------------------------------------- */

static void test_fingerprint_attacks(void)
{
    vu_err e;
    char out[VU_FPR_MAX], out2[VU_FPR_MAX];

    /*
     * OpenConnect's --servercert accepts "a partial match of the hash ... if it
     * is at least 4 characters past the prefix". A truncated value therefore
     * does not weaken pinning slightly, it effectively turns it off, and it
     * would look like a working configuration. Every one of these must be
     * refused rather than forwarded.
     */
    static const char *truncated[] = {
        "sha256:abcd", "sha256:", "sha1:abcd", "sha1:", "abcd", "",
        "sha256:1111111111111111111111111111111111111111111111111111111111111",  /* 63 */
        "sha1:111111111111111111111111111111111111111",                          /* 39 */
        "pin-sha256:", "pin-sha256:AAAA", "pin-sha256:AAAAAAAA",
    };
    for (size_t i = 0; i < sizeof truncated / sizeof *truncated; ++i) {
        vu_err_clear(&e);
        CHECK(!vu_canon_fingerprint(truncated[i], out, sizeof out, &e),
              "the partial-match hazard means '%s' must be refused", truncated[i]);
    }

    /* Over-long, wrong alphabet, wrong prefix, embedded junk. */
    static const char *malformed[] = {
        "sha256:11111111111111111111111111111111111111111111111111111111111111111", /* 65 */
        "sha256:zzzz111111111111111111111111111111111111111111111111111111111111",
        "md5:11111111111111111111111111111111",
        "sha512:1111", "SHA256:1111", "sha256::1111",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111 ",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
        "pin-sha256:not base64!!",
        "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",   /* unpadded */
        "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",  /* 31 bytes */
        "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", /* 34 bytes */
        "pin-sha256:AAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  /* embedded space */
    };
    for (size_t i = 0; i < sizeof malformed / sizeof *malformed; ++i) {
        vu_err_clear(&e);
        CHECK(!vu_canon_fingerprint(malformed[i], out, sizeof out, &e),
              "'%s' must be refused", malformed[i]);
    }

    /* Bare hex, as `openconnect --authenticate` emits it, gains its prefix. */
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint("1111111111111111111111111111111111111111", out, sizeof out, &e),
          "bare 40 hex is a sha1: %s", e.msg);
    CHECK(strcmp(out, "sha1:1111111111111111111111111111111111111111") == 0, "got %s", out);

    /* Case is not identity: two spellings must not be two approvals. */
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                               out, sizeof out, &e) == false,
          "an uppercase prefix is a second spelling and must be refused");
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                               out, sizeof out, &e), "uppercase hex digits: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                               out2, sizeof out2, &e), "lowercase hex digits: %s", e.msg);
    CHECK(strcmp(out, out2) == 0, "hex case must canonicalise: %s vs %s", out, out2);

    /*
     * pin-sha256 has slack: 32 bytes is 256 bits, and 43 base64 characters carry
     * 258, so the last character has two bits that decode to nothing. Two
     * different spellings therefore decode to the SAME 32 bytes. Decoding and
     * re-encoding collapses them; comparing the supplied strings would not, and
     * the registry would hold two records for one pin.
     */
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint("pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                               out, sizeof out, &e), "pin A: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint("pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=",
                               out2, sizeof out2, &e), "pin B: %s", e.msg);
    CHECK(strcmp(out, out2) == 0,
          "two spellings of one pin must canonicalise to one value: %s vs %s", out, out2);

    /* Canonicalisation is idempotent, or a re-approved record would not compare
     * byte-equal to the one already stored. */
    char again[VU_FPR_MAX];
    vu_err_clear(&e);
    CHECK(vu_canon_fingerprint(out, again, sizeof again, &e), "re-canonicalise: %s", e.msg);
    CHECK(strcmp(out, again) == 0, "canonicalisation must be idempotent");
}

/* ------------------------------------------------------------------------- */
/* SUDO_UID, the one input that decides whose approvals apply.               */
/* ------------------------------------------------------------------------- */

static void test_sudo_uid_attacks(void)
{
    vu_err e;
    uid_t uid = 12345;
    char *saved = getenv("SUDO_UID");
    char keep[64] = "";
    if (saved) vu_path(keep, sizeof keep, "%s", saved);

    /* Refusal, never a default: a default would silently merge two users'
     * approvals and state. */
    static const char *bad[] = {
        "", " ", "0", "-1", "+1000", " 1000", "1000 ", "1000x", "x1000",
        "01000", "1e3", "0x3e8", "1000\n", "1000\t", "1000,1001", "1000 1001",
        "2147483648", "99999999999999999999", "nobody", "root", ".", "-",
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        setenv("SUDO_UID", bad[i], 1);
        vu_err_clear(&e);
        CHECK(!vu_sudo_uid(&uid, &e), "SUDO_UID='%s' must be refused", bad[i]);
        CHECK(e.msg[0] != '\0', "SUDO_UID='%s' refused without a reason", bad[i]);
    }
    unsetenv("SUDO_UID");
    vu_err_clear(&e);
    CHECK(!vu_sudo_uid(&uid, &e), "an unset SUDO_UID must be refused");
    CHECK(strstr(e.msg, "sudo") != NULL, "say how the helper is meant to be invoked: %s", e.msg);

    /* uid 0 is refused specifically: it would collide with the namespace root
     * and a root caller has no business on this path. */
    setenv("SUDO_UID", "0", 1);
    vu_err_clear(&e);
    CHECK(!vu_sudo_uid(&uid, &e), "SUDO_UID=0 must be refused");

    setenv("SUDO_UID", "1000", 1);
    vu_err_clear(&e);
    CHECK(vu_sudo_uid(&uid, &e) && uid == 1000, "a plain uid must be accepted: %s", e.msg);
    setenv("SUDO_UID", "2147483647", 1);
    vu_err_clear(&e);
    CHECK(vu_sudo_uid(&uid, &e) && uid == 2147483647, "the top of the range: %s", e.msg);

    if (keep[0]) setenv("SUDO_UID", keep, 1); else unsetenv("SUDO_UID");
}

/* ------------------------------------------------------------------------- */
/* The environment handed to OpenConnect.                                    */
/* ------------------------------------------------------------------------- */

static void test_environment(void)
{
    /*
     * Set every variable that can change how a program or a shell behaves, then
     * assert none of them survives. vpnc-script runs under /bin/sh as root, so
     * BASH_ENV, ENV and IFS matter as much as the loader variables.
     */
    static const char *hostile[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
        "BASH_ENV", "ENV", "IFS", "CDPATH", "PS4", "SHELLOPTS", "BASHOPTS",
        "PATH", "TMPDIR", "HOME", "SHELL",
    };
    /*
     * Saved and restored as hygiene, not as a fix.
     *
     * On the first run of this corpus, clobbering HOME here broke every fixture
     * created afterwards, because fixture paths were built from $HOME. They are
     * built from the password database now (vu_test_base), so that coupling is
     * gone and this restore no longer holds the corpus together - it just leaves
     * the runner's environment as it found it.
     */
    char *saved[sizeof hostile / sizeof *hostile];
    for (size_t i = 0; i < sizeof hostile / sizeof *hostile; ++i) {
        const char *v = getenv(hostile[i]);
        /* strdup rather than a fixed buffer: PATH on a developer machine is
         * routinely longer than VU_PATH_MAX, and the first version of this
         * aborted the whole run on it. */
        saved[i] = v ? strdup(v) : NULL;
        CHECK(!v || saved[i] != NULL, "cannot save %s", hostile[i]);
        setenv(hostile[i], "/nonexistent/evil", 1);
    }
    setenv("IFS", " \t\n", 1);
    setenv("PATH", "", 1);

    char **env = vu_clean_env(1000, "11111111-1111-1111-1111-111111111111",
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    CHECK(env != NULL && env[0] != NULL, "the constructed environment must not be empty");

    size_t n = 0;
    const char *path_value = NULL;
    for (char **p = env; *p; ++p) {
        n++;
        if (strncmp(*p, "PATH=", 5) == 0) path_value = *p + 5;
        for (size_t i = 0; i < sizeof hostile / sizeof *hostile; ++i) {
            if (strcmp(hostile[i], "PATH") == 0) continue;   /* PATH is set BY us */
            size_t klen = strlen(hostile[i]);
            CHECK(!(strncmp(*p, hostile[i], klen) == 0 && (*p)[klen] == '='),
                  "%s must not survive into the exec'd environment", hostile[i]);
        }
        CHECK(strncmp(*p, "LD_", 3) != 0, "no LD_* variable may survive: %s", *p);
        CHECK(strncmp(*p, "DYLD_", 5) != 0, "no DYLD_* variable may survive: %s", *p);
    }
    CHECK(n == 5, "the environment should be PATH plus the four VUP_* telemetry "
                  "variables and nothing else, got %zu entries", n);

    /*
     * PATH must be present, absolute, and NOT empty. Verified chain: the shipped
     * vpnc-script does PATH=/sbin:/usr/sbin:$PATH, so an empty value becomes
     * "/sbin:/usr/sbin:" — and a trailing colon means the current directory.
     */
    CHECK(path_value != NULL, "PATH must be set explicitly");
    if (path_value) {
        CHECK(*path_value == '/', "PATH must start with an absolute entry: %s", path_value);
        size_t len = strlen(path_value);
        CHECK(len > 0, "PATH must not be empty");
        CHECK(path_value[len - 1] != ':', "PATH must not end in ':' (that is the cwd)");
        CHECK(strstr(path_value, "::") == NULL, "PATH must contain no empty entry");
        CHECK(strstr(path_value, ".:") == NULL && strcmp(path_value, ".") != 0,
              "PATH must contain no relative entry");
    }

    /* Called twice with the same arguments, the same answer: the caller
     * execve's straight after. */
    char **again = vu_clean_env(1000, "11111111-1111-1111-1111-111111111111",
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    CHECK(again != NULL && strcmp(again[0], env[0]) == 0, "vu_clean_env must be stable");

    for (size_t i = 0; i < sizeof hostile / sizeof *hostile; ++i) {
        if (saved[i]) { setenv(hostile[i], saved[i], 1); free(saved[i]); }
        else unsetenv(hostile[i]);
    }
}

/* ------------------------------------------------------------------------- */
/* Descriptor hygiene.                                                       */
/* ------------------------------------------------------------------------- */

static void test_std_fds(void)
{
    /*
     * Verified before the fix: invoked with stdin closed, vu_lock_acquire
     * returned fd 0, and the helper then execve's OpenConnect with
     * --cookie-on-stdin — so OpenConnect would read the LOCK FILE as the session
     * cookie. Not an escalation, but a privileged program whose behaviour
     * depends on how its caller arranged its descriptors.
     *
     * Tested in a child process: closing descriptor 0 in the test runner itself
     * would sabotage everything after it.
     */
    pid_t child = fork();
    CHECK(child >= 0, "fork failed: %s", strerror(errno));
    if (child == 0) {
        vu_err e; vu_err_clear(&e);
        if (close(0) != 0) _exit(20);
        if (!vu_ensure_std_fds(&e)) _exit(21);
        if (fcntl(0, F_GETFD) < 0) _exit(22);            /* must be open now */
        int probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (probe < 0) _exit(23);
        if (probe == 0) _exit(24);                        /* 0 must be taken */
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child, "waitpid: %s", strerror(errno));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "with stdin closed, descriptor 0 must be reserved before anything else "
          "opens a file (child exit %d)", WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* All three, closed at once — the shape `0<&- 1>&- 2>&-` produces. */
    child = fork();
    CHECK(child >= 0, "fork failed: %s", strerror(errno));
    if (child == 0) {
        int report = dup(2);                              /* keep a way to fail loudly */
        vu_err e; vu_err_clear(&e);
        close(0); close(1); close(2);
        if (!vu_ensure_std_fds(&e)) _exit(30);
        for (int fd = 0; fd <= 2; ++fd) if (fcntl(fd, F_GETFD) < 0) _exit(31);
        int probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (probe <= 2) _exit(32);
        (void)report;
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child, "waitpid: %s", strerror(errno));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "all three standard descriptors must be reserved (child exit %d)",
          WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* Idempotent: calling it when nothing is closed must change nothing. */
    {
        vu_err e; vu_err_clear(&e);
        CHECK(vu_ensure_std_fds(&e), "must succeed when 0,1,2 are already open: %s", e.msg);
    }

    /* The standard descriptors must NOT be marked close-on-exec: OpenConnect is
     * execve'd and needs all three. */
    child = fork();
    if (child == 0) {
        vu_err e; vu_err_clear(&e);
        close(0);
        if (!vu_ensure_std_fds(&e)) _exit(40);
        int flags = fcntl(0, F_GETFD);
        _exit((flags >= 0 && (flags & FD_CLOEXEC) == 0) ? 0 : 41);
    }
    CHECK(waitpid(child, &status, 0) == child, "waitpid: %s", strerror(errno));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "a reopened standard descriptor must survive execve (child exit %d)",
          WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/* ------------------------------------------------------------------------- */
/* State that root is asked to act on.                                       */
/* ------------------------------------------------------------------------- */

static void test_state_trust(void)
{
    make_base("state");
    vu_err e;
    char root[VU_PATH_MAX];
    vu_path(root, sizeof root, "%s/run", g_base);
    uid_t me = getuid();

    vu_state_paths p;
    vu_err_clear(&e);
    CHECK(vu_state_paths_in(root, me, ID_A, &p, &e), "paths: %s", e.msg);

    /* Nothing exists yet: "no state" is an answer, not a failure, and verifying
     * must not bring the tree into existence. */
    bool present = true;
    vu_err_clear(&e);
    CHECK(vu_state_verify(&p, me, &present, &e), "verifying an absent tree must succeed: %s", e.msg);
    CHECK(!present, "an absent tree must report present=false");
    CHECK(access(root, F_OK) != 0, "verification must not create the state root");

    /* Now build it the way connect does, and record a live process. */
    int lock = -1;
    vu_err_clear(&e);
    CHECK(vu_lock_acquire(&p, me, &lock, &e), "lock: %s", e.msg);
    vu_proc self;
    vu_err_clear(&e);
    CHECK(vu_proc_identity(getpid(), &self, &e), "identity: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_state_record(&p, &self, "https://vpn.example.com:443", &e), "record: %s", e.msg);

    vu_state_status st;
    vu_proc found;
    vu_err_clear(&e);
    CHECK(vu_state_check(&p, self.exe, me, &st, &found, &e) && st == VU_STATE_LIVE,
          "our own process must read back as live: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_state_verify(&p, me, &present, &e) && present, "a built tree must verify: %s", e.msg);

    /*
     * A state file anyone can write is a state file that decides which pid root
     * signals. Before step 9 this was believed: the directory is 0700 and
     * root-owned, which made the check look redundant — until `stop`, which
     * never verified the directory at all.
     */
    CHECK(chmod(p.pid, 0666) == 0, "chmod: %s", strerror(errno));
    vu_err_clear(&e);
    CHECK(!vu_state_check(&p, self.exe, me, &st, &found, &e),
          "a world-writable pid file must not be believed");
    CHECK(strstr(e.msg, "group or other") != NULL, "say why: %s", e.msg);
    CHECK(chmod(p.pid, 0600) == 0, "chmod back: %s", strerror(errno));

    CHECK(chmod(p.started, 0604) == 0, "chmod: %s", strerror(errno));
    vu_err_clear(&e);
    /* The start token is what defeats pid reuse, so an untrusted token must not
     * be treated as "no token" — that would silently drop the reuse check. */
    CHECK(!vu_state_check(&p, self.exe, me, &st, &found, &e) || st != VU_STATE_LIVE,
          "an untrusted start token must not yield a live verdict");
    CHECK(chmod(p.started, 0600) == 0, "chmod back: %s", strerror(errno));

    /* A group-writable profile directory: verification must refuse, and the
     * refusal must not be reported as "absent". */
    CHECK(chmod(p.profile_dir, 0770) == 0, "chmod: %s", strerror(errno));
    present = true;
    vu_err_clear(&e);
    CHECK(!vu_state_verify(&p, me, &present, &e),
          "a group-writable profile directory must be refused");
    CHECK(!present, "a refused tree must not report present=true");
    CHECK(chmod(p.profile_dir, 0700) == 0, "chmod back: %s", strerror(errno));

    /* Ownership: a directory owned by somebody else must be refused. Cannot be
     * created without privilege, so the check is exercised by asking for the
     * wrong expected owner — the identical comparison in the identical code. */
    present = true;
    vu_err_clear(&e);
    CHECK(!vu_state_verify(&p, me + 1, &present, &e),
          "a state tree owned by another uid must be refused");
    vu_err_clear(&e);
    CHECK(!vu_state_check(&p, self.exe, me + 1, &st, &found, &e),
          "state files owned by another uid must be refused");

    /* A pid file naming a process that is not the one we started. */
    {
        int fd = open(p.pid, O_WRONLY | O_TRUNC, 0600);
        CHECK(fd >= 0, "reopen pid file: %s", strerror(errno));
        CHECK(write(fd, "1\n", 2) == 2, "write pid: %s", strerror(errno));
        close(fd);
        vu_err_clear(&e);
        CHECK(vu_state_check(&p, self.exe, me, &st, &found, &e) && st == VU_STATE_STALE,
              "pid 1 is running but is not our executable: must be stale, not live");
    }

    /* Garbage, and shapes that a naive parse would accept. */
    static const char *junk[] = { "", "\n", "0", "-1", "abc", "1 2", "99999999999999999999",
                                 "1\n2\n", " 1", "+1", "01" };
    for (size_t i = 0; i < sizeof junk / sizeof *junk; ++i) {
        int fd = open(p.pid, O_WRONLY | O_TRUNC, 0600);
        CHECK(fd >= 0, "reopen pid file: %s", strerror(errno));
        size_t len = strlen(junk[i]);
        CHECK(len == 0 || write(fd, junk[i], len) == (ssize_t)len, "write: %s", strerror(errno));
        close(fd);
        vu_err_clear(&e);
        bool ok = vu_state_check(&p, self.exe, me, &st, &found, &e);
        CHECK(!ok || st != VU_STATE_LIVE, "pid file '%s' must never read as live", junk[i]);
    }

    /* A symlinked state file must not be followed: the open is O_NOFOLLOW, so a
     * planted link fails rather than redirecting the read. */
    CHECK(unlink(p.pid) == 0, "unlink pid: %s", strerror(errno));
    {
        char target[VU_PATH_MAX];
        vu_path(target, sizeof target, "%s/decoy", g_base);
        int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        CHECK(fd >= 0, "decoy: %s", strerror(errno));
        CHECK(write(fd, "1\n", 2) == 2, "decoy write: %s", strerror(errno));
        close(fd);
        CHECK(symlink(target, p.pid) == 0, "symlink: %s", strerror(errno));
        vu_err_clear(&e);
        bool ok = vu_state_check(&p, self.exe, me, &st, &found, &e);
        CHECK(!ok || st != VU_STATE_LIVE, "a symlinked pid file must not be followed");
        CHECK(unlink(p.pid) == 0, "unlink link: %s", strerror(errno));
    }

    /* One tunnel per profile: the second acquire fails immediately rather than
     * queueing behind a live one. */
    {
        int second = -1;
        vu_err_clear(&e);
        CHECK(!vu_lock_acquire(&p, me, &second, &e), "a second lock must not be granted");
        CHECK(strstr(e.msg, "already has a tunnel") != NULL, "explain: %s", e.msg);
        CHECK(second == -1, "a refused lock must not return a descriptor");
    }

    /* Another uid's state is a different path; nothing crosses. */
    {
        vu_state_paths other;
        vu_err_clear(&e);
        CHECK(vu_state_paths_in(root, me + 1, ID_A, &other, &e), "other paths: %s", e.msg);
        CHECK(strcmp(other.profile_dir, p.profile_dir) != 0, "uids must not share a directory");
        bool other_present = true;
        vu_err_clear(&e);
        CHECK(vu_state_verify(&other, me, &other_present, &e) && !other_present,
              "another uid's state must simply not exist: %s", e.msg);
    }

    /* Profile ids that would escape the directory. */
    {
        static const char *escapes[] = { "..", ".", "../../etc", "a/b", "/abs", "" };
        for (size_t i = 0; i < sizeof escapes / sizeof *escapes; ++i) {
            vu_state_paths bad;
            vu_err_clear(&e);
            CHECK(!vu_state_paths_in(root, me, escapes[i], &bad, &e),
                  "profile id '%s' must not build a path", escapes[i]);
        }
    }

    vu_lock_release(lock);
    drop_base();
}

/* ------------------------------------------------------------------------- */
/* Registry records: root wrote them, which is not a reason to trust them.   */
/* ------------------------------------------------------------------------- */

static void test_registry_attacks(void)
{
    make_base("reg");
    vu_err e;
    char root[VU_PATH_MAX];
    vu_path(root, sizeof root, "%s/etc", g_base);
    uid_t me = getuid();

    vu_approval a;
    memset(&a, 0, sizeof a);
    vu_err_clear(&e);
    CHECK(vu_canon_profile_id(ID_A, a.profile_id, sizeof a.profile_id, &e), "id: %s", e.msg);
    memcpy(a.protocol, "anyconnect", sizeof "anyconnect");
    memcpy(a.origin, "https://vpn.example.com:443", sizeof "https://vpn.example.com:443");
    memcpy(a.fingerprint, FPR_A, sizeof FPR_A);
    vu_err_clear(&e);
    CHECK(vu_registry_put(root, me, me, &a, &e), "put: %s", e.msg);

    /* Another user's approval is unreachable: the uid is part of the path. */
    {
        vu_approval got;
        bool found = true;
        vu_err_clear(&e);
        CHECK(vu_registry_get(root, me, me + 1, a.profile_id, &got, &found, &e),
              "looking in another uid's namespace is not an error: %s", e.msg);
        CHECK(!found, "another uid must not see this approval");
    }

    /*
     * "proxy=" with an empty value used to parse as NONE. That is a second
     * spelling of the field that decides whether the tunnel goes through a
     * proxy at all, inside a parser whose rule is one spelling per record — and
     * the likely way to produce it is a truncated write or a hand edit, exactly
     * the cases the strict parse exists for.
     */
    static const char *bad_records[] = {
        /* empty proxy */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=\n",
        /* unknown key */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\nextra=1\n",
        /* duplicate key */
        "version=1\nprofile_id=" ID_A "\nprofile_id=" ID_B "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* missing field */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nproxy=NONE\n",
        /* truncated fingerprint: the partial-match hazard, in the registry */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=sha256:abcd\nproxy=NONE\n",
        /* non-canonical origin: no explicit port */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* non-canonical origin: a path */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443/portal\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* non-https origin */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=http://vpn.example.com:80\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* protocol outside the closed set */
        "version=1\nprofile_id=" ID_A "\nprotocol=openvpn\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* non-canonical profile id */
        "version=1\nprofile_id=11111111222233334444555555555555\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* unsupported version */
        "version=2\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* no version at all */
        "profile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* a blank line inside the record */
        "version=1\nprofile_id=" ID_A "\n\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* a line that is not key=value */
        "version=1\nprofile_id=" ID_A "\nprotocol anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* carriage return: control byte */
        "version=1\r\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A "\nproxy=NONE\n",
        /* proxy with credentials */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A
        "\nproxy=http://user:pw@proxy.example.com:3128\n",
        /* proxy scheme outside v1 */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A
        "\nproxy=https://proxy.example.com:3128\n",
        /* proxy without an explicit port */
        "version=1\nprofile_id=" ID_A "\nprotocol=anyconnect\n"
        "origin=https://vpn.example.com:443\nfingerprint=" FPR_A
        "\nproxy=http://proxy.example.com\n",
        /* empty */
        "",
    };
    for (size_t i = 0; i < sizeof bad_records / sizeof *bad_records; ++i) {
        vu_approval got;
        vu_err_clear(&e);
        CHECK(!vu_approval_parse(bad_records[i], &got, &e),
              "record #%zu must be refused", i);
        CHECK(e.msg[0] != '\0', "record #%zu refused without a reason", i);
    }

    /* Tampering on disk: contents that disagree with the filename must not
     * authorise anything, because moving a file is how one profile's approval
     * would become another's. */
    {
        vu_registry_paths rp;
        vu_err_clear(&e);
        CHECK(vu_registry_paths_in(root, me, ID_B, &rp, &e), "paths: %s", e.msg);
        char text[VU_URL_MAX];
        vu_err_clear(&e);
        CHECK(vu_approval_serialise(&a, text, sizeof text, &e), "serialise: %s", e.msg);
        int fd = open(rp.record, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        CHECK(fd >= 0, "plant record: %s", strerror(errno));
        CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text), "write: %s", strerror(errno));
        close(fd);

        vu_approval got;
        bool found = true;
        vu_err_clear(&e);
        char id_b[VU_UUID_MAX];
        vu_err ee; vu_err_clear(&ee);
        CHECK(vu_canon_profile_id(ID_B, id_b, sizeof id_b, &ee), "id: %s", ee.msg);
        CHECK(!vu_registry_get(root, me, me, id_b, &got, &found, &e),
              "a record whose contents disagree with its filename must be refused");
        CHECK(strstr(e.msg, "filename") != NULL, "say why: %s", e.msg);
        CHECK(unlink(rp.record) == 0, "cleanup: %s", strerror(errno));
    }

    /* A world-readable record is refused: the registry says which VPNs this
     * machine will establish without a password. */
    {
        vu_registry_paths rp;
        vu_err_clear(&e);
        CHECK(vu_registry_paths_in(root, me, a.profile_id, &rp, &e), "paths: %s", e.msg);
        CHECK(chmod(rp.record, 0644) == 0, "chmod: %s", strerror(errno));
        vu_approval got;
        bool found = true;
        vu_err_clear(&e);
        CHECK(!vu_registry_get(root, me, me, a.profile_id, &got, &found, &e),
              "a group- or world-accessible record must be refused");
        CHECK(chmod(rp.record, 0600) == 0, "chmod back: %s", strerror(errno));

        /* Owned by somebody else: the same comparison, reached by asking for the
         * wrong expected owner. */
        vu_err_clear(&e);
        CHECK(!vu_registry_get(root, me + 1, me, a.profile_id, &got, &found, &e),
              "a record owned by another uid must be refused");

        /* A symlinked record is not followed. */
        char decoy[VU_PATH_MAX];
        vu_path(decoy, sizeof decoy, "%s/decoy-record", g_base);
        char text[VU_URL_MAX];
        vu_err_clear(&e);
        CHECK(vu_approval_serialise(&a, text, sizeof text, &e), "serialise: %s", e.msg);
        int fd = open(decoy, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        CHECK(fd >= 0, "decoy: %s", strerror(errno));
        CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text), "write: %s", strerror(errno));
        close(fd);
        CHECK(unlink(rp.record) == 0, "unlink: %s", strerror(errno));
        CHECK(symlink(decoy, rp.record) == 0, "symlink: %s", strerror(errno));
        vu_err_clear(&e);
        CHECK(!vu_registry_get(root, me, me, a.profile_id, &got, &found, &e),
              "a symlinked record must not be followed");
        CHECK(unlink(rp.record) == 0, "cleanup: %s", strerror(errno));
    }

    /* Round-tripping: what put() stores must be exactly what parse() accepts,
     * or a re-approval would write a record the helper then refuses. */
    {
        vu_err_clear(&e);
        CHECK(vu_registry_put(root, me, me, &a, &e), "re-put: %s", e.msg);
        vu_approval got;
        bool found = false;
        vu_err_clear(&e);
        CHECK(vu_registry_get(root, me, me, a.profile_id, &got, &found, &e) && found,
              "get after put: %s", e.msg);
        CHECK(strcmp(got.origin, a.origin) == 0 &&
              strcmp(got.fingerprint, a.fingerprint) == 0 &&
              strcmp(got.protocol, a.protocol) == 0 &&
              got.proxy[0] == '\0',
              "the stored record must read back unchanged");

        char text[VU_URL_MAX], again[VU_URL_MAX];
        vu_err_clear(&e);
        CHECK(vu_approval_serialise(&a, text, sizeof text, &e), "serialise: %s", e.msg);
        CHECK(vu_approval_serialise(&got, again, sizeof again, &e), "re-serialise: %s", e.msg);
        CHECK(strcmp(text, again) == 0, "serialisation must be byte-stable");
    }

    /* An approval must never be storable in a shape that cannot be read back. */
    {
        vu_approval broken = a;
        memcpy(broken.fingerprint, "sha256:abcd", sizeof "sha256:abcd");
        vu_err_clear(&e);
        CHECK(!vu_registry_put(root, me, me, &broken, &e),
              "a record that will not parse must not be stored");
        CHECK(strstr(e.msg, "will not parse") != NULL, "say why: %s", e.msg);
        CHECK(strstr(e.msg, "hex characters") != NULL,
              "and keep the underlying reason: %s", e.msg);
    }

    drop_base();
}

/* ------------------------------------------------------------------------- */
/* Phase-one output: shell-shaped, never shell-parsed.                       */
/* ------------------------------------------------------------------------- */

static void test_auth_output_attacks(void)
{
    vu_err e;
    vu_auth a;

    /* The format upstream documents, which is also the only thing accepted. */
    static const char good[] =
        "COOKIE='abc123'\n"
        "HOST='vpn.example.com'\n"
        "CONNECT_URL='https://vpn.example.com/portal'\n"
        "FINGERPRINT='1111111111111111111111111111111111111111'\n";
    vu_err_clear(&e);
    CHECK(vu_parse_auth(good, &a, &e), "the documented format must parse: %s", e.msg);
    CHECK(strcmp(a.cookie, "abc123") == 0, "cookie: %s", a.cookie);
    /* Normalised on the way in, so the helper's strict schema never sees a bare
     * digest. */
    CHECK(strcmp(a.fingerprint, "sha1:1111111111111111111111111111111111111111") == 0,
          "the fingerprint must be canonicalised: %s", a.fingerprint);

    /*
     * Upstream intends this output to be eval'd. These are the fixtures that
     * separate "we parse the small language it emits" from "we run it".
     */
    /*
     * Shell metacharacters INSIDE a properly quoted value are data, and the
     * property worth asserting is not that they are refused — refusing them
     * would break legitimate cookies, which are opaque server blobs — but that
     * they arrive byte-for-byte and nothing ever executes them. A decoder that
     * eval'd this line would run `id`; this one returns it as a string.
     */
    static const struct { const char *text; const char *cookie; } verbatim[] = {
        { "COOKIE='$(id > /tmp/pwned)'\nCONNECT_URL='https://vpn.example.com/'\n",
          "$(id > /tmp/pwned)" },
        { "COOKIE='`id`'\nCONNECT_URL='https://vpn.example.com/'\n", "`id`" },
        { "COOKIE='a$b;c|d&e>f<g'\nCONNECT_URL='https://vpn.example.com/'\n",
          "a$b;c|d&e>f<g" },
        { "COOKIE='${IFS}'\nCONNECT_URL='https://vpn.example.com/'\n", "${IFS}" },
        { "COOKIE='a\\nb'\nCONNECT_URL='https://vpn.example.com/'\n", "a\\nb" },
        { "COOKIE='*'\nCONNECT_URL='https://vpn.example.com/'\n", "*" },
    };
    for (size_t i = 0; i < sizeof verbatim / sizeof *verbatim; ++i) {
        vu_err_clear(&e);
        CHECK(vu_parse_auth(verbatim[i].text, &a, &e),
              "verbatim fixture #%zu must decode: %s", i, e.msg);
        CHECK(strcmp(a.cookie, verbatim[i].cookie) == 0,
              "fixture #%zu must survive unchanged: got '%s', want '%s'",
              i, a.cookie, verbatim[i].cookie);
    }

    static const char *hostile[] = {
        /* a command appended OUTSIDE the quotes: this is malformed, not data */
        "COOKIE='a'; rm -rf /\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE='a'\nrm -rf /\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE='a' ; touch /tmp/x\nCONNECT_URL='https://vpn.example.com/'\n",
        /* unknown key: a hard failure, not a skipped line */
        "COOKIE='a'\nEVIL='x'\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE='a'\nPATH='/tmp'\nCONNECT_URL='https://vpn.example.com/'\n",
        /* duplicates: which one would win is not a question worth having */
        "COOKIE='a'\nCOOKIE='b'\nCONNECT_URL='https://vpn.example.com/'\n",
        "CONNECT_URL='https://vpn.example.com/'\nCONNECT_URL='https://evil.net/'\nCOOKIE='a'\n",
        /* unquoted, half-quoted, wrongly quoted */
        "COOKIE=abc\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE='abc\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE=\"abc\"\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE='abc''def'\nCONNECT_URL='https://vpn.example.com/'\n",
        /* trailing junk after the closing quote */
        "COOKIE='abc' junk\nCONNECT_URL='https://vpn.example.com/'\n",
        /* backslash escapes are not interpreted, so a value that relies on them
         * is malformed rather than decoded */
        "COOKIE='a\\'b'\nCONNECT_URL='https://vpn.example.com/'\n",
        /* leading whitespace and an exported form */
        " COOKIE='a'\nCONNECT_URL='https://vpn.example.com/'\n",
        "export COOKIE='a'\nCONNECT_URL='https://vpn.example.com/'\n",
        /* a fingerprint that would pin almost nothing */
        "COOKIE='a'\nCONNECT_URL='https://vpn.example.com/'\nFINGERPRINT='abcd'\n",
        /* a connect URL that is not a URL */
        "COOKIE='a'\nCONNECT_URL='vpn.example.com'\n",
        "COOKIE='a'\nCONNECT_URL='http://vpn.example.com/'\n",
        /* empty key, empty line with spaces, a bare word */
        "='a'\nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE='a'\n   \nCONNECT_URL='https://vpn.example.com/'\n",
        "COOKIE\nCONNECT_URL='https://vpn.example.com/'\n",
    };
    for (size_t i = 0; i < sizeof hostile / sizeof *hostile; ++i) {
        vu_err_clear(&e);
        CHECK(!vu_parse_auth(hostile[i], &a, &e), "hostile fixture #%zu must be refused", i);
        CHECK(e.msg[0] != '\0', "hostile fixture #%zu refused without a reason", i);
    }

    /* Legacy output — HOST but no CONNECT_URL — must be refused for helper mode
     * with an actionable message, not silently downgraded. Model B binds an
     * origin, and a bare HOST discards exactly what is being bound. */
    static const char legacy[] =
        "COOKIE='abc'\nHOST='vpn.example.com'\n"
        "FINGERPRINT='1111111111111111111111111111111111111111'\n";
    vu_err_clear(&e);
    CHECK(vu_parse_auth(legacy, &a, &e), "legacy output is well-formed: %s", e.msg);
    vu_err_clear(&e);
    CHECK(!vu_auth_require_helper_contract(&a, &e), "legacy output must not satisfy the contract");
    CHECK(strstr(e.msg, "too old") != NULL, "say the version is the problem: %s", e.msg);

    /* A cookie is opaque: any printable value, of any length up to the buffer,
     * must survive unexamined. The helper never interprets it. */
    {
        static const char head[] = "COOKIE='";
        static const char tail[] = "'\nCONNECT_URL='https://vpn.example.com/'\n";
        static char big[VU_COOKIE_MAX * 2];

        /* Exactly the largest cookie the buffer can hold: must parse, whole. */
        size_t body = VU_COOKIE_MAX - 1;
        size_t at = sizeof head - 1;
        memcpy(big, head, at);
        memset(big + at, 'x', body);
        at += body;
        memcpy(big + at, tail, sizeof tail);
        vu_err_clear(&e);
        CHECK(vu_parse_auth(big, &a, &e), "a maximum-length cookie must parse: %s", e.msg);
        CHECK(strlen(a.cookie) == body, "the cookie must arrive whole: %zu of %zu",
              strlen(a.cookie), body);

        /* One byte more: refused for length, NEVER truncated. A silently
         * shortened cookie would be rejected by the gateway with no clue why. */
        at = sizeof head - 1;
        memset(big + at, 'x', body + 1);
        at += body + 1;
        memcpy(big + at, tail, sizeof tail);
        vu_err_clear(&e);
        CHECK(!vu_parse_auth(big, &a, &e), "an over-long cookie must be refused");
        CHECK(strstr(e.msg, "exceeds") != NULL, "say it was the length: %s", e.msg);
    }
}

/* ------------------------------------------------------------------------- */
/* The cookie must not be expressible on the command line at all.            */
/* ------------------------------------------------------------------------- */

static void test_cookie_never_in_argv(void)
{
    vu_err e;
    vu_request req; vu_approval appr;
    fill(&req, &appr, "https://vpn.example.com/portal");

    static vu_argv cmd;
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, "/bin/sh", "/etc/vpnc/vpnc-script", &cmd, &e),
          "baseline argv: %s", e.msg);

    /*
     * Structural, not filtered: vu_request has no cookie field, so there is no
     * value for the builder to place on the command line even by mistake. The
     * assertions below are the visible half of that.
     */
    bool has_stdin_flag = false;
    for (size_t i = 0; i < cmd.n; ++i) {
        CHECK(strstr(cmd.argv[i], "--cookie=") == NULL, "no cookie value on argv: %s", cmd.argv[i]);
        CHECK(strcmp(cmd.argv[i], "--cookie") != 0, "no --cookie flag: %s", cmd.argv[i]);
        CHECK(strcmp(cmd.argv[i], "-C") != 0, "no -C flag");
        if (strcmp(cmd.argv[i], "--cookie-on-stdin") == 0) has_stdin_flag = true;
    }
    CHECK(has_stdin_flag, "--cookie-on-stdin must always be present");

    /* --non-inter must always be there too: the helper does not read stdin, so
     * OpenConnect must exit rather than prompt root-side if the cookie is
     * missing or rejected. */
    bool non_inter = false, servercert = false;
    for (size_t i = 0; i < cmd.n; ++i) {
        if (strcmp(cmd.argv[i], "--non-inter") == 0) non_inter = true;
        if (strncmp(cmd.argv[i], "--servercert=", 13) == 0) servercert = true;
    }
    CHECK(non_inter, "--non-inter must always be present");
    CHECK(servercert, "--servercert must always be present");

    /* And the fingerprint on argv is the APPROVAL's, whatever the request says.
     * Setting the request's copy to something else must not change argv — it must
     * refuse, because policy compares them. */
    memcpy(req.fingerprint, FPR_B, sizeof FPR_B);
    vu_err_clear(&e);
    CHECK(!vu_build_argv(&req, &appr, "/bin/sh", "/etc/vpnc/vpnc-script", &cmd, &e),
          "a request-supplied fingerprint must not override the approval");
}

/* ------------------------------------------------------------------------- */
/* The shared fixture set, which both decoders must agree on.                */
/* ------------------------------------------------------------------------- */

/*
 * Phase one runs in the SHELL, so twophase.sh's parse_auth_output() is the
 * decoder that actually runs; vu_parse_auth is the reference implementation with
 * the harder corpus. Two implementations of one security-relevant parser drift,
 * and drift in this one means a value the shell accepted and the reference would
 * have refused (or the reverse) reaching the privileged side.
 *
 * So the format cases live in files, and both suites read the same files:
 * tests/twophase.bats runs them through the shell, this runs them through the C.
 * See t/fixtures/auth/README for the scope — format only, not value semantics.
 */
static void test_shared_fixtures(void)
{
    static const char *dir = "t/fixtures/auth";
    DIR *d = opendir(dir);
    if (!d) {
        /* Run from the helper directory, as `make test` does. Reported rather
         * than skipped: a fixture set nobody loads is worse than none. */
        CHECK(false, "cannot open %s (run the corpus from helper/): %s", dir, strerror(errno));
        return;
    }

    size_t seen = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        bool want_accept;
        if      (strncmp(ent->d_name, "accept-", 7) == 0) want_accept = true;
        else if (strncmp(ent->d_name, "refuse-", 7) == 0) want_accept = false;
        else continue;                                   /* README, dotfiles */

        char path[VU_PATH_MAX];
        vu_path(path, sizeof path, "%s/%s", dir, ent->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { CHECK(false, "cannot read %s: %s", path, strerror(errno)); continue; }
        static char text[VU_COOKIE_MAX * 2];
        ssize_t r = read(fd, text, sizeof text - 1);
        close(fd);
        if (r < 0) { CHECK(false, "cannot read %s: %s", path, strerror(errno)); continue; }
        text[(size_t)r] = '\0';

        vu_auth a;
        vu_err e; vu_err_clear(&e);
        bool got = vu_parse_auth(text, &a, &e);
        CHECK(got == want_accept, "%s: expected %s, got %s (%s)", ent->d_name,
              want_accept ? "accept" : "refuse", got ? "accept" : "refuse", e.msg);
        if (!got) CHECK(e.msg[0] != '\0', "%s: refused without a reason", ent->d_name);
        seen++;
    }
    closedir(d);

    /* A loop that silently iterates nothing passes. Assert the set is there. */
    CHECK(seen >= 20, "expected the shared fixture set, found %zu files", seen);
}

void vu_test_adversarial(void)
{
    test_schema_attacks();
    test_origin_confusion();
    test_resolve_binding();
    test_model_b_substitution();
    test_fingerprint_attacks();
    test_sudo_uid_attacks();
    test_environment();
    test_std_fds();
    test_state_trust();
    test_registry_attacks();
    test_auth_output_attacks();
    test_cookie_never_in_argv();
    test_shared_fixtures();
}
