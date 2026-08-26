/*
 * test.c — hostile-input corpus for the policy engine.
 *
 * Per PRIVILEGED-HELPER-DESIGN.md §16, the engine is built and broken as an
 * ordinary process before any root execution exists. So this harness runs
 * unprivileged and only ever calls pure functions.
 *
 * The bias throughout is toward REJECTION cases. Accepting a good value is
 * table stakes; refusing a plausible-looking bad one is the property that
 * matters, so most assertions here are "this must not be accepted".
 */

#include "vu.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, ...) do {                                               \
        checks++;                                                           \
        if (!(cond)) {                                                      \
            failures++;                                                     \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);            \
            fprintf(stderr, __VA_ARGS__);                                   \
            fputc('\n', stderr);                                            \
        }                                                                   \
    } while (0)

/* ------------------------------------------------------------------ helpers */

static bool host_ok(const char *in, const char *expect)
{
    char out[VU_HOST_MAX]; vu_err e; vu_err_clear(&e);
    if (!vu_canon_host(in, out, sizeof out, NULL, &e)) return false;
    return strcmp(out, expect) == 0;
}
static bool host_rejected(const char *in)
{
    char out[VU_HOST_MAX]; vu_err e; vu_err_clear(&e);
    return !vu_canon_host(in, out, sizeof out, NULL, &e);
}
static bool fpr_ok(const char *in, const char *expect)
{
    char out[VU_FPR_MAX]; vu_err e; vu_err_clear(&e);
    if (!vu_canon_fingerprint(in, out, sizeof out, &e)) return false;
    return strcmp(out, expect) == 0;
}
static bool fpr_rejected(const char *in)
{
    char out[VU_FPR_MAX]; vu_err e; vu_err_clear(&e);
    return !vu_canon_fingerprint(in, out, sizeof out, &e);
}
static bool url_rejected(const char *in)
{
    vu_url u; vu_err e; vu_err_clear(&e);
    return !vu_parse_url(in, &u, &e);
}
static bool origin_of(const char *in, const char *expect)
{
    vu_url u; vu_err e; vu_err_clear(&e);
    if (!vu_parse_url(in, &u, &e)) return false;
    return strcmp(u.origin, expect) == 0;
}
static bool proxy_rejected(const char *in)
{
    char out[VU_PROXY_MAX]; vu_err e; vu_err_clear(&e);
    return !vu_canon_proxy(in, out, sizeof out, &e);
}
static bool tun_rejected(const char *kv)
{
    char out[96]; vu_err e; vu_err_clear(&e);
    return !vu_render_tunable(kv, out, sizeof out, &e);
}
static bool tun_is(const char *kv, const char *expect)
{
    char out[96]; vu_err e; vu_err_clear(&e);
    if (!vu_render_tunable(kv, out, sizeof out, &e)) return false;
    return strcmp(out, expect) == 0;
}
static bool auth_rejected(const char *text)
{
    vu_auth a; vu_err e; vu_err_clear(&e);
    return !vu_parse_auth(text, &a, &e);
}

/* -------------------------------------------------------------------- hosts */

static void test_hosts(void)
{
    CHECK(host_ok("VPN.Example.COM", "vpn.example.com"), "host lowercasing");
    CHECK(host_ok("vpn.example.com.", "vpn.example.com"), "trailing dot stripped");
    CHECK(host_ok("10.0.0.1", "10.0.0.1"), "IPv4 canonical");
    CHECK(host_ok("010.0.0.1", "10.0.0.1") || host_rejected("010.0.0.1"),
          "leading-zero IPv4 is either canonicalised or refused, never passed through");
    CHECK(host_ok("[2001:db8::1]", "[2001:db8::1]"), "bracketed IPv6");
    CHECK(host_ok("[2001:DB8:0:0:0:0:0:1]", "[2001:db8::1]"), "IPv6 compressed on canonicalise");

    CHECK(host_rejected(""), "empty host");
    CHECK(host_rejected("."), "bare dot");
    CHECK(host_rejected("vpn..example.com"), "empty label");
    CHECK(host_rejected("-vpn.example.com"), "label starting with hyphen");
    CHECK(host_rejected("vpn-.example.com"), "label ending with hyphen");
    CHECK(host_rejected("vpn_example.com"), "underscore is not a DNS label char");
    CHECK(host_rejected("vpn.example.com:443"), "port must not be inside a host");
    CHECK(host_rejected("2001:db8::1"), "unbracketed IPv6 is ambiguous with host:port");
    CHECK(host_rejected("999.999.999.999"), "impossible dotted quad");
    /* The classic: rev 2's regex accepted this. A regex sees digits and dots. */
    CHECK(host_rejected("999.999.999.999/99"), "CIDR is not a host");
    CHECK(host_rejected("vpn.exämple.com"), "non-ASCII refused (IDNA out of scope for v1)");
    CHECK(host_rejected("vpn.example.com\n"), "trailing newline");
    CHECK(host_rejected("vpn .example.com"), "embedded space");
    {
        char big[300];
        memset(big, 'a', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        CHECK(host_rejected(big), "over-length host");
    }
    {
        /* 253 octets is the limit; a 64-byte label is over the per-label limit. */
        char label[70];
        memset(label, 'a', 64);
        label[64] = '\0';
        char name[128];
        snprintf(name, sizeof name, "%s.example.com", label);
        CHECK(host_rejected(name), "64-byte label");
    }
}

/* ---------------------------------------------------------------------- URLs */

static void test_urls(void)
{
    CHECK(origin_of("https://vpn.example.com", "https://vpn.example.com:443"),
          "absent port canonicalises to 443");
    CHECK(origin_of("https://vpn.example.com:443", "https://vpn.example.com:443"),
          "explicit 443 canonicalises to 443");
    CHECK(origin_of("https://vpn.example.com:8443", "https://vpn.example.com:8443"),
          "non-default port retained");
    CHECK(origin_of("HTTPS://VPN.Example.com/x", "https://vpn.example.com:443"),
          "scheme and host are case-insensitive");
    CHECK(origin_of("https://[2001:db8::42]:443/gateway", "https://[2001:db8::42]:443"),
          "bracketed IPv6 authority — the gap rev 2 left open");

    /* Query strings must survive: rev 2's path charset made these impossible,
     * which is what prompted dropping shell-shaped validation of argv fields. */
    {
        vu_url u; vu_err e; vu_err_clear(&e);
        CHECK(vu_parse_url("https://vpn.example.com/portal?session=a&b=c%20d", &u, &e),
              "query string accepted: %s", e.msg);
        CHECK(strcmp(u.path, "/portal") == 0, "path split");
        CHECK(strcmp(u.query, "session=a&b=c%20d") == 0, "query split");
        CHECK(strcmp(u.origin, "https://vpn.example.com:443") == 0, "origin ignores path/query");
    }

    CHECK(url_rejected("http://vpn.example.com"), "http refused");
    CHECK(url_rejected("ftp://vpn.example.com"), "ftp refused");
    CHECK(url_rejected("https://user:pw@vpn.example.com"), "userinfo refused");
    CHECK(url_rejected("https://vpn.example.com#frag"), "fragment refused");
    CHECK(url_rejected("https://vpn.example.com/x#frag"), "fragment after path refused");
    CHECK(url_rejected("https://"), "empty authority");
    CHECK(url_rejected("https://vpn.example.com:0"), "port 0");
    CHECK(url_rejected("https://vpn.example.com:65536"), "port out of range");
    CHECK(url_rejected("https://vpn.example.com:0443"), "non-canonical port spelling");
    CHECK(url_rejected("https://vpn.example.com:https"), "non-numeric port");
    CHECK(url_rejected("https://vpn.example.com/a b"), "space in path");
    CHECK(url_rejected("https://vpn.example.com/a\nb"), "newline in path");
    CHECK(url_rejected("https://[2001:db8::1"), "unterminated IPv6 authority");
    CHECK(url_rejected("https://[2001:db8::1]junk"), "junk after IPv6 authority");
    CHECK(url_rejected(""), "empty URL");
}

/* -------------------------------------------------------------- fingerprints */

static void test_fingerprints(void)
{
    /* Upstream's --authenticate emits bare hex; we normalise it. */
    CHECK(fpr_ok("469bb424ec8835944d30bc77c77e8fc1d8e23a42",
                 "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42"),
          "bare 40-hex becomes sha1:");
    CHECK(fpr_ok("469BB424EC8835944D30BC77C77E8FC1D8E23A42",
                 "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42"),
          "hex lowercased");
    CHECK(fpr_ok("sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42",
                 "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42"),
          "prefixed sha1 passes through canonically");

    /* THE case that motivated full-length enforcement: OpenConnect accepts a
     * partial hash "at least 4 characters past the prefix", so a short value
     * would silently pin almost nothing. */
    CHECK(fpr_rejected("sha256:abcd"), "partial sha256 refused");
    CHECK(fpr_rejected("sha1:469bb424"), "partial sha1 refused");
    CHECK(fpr_rejected("469bb424"), "short bare hex refused");
    CHECK(fpr_rejected("sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a4"), "39 hex refused");
    CHECK(fpr_rejected("sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a422"), "41 hex refused");
    CHECK(fpr_rejected("sha1:469bb424ec8835944d30bc77c77e8fc1d8e23aZZ"), "non-hex refused");
    CHECK(fpr_rejected("md5:0123456789abcdef0123456789abcdef"), "unknown prefix refused");
    CHECK(fpr_rejected(""), "empty fingerprint refused");

    /* pin-sha256 must decode to exactly 32 bytes, and must round-trip to one
     * canonical spelling so the registry cannot hold two equal-but-different
     * pins. */
    {
        uint8_t raw[32];
        for (size_t i = 0; i < sizeof raw; ++i) raw[i] = (uint8_t)i;
        char b64[64];
        CHECK(vu_b64_encode(raw, sizeof raw, b64, sizeof b64), "b64 encode");
        char in[128], want[128];
        snprintf(in,   sizeof in,   "pin-sha256:%s", b64);
        snprintf(want, sizeof want, "pin-sha256:%s", b64);
        CHECK(fpr_ok(in, want), "pin-sha256 round-trips canonically");
    }
    CHECK(fpr_rejected("pin-sha256:AAAA"), "pin-sha256 decoding to 3 bytes refused");
    CHECK(fpr_rejected("pin-sha256:not!base64=="), "pin-sha256 non-alphabet refused");
    CHECK(fpr_rejected("pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
          "pin-sha256 without padding refused (unpadded is a second spelling)");
    CHECK(fpr_rejected("pin-sha256: AAAA"), "whitespace in base64 refused");
}

/* ------------------------------------------------------------ closed fields */

static void test_closed_fields(void)
{
    vu_err e;

    vu_err_clear(&e);
    CHECK(vu_valid_protocol("anyconnect", &e), "anyconnect permitted");
    vu_err_clear(&e);
    CHECK(!vu_valid_protocol("AnyConnect", &e), "protocol enum is case-sensitive");
    vu_err_clear(&e);
    CHECK(!vu_valid_protocol("anyconnect ", &e), "trailing space refused");
    vu_err_clear(&e);
    CHECK(!vu_valid_protocol("", &e), "empty protocol refused");

    char id[VU_UUID_MAX];
    vu_err_clear(&e);
    CHECK(vu_canon_profile_id("A7D1BB99-538C-4DB4-B357-0123456789AB", id, sizeof id, &e) &&
          strcmp(id, "a7d1bb99-538c-4db4-b357-0123456789ab") == 0, "UUID lowercased");
    vu_err_clear(&e);
    CHECK(vu_canon_profile_id("a7d1bb99538c4db4b3570123456789ab", id, sizeof id, &e) &&
          strcmp(id, "a7d1bb99-538c-4db4-b357-0123456789ab") == 0, "32 hex becomes a UUID");
    vu_err_clear(&e);
    CHECK(!vu_canon_profile_id("../../etc/passwd", id, sizeof id, &e), "path traversal refused");
    vu_err_clear(&e);
    CHECK(!vu_canon_profile_id("Frankfurt VPN", id, sizeof id, &e), "a profile NAME is not an id");
    vu_err_clear(&e);
    CHECK(!vu_canon_profile_id("a7d1bb99-538c-4db4-b357-0123456789a", id, sizeof id, &e),
          "short UUID refused");

    /* Proxy: the shipped <proxy> field must keep working, but narrowly. */
    char px[VU_PROXY_MAX];
    vu_err_clear(&e);
    CHECK(vu_canon_proxy("socks5://127.0.0.1:1080", px, sizeof px, &e) &&
          strcmp(px, "socks5://127.0.0.1:1080") == 0, "socks5 proxy: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_canon_proxy("http://Proxy.Example.COM:3128", px, sizeof px, &e) &&
          strcmp(px, "http://proxy.example.com:3128") == 0, "http proxy canonicalised");
    CHECK(proxy_rejected("https://proxy.example.com:3128"), "https proxy not in v1 (see 17.5)");
    CHECK(proxy_rejected("http://user:pw@proxy.example.com:3128"), "proxy credentials refused");
    CHECK(proxy_rejected("http://proxy.example.com"), "proxy without a port refused");
    CHECK(proxy_rejected("http://proxy.example.com:3128/path"), "proxy path refused");
    CHECK(proxy_rejected("http://proxy.example.com:3128?q=1"), "proxy query refused");
    CHECK(proxy_rejected("socks4://proxy.example.com:1080"), "socks4 refused");

    vu_err_clear(&e);
    CHECK(vu_valid_useragent("AnyConnect Windows 4.10.06079", &e), "useragent accepted");
    vu_err_clear(&e);
    CHECK(!vu_valid_useragent("", &e), "empty useragent refused");
    vu_err_clear(&e);
    CHECK(!vu_valid_useragent("bad\nheader", &e), "newline in useragent refused");

    /* resolve: syntax here, binding in the policy test. */
    vu_resolve r;
    vu_err_clear(&e);
    CHECK(vu_canon_resolve("VPN.example.com:10.0.0.1", &r, &e) &&
          strcmp(r.host, "vpn.example.com") == 0 && strcmp(r.ip, "10.0.0.1") == 0,
          "resolve split and canonicalised: %s", e.msg);
    vu_err_clear(&e);
    CHECK(!vu_canon_resolve("vpn.example.com:notanip", &r, &e), "non-numeric resolve address refused");
    vu_err_clear(&e);
    CHECK(!vu_canon_resolve("vpn.example.com", &r, &e), "resolve without an address refused");
    vu_err_clear(&e);
    CHECK(!vu_canon_resolve("vpn.example.com:", &r, &e), "resolve with empty address refused");
}

/* ----------------------------------------------------------------- tunables */

static void test_tunables(void)
{
    CHECK(tun_is("no-dtls", "--no-dtls"), "bare boolean tunable");
    CHECK(tun_is("no-dtls=true", "--no-dtls"), "boolean with true");
    CHECK(tun_is("mtu=1400", "--mtu=1400"), "integer tunable");
    CHECK(tun_is("force-dpd=30", "--force-dpd=30"), "force-dpd is the real flag name");

    CHECK(tun_rejected("dpd=30"), "--dpd does not exist upstream");
    CHECK(tun_rejected("script=/tmp/evil"), "script is not a tunable");
    CHECK(tun_rejected("csd-wrapper=/tmp/evil"), "csd-wrapper is not a tunable");
    CHECK(tun_rejected("mtu=0"), "mtu below range");
    CHECK(tun_rejected("mtu=99999"), "mtu above range");
    CHECK(tun_rejected("mtu=1400x"), "trailing garbage in integer");
    CHECK(tun_rejected("mtu=-1"), "negative integer");
    CHECK(tun_rejected("mtu=01400"), "non-canonical integer spelling");
    CHECK(tun_rejected("mtu"), "integer tunable without a value");
    CHECK(tun_rejected("no-dtls=false"), "boolean=false is a typo, not a disable");
    CHECK(tun_rejected(""), "empty tunable");
}

/* ------------------------------------------------------- phase-one parsing */

static void test_auth_parse(void)
{
    static const char good[] =
        "COOKIE='3311180634@13561856@1339425499@B315A0E29D16C6FD92EE'\n"
        "HOST='10.0.0.1'\n"
        "CONNECT_URL='https://vpnserver.example.com'\n"
        "FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'\n"
        "RESOLVE='vpnserver.example.com:10.0.0.1'\n";

    vu_auth a; vu_err e; vu_err_clear(&e);
    CHECK(vu_parse_auth(good, &a, &e), "upstream's documented output parses: %s", e.msg);
    CHECK(a.have_cookie && a.have_connect_url && a.have_fingerprint, "all keys captured");
    CHECK(strcmp(a.fingerprint, "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42") == 0,
          "fingerprint canonicalised during parse, got '%s'", a.fingerprint);
    vu_err_clear(&e);
    CHECK(vu_auth_require_helper_contract(&a, &e), "contract satisfied: %s", e.msg);

    /* Shell injection attempts: none of these may be interpreted, and none may
     * be quietly accepted either. */
    CHECK(auth_rejected("COOKIE='abc'; rm -rf /\n"), "trailing shell after a value");
    CHECK(auth_rejected("COOKIE='abc' && id\n"), "trailing && after a value");
    CHECK(auth_rejected("COOKIE=$(id)\n"), "command substitution as the value");
    CHECK(auth_rejected("COOKIE=`id`\n"), "backtick substitution as the value");
    CHECK(auth_rejected("COOKIE=abc\n"), "unquoted value refused");
    CHECK(auth_rejected("COOKIE='abc\n"), "unterminated quote refused");
    CHECK(auth_rejected("COOKIE='ab'c'\n"), "embedded quote refused");
    CHECK(auth_rejected("EVIL='x'\nCOOKIE='abc'\n"), "unknown key is a hard failure, not skipped");
    CHECK(auth_rejected("COOKIE='a'\nCOOKIE='b'\n"), "duplicate key refused");
    CHECK(auth_rejected("COOKIE='a'\n\nHOST='h'\n"), "blank line in the middle refused");
    CHECK(auth_rejected("no key at all\n"), "line without '=' refused");
    CHECK(auth_rejected(""), "empty output refused");

    /* A literal backslash-n inside the value is data, not an escape. It must be
     * preserved verbatim, since we are explicitly not processing escapes. */
    {
        vu_auth b; vu_err e2; vu_err_clear(&e2);
        CHECK(vu_parse_auth("COOKIE='a\\nb'\n", &b, &e2), "backslash-n is literal: %s", e2.msg);
        CHECK(strcmp(b.cookie, "a\\nb") == 0, "backslash preserved, got '%s'", b.cookie);
    }

    /* The legacy contract: HOST but no CONNECT_URL must refuse in helper mode. */
    {
        static const char legacy[] =
            "COOKIE='abc'\n"
            "HOST='10.0.0.1'\n"
            "FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'\n";
        vu_auth l; vu_err e3; vu_err_clear(&e3);
        CHECK(vu_parse_auth(legacy, &l, &e3), "legacy output parses: %s", e3.msg);
        vu_err_clear(&e3);
        CHECK(!vu_auth_require_helper_contract(&l, &e3), "legacy HOST-only refused for helper mode");
        CHECK(strstr(e3.msg, "too old") != NULL, "refusal names the cause: '%s'", e3.msg);
    }

    /* No cookie means authentication failed, whatever else was printed. */
    {
        vu_auth n; vu_err e4; vu_err_clear(&e4);
        CHECK(vu_parse_auth("CONNECT_URL='https://vpn.example.com'\n", &n, &e4), "parses");
        vu_err_clear(&e4);
        CHECK(!vu_auth_require_helper_contract(&n, &e4), "missing COOKIE refused");
    }

    /* An over-long cookie must fail loudly rather than be truncated. */
    {
        char big[VU_COOKIE_MAX + 200];
        int k = snprintf(big, sizeof big, "COOKIE='");
        memset(big + k, 'A', VU_COOKIE_MAX + 50);
        snprintf(big + k + VU_COOKIE_MAX + 50, 4, "'\n");
        CHECK(auth_rejected(big), "over-long cookie refused, not truncated");
    }
}

/* ------------------------------------------------------------ Model B policy */

static void fill_ok(vu_request *req, vu_approval *appr)
{
    vu_err e; vu_err_clear(&e);
    memset(req, 0, sizeof *req);
    memset(appr, 0, sizeof *appr);

    vu_canon_profile_id("a7d1bb99538c4db4b3570123456789ab", req->profile_id, sizeof req->profile_id, &e);
    snprintf(req->protocol, sizeof req->protocol, "anyconnect");
    vu_parse_url("https://vpn.example.com/portal?session=xyz", &req->url, &e);
    vu_canon_fingerprint("469bb424ec8835944d30bc77c77e8fc1d8e23a42",
                         req->fingerprint, sizeof req->fingerprint, &e);

    memcpy(appr->profile_id, req->profile_id, sizeof appr->profile_id);
    memcpy(appr->protocol, req->protocol, sizeof appr->protocol);
    snprintf(appr->origin, sizeof appr->origin, "https://vpn.example.com:443");
    memcpy(appr->fingerprint, req->fingerprint, sizeof appr->fingerprint);
    appr->proxy[0] = '\0';
}

static void test_policy(void)
{
    vu_request req; vu_approval appr; vu_err e;

    fill_ok(&req, &appr);
    vu_err_clear(&e);
    CHECK(vu_policy_check(&req, &appr, &e), "approved request passes: %s", e.msg);

    /* Path and query are session data: they must NOT affect authorisation. */
    fill_ok(&req, &appr);
    vu_err_clear(&e);
    vu_parse_url("https://vpn.example.com/a/totally/different/path?s=2", &req.url, &e);
    vu_err_clear(&e);
    CHECK(vu_policy_check(&req, &appr, &e), "differing path/query still authorised: %s", e.msg);

    /* Everything else must not. */
    fill_ok(&req, &appr);
    vu_err_clear(&e);
    vu_parse_url("https://other.example.com/portal", &req.url, &e);
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "different host refused");

    fill_ok(&req, &appr);
    vu_err_clear(&e);
    vu_parse_url("https://vpn.example.com:8443/portal", &req.url, &e);
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "different port refused");

    fill_ok(&req, &appr);
    snprintf(req.protocol, sizeof req.protocol, "gp");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "protocol substitution refused");

    fill_ok(&req, &appr);
    vu_err_clear(&e);
    vu_canon_fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                         req.fingerprint, sizeof req.fingerprint, &e);
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "fingerprint mismatch refused");
    CHECK(strstr(e.msg, "re-approve") != NULL, "mismatch tells the user to re-approve: '%s'", e.msg);

    fill_ok(&req, &appr);
    snprintf(req.proxy, sizeof req.proxy, "socks5://127.0.0.1:1080");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "proxy added to a NONE approval refused");

    fill_ok(&req, &appr);
    snprintf(appr.proxy, sizeof appr.proxy, "socks5://127.0.0.1:1080");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "proxy dropped from a proxy approval refused");

    fill_ok(&req, &appr);
    vu_err_clear(&e);
    vu_canon_profile_id("ffffffffffffffffffffffffffffffff", req.profile_id, sizeof req.profile_id, &e);
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e), "unapproved profile-id refused");

    /* --resolve binding: well-formed but naming the wrong host. */
    fill_ok(&req, &appr);
    req.has_resolve = true;
    vu_err_clear(&e);
    CHECK(vu_canon_resolve("vpn.example.com:10.0.0.1", &req.resolve, &e), "resolve parses");
    vu_err_clear(&e);
    CHECK(vu_policy_check(&req, &appr, &e), "resolve for the approved host passes: %s", e.msg);

    vu_err_clear(&e);
    CHECK(vu_canon_resolve("attacker.example.com:10.0.0.1", &req.resolve, &e), "resolve parses");
    vu_err_clear(&e);
    CHECK(!vu_policy_check(&req, &appr, &e),
          "well-formed --resolve naming an unrelated host refused");

    /* The address itself may change between authentications. */
    vu_err_clear(&e);
    CHECK(vu_canon_resolve("vpn.example.com:203.0.113.9", &req.resolve, &e), "resolve parses");
    vu_err_clear(&e);
    CHECK(vu_policy_check(&req, &appr, &e), "changed IP for the approved host passes: %s", e.msg);
}

/* --------------------------------------------------------------------- main */

int main(void)
{
    test_hosts();
    test_urls();
    test_fingerprints();
    test_closed_fields();
    test_tunables();
    test_auth_parse();
    test_policy();

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
