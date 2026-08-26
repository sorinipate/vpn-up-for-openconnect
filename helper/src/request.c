/*
 * request.c — the closed argv schema for `vpn-up-helper connect` (§8).
 *
 * Extracted from helper_main.c during step 9 (adversarial tests) for one
 * reason: main() refuses to run as anything but root before it ever looks at
 * argv, so while the parser lived inside that file it could not be attacked
 * from an unprivileged test at all. The only reachable schema test was "does
 * the binary refuse to run without sudo", which tests the guard rather than the
 * grammar.
 *
 * That is backwards for the one function whose whole job is to decide what root
 * is allowed to be asked for. It is also a pure function — no I/O, no
 * privilege, no globals — so there was never a reason for it to sit behind the
 * root check. Now the corpus feeds it hostile argv directly, and the code under
 * test is byte-for-byte the code that runs as root.
 */

#include "vu.h"

#include <string.h>

/*
 * Fetch the value after a flag.
 *
 * A value that looks like a flag is refused. Note the asymmetry with §9, which
 * deliberately dropped the universal "no value may begin with '-'" rule: that
 * rule was wrong for GENERATED argv, where every element is --flag=value and a
 * dash inside a value cannot become another option. Here we are scanning OUR
 * OWN argv, where `--useragent --quiet` really is a forgotten argument, and
 * silently consuming the next flag as a value is how a caller ends up with a
 * request that does not mean what it says.
 *
 * The cost is that a User-Agent beginning with '-' cannot be expressed in
 * helper mode. Prompt mode still accepts it.
 */
static const char *next_value(int argc, char **argv, int *i, const char *flag, vu_err *e)
{
    if (*i + 1 >= argc) {
        vu_err_set(e, "%s needs a value", flag);
        return NULL;
    }
    const char *v = argv[++(*i)];
    if (v[0] == '-') {
        vu_err_set(e, "%s was given '%s', which looks like a flag", flag, v);
        return NULL;
    }
    return v;
}

/* Refuse a flag given twice rather than letting the last one win.
 *
 * Last-wins is how a request comes to differ from what an operator reading the
 * command line would predict, and the whole point of a closed schema is that
 * the two cannot diverge. It matters most for --profile-id and --connect-url,
 * where two spellings in one command line are the shape an injection attempt
 * takes when it can append but not rewrite. */
static bool once(const char **slot, const char *flag, vu_err *e)
{
    if (*slot) { vu_err_set(e, "%s was given more than once", flag); return false; }
    return true;
}

bool vu_request_from_argv(int argc, char **argv, vu_request *req, vu_err *e)
{
    if (!req || (argc > 0 && !argv)) { vu_err_set(e, "request: null argument"); return false; }
    memset(req, 0, sizeof *req);

    const char *raw_id = NULL, *raw_proto = NULL, *raw_url = NULL;
    const char *raw_resolve = NULL, *raw_proxy = NULL, *raw_ua = NULL;
    const char *raw_tunables[VU_TUNABLE_MAX];
    size_t n_tun = 0;
    bool seen_quiet = false;

    for (int i = 0; i < argc; ++i) {
        const char *a = argv[i];
        if (strcmp(a, "--profile-id") == 0) {
            if (!once(&raw_id, a, e)) return false;
            if (!(raw_id = next_value(argc, argv, &i, a, e))) return false;
        } else if (strcmp(a, "--protocol") == 0) {
            if (!once(&raw_proto, a, e)) return false;
            if (!(raw_proto = next_value(argc, argv, &i, a, e))) return false;
        } else if (strcmp(a, "--connect-url") == 0) {
            if (!once(&raw_url, a, e)) return false;
            if (!(raw_url = next_value(argc, argv, &i, a, e))) return false;
        } else if (strcmp(a, "--resolve") == 0) {
            if (!once(&raw_resolve, a, e)) return false;
            if (!(raw_resolve = next_value(argc, argv, &i, a, e))) return false;
        } else if (strcmp(a, "--proxy") == 0) {
            if (!once(&raw_proxy, a, e)) return false;
            if (!(raw_proxy = next_value(argc, argv, &i, a, e))) return false;
        } else if (strcmp(a, "--useragent") == 0) {
            if (!once(&raw_ua, a, e)) return false;
            if (!(raw_ua = next_value(argc, argv, &i, a, e))) return false;
        } else if (strcmp(a, "--quiet") == 0) {
            if (seen_quiet) { vu_err_set(e, "--quiet was given more than once"); return false; }
            seen_quiet = true;
            req->quiet = true;
        } else if (strcmp(a, "--tunable") == 0) {
            const char *v = next_value(argc, argv, &i, a, e);
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

    /*
     * Tunables are rendered to the flag OpenConnect will receive, and the same
     * knob may not be named twice. Two --mtu values on one command line reach
     * OpenConnect as "--mtu=1400 --mtu=1500", where the effective value is
     * whichever one it happens to prefer — a request whose meaning cannot be
     * read off the request. Both spellings are individually valid, so nothing
     * else in the pipeline would have objected.
     */
    for (size_t i = 0; i < n_tun; ++i) {
        if (!vu_render_tunable(raw_tunables[i], req->tunables[i], VU_TUNABLE_LEN, e))
            return false;
        /* Compare the RENDERED flag, so "no-dtls" and "no-dtls=true" — two
         * spellings of one knob — collide as they should. */
        const char *eq = strchr(req->tunables[i], '=');
        size_t len = eq ? (size_t)(eq - req->tunables[i]) : strlen(req->tunables[i]);
        for (size_t j = 0; j < i; ++j) {
            const char *pe = strchr(req->tunables[j], '=');
            size_t plen = pe ? (size_t)(pe - req->tunables[j]) : strlen(req->tunables[j]);
            if (plen == len && memcmp(req->tunables[j], req->tunables[i], len) == 0) {
                vu_err_set(e, "tunable '%.*s' was given more than once",
                           (int)len, req->tunables[i]);
                return false;
            }
        }
    }
    req->n_tunables = n_tun;
    return true;
}
