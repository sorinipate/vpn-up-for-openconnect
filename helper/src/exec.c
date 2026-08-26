/* exec.c — phase-two argv construction and the pre-execve path checks. */

#include "vu_exec.h"
#include "vu_state.h"

#include <unistd.h>

#include <stdio.h>
#include <string.h>

/*
 * Two element builders, both with literal format strings. An earlier draft
 * passed the format through a parameter, which works but puts a variable format
 * string in the one program where that is least appropriate; these are duller
 * and there is nothing to reason about.
 */
static bool push_lit(vu_argv *a, vu_err *e, const char *text)
{
    if (a->n >= VU_ARGV_MAX) { vu_err_set(e, "argv: too many arguments"); return false; }
    int n = snprintf(a->store[a->n], VU_ARGV_ITEM, "%s", text);
    if (n < 0 || (size_t)n >= VU_ARGV_ITEM) {
        vu_err_set(e, "argv: '%s' does not fit", text);
        return false;
    }
    a->argv[a->n] = a->store[a->n];
    a->n++;
    return true;
}

static bool push_kv(vu_argv *a, vu_err *e, const char *flag, const char *val)
{
    if (a->n >= VU_ARGV_MAX) { vu_err_set(e, "argv: too many arguments"); return false; }
    int n = snprintf(a->store[a->n], VU_ARGV_ITEM, "%s=%s", flag, val);
    if (n < 0 || (size_t)n >= VU_ARGV_ITEM) {
        vu_err_set(e, "argv: value for %s does not fit", flag);
        return false;
    }
    a->argv[a->n] = a->store[a->n];
    a->n++;
    return true;
}

bool vu_build_argv(const vu_request *req, const vu_approval *appr,
                   const char *openconnect_path, const char *script_path,
                   vu_argv *out, vu_err *e)
{
    if (!req || !appr || !openconnect_path || !script_path || !out) {
        vu_err_set(e, "argv: null argument");
        return false;
    }
    memset(out, 0, sizeof *out);

    /*
     * Refuse to build anything for a request that has not been authorised.
     * helper_main checks this too, deliberately: the argv builder is the last
     * thing between a request and root running OpenConnect, and there should be
     * no way to call it that skips the policy gate.
     */
    if (!vu_policy_check(req, appr, e)) return false;

    /* argv[0] is the pinned path, not a bare name: execve performs no PATH
     * search, and this keeps ps output honest about what is running. */
    if (!push_lit(out, e, openconnect_path)) return false;

    /* Unconditional, and the reasons belong next to the code:
     *   --cookie-on-stdin  the cookie never touches argv, so never appears in ps
     *   --non-inter        the helper does not read stdin, so OpenConnect must
     *                      not be able to fall back to prompting root-side if
     *                      the cookie is missing or rejected; it has to exit */
    if (!push_lit(out, e, "--cookie-on-stdin")) return false;
    if (!push_lit(out, e, "--non-inter"))       return false;

    if (!push_kv(out, e, "--protocol", req->protocol)) return false;

    /* From the REGISTRY, never the request. This is what stops a caller
     * substituting a gateway even when it controls DNS or supplies --resolve. */
    if (!push_kv(out, e, "--servercert", appr->fingerprint)) return false;

    /* Explicit, rather than trusting OpenConnect's compiled-in default, which
     * may sit in a user-writable prefix. Fixed path, no caller input, no
     * shell-significant character — OpenConnect runs it via /bin/sh -c. */
    if (!push_kv(out, e, "--script", script_path)) return false;

    /* Proxy: the approved record decides. NONE emits --no-proxy explicitly
     * rather than merely omitting --proxy, so environment-driven discovery
     * cannot quietly insert one. */
    if (appr->proxy[0]) {
        if (!push_kv(out, e, "--proxy", appr->proxy)) return false;
    } else if (!push_lit(out, e, "--no-proxy")) {
        return false;
    }

    if (req->has_resolve) {
        char hv[VU_HOST_MAX * 2 + 2];
        int n = snprintf(hv, sizeof hv, "%s:%s", req->resolve.host, req->resolve.ip);
        if (n < 0 || (size_t)n >= sizeof hv) {
            vu_err_set(e, "argv: --resolve value does not fit");
            return false;
        }
        if (!push_kv(out, e, "--resolve", hv)) return false;
    }

    if (req->useragent[0] && !push_kv(out, e, "--useragent", req->useragent)) return false;
    if (req->quiet && !push_lit(out, e, "-q")) return false;

    for (size_t i = 0; i < req->n_tunables; ++i) {
        if (!push_lit(out, e, req->tunables[i])) return false;
    }

    /*
     * The connect URL last, as a positional. Rebuilt from canonical parts
     * rather than echoed back verbatim, so what OpenConnect receives is exactly
     * what was validated and authorised: the origin is the one matched against
     * the approved record, and the path and query are forwarded unexamined
     * because they are session data and meet no shell on the way (§9).
     *
     * A side effect worth noting: a request for https://host/x becomes
     * https://host:443/x. Equivalent, and more explicit about what was pinned.
     */
    {
        char url[VU_URL_MAX];
        int n;
        if (req->url.query[0])
            n = snprintf(url, sizeof url, "%s%s?%s",
                         req->url.origin, req->url.path, req->url.query);
        else
            n = snprintf(url, sizeof url, "%s%s", req->url.origin, req->url.path);
        if (n < 0 || (size_t)n >= sizeof url) {
            vu_err_set(e, "argv: connect URL does not fit");
            return false;
        }
        if (!push_lit(out, e, url)) return false;
    }

    out->argv[out->n] = NULL;
    return true;
}

bool vu_exec_precheck(const char *openconnect_path, const char *script_path,
                      uid_t owner, uid_t caller_uid,
                      vu_closure_report *report, vu_err *e)
{
    vu_closure_spec spec;
    vu_closure_spec_default(&spec, openconnect_path, script_path, owner);

    /*
     * The probe runs only as root, because dropping privilege is the mechanism
     * (§11.5), and only when we know who the caller is - the question is whether
     * THEY can write a trusted object despite its mode bits. Without a caller
     * uid it is skipped rather than answered wrongly.
     */
    spec.probe_uid = caller_uid;
    spec.probe = (geteuid() == 0) && caller_uid != 0;

    static vu_closure_report local;
    if (!report) report = &local;
    return vu_closure_check(&spec, report, e);
}
