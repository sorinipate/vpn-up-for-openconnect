/*
 * policy.c — Model B enforcement (§7).
 *
 * Approval authorises a specific privileged capability, not merely a
 * certificate. Every field of the approved record is checked, so approving one
 * profile cannot be leveraged into switching protocol or substituting a proxy
 * later.
 *
 * This is where two-phase's one concession is paid back: the helper performs no
 * server authentication of its own, so without this check a caller could pin
 * any fingerprint it liked and reach any gateway. Here the fingerprint and the
 * endpoint come from root-owned state instead of from the request.
 */

#include "vu.h"

#include <string.h>

bool vu_policy_check(const vu_request *req, const vu_approval *appr, vu_err *e)
{
    if (!req || !appr) { vu_err_set(e, "policy: null"); return false; }

    if (strcmp(req->profile_id, appr->profile_id) != 0) {
        vu_err_set(e, "policy: profile-id does not match the approved record");
        return false;
    }
    if (strcmp(req->protocol, appr->protocol) != 0) {
        vu_err_set(e, "policy: protocol '%s' was not approved for this profile", req->protocol);
        return false;
    }

    /* Origin, not URL: the request's path and query are session data and are
     * deliberately excluded from the comparison. */
    if (strcmp(req->url.origin, appr->origin) != 0) {
        vu_err_set(e, "policy: endpoint %s was not approved (approved: %s)",
                   req->url.origin, appr->origin);
        return false;
    }

    /* The fingerprint is supplied by the registry, so a mismatch means the
     * caller tried to override it, or the record is inconsistent. Either way
     * this is re-approval territory, never a silent update. */
    if (strcmp(req->fingerprint, appr->fingerprint) != 0) {
        vu_err_set(e, "policy: server fingerprint differs from the approved record; "
                      "re-approve this profile if the gateway certificate changed");
        return false;
    }

    /* Proxy: "" means NONE, and the helper then passes --no-proxy explicitly so
     * environment-driven discovery cannot substitute one. */
    if (strcmp(req->proxy, appr->proxy) != 0) {
        if (appr->proxy[0] == '\0')
            vu_err_set(e, "policy: this profile was approved without a proxy");
        else if (req->proxy[0] == '\0')
            vu_err_set(e, "policy: this profile was approved with a proxy (%s)", appr->proxy);
        else
            vu_err_set(e, "policy: proxy %s was not approved (approved: %s)",
                       req->proxy, appr->proxy);
        return false;
    }

    /* --resolve binds semantically, not just syntactically: it tells
     * OpenConnect how to resolve a name, so a well-formed value naming an
     * unrelated host is still wrong. The address half is free to change between
     * authentications — the fingerprint carries identity. */
    if (req->has_resolve) {
        char origin_host[VU_HOST_MAX];
        if (!vu_origin_host(appr->origin, origin_host, sizeof origin_host)) {
            vu_err_set(e, "policy: approved origin is malformed");
            return false;
        }
        if (strcmp(req->resolve.host, origin_host) != 0) {
            vu_err_set(e, "policy: --resolve names %s, not the approved host %s",
                       req->resolve.host, origin_host);
            return false;
        }
    }
    return true;
}
