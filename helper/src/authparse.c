/*
 * authparse.c — decoder for `openconnect --authenticate` output (§4).
 *
 * Upstream emits this so it can be eval'd:
 *
 *     COOKIE='3311180634@13561856@...'
 *     HOST='10.0.0.1'
 *     CONNECT_URL='https://vpnserver.example.com'
 *     FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'
 *     RESOLVE='vpnserver.example.com:10.0.0.1'
 *
 * We do not eval it, and — the distinction that matters — we do not parse
 * shell either. We parse the small fixed language above: five known keys,
 * single-quoted, with NO escape processing. A backslash, `$` or backtick inside
 * a value is a literal byte here, exactly as it would be inside single quotes,
 * and nothing in this file can be talked into executing anything.
 *
 * This runs UNPRIVILEGED, in vpn-up, on the stdout of a network-facing program.
 * It is treated as hostile input regardless.
 */

#include "vu.h"

#include <string.h>

typedef struct {
    const char *key;
    char       *dst;
    size_t      cap;
    bool       *seen;
} slot;

/* Copy a value, refusing truncation: a silently shortened cookie or URL would
 * fail later in a way nobody could diagnose. */
static bool put(slot *s, const char *val, size_t len, vu_err *e)
{
    if (*s->seen) {
        vu_err_set(e, "auth output: duplicate key %s", s->key);
        return false;
    }
    if (len + 1 > s->cap) {
        vu_err_set(e, "auth output: %s exceeds %zu bytes", s->key, s->cap - 1);
        return false;
    }
    memcpy(s->dst, val, len);
    s->dst[len] = '\0';
    *s->seen = true;
    return true;
}

bool vu_parse_auth(const char *text, vu_auth *out, vu_err *e)
{
    if (!text || !out) { vu_err_set(e, "auth output: null"); return false; }
    memset(out, 0, sizeof *out);

    slot slots[] = {
        { "COOKIE",      out->cookie,      sizeof out->cookie,      &out->have_cookie      },
        { "HOST",        out->host,        sizeof out->host,        &out->have_host        },
        { "CONNECT_URL", out->connect_url, sizeof out->connect_url, &out->have_connect_url },
        { "FINGERPRINT", out->fingerprint, sizeof out->fingerprint, &out->have_fingerprint },
        { "RESOLVE",     out->resolve,     sizeof out->resolve,     &out->have_resolve     },
    };
    const size_t nslots = sizeof slots / sizeof *slots;

    const char *p = text;
    size_t lineno = 0;

    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        lineno++;

        /* A trailing newline at end of output is normal; a blank line anywhere
         * is not something OpenConnect emits, so it is a hard failure rather
         * than something to skip past (§4: nothing is skipped). */
        if (len == 0) {
            if (nl && *(nl + 1) == '\0') break;
            vu_err_set(e, "auth output: blank line %zu", lineno);
            return false;
        }

        const char *eq = memchr(p, '=', len);
        if (!eq) {
            vu_err_set(e, "auth output: line %zu is not KEY='VALUE'", lineno);
            return false;
        }
        size_t klen = (size_t)(eq - p);

        slot *found = NULL;
        for (size_t i = 0; i < nslots; ++i) {
            if (strlen(slots[i].key) == klen && memcmp(p, slots[i].key, klen) == 0) {
                found = &slots[i];
                break;
            }
        }
        if (!found) {
            /* Unknown keys are refused, not ignored: a future OpenConnect
             * emitting something we do not understand must be a visible
             * failure, not a silently dropped field. */
            vu_err_set(e, "auth output: unrecognised key on line %zu", lineno);
            return false;
        }

        /* Value must be wrapped in single quotes and end the line exactly. */
        const char *v = eq + 1;
        size_t vroom = len - klen - 1;
        if (vroom < 2 || v[0] != '\'' || v[vroom - 1] != '\'') {
            vu_err_set(e, "auth output: %s is not single-quoted", found->key);
            return false;
        }
        const char *val = v + 1;
        size_t vlen = vroom - 2;

        /* A single-quoted shell string cannot contain a quote, so one here
         * means the line is not what it claims to be. */
        if (memchr(val, '\'', vlen)) {
            vu_err_set(e, "auth output: %s contains a quote", found->key);
            return false;
        }
        for (size_t i = 0; i < vlen; ++i) {
            unsigned char c = (unsigned char)val[i];
            if (c < 0x20 || c == 0x7f) {
                vu_err_set(e, "auth output: %s contains a control byte", found->key);
                return false;
            }
        }

        if (!put(found, val, vlen, e)) return false;

        if (!nl) break;
        p = nl + 1;
    }

    if (lineno == 0) { vu_err_set(e, "auth output: empty"); return false; }

    /* Canonicalise the fingerprint here, unprivileged, so the privileged side
     * never has to widen its schema to accept upstream's bare hex form (§4). */
    if (out->have_fingerprint) {
        char canon[VU_FPR_MAX];
        if (!vu_canon_fingerprint(out->fingerprint, canon, sizeof canon, e)) return false;
        memcpy(out->fingerprint, canon, strlen(canon) + 1);
    }
    return true;
}

bool vu_auth_require_helper_contract(const vu_auth *a, vu_err *e)
{
    if (!a) { vu_err_set(e, "auth output: null"); return false; }
    if (!a->have_cookie || a->cookie[0] == '\0') {
        vu_err_set(e, "auth output: no COOKIE — authentication did not succeed");
        return false;
    }
    if (!a->have_fingerprint) {
        vu_err_set(e, "auth output: no FINGERPRINT — cannot pin the server");
        return false;
    }
    if (!a->have_connect_url) {
        /* Upstream's compatibility idiom is ${CONNECT_URL:-$HOST}. Helper mode
         * does not adopt it: Model B binds an origin, and a numeric HOST
         * discards exactly what is being bound. Detect the output contract
         * rather than guessing a version number. */
        vu_err_set(e, "OpenConnect too old for hardened helper mode "
                      "(--authenticate produced no CONNECT_URL)");
        return false;
    }
    return true;
}
