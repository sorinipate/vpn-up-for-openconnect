/* validate.c — primitives, host/URL, fingerprints, closed fields, tunables. */

#include "vu.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------- errors */

void vu_err_clear(vu_err *e) { if (e) e->msg[0] = '\0'; }

void vu_err_set(vu_err *e, const char *fmt, ...)
{
    if (!e || e->msg[0] != '\0') return;   /* keep the earliest failure */
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof e->msg, fmt, ap);
    va_end(ap);
}

/* Copy with an explicit capacity. Truncation is a failure, never silent: a
 * truncated host or fingerprint would compare unequal in confusing ways, or
 * worse, equal to something it is not. */
static bool copy_out(char *out, size_t cap, const char *src, size_t len)
{
    if (!out || cap == 0 || len + 1 > cap) return false;
    memcpy(out, src, len);
    out[len] = '\0';
    return true;
}

static bool copy_str(char *out, size_t cap, const char *src)
{
    return copy_out(out, cap, src, strlen(src));
}

/* --------------------------------------------------------------- primitives */

bool vu_ascii_printable(const char *s, size_t min_len, size_t max_len)
{
    if (!s) return false;
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p, ++n) {
        if (*p < 0x20 || *p > 0x7e) return false;   /* control bytes and >ASCII */
        if (n > max_len) return false;
    }
    return n >= min_len && n <= max_len;
}

/* Shared integer parse. Rejects: empty, sign, leading zero (so one value has
 * one spelling), non-digits, trailing garbage, and out-of-range. */
static bool parse_bounded(const char *s, long lo, long hi, long *out, vu_err *e,
                          const char *what)
{
    if (!s || !*s) { vu_err_set(e, "%s: empty", what); return false; }
    if (s[0] == '0' && s[1] != '\0') {
        vu_err_set(e, "%s: leading zero not canonical", what);
        return false;
    }
    for (const char *p = s; *p; ++p) {
        if (*p < '0' || *p > '9') { vu_err_set(e, "%s: not a number", what); return false; }
    }
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        vu_err_set(e, "%s: unparseable", what);
        return false;
    }
    if (v < lo || v > hi) {
        vu_err_set(e, "%s: out of range %ld..%ld", what, lo, hi);
        return false;
    }
    *out = v;
    return true;
}

bool vu_parse_u16(const char *s, uint16_t lo, uint16_t hi, uint16_t *out, vu_err *e)
{
    long v;
    if (!parse_bounded(s, lo, hi, &v, e, "number")) return false;
    if (out) *out = (uint16_t)v;
    return true;
}

bool vu_parse_i32(const char *s, int32_t lo, int32_t hi, int32_t *out, vu_err *e)
{
    long v;
    if (!parse_bounded(s, lo, hi, &v, e, "number")) return false;
    if (out) *out = (int32_t)v;
    return true;
}

/* ------------------------------------------------------------------ base64 */

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool vu_b64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!in || !out || !out_len) return false;
    size_t n = strlen(in);
    if (n == 0 || n % 4 != 0) return false;      /* padding is mandatory */

    size_t pad = 0;
    if (in[n - 1] == '=') pad++;
    if (n >= 2 && in[n - 2] == '=') pad++;
    if (pad > 2) return false;

    size_t need = n / 4 * 3 - pad;
    if (need > out_cap) return false;

    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int q[4];
        for (size_t k = 0; k < 4; ++k) {
            char c = in[i + k];
            if (c == '=') {
                /* Padding only in the final quantum, and only trailing. */
                if (i + 4 != n) return false;
                if (k < 2) return false;
                if (k == 2 && in[i + 3] != '=') return false;
                q[k] = -1;
            } else {
                q[k] = b64_val(c);
                if (q[k] < 0) return false;      /* whitespace included */
            }
        }
        uint32_t acc = (uint32_t)q[0] << 18 | (uint32_t)q[1] << 12;
        if (q[2] >= 0) acc |= (uint32_t)q[2] << 6;
        if (q[3] >= 0) acc |= (uint32_t)q[3];

        out[o++] = (uint8_t)(acc >> 16);
        if (q[2] >= 0) out[o++] = (uint8_t)(acc >> 8);
        if (q[3] >= 0) out[o++] = (uint8_t)acc;
    }
    *out_len = o;
    return o == need;
}

bool vu_b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!in || !out) return false;
    size_t need = (in_len + 2) / 3 * 4;
    if (need + 1 > out_cap) return false;

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t acc = (uint32_t)in[i] << 16;
        size_t have = 1;
        if (i + 1 < in_len) { acc |= (uint32_t)in[i + 1] << 8; have = 2; }
        if (i + 2 < in_len) { acc |= (uint32_t)in[i + 2];      have = 3; }

        out[o++] = A[(acc >> 18) & 0x3f];
        out[o++] = A[(acc >> 12) & 0x3f];
        out[o++] = have > 1 ? A[(acc >> 6) & 0x3f] : '=';
        out[o++] = have > 2 ? A[acc & 0x3f]        : '=';
    }
    out[o] = '\0';
    return true;
}

/* ---------------------------------------------------------------- host/URL */

static bool is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

/* One DNS label: 1..63 bytes of [A-Za-z0-9-], no leading or trailing '-'. */
static bool valid_label(const char *p, size_t len)
{
    if (len < 1 || len > 63) return false;
    if (p[0] == '-' || p[len - 1] == '-') return false;
    for (size_t i = 0; i < len; ++i) {
        char c = p[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
    }
    return true;
}

static bool canon_ipv4(const char *s, char *out, size_t cap)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return false;
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &a, buf, sizeof buf)) return false;
    return copy_str(out, cap, buf);
}

/* Emits the literal WITHOUT brackets; callers add them for URL authorities. */
static bool canon_ipv6(const char *s, char *out, size_t cap)
{
    struct in6_addr a;
    if (inet_pton(AF_INET6, s, &a) != 1) return false;
    char buf[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, &a, buf, sizeof buf)) return false;
    return copy_str(out, cap, buf);
}

bool vu_canon_host(const char *in, char *out, size_t out_cap, vu_host_kind *kind, vu_err *e)
{
    if (!in || !*in) { vu_err_set(e, "host: empty"); return false; }
    size_t n = strlen(in);
    if (n >= VU_HOST_MAX) { vu_err_set(e, "host: too long"); return false; }

    /* Bracketed IPv6 literal. */
    if (in[0] == '[') {
        if (in[n - 1] != ']' || n < 4) { vu_err_set(e, "host: malformed IPv6 literal"); return false; }
        char inner[VU_HOST_MAX];
        if (!copy_out(inner, sizeof inner, in + 1, n - 2)) { vu_err_set(e, "host: too long"); return false; }
        char canon[VU_HOST_MAX];
        if (!canon_ipv6(inner, canon, sizeof canon)) { vu_err_set(e, "host: invalid IPv6 address"); return false; }
        char bracketed[VU_HOST_MAX];
        if (snprintf(bracketed, sizeof bracketed, "[%s]", canon) >= (int)sizeof bracketed) {
            vu_err_set(e, "host: too long"); return false;
        }
        if (kind) *kind = VU_HOST_IPV6;
        if (!copy_str(out, out_cap, bracketed)) { vu_err_set(e, "host: output too small"); return false; }
        return true;
    }

    /* A bare colon means an unbracketed IPv6 literal, which is ambiguous with
     * host:port in an authority. Refuse rather than guess. */
    if (strchr(in, ':')) {
        vu_err_set(e, "host: IPv6 literal must be bracketed");
        return false;
    }

    /* A dotted quad is an address, not a DNS name (§7/§9). */
    if (canon_ipv4(in, out, out_cap)) {
        if (kind) *kind = VU_HOST_IPV4;
        return true;
    }

    /* DNS name: strip at most one trailing dot, then validate per label. */
    char work[VU_HOST_MAX];
    size_t wn = n;
    if (in[wn - 1] == '.') wn--;
    if (wn == 0) { vu_err_set(e, "host: empty after trailing dot"); return false; }
    if (wn > 253) { vu_err_set(e, "host: exceeds 253 octets"); return false; }
    if (!copy_out(work, sizeof work, in, wn)) { vu_err_set(e, "host: too long"); return false; }

    size_t start = 0;
    for (size_t i = 0; i <= wn; ++i) {
        if (i == wn || work[i] == '.') {
            if (!valid_label(work + start, i - start)) {
                vu_err_set(e, "host: invalid label");
                return false;
            }
            start = i + 1;
        }
    }
    /* A name whose final label is all digits is indistinguishable from a
     * malformed address (999.999.999.999 reaches here, because inet_pton
     * refused it as a quad and every label is a valid DNS label). Resolvers and
     * URL parsers disagree about such strings, and a closed schema must not
     * hand OpenConnect something we and it might read differently. */
    {
        const char *last = work;
        for (size_t i = 0; i < wn; ++i) if (work[i] == '.') last = work + i + 1;
        bool all_digits = *last != '\0';
        for (const char *q = last; *q; ++q) if (*q < '0' || *q > '9') { all_digits = false; break; }
        if (all_digits) {
            vu_err_set(e, "host: final label is numeric - not a name, not a valid address");
            return false;
        }
    }
    for (size_t i = 0; i < wn; ++i) work[i] = lower(work[i]);
    if (kind) *kind = VU_HOST_DNS;
    if (!copy_str(out, out_cap, work)) { vu_err_set(e, "host: output too small"); return false; }
    return true;
}

bool vu_origin_host(const char *origin, char *out, size_t out_cap)
{
    static const char pfx[] = "https://";
    if (!origin || strncmp(origin, pfx, sizeof pfx - 1) != 0) return false;
    const char *h = origin + sizeof pfx - 1;
    const char *colon;
    if (*h == '[') {
        const char *close = strchr(h, ']');
        if (!close) return false;
        colon = strchr(close, ':');
    } else {
        colon = strrchr(h, ':');
    }
    if (!colon) return false;
    return copy_out(out, out_cap, h, (size_t)(colon - h));
}

bool vu_parse_url(const char *in, vu_url *out, vu_err *e)
{
    if (!in || !out) { vu_err_set(e, "url: null"); return false; }
    memset(out, 0, sizeof *out);

    size_t n = strlen(in);
    if (n == 0) { vu_err_set(e, "url: empty"); return false; }
    if (n >= VU_URL_MAX) { vu_err_set(e, "url: too long"); return false; }
    /* Bytes that cannot appear in a URL at all. Stricter than
     * vu_ascii_printable, which permits space because a User-Agent legitimately
     * contains spaces: a raw space in a URL is invalid (it must be %20) and
     * risks being read differently by us and by whatever consumes it. */
    for (const unsigned char *q = (const unsigned char *)in; *q; ++q) {
        if (*q <= 0x20 || *q >= 0x7f) {
            vu_err_set(e, "url: space, control byte, or non-ASCII byte");
            return false;
        }
    }

    /* Scheme: https only. Schemes are case-insensitive, so accept and lower. */
    static const char scheme[] = "https://";
    size_t sl = sizeof scheme - 1;
    if (n <= sl) { vu_err_set(e, "url: no authority"); return false; }
    for (size_t i = 0; i < sl; ++i) {
        if (lower(in[i]) != scheme[i]) { vu_err_set(e, "url: scheme must be https"); return false; }
    }

    if (strchr(in, '#')) { vu_err_set(e, "url: fragment not permitted"); return false; }

    const char *auth = in + sl;
    size_t alen = strcspn(auth, "/?");
    if (alen == 0) { vu_err_set(e, "url: empty authority"); return false; }

    char authority[VU_HOST_MAX + 8];
    if (!copy_out(authority, sizeof authority, auth, alen)) {
        vu_err_set(e, "url: authority too long");
        return false;
    }
    if (strchr(authority, '@')) { vu_err_set(e, "url: userinfo not permitted"); return false; }

    /* Split host from an optional port, minding a bracketed IPv6 literal. */
    char hostpart[VU_HOST_MAX];
    const char *portpart = NULL;
    if (authority[0] == '[') {
        char *close = strchr(authority, ']');
        if (!close) { vu_err_set(e, "url: malformed IPv6 authority"); return false; }
        size_t hl = (size_t)(close - authority) + 1;
        if (!copy_out(hostpart, sizeof hostpart, authority, hl)) {
            vu_err_set(e, "url: host too long"); return false;
        }
        if (close[1] == ':')      portpart = close + 2;
        else if (close[1] != '\0'){ vu_err_set(e, "url: junk after IPv6 authority"); return false; }
    } else {
        char *colon = strrchr(authority, ':');
        if (colon) {
            if (!copy_out(hostpart, sizeof hostpart, authority, (size_t)(colon - authority))) {
                vu_err_set(e, "url: host too long"); return false;
            }
            portpart = colon + 1;
        } else if (!copy_str(hostpart, sizeof hostpart, authority)) {
            vu_err_set(e, "url: host too long"); return false;
        }
    }

    if (!vu_canon_host(hostpart, out->host, sizeof out->host, &out->host_kind, e)) return false;

    if (portpart) {
        if (!vu_parse_u16(portpart, 1, 65535, &out->port, e)) {
            vu_err_set(e, "url: invalid port");
            return false;
        }
    } else {
        out->port = 443;            /* §7: absent -> 443 */
    }

    const char *rest = auth + alen;
    const char *q = strchr(rest, '?');
    if (q) {
        if (!copy_out(out->path, sizeof out->path, rest, (size_t)(q - rest))) {
            vu_err_set(e, "url: path too long"); return false;
        }
        if (!copy_str(out->query, sizeof out->query, q + 1)) {
            vu_err_set(e, "url: query too long"); return false;
        }
    } else if (!copy_str(out->path, sizeof out->path, rest)) {
        vu_err_set(e, "url: path too long");
        return false;
    }

    if (snprintf(out->origin, sizeof out->origin, "https://%s:%u",
                 out->host, (unsigned)out->port) >= (int)sizeof out->origin) {
        vu_err_set(e, "url: origin too long");
        return false;
    }
    return true;
}

/* ------------------------------------------------------------- fingerprints */

static bool all_hex_lower(const char *s, size_t len, char *out, size_t cap)
{
    if (strlen(s) != len) return false;
    char buf[VU_FPR_MAX];
    if (len + 1 > sizeof buf) return false;
    for (size_t i = 0; i < len; ++i) {
        if (!is_hex(s[i])) return false;
        buf[i] = lower(s[i]);
    }
    buf[len] = '\0';
    return copy_out(out, cap, buf, len);
}

bool vu_canon_fingerprint(const char *in, char *out, size_t out_cap, vu_err *e)
{
    if (!in || !*in) { vu_err_set(e, "fingerprint: empty"); return false; }
    if (strlen(in) >= VU_FPR_MAX) { vu_err_set(e, "fingerprint: too long"); return false; }

    char hex[VU_FPR_MAX];

    if (strncmp(in, "pin-sha256:", 11) == 0) {
        uint8_t raw[64];
        size_t rawlen = 0;
        if (!vu_b64_decode(in + 11, raw, sizeof raw, &rawlen)) {
            vu_err_set(e, "fingerprint: pin-sha256 is not strict base64");
            return false;
        }
        if (rawlen != 32) {
            vu_err_set(e, "fingerprint: pin-sha256 decodes to %zu bytes, need 32", rawlen);
            return false;
        }
        /* Re-encode so two spellings of one pin cannot differ in the registry. */
        char b64[64];
        if (!vu_b64_encode(raw, rawlen, b64, sizeof b64)) {
            vu_err_set(e, "fingerprint: re-encode failed"); return false;
        }
        char full[VU_FPR_MAX];
        if (snprintf(full, sizeof full, "pin-sha256:%s", b64) >= (int)sizeof full) {
            vu_err_set(e, "fingerprint: too long"); return false;
        }
        if (!copy_str(out, out_cap, full)) { vu_err_set(e, "fingerprint: output too small"); return false; }
        return true;
    }

    const char *body = in;
    size_t want = 0;
    const char *label = NULL;

    if (strncmp(in, "sha1:", 5) == 0)        { body = in + 5;  want = 40; label = "sha1"; }
    else if (strncmp(in, "sha256:", 7) == 0) { body = in + 7;  want = 64; label = "sha256"; }
    else if (strchr(in, ':'))                { vu_err_set(e, "fingerprint: unknown prefix"); return false; }
    else {
        /* Bare hex, as `openconnect --authenticate` emits. Length picks the
         * algorithm; nothing else is accepted. */
        size_t n = strlen(in);
        if (n == 40)      { want = 40; label = "sha1"; }
        else if (n == 64) { want = 64; label = "sha256"; }
        else {
            vu_err_set(e, "fingerprint: bare digest must be 40 or 64 hex, got %zu", n);
            return false;
        }
    }

    if (!all_hex_lower(body, want, hex, sizeof hex)) {
        vu_err_set(e, "fingerprint: %s needs exactly %zu hex characters", label, want);
        return false;
    }
    char full[VU_FPR_MAX];
    if (snprintf(full, sizeof full, "%s:%s", label, hex) >= (int)sizeof full) {
        vu_err_set(e, "fingerprint: too long"); return false;
    }
    if (!copy_str(out, out_cap, full)) { vu_err_set(e, "fingerprint: output too small"); return false; }
    return true;
}

/* ------------------------------------------------------------ closed fields */

bool vu_canon_profile_id(const char *in, char *out, size_t out_cap, vu_err *e)
{
    if (!in) { vu_err_set(e, "profile-id: null"); return false; }
    char hex[33];
    size_t h = 0;
    size_t n = strlen(in);

    if (n == 36) {
        static const int dash[] = { 8, 13, 18, 23 };
        for (size_t i = 0; i < n; ++i) {
            bool want_dash = false;
            for (size_t d = 0; d < sizeof dash / sizeof *dash; ++d)
                if ((int)i == dash[d]) want_dash = true;
            if (want_dash) {
                if (in[i] != '-') { vu_err_set(e, "profile-id: malformed UUID"); return false; }
            } else {
                if (!is_hex(in[i]) || h >= 32) { vu_err_set(e, "profile-id: malformed UUID"); return false; }
                hex[h++] = lower(in[i]);
            }
        }
    } else if (n == 32) {
        for (size_t i = 0; i < n; ++i) {
            if (!is_hex(in[i])) { vu_err_set(e, "profile-id: not 32 hex characters"); return false; }
            hex[h++] = lower(in[i]);
        }
    } else {
        vu_err_set(e, "profile-id: must be a UUID or 32 hex characters");
        return false;
    }
    if (h != 32) { vu_err_set(e, "profile-id: malformed"); return false; }
    hex[32] = '\0';

    char full[VU_UUID_MAX];
    if (snprintf(full, sizeof full, "%.8s-%.4s-%.4s-%.4s-%.12s",
                 hex, hex + 8, hex + 12, hex + 16, hex + 20) >= (int)sizeof full) {
        vu_err_set(e, "profile-id: too long"); return false;
    }
    if (!copy_str(out, out_cap, full)) { vu_err_set(e, "profile-id: output too small"); return false; }
    return true;
}

bool vu_valid_protocol(const char *in, vu_err *e)
{
    static const char *ok[] = { "anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array" };
    if (!in) { vu_err_set(e, "protocol: null"); return false; }
    for (size_t i = 0; i < sizeof ok / sizeof *ok; ++i)
        if (strcmp(in, ok[i]) == 0) return true;
    vu_err_set(e, "protocol: not in the permitted set");
    return false;
}

bool vu_canon_proxy(const char *in, char *out, size_t out_cap, vu_err *e)
{
    if (!in || !*in) { vu_err_set(e, "proxy: empty"); return false; }
    if (!vu_ascii_printable(in, 1, VU_PROXY_MAX - 1)) {
        vu_err_set(e, "proxy: non-printable or non-ASCII byte"); return false;
    }

    const char *rest = NULL;
    const char *scheme = NULL;
    if      (strncmp(in, "http://",   7) == 0) { scheme = "http";   rest = in + 7; }
    else if (strncmp(in, "socks5://", 9) == 0) { scheme = "socks5"; rest = in + 9; }
    else {
        /* https:// is deliberately absent until an integration test proves the
         * installed OpenConnect handles it as intended (§17.5). */
        vu_err_set(e, "proxy: scheme must be http:// or socks5://");
        return false;
    }

    if (strchr(rest, '@')) { vu_err_set(e, "proxy: credentials not permitted"); return false; }
    if (strpbrk(rest, "/?#")) { vu_err_set(e, "proxy: path, query and fragment not permitted"); return false; }

    char hostpart[VU_HOST_MAX];
    const char *portpart;
    if (rest[0] == '[') {
        const char *close = strchr(rest, ']');
        if (!close || close[1] != ':') { vu_err_set(e, "proxy: need [IPv6]:port"); return false; }
        if (!copy_out(hostpart, sizeof hostpart, rest, (size_t)(close - rest) + 1)) {
            vu_err_set(e, "proxy: host too long"); return false;
        }
        portpart = close + 2;
    } else {
        const char *colon = strrchr(rest, ':');
        if (!colon) { vu_err_set(e, "proxy: an explicit port is required"); return false; }
        if (!copy_out(hostpart, sizeof hostpart, rest, (size_t)(colon - rest))) {
            vu_err_set(e, "proxy: host too long"); return false;
        }
        portpart = colon + 1;
    }

    char host[VU_HOST_MAX];
    if (!vu_canon_host(hostpart, host, sizeof host, NULL, e)) return false;
    uint16_t port;
    if (!vu_parse_u16(portpart, 1, 65535, &port, e)) { vu_err_set(e, "proxy: invalid port"); return false; }

    char full[VU_PROXY_MAX];
    if (snprintf(full, sizeof full, "%s://%s:%u", scheme, host, (unsigned)port) >= (int)sizeof full) {
        vu_err_set(e, "proxy: too long"); return false;
    }
    if (!copy_str(out, out_cap, full)) { vu_err_set(e, "proxy: output too small"); return false; }
    return true;
}

bool vu_valid_useragent(const char *in, vu_err *e)
{
    if (!vu_ascii_printable(in, 1, VU_UA_MAX - 1)) {
        vu_err_set(e, "useragent: must be 1..%d printable ASCII bytes", VU_UA_MAX - 1);
        return false;
    }
    return true;
}

bool vu_canon_resolve(const char *in, vu_resolve *out, vu_err *e)
{
    if (!in || !out) { vu_err_set(e, "resolve: null"); return false; }
    memset(out, 0, sizeof *out);

    /* HOST:IP. The IP may be v6, so split on the FIRST colon that separates a
     * complete host — brackets disambiguate as elsewhere. */
    const char *sep;
    if (in[0] == '[') {
        const char *close = strchr(in, ']');
        if (!close || close[1] != ':') { vu_err_set(e, "resolve: need [IPv6]:address"); return false; }
        sep = close + 1;
    } else {
        sep = strchr(in, ':');
    }
    if (!sep) { vu_err_set(e, "resolve: expected HOST:IP"); return false; }

    char hostpart[VU_HOST_MAX];
    if (!copy_out(hostpart, sizeof hostpart, in, (size_t)(sep - in))) {
        vu_err_set(e, "resolve: host too long"); return false;
    }
    if (!vu_canon_host(hostpart, out->host, sizeof out->host, NULL, e)) return false;

    const char *ip = sep + 1;
    if (!*ip) { vu_err_set(e, "resolve: empty address"); return false; }
    /* The address half must be numeric — that is the entire point of --resolve. */
    if (canon_ipv4(ip, out->ip, sizeof out->ip)) return true;
    if (ip[0] == '[') {
        size_t iplen = strlen(ip);
        if (ip[iplen - 1] == ']') {
            char inner[VU_HOST_MAX];
            if (copy_out(inner, sizeof inner, ip + 1, iplen - 2) &&
                canon_ipv6(inner, out->ip, sizeof out->ip)) return true;
        }
    } else if (canon_ipv6(ip, out->ip, sizeof out->ip)) {
        return true;
    }
    vu_err_set(e, "resolve: address is not a numeric IPv4 or IPv6 literal");
    return false;
}

/* --------------------------------------------------------------- tunables */

static const vu_tunable TUNABLES[] = {
    { "no-dtls",            VU_TUN_BOOL, 0,   0,    "--no-dtls" },
    { "no-http-keepalive",  VU_TUN_BOOL, 0,   0,    "--no-http-keepalive" },
    { "disable-ipv6",       VU_TUN_BOOL, 0,   0,    "--disable-ipv6" },
    { "mtu",                VU_TUN_INT,  576, 9000, "--mtu" },
    { "base-mtu",           VU_TUN_INT,  576, 9000, "--base-mtu" },
    { "reconnect-timeout",  VU_TUN_INT,  1,   3600, "--reconnect-timeout" },
    { "force-dpd",          VU_TUN_INT,  0,   3600, "--force-dpd" },
};

const vu_tunable *vu_tunable_lookup(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof TUNABLES / sizeof *TUNABLES; ++i)
        if (strcmp(name, TUNABLES[i].name) == 0) return &TUNABLES[i];
    return NULL;
}

bool vu_render_tunable(const char *kv, char *out, size_t out_cap, vu_err *e)
{
    if (!kv || !*kv) { vu_err_set(e, "tunable: empty"); return false; }

    char name[64];
    const char *eq = strchr(kv, '=');
    const char *val = NULL;
    if (eq) {
        if (!copy_out(name, sizeof name, kv, (size_t)(eq - kv))) {
            vu_err_set(e, "tunable: name too long"); return false;
        }
        val = eq + 1;
    } else if (!copy_str(name, sizeof name, kv)) {
        vu_err_set(e, "tunable: name too long"); return false;
    }

    const vu_tunable *t = vu_tunable_lookup(name);
    if (!t) { vu_err_set(e, "tunable: '%s' is not in the permitted table", name); return false; }

    if (t->kind == VU_TUN_BOOL) {
        /* A boolean carries no value: "name", "name=true", "name=1". Anything
         * else is a typo we refuse rather than guess at. */
        if (val && strcmp(val, "true") != 0 && strcmp(val, "1") != 0) {
            vu_err_set(e, "tunable: '%s' is a boolean", name);
            return false;
        }
        if (!copy_str(out, out_cap, t->flag)) { vu_err_set(e, "tunable: output too small"); return false; }
        return true;
    }

    if (!val || !*val) { vu_err_set(e, "tunable: '%s' needs a value", name); return false; }
    int32_t v;
    if (!vu_parse_i32(val, t->lo, t->hi, &v, e)) {
        vu_err_set(e, "tunable: '%s' must be an integer in %d..%d", name, t->lo, t->hi);
        return false;
    }
    char full[96];
    if (snprintf(full, sizeof full, "%s=%d", t->flag, v) >= (int)sizeof full) {
        vu_err_set(e, "tunable: too long"); return false;
    }
    if (!copy_str(out, out_cap, full)) { vu_err_set(e, "tunable: output too small"); return false; }
    return true;
}
