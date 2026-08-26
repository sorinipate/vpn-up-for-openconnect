/*
 * vu.h — the VPN Up privileged-helper policy engine.
 *
 * This is the validation and parsing layer described in PRIVILEGED-HELPER-DESIGN.md
 * (revision 3, §4 §7 §8 §9). It deliberately contains NO privileged operation:
 * no execve, no setuid, no ownership walks, no file I/O beyond what a caller
 * hands it as a buffer. Per §16 the policy engine is built and broken as an
 * ordinary process first; root execution is wired around it only afterwards.
 *
 * Design rules this file follows:
 *   - Every entry point is total: any byte string in, a bool out, never a crash
 *     and never a silent truncation. Callers pass an explicit output capacity.
 *   - Validation is semantic, not shell-shaped (§9). No blanket
 *     metacharacter or leading-dash rules: values are checked against the
 *     parser that actually consumes them, using libc where libc is correct
 *     (inet_pton, strtol) rather than hand-rolled character classes.
 *   - Canonicalisation is single-valued. Two inputs that mean the same thing
 *     produce byte-identical output, so registry comparison is memcmp-simple.
 */
#ifndef VU_H
#define VU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Buffer sizes include the NUL. */
#define VU_HOST_MAX      256   /* 253 octets of DNS name, or a bracketed v6 literal */
#define VU_ORIGIN_MAX    320   /* "https://" + host + ":65535" */
#define VU_URL_MAX      2048
#define VU_FPR_MAX       128   /* "pin-sha256:" + 44 base64 chars, or "sha256:" + 64 hex */
#define VU_UUID_MAX       37
#define VU_UA_MAX        129   /* §8: 1..128 bytes */
#define VU_PROXY_MAX     320
#define VU_PROTO_MAX      16
#define VU_COOKIE_MAX   8192
#define VU_ERR_MAX       160

/* Error reporting: a short, non-secret reason. Never echoes a cookie or a
 * passphrase; callers may log it. */
typedef struct {
    char msg[VU_ERR_MAX];
} vu_err;

void vu_err_clear(vu_err *e);
/* Sets the first error only — the earliest failure is the informative one. */
void vu_err_set(vu_err *e, const char *fmt, ...);

/* ---------------------------------------------------------------- primitives */

/* Printable ASCII (0x20..0x7e), no control bytes, no NUL, length in [min,max]. */
bool vu_ascii_printable(const char *s, size_t min_len, size_t max_len);

/* strtol with an explicit range, no trailing garbage, no sign, no leading zero
 * (so a canonical value has exactly one spelling). */
bool vu_parse_u16(const char *s, uint16_t lo, uint16_t hi, uint16_t *out, vu_err *e);
bool vu_parse_i32(const char *s, int32_t lo, int32_t hi, int32_t *out, vu_err *e);

/* Base64 (standard alphabet, mandatory padding, no whitespace tolerated).
 * Strictness is the point: a lax decoder makes two spellings of one pin. */
bool vu_b64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);
bool vu_b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/* --------------------------------------------------------------- host / URL */

typedef enum { VU_HOST_DNS, VU_HOST_IPV4, VU_HOST_IPV6 } vu_host_kind;

/*
 * Canonicalise an authority host (§7):
 *   DNS  -> ASCII only, lowercased, one trailing dot stripped, per-label rules
 *   IPv4 -> inet_pton then inet_ntop
 *   IPv6 -> accepted bracketed, emitted bracketed, inet_pton then inet_ntop
 * A dotted-quad is an address, never a DNS name; non-ASCII is refused outright
 * because IDNA is explicitly out of scope for helper v1.
 */
bool vu_canon_host(const char *in, char *out, size_t out_cap, vu_host_kind *kind, vu_err *e);

typedef struct {
    char         host[VU_HOST_MAX];    /* canonical, bracketed if IPv6 */
    vu_host_kind host_kind;
    uint16_t     port;                 /* absent -> 443 */
    char         origin[VU_ORIGIN_MAX];/* "https://host:port", always explicit */
    char         path[VU_URL_MAX];     /* "" or "/..." — forwarded, never compared */
    char         query[VU_URL_MAX];    /* "" or "..." after '?' — likewise */
} vu_url;

/*
 * Parse a phase-two connect URL (§8). Requires https, forbids userinfo and any
 * fragment, and canonicalises the origin. Path and query are validated only as
 * transportable bytes: they are forwarded to OpenConnect as one argv element,
 * never interpreted by a shell, so restricting them to a URL-ish charset would
 * reject legitimate session URLs while protecting nothing (§9).
 */
bool vu_parse_url(const char *in, vu_url *out, vu_err *e);

/* ------------------------------------------------------------- fingerprints */

/*
 * Canonicalise a server fingerprint to exactly one representation (§4):
 *   40 hex  or sha1:<40>       -> "sha1:<40 lowercase hex>"
 *   64 hex  or sha256:<64>     -> "sha256:<64 lowercase hex>"
 *   pin-sha256:<base64>        -> decode, require exactly 32 bytes, re-encode
 *
 * Short values are REFUSED rather than forwarded. OpenConnect's --servercert
 * accepts a partial hash "at least 4 characters past the prefix", so a
 * truncated fingerprint pins almost nothing — accepting one would silently
 * turn certificate pinning off.
 */
bool vu_canon_fingerprint(const char *in, char *out, size_t out_cap, vu_err *e);

/* ------------------------------------------------------------ closed fields */

/* RFC 4122 UUID or 32 bare hex, canonicalised to lowercase 8-4-4-4-12. */
bool vu_canon_profile_id(const char *in, char *out, size_t out_cap, vu_err *e);

/* Closed enum; no pass-through. */
bool vu_valid_protocol(const char *in, vu_err *e);

/* http:// or socks5:// with an explicit port. No credentials, no userinfo, no
 * path, query or fragment. https:// is deliberately absent from v1 (§17.5). */
bool vu_canon_proxy(const char *in, char *out, size_t out_cap, vu_err *e);

/* HTTP header value, 1..128 printable ASCII. In the schema because upstream
 * documents servers that need it to authenticate *or connect*. */
bool vu_valid_useragent(const char *in, vu_err *e);

/* HOST:IP — both canonicalised. Binding to the approved origin is a separate
 * policy step (vu_policy_check), because syntax alone cannot tell you whether
 * the host is the right one. */
typedef struct {
    char host[VU_HOST_MAX];
    char ip[VU_HOST_MAX];
} vu_resolve;

bool vu_canon_resolve(const char *in, vu_resolve *out, vu_err *e);

/* --------------------------------------------------------------- tunables */

typedef enum { VU_TUN_BOOL, VU_TUN_INT } vu_tun_kind;

typedef struct {
    const char *name;
    vu_tun_kind kind;
    int32_t     lo, hi;      /* VU_TUN_INT only */
    const char *flag;        /* emitted OpenConnect flag */
} vu_tunable;

/* The closed table (§10). Booleans and bounded integers cannot express a
 * program to run, which is the whole reason a tunable is allowed at all. */
const vu_tunable *vu_tunable_lookup(const char *name);
/* Validates one "name=value" (or bare "name" for a boolean) against the table
 * and renders the flag OpenConnect should receive. */
bool vu_render_tunable(const char *kv, char *out, size_t out_cap, vu_err *e);

/* ------------------------------------------------ phase-one output parsing */

/*
 * Decoder for `openconnect --authenticate` output (§4).
 *
 * The format is shell-shaped — KEY='VALUE' — because upstream intends it to be
 * eval'd. We do not eval it and we do not parse shell: we parse the small
 * language actually emitted. Exactly the five known keys, single-quoted, no
 * duplicates, no escape interpretation of any kind, and anything unrecognised
 * is a hard failure rather than a skipped line.
 */
typedef struct {
    char cookie[VU_COOKIE_MAX];
    char host[VU_HOST_MAX];         /* legacy; informational only */
    char connect_url[VU_URL_MAX];
    char fingerprint[VU_FPR_MAX];   /* canonicalised on the way in */
    char resolve[VU_HOST_MAX * 2];
    bool have_cookie, have_host, have_connect_url, have_fingerprint, have_resolve;
} vu_auth;

bool vu_parse_auth(const char *text, vu_auth *out, vu_err *e);

/*
 * Helper mode requires CONNECT_URL and refuses the legacy HOST-only output
 * (§4). Model B binds an origin, and collapsing to a numeric HOST discards
 * exactly the information being bound. This detects the output contract rather
 * than guessing a minimum OpenConnect version.
 */
bool vu_auth_require_helper_contract(const vu_auth *a, vu_err *e);

/* ------------------------------------------------------- request and policy */

/* Rendered tunable flags (§10). Small on purpose: the table has seven entries
 * and a request naming the same one twice is a mistake, not a use case. */
#define VU_TUNABLE_MAX   8
#define VU_TUNABLE_LEN  96

typedef struct {
    char       profile_id[VU_UUID_MAX];
    char       protocol[VU_PROTO_MAX];
    vu_url     url;
    char       fingerprint[VU_FPR_MAX];   /* from the REGISTRY, never the caller */
    vu_resolve resolve;   bool has_resolve;
    char       proxy[VU_PROXY_MAX];       /* "" means none */
    char       useragent[VU_UA_MAX];      /* "" means unset */
    char       tunables[VU_TUNABLE_MAX][VU_TUNABLE_LEN];
    size_t     n_tunables;
    bool       quiet;
} vu_request;

/* One approved capability record (§7). Not merely a certificate: protocol,
 * origin and proxy are part of what was authorised. */
typedef struct {
    char profile_id[VU_UUID_MAX];
    char protocol[VU_PROTO_MAX];
    char origin[VU_ORIGIN_MAX];
    char fingerprint[VU_FPR_MAX];
    char proxy[VU_PROXY_MAX];   /* "" means NONE — the helper then passes --no-proxy */
} vu_approval;

/*
 * Enforce Model B. Every field is checked; a mismatch refuses. Approving one
 * profile must not let a later caller switch protocol or substitute a proxy.
 * A fingerprint mismatch is reported as needing re-approval, never updated.
 */
bool vu_policy_check(const vu_request *req, const vu_approval *appr, vu_err *e);

/*
 * Parse `vpn-up-helper connect`'s argv into a validated request (§8).
 *
 * Lives here, with the rest of the pure validation layer, because that is what
 * it is: no I/O, no privilege, no globals. It was originally static inside
 * helper_main.c, where the root check ran first and the grammar could therefore
 * never be attacked by an unprivileged test — see request.c for why that was
 * the wrong place for it.
 *
 * The schema is closed: every recognised flag may appear at most once, an
 * unrecognised one is a hard failure rather than something forwarded, and no
 * field is copied across without going through its own validator.
 */
bool vu_request_from_argv(int argc, char **argv, vu_request *req, vu_err *e);

/* Extract the host component of a canonical origin, for the resolve binding. */
bool vu_origin_host(const char *origin, char *out, size_t out_cap);

#endif /* VU_H */
