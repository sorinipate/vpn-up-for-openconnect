/*
 * vu_exec.h — building the phase-two OpenConnect invocation (§4, §8, §16 step 7).
 *
 * The argv construction is deliberately a PURE function, separate from the
 * privileged sequencing in helper_main.c. It is the part where a mistake means
 * root runs something it should not, and keeping it free of side effects is
 * what makes it testable element-by-element without privilege — the same
 * discipline as steps 4 and 5.
 */
#ifndef VU_EXEC_H
#define VU_EXEC_H

#include "vu.h"
#include "vu_closure.h"
#include "vu_registry.h"

/*
 * Pinned executables. Set at install time (-DVU_OPENCONNECT=...) once §17.2 is
 * settled; the defaults name the supported source per platform. Never taken
 * from the environment or from the request — a caller who chooses the binary
 * chooses what root executes.
 *
 * macOS defaults to MacPorts because Homebrew's prefix is owned by the
 * installing user and is therefore unusable for helper mode (§11.6).
 */
#ifndef VU_OPENCONNECT
#  if defined(__APPLE__)
#    define VU_OPENCONNECT "/opt/local/sbin/openconnect"
#  else
#    define VU_OPENCONNECT "/usr/sbin/openconnect"
#  endif
#endif

/*
 * The REAL vpnc-script — the standard, third-party vpnc-scripts project file
 * this program does not ship — is passed EXPLICITLY rather than relying on
 * OpenConnect's compiled-in default, because that default may live in a
 * user-writable prefix (§1.3). Named _REAL because OpenConnect itself never
 * invokes this path directly any more: it invokes VU_VPNC_SCRIPT (below), a
 * wrapper this program DOES ship, which records tunnel-up/down telemetry
 * (connection-state design plan §2) and then delegates here unchanged so
 * network configuration still happens exactly as it always has.
 */
#ifndef VU_VPNC_SCRIPT_REAL
#  if defined(__APPLE__)
/* The "vpnc-scripts" MacPorts port (a declared library dependency of its
 * "openconnect" port) installs here, confirmed directly against a real
 * install (`port contents openconnect`, `port contents vpnc-scripts`) —
 * NOT /opt/local/etc/vpnc, which this constant named before that check and
 * which vpnc-scripts never creates. */
#    define VU_VPNC_SCRIPT_REAL "/opt/local/etc/vpnc-scripts/vpnc-script"
#  else
#    define VU_VPNC_SCRIPT_REAL "/etc/vpnc/vpnc-script"
#  endif
#endif

/*
 * The vpnc-script wrapper OpenConnect actually invokes via --script. Root-owned,
 * installed alongside the two privileged binaries (helper_dir() in twophase.sh),
 * and subject to its own, lighter-weight closure check (vu_wrapper_precheck) —
 * see the connection-state design plan for why this is a separate object from
 * VU_VPNC_SCRIPT_REAL rather than a second full closure walk. Fixed at compile
 * time, same reasoning as every other pinned path here: this value, and never
 * anything caller- or environment-supplied, is what OpenConnect's --script
 * names.
 */
#ifndef VU_VPNC_SCRIPT
#  if defined(__APPLE__)
#    define VU_VPNC_SCRIPT "/opt/vpn-up/bin/vpn-up-vpnc-wrapper"
#  else
#    define VU_VPNC_SCRIPT "/usr/local/libexec/vpn-up/vpn-up-vpnc-wrapper"
#  endif
#endif

#define VU_ARGV_MAX  32
#define VU_ARGV_ITEM VU_URL_MAX      /* the connect URL is the longest element */

/* Storage plus the NULL-terminated vector. Large enough that callers declare it
 * static rather than on the stack. */
typedef struct {
    char   store[VU_ARGV_MAX][VU_ARGV_ITEM];
    char  *argv[VU_ARGV_MAX + 1];
    size_t n;
} vu_argv;

/*
 * Build the phase-two invocation from a validated request and its approved
 * record. Three elements are unconditional, and the reasons are worth keeping
 * next to the code:
 *
 *   --cookie-on-stdin  the cookie never touches argv, so it never appears in ps
 *   --non-inter        the helper does not read stdin, so OpenConnect must not
 *                      be able to fall back to prompting root-side if the
 *                      cookie is missing or rejected — it has to exit instead
 *   --servercert=      taken from the REGISTRY, never the request. This is what
 *                      stops a caller substituting a gateway even when it
 *                      controls DNS or supplies its own --resolve
 *
 * Never emitted: --background, --pid-file, --script with caller input,
 * --csd-*, --config, --xmlconfig, --external-browser, or anything at all that
 * did not come from the closed schema.
 */
bool vu_build_argv(const vu_request *req, const vu_approval *appr,
                   const char *openconnect_path, const char *script_path,
                   vu_argv *out, vu_err *e);

/*
 * The trusted-execution-closure check, run immediately before execve.
 *
 * Step 7 checked two files. Step 10 replaced that with the full §11.4 walk —
 * library search paths, /bin/sh, the script's interpreter, the sourced hook
 * directories and every PATH entry — because a root-owned binary that loads a
 * user-writable library, or sources a user-writable hook, is the same bug as a
 * user-writable binary.
 *
 * `report` may be NULL when the caller only wants the verdict; when it is not,
 * it is populated for printing and names the objects that failed. See
 * vu_closure_check, of which this is the pinned-path wrapper.
 */
/*
 * `caller_uid` is the invoking user (SUDO_UID), and is what the
 * effective-writability probe drops to - not `owner`, which is 0. §11.5 asks
 * whether the CALLER can write a trusted object despite its mode bits; asking
 * that about root is meaningless. Pass 0 to skip the probe.
 */
bool vu_exec_precheck(const char *openconnect_path, const char *script_path,
                      uid_t owner, uid_t caller_uid,
                      vu_closure_report *report, vu_err *e);

#endif /* VU_EXEC_H */
