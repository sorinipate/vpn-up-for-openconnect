/*
 * vu_closure.h — the trusted execution closure (§11.4), checked as one thing.
 *
 * Step 10 of §16. The requirement this implements, verbatim from the design:
 *
 *   Every executable, script, library, interpreter, sourced hook and search
 *   path reachable from the privileged OpenConnect execution must be outside
 *   the caller's write control.
 *
 * Steps 5 and 7 covered two files of that: the openconnect binary and the pinned
 * vpnc-script. This covers the rest, and the rest is most of it:
 *
 *   the openconnect binary            executed as root
 *   its library search paths          a root-owned binary loading a
 *                                     user-writable library is the same bug
 *                                     wearing a hat
 *   /bin/sh                           OpenConnect runs the script through it
 *   the vpnc-script's own interpreter its shebang, if it has one
 *   the pinned vpnc-script            executed as root on every connect
 *   /etc/vpnc and its *.d directories run_hooks() SOURCES their contents, so
 *                                     the execute bit is irrelevant and
 *                                     DIRECTORY writability is what matters
 *   every PATH entry                  vpnc-script resolves route, ifconfig,
 *                                     ip, resolvconf through it
 *   /etc/ld.so.preload, ld.so.conf    both name libraries or directories the
 *                                     loader will use, as root
 *
 * The result is a REPORT, not just a bool. A closure failure is something a
 * person has to fix on their machine, so "refused" without naming the object
 * and the reason would be useless — and the commonest failure by far is a
 * Homebrew OpenConnect, where the useful output is which component of the chain
 * is user-owned (§11.6).
 *
 * Honest scope, stated here because it decides what macOS does:
 *
 *   The LIBRARY closure is implemented for Linux only. macOS needs Mach-O
 *   LC_LOAD_DYLIB, the dyld shared cache and the DYLD_* search rules, which is
 *   step 13. Until then this reports the library row as unverified, so the
 *   overall verdict on macOS is REFUSED — which is §11.7's fail-closed
 *   behaviour, implemented rather than merely documented.
 *
 * Everything else is checked on both platforms, and every root and expected
 * owner is a parameter, so the corpus exercises the real checks unprivileged.
 */
#ifndef VU_CLOSURE_H
#define VU_CLOSURE_H

#include "vu.h"
#include "vu_state.h"

#include <stdio.h>

/*
 * Is the ELF/ld.so library closure compiled in?
 *
 * On by default on Linux, off elsewhere — so macOS fails closed per §11.7
 * without a special case at every call site.
 *
 * It can be forced on for TESTING (-DVU_LIBRARY_CLOSURE_ELF=1), and that seam
 * earns its keep twice: the Linux-only branch is compiled on the development
 * machine instead of first meeting a compiler in CI, and the corpus exercises
 * the DT_RUNPATH and ld.so.conf logic against hand-built fixtures on either
 * platform. Three of four CI failures in earlier steps were Linux-only code
 * that had never been compiled locally.
 *
 * It is not a way to weaken production: with it forced on against a REAL macOS
 * install, the ELF parse of a Mach-O binary reports "not an ELF binary" and the
 * check still refuses. Only a synthetic ELF fixture gets past it.
 */
#ifndef VU_LIBRARY_CLOSURE_ELF
#  if defined(__linux__)
#    define VU_LIBRARY_CLOSURE_ELF 1
#  else
#    define VU_LIBRARY_CLOSURE_ELF 0
#  endif
#endif

/*
 * Loader-configuration paths, overridable at build time like the state and
 * registry roots and for the same reason: a test build can point them at a
 * fixture, and no RUNTIME input can. Production uses the real paths.
 */
#ifndef VU_LDSO_PRELOAD
#  define VU_LDSO_PRELOAD "/etc/ld.so.preload"
#endif
#ifndef VU_LDSO_CONF
#  define VU_LDSO_CONF "/etc/ld.so.conf"
#endif
#ifndef VU_LDSO_CONF_DIR
#  define VU_LDSO_CONF_DIR "/etc/ld.so.conf.d"
#endif

#define VU_CLOSURE_MAX 128

typedef struct {
    char        path[VU_PATH_MAX];
    const char *role;                 /* static string: what this object is */
    bool        ok;
    bool        checked;              /* false = we could not form a verdict */
    char        reason[VU_ERR_MAX];   /* why not, when !ok */
} vu_closure_item;

typedef struct {
    vu_closure_item items[VU_CLOSURE_MAX];
    size_t          n;
    size_t          n_failed;
    bool            truncated;        /* more objects than the report can hold */
} vu_closure_report;

/*
 * Every root is a parameter. In production these are the compile-time pins and
 * owner 0; the corpus points them at fixture trees and passes its own uid, so
 * the code under test is the code that runs as root.
 */
typedef struct {
    const char *openconnect;      /* pinned binary                            */
    const char *script;           /* pinned vpnc-script                       */
    const char *shell;            /* "/bin/sh"                                */
    const char *path_env;         /* the PATH the helper will hand over       */
    const char *hooks_root;       /* "/etc/vpnc"                              */
    const char *ldso_preload;     /* "/etc/ld.so.preload"                     */
    const char *ldso_conf;        /* "/etc/ld.so.conf"                        */
    const char *ldso_conf_dir;    /* "/etc/ld.so.conf.d"                      */
    /*
     * The loader's built-in search directories. NULL means the compiled-in list
     * (/lib, /usr/lib and the multiarch variants). A parameter so the corpus can
     * pass an empty list: a test asserting something about a FIXTURE tree should
     * not also depend on the permissions of the host's /usr/lib, which is an
     * environmental difference between a developer machine and a CI runner and
     * exactly the kind of thing that produces a red build nobody can reproduce.
     */
    const char *const *default_libdirs;
    size_t             n_default_libdirs;
    bool               no_default_libdirs;  /* explicitly none, vs. "use the built-in list" */

    uid_t       owner;            /* required owner: 0 in production          */
    uid_t       probe_uid;        /* uid for the effective-writability probe   */
    bool        probe;            /* run it (needs root; see §11.5)           */
} vu_closure_spec;

/* Fill in the production defaults, then override what a caller needs. */
void vu_closure_spec_default(vu_closure_spec *s, const char *openconnect,
                             const char *script, uid_t owner);

/*
 * Walk the closure. Returns true when EVERY object checked out, false when any
 * did not or when a verdict could not be formed; either way the report is
 * populated and is what a caller should print.
 *
 * `e` carries a one-line summary for callers that only want that.
 */
bool vu_closure_check(const vu_closure_spec *s, vu_closure_report *out, vu_err *e);

/* Print the report, failures first, one object per line. */
void vu_closure_print(const vu_closure_report *r, FILE *to);

#endif /* VU_CLOSURE_H */
