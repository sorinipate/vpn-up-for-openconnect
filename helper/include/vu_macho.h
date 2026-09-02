/*
 * vu_macho.h — just enough Mach-O to answer the same question elf.h answers
 * for ELF: what will dyld load when this binary runs?
 *
 * Step 13 of PRIVILEGED-HELPER-DESIGN.md §16 / design doc §17.1. Verified
 * directly against a real MacPorts `openconnect` (macOS 26.6, arm64) before
 * writing this, not reasoned about — see §17.1 for the findings this API is
 * shaped by. Two things distinguish this from vu_elf.h's model, and both
 * change the API on purpose:
 *
 *   1. ELF's DT_NEEDED is a bare soname, resolved by SEARCHING a directory
 *      list (DT_RPATH/DT_RUNPATH, ld.so.conf, defaults) — so verifying every
 *      directory on that list is sufficient, and elf.c never needs to open a
 *      second file. Mach-O's LC_LOAD_DYLIB instead usually names a complete,
 *      already-resolved path (confirmed: the real openconnect's full
 *      transitive dependency graph uses zero @rpath/@loader_path/
 *      @executable_path tokens). A dependency can therefore point ANYWHERE,
 *      not just within an already-verified directory — so unlike ELF, the
 *      closure walk (closure.c) must open and recurse into every non-cache
 *      dependency this returns, not just verify directories.
 *
 *   2. Where Mach-O DOES use a directory-search token (@rpath, resolved
 *      against this image's own LC_RPATH list, first match wins) the ELF
 *      strategy still applies directly: verify every LC_RPATH directory, not
 *      which one a given dependency would actually resolve to. @loader_path
 *      and @executable_path used directly (not via @rpath) name exactly one
 *      path, like $ORIGIN, and are expanded here the same way $ORIGIN is in
 *      elf.c — EXCEPT that the two tokens are not interchangeable the way a
 *      single $ORIGIN is: @loader_path is always relative to the file being
 *      parsed, but @executable_path is always relative to the top-level
 *      binary, REGARDLESS of which image in a dependency chain contains the
 *      reference. A dependency three levels deep in openconnect's graph that
 *      names "@executable_path/../lib/x.dylib" means openconnect's own
 *      directory, not its own. That is why this API takes both paths
 *      separately rather than one, unlike elf.c's single $ORIGIN.
 *
 * The dyld shared cache is the other real difference: most of the macOS base
 * system (libSystem, and every /System/Library/Frameworks/ (star).framework/...
 * dependency checked directly — Security, CoreFoundation, CoreServices — all
 * confirmed absent as files) resolves from the cache rather than any file on
 * disk. This module does not decide trust for those; it reports the resolved
 * path as-is and lets closure.c apply _dyld_shared_cache_contains_path()
 * (declared locally there — it has no public header) before falling back to
 * a filesystem check.
 *
 * Same posture as elf.c otherwise: hand-rolled rather than <mach-o/loader.h>
 * struct layouts (this parses files whose byte order/class may differ from
 * the host on purpose, for the test fixtures), bounds-checked, read-only,
 * one caller-provided buffer.
 */
#ifndef VU_MACHO_H
#define VU_MACHO_H

#include "vu.h"
#include "vu_state.h"

/* Same rationale as VU_ELF_NEEDED_MAX/RPATH_MAX/NAME_MAX: generous, bounded,
 * and a hit is reported rather than silently truncated. */
#define VU_MACHO_DYLIB_MAX  64
#define VU_MACHO_RPATH_MAX  16
#define VU_MACHO_NAME_MAX   VU_PATH_MAX

typedef struct {
    /* Every LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_LOAD_UPWARD_DYLIB /
     * LC_REEXPORT_DYLIB entry, in link order, with @executable_path and
     * @loader_path already expanded (using `path` and the file itself,
     * respectively). An entry that still starts with "@rpath/" after that
     * pass is left as-is: resolving it needs the CALLER's own LC_RPATH list
     * (searched by the loading image, which is this file only for its own
     * direct dependents — closure.c never needs the resolved rpath target,
     * only the directories, per point 2 above), so this module reports the
     * unresolved "@rpath/..." string for the record and the caller verifies
     * the directories instead of chasing it further. */
    char   dylib[VU_MACHO_DYLIB_MAX][VU_MACHO_NAME_MAX];
    size_t n_dylib;

    /* LC_RPATH entries, with @executable_path/@loader_path expanded the same
     * way. SECURITY relevant exactly like ELF's rpath[]: dyld searches these,
     * in order, for any dependent that names "@rpath/...". */
    char   rpath[VU_MACHO_RPATH_MAX][VU_PATH_MAX];
    size_t n_rpath;

    bool   is_macho;     /* false for a non-Mach-O file — not an error, mirrors is_elf */
    bool   is_64, is_le;
    bool   is_fat;        /* was a universal/fat binary; a single slice was selected */
    bool   truncated;     /* a limit above was hit */
} vu_macho_info;

/*
 * Parse a Mach-O (or fat/universal) file's load commands.
 *
 * `path` is the file being parsed (its directory is @loader_path).
 * `exe_path` is the top-level binary this parse is ultimately in service of
 * (its directory is @executable_path) — pass `path` itself for a top-level
 * call, and the ORIGINAL top-level path, unchanged, for every recursive call
 * into a dependency (closure.c threads it through vu_dylib_closure exactly
 * this way). Getting this wrong silently mis-resolves any dependency, three
 * levels deep or more, that uses @executable_path — which this API makes
 * structurally hard to get wrong rather than documenting as a caller
 * obligation.
 *
 * For a fat binary, the slice matching the HOST's own architecture is
 * selected (the one dyld would actually load here) — a fat binary presenting
 * a trustworthy arm64 slice and a hostile x86_64 one is not close, on a
 * machine that will only ever run the former; verifying the other slice too
 * would be verifying code that can never execute. If no slice matches the
 * host architecture, or a 64-bit fat header (rare, large-fat-file only) is
 * seen, this fails (returns false) rather than guessing.
 *
 * Returns false only on an error that prevents a verdict. A file that is
 * simply not Mach-O sets is_macho = false and returns true, same as elf.c's
 * "this is a shell script" case.
 */
bool vu_macho_dylibs(const char *path, const char *exe_path, vu_macho_info *out, vu_err *e);

#endif /* VU_MACHO_H */
