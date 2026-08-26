/*
 * vu_elf.h — just enough ELF to answer one question: where will the dynamic
 * loader look for this binary's libraries?
 *
 * Step 10 of PRIVILEGED-HELPER-DESIGN.md §16. §11.4 requires the dynamic
 * library closure to be outside the caller's write control — "a root-owned
 * binary loading a user-writable library is the same bug wearing a hat".
 *
 * THE KEY SIMPLIFICATION, and it is worth stating before the API:
 *
 *   The check does not enumerate and verify every library. It verifies every
 *   DIRECTORY the loader will search. Given a constructed environment with no
 *   LD_LIBRARY_PATH (vu_clean_env), a library can only be loaded from a
 *   directory on that search list — so if every directory on it is root-owned
 *   and not group- or world-writable, every library that can be loaded is too.
 *
 * That is both stronger and much smaller than walking a dependency graph: it
 * covers libraries we have never heard of, dlopen'd plugins, and versions that
 * change under us. DT_NEEDED is still read, but for the REPORT — a concrete list
 * of what is being trusted is far more useful to a person than "the search paths
 * are fine".
 *
 * This file is pure byte handling: no syscalls beyond reading the file, no
 * allocation, no platform assumptions. It compiles and is tested on macOS as
 * well, against hand-built ELF fixtures, which is the only way to test the
 * parser without a Linux toolchain (see t/test_closure.c).
 */
#ifndef VU_ELF_H
#define VU_ELF_H

#include "vu.h"
#include "vu_state.h"

/* Generous, but bounded: a real openconnect links against a couple of dozen
 * libraries. Exceeding either limit is reported, never silently truncated —
 * a closure check that quietly stopped looking would be worse than none. */
#define VU_ELF_NEEDED_MAX   64
#define VU_ELF_RPATH_MAX    16
#define VU_ELF_NAME_MAX     256

typedef struct {
    /* DT_NEEDED sonames, in link order. Informational: used for the report. */
    char   needed[VU_ELF_NEEDED_MAX][VU_ELF_NAME_MAX];
    size_t n_needed;

    /* DT_RPATH / DT_RUNPATH directories, split on ':' and with $ORIGIN
     * expanded to the directory holding the binary. These are SECURITY
     * relevant: the loader searches them, so each must be a trusted directory. */
    char   rpath[VU_ELF_RPATH_MAX][VU_PATH_MAX];
    size_t n_rpath;

    bool   is_elf;          /* false for a non-ELF file, which is not an error
                             * here — the caller decides what that means */
    bool   is_64, is_le;
    bool   had_runpath;     /* DT_RUNPATH present (as opposed to DT_RPATH) */
    bool   truncated;       /* a limit above was hit; the report must say so */
} vu_elf_info;

/*
 * Read the dynamic section of an ELF executable or shared object.
 *
 * Returns false only on an error that prevents a verdict: unreadable file,
 * malformed headers, an offset outside the file. A file that is simply not ELF
 * sets is_elf = false and returns TRUE, because "this is a shell script" is a
 * legitimate answer that the closure walk handles differently (it then wants the
 * interpreter, not the libraries).
 *
 * A dynamic entry naming $LIB or $PLATFORM is refused rather than guessed at:
 * expanding those correctly needs the loader's own notion of the machine, and a
 * search path we cannot resolve is a search path we cannot verify.
 */
bool vu_elf_dynamic(const char *path, vu_elf_info *out, vu_err *e);

#endif /* VU_ELF_H */
