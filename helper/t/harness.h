/* harness.h — shared assertion machinery for the helper test corpora. */
#ifndef VU_HARNESS_H
#define VU_HARNESS_H

#include <stddef.h>
#include <stdio.h>

extern int vu_checks;
extern int vu_failures;

#define CHECK(cond, ...) do {                                               \
        vu_checks++;                                                        \
        if (!(cond)) {                                                      \
            vu_failures++;                                                  \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);            \
            fprintf(stderr, __VA_ARGS__);                                   \
            fputc('\n', stderr);                                            \
        }                                                                   \
    } while (0)

/*
 * Recursive delete for test fixtures, with no shell involved.
 *
 * Was system("rm -rf '<path>'"), which glibc flags as warn_unused_result and
 * which -Werror then rejects. Consuming the return value would have silenced
 * that, but building a shell command line out of a path is the pattern this
 * project spends the design document arguing against — so the shell is gone
 * instead of quietened.
 */
void vu_rm_rf(const char *path);

/*
 * Build a path (or any bounded string) into a fixed buffer, aborting the run if
 * it does not fit.
 *
 * Replaces bare snprintf() at every path-building site in the corpus. GCC's
 * -Wformat-truncation — which clang does not implement, so it only shows up in
 * CI — rejects `snprintf(buf, sizeof buf, "%s/a", other)` whenever buf and
 * other are the same size, because the result provably might not fit. Checking
 * the return value at each of the fifteen call sites would satisfy the
 * compiler; funnelling them through one function that cannot truncate is
 * shorter, and turns "we would notice truncation" into "truncation cannot
 * happen". The format attribute keeps -Wformat checking at the call sites.
 */
void vu_path(char *out, size_t cap, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

void vu_test_policy(void);   /* t/test_policy.c — validators, parser, Model B */
void vu_test_state(void);    /* t/test_state.c  — paths, dirs, locks, identity */
void vu_test_registry(void); /* t/test_registry.c — Model B approval records */
void vu_test_exec(void);     /* t/test_exec.c     — the phase-two argv itself */
void vu_test_adversarial(void); /* t/test_adversarial.c — step 9: attacks, not features */
void vu_test_closure(void);      /* t/test_closure.c     — step 10: the execution closure */
void vu_test_integration(void);  /* t/test_integration.c — step 11: a real execve */

#endif
