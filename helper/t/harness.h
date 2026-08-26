/* harness.h — shared assertion machinery for the helper test corpora. */
#ifndef VU_HARNESS_H
#define VU_HARNESS_H

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

void vu_test_policy(void);   /* t/test_policy.c — validators, parser, Model B */
void vu_test_state(void);    /* t/test_state.c  — paths, dirs, locks, identity */

#endif
