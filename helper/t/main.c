/*
 * main.c — runs every corpus in one process, so `make test` is one command with
 * one summary. Both corpora are unprivileged by construction (§16 step 4/5).
 */
#include "harness.h"

int main(void)
{
    vu_test_policy();
    vu_test_state();

    printf("%d checks, %d failures\n", vu_checks, vu_failures);
    return vu_failures == 0 ? 0 : 1;
}
