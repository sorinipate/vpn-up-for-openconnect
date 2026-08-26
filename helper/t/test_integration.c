/*
 * test_integration.c — step 11 of PRIVILEGED-HELPER-DESIGN.md §16.
 *
 * Two claims in §18 are marked "integration test, not source inspection", and
 * they are the only two in the whole plan marked that way:
 *
 *   Locking: two concurrent connects to one profile — exactly one proceeds; the
 *   lock survives execve and is released when OpenConnect exits.
 *
 *   Cookie handling: never in argv, never in a log, never in ps; stdin is passed
 *   through unread, so a cookie longer than any buffer still works.
 *
 * Neither is establishable by reading the helper's source. The first depends on
 * the kernel's flock-across-execve semantics; the second on the helper never
 * touching bytes it forwards. Both need a real execve into a real second
 * process, so this corpus performs one — using the ACTUAL functions the helper
 * calls, in the same order, with a stand-in binary in place of OpenConnect.
 *
 * It needs no root and no VPN gateway, which is what makes it a test rather
 * than a manual procedure: the state root and expected owner have been
 * parameters since step 5 precisely so that the privileged sequence could be
 * exercised unprivileged. The end-to-end run of the real vpn-up-helper binary
 * under sudo is t/integration/run.sh, which needs both and is therefore opt-in.
 *
 * The cookie here is 100000 bytes: larger than VU_COOKIE_MAX (8192), larger than
 * any buffer in this project, and larger than a pipe. If anything in the chain
 * were quietly reading, buffering or truncating it, this fails.
 */

#include "harness.h"
#include "vu_closure.h"
#include "vu_exec.h"
#include "vu_state.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef VU_FAKE_OPENCONNECT
#define VU_FAKE_OPENCONNECT "build/fake-openconnect"
#endif

#define ID_A  "11111111-2222-3333-4444-555555555555"
#define FPR_A "sha256:1111111111111111111111111111111111111111111111111111111111111111"

/*
 * A marker buried in the MIDDLE of the cookie.
 *
 * Deliberately not near either end: the stand-in reports the first and last 16
 * bytes as hex, so a marker there could show up in the report legitimately and
 * the assertion below would be unfalsifiable. Placed in the middle, the rule is
 * absolute — this string must appear NOWHERE in the report, which covers argv,
 * the environment and /proc/self/cmdline in one assertion.
 */
#define COOKIE_MARKER "vu-cookie-must-never-be-visible-anywhere"
#define COOKIE_LEN 100000u

static char g_base[VU_PATH_MAX];

static void make_base(const char *tag)
{
    vu_path(g_base, sizeof g_base, "%s/.vpn-up-integration-%s-%ld",
            vu_test_base(), tag, (long)getpid());
    vu_rm_rf(g_base);
    CHECK(mkdir(g_base, 0700) == 0, "cannot create %s: %s", g_base, strerror(errno));
}

static unsigned long long digest(unsigned long long h, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) h = h * 1000003u + p[i];
    return h;
}

static void build_cookie(char *out, size_t len)
{
    for (size_t i = 0; i < len; ++i) out[i] = (char)('a' + (i % 26));
    size_t at = len / 2;
    memcpy(out + at, COOKIE_MARKER, sizeof COOKIE_MARKER - 1);
}

/* One line of the stand-in's report, or NULL. */
static const char *report_line(const char *report, const char *key, char *buf, size_t cap)
{
    size_t klen = strlen(key);
    const char *p = report;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *nl = strchr(v, '\n');
            size_t len = nl ? (size_t)(nl - v) : strlen(v);
            if (len + 1 > cap) return NULL;
            memcpy(buf, v, len);
            buf[len] = '\0';
            return buf;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return NULL;
}

static bool report_has(const char *report, const char *line)
{
    /* Whole-line match, so "env=PATH=..." cannot be satisfied by a prefix. */
    size_t len = strlen(line);
    const char *p = report;
    while (p && *p) {
        if (strncmp(p, line, len) == 0 && (p[len] == '\n' || p[len] == '\0')) return true;
        p = strchr(p, '\n');
        if (p) p++;
    }
    return false;
}

/* Fill a request and approval that pass the policy gate. */
static void fill(vu_request *req, vu_approval *appr)
{
    vu_err e; vu_err_clear(&e);
    memset(req, 0, sizeof *req);
    memset(appr, 0, sizeof *appr);
    CHECK(vu_canon_profile_id(ID_A, req->profile_id, sizeof req->profile_id, &e), "id: %s", e.msg);
    memcpy(req->protocol, "anyconnect", sizeof "anyconnect");
    CHECK(vu_parse_url("https://vpn.example.com/portal", &req->url, &e), "url: %s", e.msg);
    memcpy(req->fingerprint, FPR_A, sizeof FPR_A);
    memcpy(appr->profile_id, req->profile_id, sizeof appr->profile_id);
    memcpy(appr->protocol, "anyconnect", sizeof "anyconnect");
    memcpy(appr->origin, req->url.origin, sizeof appr->origin);
    memcpy(appr->fingerprint, FPR_A, sizeof FPR_A);
}

/* ------------------------------------------------------------------------- */

static void test_execve_boundary(void)
{
    make_base("exec");
    vu_err e;

    char root[VU_PATH_MAX];
    vu_path(root, sizeof root, "%s/run", g_base);
    uid_t me = getuid();

    /*
     * The stand-in must exist, or every assertion below would pass vacuously —
     * and its path must be ABSOLUTE.
     *
     * The first version used the relative path the Makefile builds, and the child
     * died at execve with no explanation: vu_harden_process does chdir("/")
     * before the exec, so a relative path no longer resolves. That is the
     * §11.3 requirement demonstrating itself, and the reason the real helper
     * pins an absolute path (§11.1) rather than relying on a lookup.
     */
    char fake[VU_PATH_MAX];
    {
        char *real = realpath(VU_FAKE_OPENCONNECT, NULL);
        if (!real) {
            CHECK(false, "stand-in '%s' not built (run from helper/, via make): %s",
                  VU_FAKE_OPENCONNECT, strerror(errno));
            vu_rm_rf(g_base);
            return;
        }
        vu_path(fake, sizeof fake, "%s", real);
        free(real);
    }

    vu_request req; vu_approval appr;
    fill(&req, &appr);

    static vu_argv cmd;
    vu_err_clear(&e);
    CHECK(vu_build_argv(&req, &appr, fake, "/etc/vpnc/vpnc-script", &cmd, &e),
          "argv: %s", e.msg);

    vu_state_paths p;
    vu_err_clear(&e);
    CHECK(vu_state_paths_in(root, me, req.profile_id, &p, &e), "paths: %s", e.msg);

    static char cookie[COOKIE_LEN];
    build_cookie(cookie, sizeof cookie);
    unsigned long long want_digest =
        digest(1469598103934665603ull, (const unsigned char *)cookie, sizeof cookie);

    int to_child[2], from_child[2];
    CHECK(pipe(to_child) == 0, "pipe: %s", strerror(errno));
    CHECK(pipe(from_child) == 0, "pipe: %s", strerror(errno));

    pid_t child = fork();
    CHECK(child >= 0, "fork: %s", strerror(errno));
    if (child == 0) {
        /*
         * The helper's connect sequence, in the helper's order: lock, prune,
         * harden, record, execve. Any deviation here would make the test a test
         * of something else.
         */
        if (dup2(to_child[0], 0) < 0) _exit(90);
        if (dup2(from_child[1], 1) < 0) _exit(91);
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);

        vu_err ce; vu_err_clear(&ce);
        int lock_fd = -1;
        if (!vu_lock_acquire(&p, me, &lock_fd, &ce)) _exit(92);

        vu_proc self;
        if (!vu_proc_identity(getpid(), &self, &ce)) _exit(93);
        if (!vu_state_record(&p, &self, appr.origin, &ce)) _exit(94);

        if (!vu_harden_process(lock_fd, &ce)) _exit(95);

        execve(fake, cmd.argv, vu_clean_env());
        _exit(96);
    }

    close(to_child[0]);
    close(from_child[1]);

    /*
     * SIGPIPE is ignored for the duration. Without this, a child that dies
     * before reading the cookie kills the test runner with signal 13 and the
     * output is an exit code with no diagnosis — which is exactly what happened
     * the first time this ran, and it took a second run to find out why. A
     * harness whose failure mode is "the harness dies" cannot report anything.
     */
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);

    /* Write the whole cookie, then close: the stand-in reads to EOF before it
     * writes anything, so this cannot deadlock however large the cookie is. */
    size_t written = 0;
    bool write_failed = false;
    while (written < sizeof cookie) {
        ssize_t w = write(to_child[1], cookie + written, sizeof cookie - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            write_failed = true;
            break;
        }
        written += (size_t)w;
    }
    close(to_child[1]);

    if (write_failed || written != sizeof cookie) {
        /* The child is gone. Reap it and say what it reported, so the failure
         * names the step that broke rather than the symptom. */
        int st = 0;
        (void)waitpid(child, &st, 0);
        static const char *why[] = {
            [90] = "dup2 of the cookie pipe onto stdin",
            [91] = "dup2 of the report pipe onto stdout",
            [92] = "vu_lock_acquire",
            [93] = "vu_proc_identity",
            [94] = "vu_state_record",
            [95] = "vu_harden_process",
            [96] = "execve of the stand-in",
        };
        int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        const char *step = (code >= 90 && code <= 96 && why[code]) ? why[code] : "(unknown)";
        CHECK(false, "the child died before reading the cookie: exit %d, at %s", code, step);
        close(from_child[0]);
        signal(SIGPIPE, old_pipe);
        vu_rm_rf(g_base);
        return;
    }

    static char report[65536];
    size_t got = 0;
    while (got < sizeof report - 1) {
        ssize_t r = read(from_child[0], report + got, sizeof report - 1 - got);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        got += (size_t)r;
        report[got] = '\0';
        if (strstr(report, "FAKE-REPORT-END")) break;
    }
    report[got] = '\0';
    CHECK(strstr(report, "FAKE-REPORT-BEGIN") != NULL, "no report from the stand-in");
    CHECK(strstr(report, "FAKE-REPORT-END") != NULL, "truncated report from the stand-in");

    char buf[VU_PATH_MAX * 2];

    /* ---- the cookie arrived whole, and nowhere it should not be ---------- */

    const char *bytes = report_line(report, "stdin_bytes", buf, sizeof buf);
    CHECK(bytes && strtoull(bytes, NULL, 10) == COOKIE_LEN,
          "the whole cookie must arrive: got %s of %u", bytes ? bytes : "(none)", COOKIE_LEN);

    char dbuf[64];
    const char *dg = report_line(report, "stdin_digest", dbuf, sizeof dbuf);
    CHECK(dg && strtoull(dg, NULL, 10) == want_digest,
          "the cookie must arrive UNMODIFIED and in order: digest %s, expected %llu",
          dg ? dg : "(none)", want_digest);

    /*
     * The assertion the whole design turns on. The marker sits in the middle of
     * the cookie and the report contains argv, the environment and (on Linux)
     * /proc/self/cmdline — what ps itself reads. If the cookie reached the
     * command line, the environment, or anything else visible from outside the
     * process, it is in this report.
     */
    CHECK(strstr(report, COOKIE_MARKER) == NULL,
          "the cookie must not appear in argv, the environment, or the process table");

    /* ---- the argv is exactly what the builder produced ------------------- */

    for (size_t i = 0; i < cmd.n; ++i) {
        char want[VU_PATH_MAX * 2];
        vu_path(want, sizeof want, "argv[%zu]=%s", i, cmd.argv[i]);
        CHECK(report_has(report, want), "argv element %zu did not arrive as '%s'", i, cmd.argv[i]);
    }
    {
        char argc_line[64];
        vu_path(argc_line, sizeof argc_line, "argc=%zu", cmd.n);
        CHECK(report_has(report, argc_line), "argc must be exactly %zu, with nothing appended", cmd.n);
    }

    /* ---- privileged-process hygiene, observed from the far side ---------- */

    const char *cwd = report_line(report, "cwd", buf, sizeof buf);
    CHECK(cwd && strcmp(cwd, "/") == 0,
          "the exec'd process must run from / (an empty PATH plus a caller-chosen "
          "cwd is a root-exec path): got %s", cwd ? cwd : "(none)");

    const char *um = report_line(report, "umask", buf, sizeof buf);
    CHECK(um && strcmp(um, "0077") == 0, "umask must be 077, got %s", um ? um : "(none)");

    const char *nenv = report_line(report, "env_count", buf, sizeof buf);
    CHECK(nenv && strcmp(nenv, "1") == 0,
          "the environment must be PATH and nothing else, got %s entries", nenv ? nenv : "(none)");
    {
        char want[VU_PATH_MAX];
        vu_path(want, sizeof want, "env=PATH=%s", VU_HELPER_PATH);
        CHECK(report_has(report, want), "PATH must be exactly the pinned value");
    }

    /*
     * Descriptors. Everything above stderr closed EXCEPT the lock — so the set
     * is 0, 1, 2 and one more. This is also the first direct evidence that the
     * lock descriptor itself survived the execve.
     */
    const char *fds = report_line(report, "fds", buf, sizeof buf);
    CHECK(fds != NULL, "the stand-in must report its descriptors");
    if (fds) {
        size_t n_open = 0;
        for (const char *q = fds; *q; ++q) if (*q == ',') n_open++;
        CHECK(n_open == 4, "expected 0,1,2 plus the lock, got '%s'", fds);
        CHECK(strncmp(fds, "0,1,2,", 6) == 0, "the standard descriptors must be intact: '%s'", fds);
    }
    CHECK(strstr(report, "inherited_fd=") != NULL,
          "the lock descriptor must survive the execve as a valid open file");

    /* ---- the lock is HELD by the exec'd process -------------------------- */

    {
        int second = -1;
        vu_err_clear(&e);
        CHECK(!vu_lock_acquire(&p, me, &second, &e),
              "while the exec'd process runs, a second connect for the same profile "
              "must be refused — this is 'one tunnel per profile' with no "
              "process-table race");
        CHECK(strstr(e.msg, "already has a tunnel") != NULL, "explain: %s", e.msg);
        CHECK(second == -1, "a refused lock must not return a descriptor");
    }

    /* ---- the recorded identity still matches after the execve ------------ */

    {
        /*
         * The pid and start token were recorded BEFORE the execve, from the
         * pre-exec image. execve replaces the image without creating a process,
         * so both must still identify the process now running OpenConnect —
         * otherwise `stop` would see stale state for every live tunnel. That is
         * a kernel property, not a code property, which is why it is asserted
         * here and not in a unit test.
         */
        vu_state_status st;
        vu_proc found;
        vu_err_clear(&e);
        CHECK(vu_state_check(&p, fake, me, &st, &found, &e) &&
              st == VU_STATE_LIVE,
              "the pid and start token recorded before execve must still identify "
              "the process after it: %s", e.msg);
        CHECK(found.pid == child, "the recorded pid must be the exec'd process: %ld vs %ld",
              (long)found.pid, (long)child);
    }

    /* ---- and it is RELEASED when that process exits ---------------------- */

    CHECK(kill(child, SIGTERM) == 0, "signal the stand-in: %s", strerror(errno));
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child, "waitpid: %s", strerror(errno));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "the stand-in should exit cleanly on SIGTERM (status %d)", status);
    close(from_child[0]);
    signal(SIGPIPE, old_pipe);

    {
        /*
         * Nobody unlocked anything: the process holding the descriptor exited and
         * the kernel dropped the lock. That is what makes stale state
         * self-healing without a reaper.
         */
        int again = -1;
        vu_err_clear(&e);
        CHECK(vu_lock_acquire(&p, me, &again, &e),
              "the lock must be released by the kernel when the exec'd process "
              "exits, with nothing having called unlock: %s", e.msg);
        vu_lock_release(again);
    }

    {
        vu_state_status st;
        vu_err_clear(&e);
        CHECK(vu_state_check(&p, fake, me, &st, NULL, &e) &&
              st == VU_STATE_STALE,
              "once the process is gone the recorded state must read as stale: %s", e.msg);
    }

    vu_rm_rf(g_base);
}

/* ------------------------------------------------------------------------- */

/*
 * §18: "two concurrent connects to one profile — exactly one proceeds."
 *
 * Both children race for the same lock with no ordering between them. The
 * assertion is not that a particular one wins; it is that the count of winners
 * is exactly one.
 */
static void test_concurrent_connects(void)
{
    make_base("race");
    vu_err e;
    char root[VU_PATH_MAX];
    vu_path(root, sizeof root, "%s/run", g_base);
    uid_t me = getuid();

    vu_state_paths p;
    vu_err_clear(&e);
    CHECK(vu_state_paths_in(root, me, ID_A, &p, &e), "paths: %s", e.msg);

    /* Create the tree first, so the race is over the LOCK and not over mkdir. */
    int warm = -1;
    vu_err_clear(&e);
    CHECK(vu_lock_acquire(&p, me, &warm, &e), "warm-up lock: %s", e.msg);
    vu_lock_release(warm);

    enum { RACERS = 8 };
    int ready[2];
    CHECK(pipe(ready) == 0, "pipe: %s", strerror(errno));

    pid_t kids[RACERS];
    for (int i = 0; i < RACERS; ++i) {
        kids[i] = fork();
        CHECK(kids[i] >= 0, "fork: %s", strerror(errno));
        if (kids[i] == 0) {
            close(ready[1]);
            /*
             * The starting gun. Block until the parent closes the write end,
             * which arrives here as EOF, so all racers are released at the same
             * instant and this is a real race rather than eight sequential
             * acquisitions.
             *
             * The result is CONSUMED, not cast away. glibc marks read() with
             * warn_unused_result under _FORTIFY_SOURCE, and `(void)` does not
             * suppress -Wunused-result in gcc - only in clang. Neither clang nor
             * gcc on macOS diagnoses this, because the attribute comes from the
             * LIBC rather than the compiler, so it is invisible outside a glibc
             * build. See t/README.
             *
             * Consuming it properly also fixes a real if unlikely bug: a signal
             * delivered while waiting would have released one racer early and
             * quietly weakened the race the test exists to create.
             */
            for (;;) {
                char b;
                ssize_t r = read(ready[0], &b, 1);
                if (r >= 0) break;          /* EOF or a byte: either releases us */
                if (errno == EINTR) continue;
                _exit(3);                   /* barrier broken; parent counts it */
            }
            close(ready[0]);

            vu_err ce; vu_err_clear(&ce);
            int fd = -1;
            if (!vu_lock_acquire(&p, me, &fd, &ce)) _exit(1);
            /* Hold it long enough that every other racer has certainly tried. */
            struct timespec ts = { 0, 300 * 1000 * 1000 };
            (void)nanosleep(&ts, NULL);
            vu_lock_release(fd);
            _exit(0);
        }
    }
    close(ready[0]);
    close(ready[1]);                    /* the starting gun */

    int winners = 0, losers = 0, odd = 0;
    for (int i = 0; i < RACERS; ++i) {
        int status = 0;
        CHECK(waitpid(kids[i], &status, 0) == kids[i], "waitpid: %s", strerror(errno));
        if (!WIFEXITED(status)) { odd++; continue; }
        if (WEXITSTATUS(status) == 0) winners++;
        else if (WEXITSTATUS(status) == 1) losers++;
        else odd++;
    }
    CHECK(odd == 0, "%d racers exited abnormally", odd);
    CHECK(winners == 1, "exactly one concurrent connect must proceed, %d did", winners);
    CHECK(losers == RACERS - 1, "the rest must be refused immediately, %d were", losers);

    vu_rm_rf(g_base);
}

/* ------------------------------------------------------------------------- */

/*
 * The closure check runs before every execve, so it is on the connect path and
 * its cost is paid every time. Not a benchmark — an assertion that it is not
 * accidentally quadratic or doing something absurd, since a check nobody can
 * afford is a check somebody will remove.
 */
static void test_closure_cost(void)
{
    make_base("cost");
    vu_closure_spec s;
    vu_closure_report rep;
    vu_err e;

    vu_closure_spec_default(&s, VU_FAKE_OPENCONNECT, "/etc/vpnc/vpnc-script", getuid());
    s.no_default_libdirs = true;
    s.probe = false;

    struct timespec t0, t1;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0, "clock: %s", strerror(errno));
    for (int i = 0; i < 20; ++i) {
        vu_err_clear(&e);
        (void)vu_closure_check(&s, &rep, &e);
    }
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0, "clock: %s", strerror(errno));

    double ms = ((double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                 (double)(t1.tv_nsec - t0.tv_nsec) / 1e6) / 20.0;
    /* Generous: this is a smoke bound, not a performance target. A real
     * installation adds the library directories and the hook walk, and it is
     * still filesystem metadata reads. */
    CHECK(ms < 250.0, "one closure check took %.1f ms, which is too slow to run "
                      "before every connect", ms);

    vu_rm_rf(g_base);
}

void vu_test_integration(void)
{
    test_execve_boundary();
    test_concurrent_connects();
    test_closure_cost();
}
