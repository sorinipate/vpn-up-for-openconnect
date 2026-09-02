/*
 * fake-openconnect.c — stands in for OpenConnect at the execve boundary.
 *
 * Step 11 of PRIVILEGED-HELPER-DESIGN.md §16. Two claims in §18 are marked
 * "integration test, not source inspection", and both are about what the process
 * on the far side of execve actually receives:
 *
 *   - the per-profile lock survives the execve and is released when OpenConnect
 *     exits, so "one tunnel per profile" holds with no process-table race;
 *   - stdin is passed through unread, so a cookie longer than any buffer in this
 *     project still arrives whole.
 *
 * Neither can be established by reading the helper's source: the first depends on
 * the kernel's flock semantics across execve, and the second on the helper never
 * touching the bytes. Both need a real second process, so here is one.
 *
 * It is a compiled C program rather than a shell script for a reason that is not
 * incidental: the closure check (§11.4) parses the pinned binary's ELF dynamic
 * section, and a script is refused with "not an ELF binary". A stand-in that
 * could not pass the real check would not be standing in for much.
 *
 * The report goes to STDOUT, not to a file named by an environment variable,
 * because the helper hands the child a constructed environment with only PATH
 * and the four VUP_* telemetry variables (connection-state design plan §2) —
 * a stand-in that needed a DIFFERENT env var to work would be testing a
 * different program than the one that ships.
 *
 * It reports what it sees and then waits for SIGTERM, so the parent can inspect
 * the lock while it is held and then observe the release. The timeout is a
 * backstop: a test that hangs is worse than a test that fails.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef FAKE_TIMEOUT_SECONDS
#define FAKE_TIMEOUT_SECONDS 20
#endif

extern char **environ;

static volatile sig_atomic_t got_term = 0;
static void on_term(int sig) { (void)sig; got_term = 1; }

/*
 * A cheap rolling checksum. Not cryptographic and not meant to be: the question
 * is "did every byte arrive, in order, unmodified", and for that a length plus a
 * position-sensitive sum over 100KB is conclusive enough while staying
 * dependency-free.
 */
static unsigned long long digest(unsigned long long h, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) h = h * 1000003u + p[i];
    return h;
}

int main(int argc, char **argv)
{
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);

    /*
     * Read stdin FIRST, before writing anything. The parent writes a cookie
     * larger than a pipe buffer and then reads this report, so any other order
     * deadlocks — and a deadlocked integration test is the classic way this kind
     * of harness becomes permanently disabled.
     */
    unsigned long long h = 1469598103934665603ull;
    unsigned long long total = 0;
    unsigned char first[16], last[16];
    size_t n_first = 0, n_last = 0;
    for (;;) {
        unsigned char buf[4096];
        ssize_t r = read(0, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        size_t got = (size_t)r;
        h = digest(h, buf, got);
        total += got;
        for (size_t i = 0; i < got && n_first < sizeof first; ++i) first[n_first++] = buf[i];
        n_last = got < sizeof last ? got : sizeof last;
        memcpy(last, buf + got - n_last, n_last);
    }

    printf("FAKE-REPORT-BEGIN\n");
    printf("argc=%d\n", argc);
    for (int i = 0; i < argc; ++i) printf("argv[%d]=%s\n", i, argv[i]);

    printf("stdin_bytes=%llu\n", total);
    printf("stdin_digest=%llu\n", h);
    printf("stdin_first=");
    for (size_t i = 0; i < n_first; ++i) printf("%02x", first[i]);
    printf("\nstdin_last=");
    for (size_t i = 0; i < n_last; ++i) printf("%02x", last[i]);
    printf("\n");

    char cwd[4096];
    printf("cwd=%s\n", getcwd(cwd, sizeof cwd) ? cwd : "(unavailable)");

    /* umask is read by setting it and putting it back. */
    mode_t um = umask(077);
    umask(um);
    printf("umask=%04o\n", (unsigned)um);

    size_t nenv = 0;
    for (char **e = environ; *e; ++e) { printf("env=%s\n", *e); nenv++; }
    printf("env_count=%zu\n", nenv);

    /*
     * Which descriptors are open. The helper closes everything above stderr
     * except the retained lock, so this is how a test confirms the lock survived
     * and nothing else came along with it.
     */
    printf("fds=");
    for (int fd = 0; fd < 64; ++fd)
        if (fcntl(fd, F_GETFD) >= 0) printf("%d,", fd);
    printf("\n");

    /*
     * Whether an inherited descriptor still holds a lock. LOCK_EX|LOCK_NB from
     * THIS process would succeed on a lock this process already owns (flock is
     * per-open-file-description and we inherited the description), so that tells
     * us nothing. The parent tests the lock from outside instead; what is useful
     * here is simply whether the descriptor is still a valid open file.
     */
    for (int fd = 3; fd < 64; ++fd) {
        struct stat st;
        if (fstat(fd, &st) == 0)
            printf("inherited_fd=%d size=%lld mode=%04o\n",
                   fd, (long long)st.st_size, (unsigned)(st.st_mode & 07777));
    }

#if defined(__linux__)
    /*
     * The process table, from the process itself. "The cookie never appears in
     * ps" is the claim; /proc/self/cmdline is what ps reads, so this is the
     * primary source rather than a proxy for it.
     */
    int cf = open("/proc/self/cmdline", O_RDONLY);
    if (cf >= 0) {
        char cmd[8192];
        ssize_t r = read(cf, cmd, sizeof cmd - 1);
        close(cf);
        if (r > 0) {
            for (ssize_t i = 0; i < r; ++i) if (cmd[i] == '\0') cmd[i] = ' ';
            cmd[r] = '\0';
            printf("proc_cmdline=%s\n", cmd);
        }
    }
#endif

    printf("pid=%ld\n", (long)getpid());
    printf("uid=%ld euid=%ld\n", (long)getuid(), (long)geteuid());
    printf("FAKE-REPORT-END\n");
    fflush(stdout);

    /*
     * Stay alive so the parent can observe the lock being HELD, then exit so it
     * can observe the release. SIGTERM is the normal path; the timeout only
     * matters if a test forgets, and it exits rather than hanging CI.
     */
    for (int i = 0; i < FAKE_TIMEOUT_SECONDS * 20 && !got_term; ++i) {
        struct timespec ts = { 0, 50 * 1000 * 1000 };
        (void)nanosleep(&ts, NULL);
    }
    return got_term ? 0 : 3;
}
