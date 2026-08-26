/*
 * test_state.c — corpus for the root state, locking, identity and hygiene
 * primitives (§16 step 5).
 *
 * Everything here runs UNPRIVILEGED. That is possible only because the two
 * things a privileged version would hardcode are parameters instead: the state
 * root (vu_state_paths_in) and the expected owner (vu_dir_ensure's expect_uid).
 * So the code under test is the same code that will run as root, rather than a
 * weakened copy of it — which is the entire point of building this layer before
 * privilege exists.
 */

#include "vu_state.h"
#include "harness.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>   /* getrlimit, struct rlimit, RLIMIT_CORE */
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_root[VU_PATH_MAX];

static void make_root(void)
{
    /* mkdtemp needs a writable template; TMPDIR is honoured where set. */
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    char base[VU_PATH_MAX];
    snprintf(base, sizeof base, "%s", tmp);
    size_t bn = strlen(base);
    while (bn > 1 && base[bn - 1] == '/') base[--bn] = '\0';   /* TMPDIR often ends in / */
    snprintf(g_root, sizeof g_root, "%s/vu-state-test-XXXXXX", base);
    if (!mkdtemp(g_root)) {
        fprintf(stderr, "cannot create temp root: %s\n", strerror(errno));
        exit(2);
    }
    /* The production contract is 0700 with no group/other bits; match it so the
     * checks under test are the real ones. */
    chmod(g_root, 0700);
}

static const char *PROFILE = "a7d1bb99-538c-4db4-b357-0123456789ab";

/* --------------------------------------------------------------- SUDO_UID */

static void test_sudo_uid(void)
{
    uid_t u; vu_err e;

    unsetenv("SUDO_UID");
    vu_err_clear(&e);
    CHECK(!vu_sudo_uid(&u, &e), "absent SUDO_UID refused rather than defaulted");

    /* A default here would silently merge two users' state, so every malformed
     * spelling has to fail rather than be coerced. */
    const char *bad[] = { "", "0", "abc", "501x", " 501", "0501", "-1", "99999999999" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        setenv("SUDO_UID", bad[i], 1);
        vu_err_clear(&e);
        CHECK(!vu_sudo_uid(&u, &e), "SUDO_UID='%s' refused", bad[i]);
    }

    setenv("SUDO_UID", "501", 1);
    vu_err_clear(&e);
    CHECK(vu_sudo_uid(&u, &e) && u == 501, "SUDO_UID=501 accepted: %s", e.msg);
    unsetenv("SUDO_UID");
}

/* ------------------------------------------------------------ path layout */

static void test_paths(void)
{
    vu_state_paths p; vu_err e;
    char want[VU_PATH_MAX];

    vu_err_clear(&e);
    CHECK(vu_state_paths_in("/run/vpn-up", 501, PROFILE, &p, &e), "paths built: %s", e.msg);
    snprintf(want, sizeof want, "/run/vpn-up/501/%s", PROFILE);
    CHECK(strcmp(p.profile_dir, want) == 0, "profile dir is uid-namespaced, got '%s'", p.profile_dir);
    snprintf(want, sizeof want, "/run/vpn-up/501/%s/lock", PROFILE);
    CHECK(strcmp(p.lock, want) == 0, "lock path");

    /* The uid component is what keeps one user from addressing another's
     * identically-named profile. */
    vu_state_paths q;
    vu_err_clear(&e);
    CHECK(vu_state_paths_in("/run/vpn-up", 502, PROFILE, &q, &e), "second uid");
    CHECK(strcmp(p.profile_dir, q.profile_dir) != 0, "different uids get different dirs");

    /* A non-canonical id must not be able to build a path at all. */
    vu_err_clear(&e);
    CHECK(!vu_state_paths_in("/run/vpn-up", 501, "../../etc", &p, &e), "traversal refused");
    vu_err_clear(&e);
    CHECK(!vu_state_paths_in("/run/vpn-up", 501, "..", &p, &e), "'..' refused");
    vu_err_clear(&e);
    CHECK(!vu_state_paths_in("/run/vpn-up", 501, ".", &p, &e), "'.' refused");
    vu_err_clear(&e);
    CHECK(!vu_state_paths_in("/run/vpn-up", 501, "a/b", &p, &e), "embedded slash refused");
    vu_err_clear(&e);
    CHECK(!vu_state_paths_in("/run/vpn-up", 501, "", &p, &e), "empty id refused");
    {
        char big[VU_PATH_MAX * 2];
        memset(big, 'a', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        vu_err_clear(&e);
        CHECK(!vu_state_paths_in("/run/vpn-up", 501, big, &p, &e), "over-long id refused");
    }
}

/* -------------------------------------------------------- directory safety */

static void test_dir_ensure(void)
{
    vu_err e;
    uid_t me = geteuid();
    char dir[VU_PATH_MAX], sub[VU_PATH_MAX];

    /* One owned directory per call: the chain is built explicitly, which is the
     * documented usage now that a blanket no-follow walk is known to be
     * impossible on macOS. */
    snprintf(sub, sizeof sub, "%s/a", g_root);
    vu_err_clear(&e);
    CHECK(vu_dir_ensure(sub, me, 0700, &e), "first level created: %s", e.msg);
    snprintf(sub, sizeof sub, "%s/a/b", g_root);
    vu_err_clear(&e);
    CHECK(vu_dir_ensure(sub, me, 0700, &e), "second level created: %s", e.msg);
    snprintf(dir, sizeof dir, "%s/a/b/c", g_root);
    vu_err_clear(&e);
    CHECK(vu_dir_ensure(dir, me, 0700, &e), "third level created: %s", e.msg);

    /* A missing parent is an explicit error, not a silent mkdir -p. */
    char orphan[VU_PATH_MAX];
    snprintf(orphan, sizeof orphan, "%s/nope/deeper", g_root);
    vu_err_clear(&e);
    CHECK(!vu_dir_ensure(orphan, me, 0700, &e), "missing parent refused");
    CHECK(strstr(e.msg, "parent") != NULL, "refusal names the parent: '%s'", e.msg);
    struct stat st;
    CHECK(stat(dir, &st) == 0 && S_ISDIR(st.st_mode), "dir exists");
    CHECK((st.st_mode & 07777) == 0700, "created 0700, got %04o", (unsigned)(st.st_mode & 07777));

    vu_err_clear(&e);
    CHECK(vu_dir_ensure(dir, me, 0700, &e), "idempotent: %s", e.msg);

    /* Ownership and mode are contract, not preference: a group-writable
     * directory is refused even though we own it. */
    snprintf(sub, sizeof sub, "%s/loose", g_root);
    CHECK(mkdir(sub, 0770) == 0, "made group-writable dir");
    vu_err_clear(&e);
    CHECK(!vu_dir_ensure(sub, me, 0700, &e), "group-writable dir refused");
    CHECK(strstr(e.msg, "group") != NULL, "refusal names the reason: '%s'", e.msg);

    snprintf(sub, sizeof sub, "%s/world", g_root);
    CHECK(mkdir(sub, 0707) == 0, "made other-writable dir");
    vu_err_clear(&e);
    CHECK(!vu_dir_ensure(sub, me, 0700, &e), "other-writable dir refused");

    /* Wrong owner: we cannot chown without privilege, so assert the check by
     * expecting an owner we are not. */
    snprintf(sub, sizeof sub, "%s/owned", g_root);
    CHECK(mkdir(sub, 0700) == 0, "made dir");
    vu_err_clear(&e);
    CHECK(!vu_dir_ensure(sub, me + 1, 0700, &e), "wrong owner refused");
    CHECK(strstr(e.msg, "owned by") != NULL, "refusal names the owner: '%s'", e.msg);

    /*
     * Symlink policy, which is narrower than revision 3 §11.4 claimed and needs
     * stating precisely because the difference is security-relevant:
     *
     *   - a symlink AT THE LEAF is refused. That is the component we create and
     *     verify, and following it would mean root writing wherever the link
     *     points.
     *   - a symlink in the PARENT chain is followed. It has to be: on macOS /var
     *     is a symlink, so refusing would make /var/run/vpn-up unreachable. This
     *     is safe for the directories we own because each was already verified
     *     as a real, root-owned, 0700 directory by its own vu_dir_ensure call —
     *     so no unprivileged party can plant a link inside the chain. Above the
     *     state root the prefix is system infrastructure, and if that is
     *     subverted nothing here helps.
     */
    char target[VU_PATH_MAX], link[VU_PATH_MAX], through[VU_PATH_MAX];
    snprintf(target, sizeof target, "%s/real", g_root);
    snprintf(link,   sizeof link,   "%s/link", g_root);
    CHECK(mkdir(target, 0700) == 0, "made link target");
    CHECK(symlink(target, link) == 0, "made symlink");

    vu_err_clear(&e);
    CHECK(!vu_dir_ensure(link, me, 0700, &e), "symlinked final component refused");
    CHECK(strstr(e.msg, "symlink") != NULL, "refusal names the reason: '%s'", e.msg);

    snprintf(through, sizeof through, "%s/deeper", link);
    vu_err_clear(&e);
    CHECK(vu_dir_ensure(through, me, 0700, &e),
          "a symlinked PARENT is followed, by design: %s", e.msg);
    {
        /* And it lands in the real target, not somewhere else. */
        char resolved[VU_PATH_MAX];
        snprintf(resolved, sizeof resolved, "%s/deeper", target);
        struct stat ls;
        CHECK(lstat(resolved, &ls) == 0 && S_ISDIR(ls.st_mode),
              "created inside the link target");
    }

    /* A plain file where a directory belongs. */
    char file[VU_PATH_MAX];
    snprintf(file, sizeof file, "%s/afile", g_root);
    int fd = open(file, O_CREAT | O_WRONLY, 0600);
    CHECK(fd >= 0, "made file");
    close(fd);
    vu_err_clear(&e);
    CHECK(!vu_dir_ensure(file, me, 0700, &e), "file where a directory belongs refused");

    vu_err_clear(&e);
    CHECK(!vu_dir_ensure("relative/path", me, 0700, &e), "relative path refused");
}

/* -------------------------------------------------------- effective writability */

static void test_writable_by(void)
{
    vu_err e;
    uid_t me = geteuid();
    char f[VU_PATH_MAX];
    bool w;

    snprintf(f, sizeof f, "%s/wtest", g_root);
    int fd = open(f, O_CREAT | O_WRONLY, 0600);
    CHECK(fd >= 0, "made writable file");
    close(fd);

    vu_err_clear(&e);
    CHECK(vu_writable_by(f, me, &w, &e) && w, "own 0600 file is writable: %s", e.msg);

    CHECK(chmod(f, 0400) == 0, "chmod 0400");
    vu_err_clear(&e);
    CHECK(vu_writable_by(f, me, &w, &e) && !w, "own 0400 file is not writable: %s", e.msg);

    /* Probing a different uid needs root. Reporting a confident "false" without
     * privilege would be worse than refusing, because a false negative here
     * reads as "safe". */
    if (me != 0) {
        vu_err_clear(&e);
        CHECK(!vu_writable_by(f, me + 1, &w, &e), "probing another uid without root refused");
        CHECK(strstr(e.msg, "root") != NULL, "refusal explains why: '%s'", e.msg);
    }
}

/* ------------------------------------------------------------------ locking */

static void test_locking(void)
{
    vu_err e;
    uid_t me = geteuid();
    vu_state_paths p;

    vu_err_clear(&e);
    CHECK(vu_state_paths_in(g_root, me, PROFILE, &p, &e), "paths: %s", e.msg);

    int fd = -1;
    vu_err_clear(&e);
    CHECK(vu_lock_acquire(&p, me, &fd, &e) && fd >= 0, "lock acquired: %s", e.msg);

    /* Must survive execve, or the "one tunnel per profile" guarantee evaporates
     * the moment the helper hands off to OpenConnect. */
    int flags = fcntl(fd, F_GETFD);
    CHECK(flags >= 0 && !(flags & FD_CLOEXEC), "FD_CLOEXEC cleared so the lock survives execve");

    /* flock is per-open-file-description, so a second acquire conflicts even
     * from the same process — which is what makes the second connect fail fast
     * instead of racing. */
    int fd2 = -1;
    vu_err_clear(&e);
    CHECK(!vu_lock_acquire(&p, me, &fd2, &e), "second acquire refused while held");
    CHECK(strstr(e.msg, "already has a tunnel") != NULL, "refusal is intelligible: '%s'", e.msg);
    CHECK(fd2 == -1, "no descriptor leaked on the failed acquire");

    vu_lock_release(fd);
    vu_err_clear(&e);
    CHECK(vu_lock_acquire(&p, me, &fd2, &e), "re-acquire after release: %s", e.msg);
    vu_lock_release(fd2);

    /* A symlinked lock path must not be followed: that is a root-owned write
     * pointed wherever the attacker likes. */
    char other[VU_PATH_MAX];
    snprintf(other, sizeof other, "%s/target-lock", g_root);
    unlink(p.lock);
    CHECK(symlink(other, p.lock) == 0, "symlinked the lock path");
    vu_err_clear(&e);
    CHECK(!vu_lock_acquire(&p, me, &fd2, &e), "symlinked lock refused");
    unlink(p.lock);
}

/* ------------------------------------------------------- identity and record */

static void test_identity_and_record(void)
{
    vu_err e;
    uid_t me = geteuid();
    vu_state_paths p;
    vu_err_clear(&e);
    CHECK(vu_state_paths_in(g_root, me, PROFILE, &p, &e), "paths");
    CHECK(vu_dir_ensure(p.uid_dir, me, 0700, &e), "uid dir: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_dir_ensure(p.profile_dir, me, 0700, &e), "profile dir: %s", e.msg);

    vu_proc self;
    vu_err_clear(&e);
    CHECK(vu_proc_identity(getpid(), &self, &e), "own identity readable: %s", e.msg);
    CHECK(self.pid == getpid(), "pid matches");
    CHECK(self.exe[0] == '/', "executable path is absolute, got '%s'", self.exe);
    CHECK(self.start_token != 0, "start token is set");

    /* A pid that has exited must not be reported as running. */
    pid_t child = fork();
    if (child == 0) _exit(0);
    int st = 0;
    waitpid(child, &st, 0);
    vu_proc dead;
    vu_err_clear(&e);
    CHECK(!vu_proc_identity(child, &dead, &e), "exited pid is not identifiable");

    /* Record, then verify. */
    vu_err_clear(&e);
    CHECK(vu_state_record(&p, &self, "https://vpn.example.com:443", &e), "recorded: %s", e.msg);

    vu_state_status status;
    vu_proc found;
    vu_err_clear(&e);
    CHECK(vu_state_check(&p, self.exe, &status, &found, &e), "check ran: %s", e.msg);
    CHECK(status == VU_STATE_LIVE, "own process reads back as live");

    /*
     * The pid-reuse case. Same pid number, different process: the start token
     * differs, so this must be STALE. Without this, `stop` running as root would
     * signal whatever unrelated process now holds the number — exactly the hole
     * `sudo kill "$pid"` leaves open today.
     */
    {
        FILE *f = fopen(p.started, "w");
        CHECK(f != NULL, "rewrite started");
        if (f) { fprintf(f, "%llu\n", (unsigned long long)(self.start_token + 1)); fclose(f); }
        vu_err_clear(&e);
        CHECK(vu_state_check(&p, self.exe, &status, &found, &e), "check ran");
        CHECK(status == VU_STATE_STALE, "start-token mismatch is stale, not live");
    }

    /* A different executable at the same live pid is also stale. */
    vu_err_clear(&e);
    CHECK(vu_state_record(&p, &self, NULL, &e), "re-recorded");
    vu_err_clear(&e);
    CHECK(vu_state_check(&p, "/usr/bin/definitely-not-us", &status, &found, &e), "check ran");
    CHECK(status == VU_STATE_STALE, "executable mismatch is stale");

    /* Garbage in the pid file is stale by definition — never signalled. */
    {
        FILE *f = fopen(p.pid, "w");
        if (f) { fprintf(f, "not-a-pid\n"); fclose(f); }
        vu_err_clear(&e);
        CHECK(vu_state_check(&p, self.exe, &status, &found, &e), "check ran");
        CHECK(status == VU_STATE_STALE, "unparseable pid is stale");
    }

    /* Missing state is ABSENT, which is a normal condition rather than an error. */
    vu_err_clear(&e);
    CHECK(vu_state_prune(&p, &e), "pruned: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_state_check(&p, self.exe, &status, &found, &e), "check ran on empty state: %s", e.msg);
    CHECK(status == VU_STATE_ABSENT, "no record reads as absent");
    vu_err_clear(&e);
    CHECK(vu_state_prune(&p, &e), "prune is idempotent: %s", e.msg);
}

/* ------------------------------------------------------------------ hygiene */

/* Run in a child, because vu_harden_process deliberately mutates the process
 * (cwd, rlimits, descriptors) and the rest of the corpus should not inherit
 * that. Exit codes report which assertion failed. */
static void test_harden(void)
{
    char probe[VU_PATH_MAX];
    snprintf(probe, sizeof probe, "%s/probe", g_root);
    int keep = open(probe, O_CREAT | O_RDWR, 0600);
    CHECK(keep >= 0, "made keep fd");

    int doomed = dup(keep);
    CHECK(doomed >= 0, "made a second fd that must be closed");

    pid_t pid = fork();
    if (pid == 0) {
        vu_err e; vu_err_clear(&e);
        if (!vu_harden_process(keep, &e)) _exit(10);

        char cwd[VU_PATH_MAX];
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/") != 0) _exit(11);

        struct rlimit rl;
        if (getrlimit(RLIMIT_CORE, &rl) != 0 || rl.rlim_cur != 0) _exit(12);

        if (fcntl(keep, F_GETFD) < 0) _exit(13);           /* must survive */
        if (fcntl(doomed, F_GETFD) >= 0) _exit(14);        /* must be closed */

        char **env = vu_clean_env();
        if (!env || !env[0] || env[1] != NULL) _exit(15);
        if (strncmp(env[0], "PATH=", 5) != 0) _exit(16);
        if (env[0][5] == '\0') _exit(17);                  /* never empty: see the
                                                             vpnc-script PATH note */
        _exit(0);
    }

    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st), "hygiene child exited normally");
    CHECK(WEXITSTATUS(st) == 0, "hygiene checks passed (exit %d)", WEXITSTATUS(st));
    close(keep);
}

/* --------------------------------------------------------------------- entry */

void vu_test_state(void)
{
    make_root();
    test_sudo_uid();
    test_paths();
    test_dir_ensure();
    test_writable_by();
    test_locking();
    test_identity_and_record();
    test_harden();
    vu_rm_rf(g_root);
}
