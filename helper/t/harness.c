#include "harness.h"

#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int vu_checks   = 0;
int vu_failures = 0;

/* Depth-first removal via directory fds, so no path is ever reassembled into a
 * string and handed to anything that interprets it. */
static void rm_at(int dirfd)
{
    DIR *d = fdopendir(dirfd);
    if (!d) { close(dirfd); return; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        if (unlinkat(dirfd, ent->d_name, 0) == 0) continue;
        /* Linux reports EISDIR here, the BSDs report EPERM: handle both rather
         * than assuming one platform's errno. */
        if (errno != EISDIR && errno != EPERM && errno != ENOTEMPTY) continue;

        int sub = openat(dirfd, ent->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub >= 0) rm_at(sub);                   /* rm_at closes sub */
        (void)unlinkat(dirfd, ent->d_name, AT_REMOVEDIR);
    }
    closedir(d);                                    /* closes dirfd */
}

void vu_rm_rf(const char *path)
{
    if (!path || !*path) return;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { (void)unlink(path); return; }
    rm_at(fd);
    (void)rmdir(path);
}

void vu_path(char *out, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, cap, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= cap) {
        /* Abort rather than continue on a shortened path: a test that quietly
         * operates on the wrong directory is worse than one that stops. The
         * realistic trigger is an unusually long TMPDIR. */
        fprintf(stderr, "test harness: path needs %d bytes, buffer holds %zu "
                        "(is TMPDIR unusually long?)\n", n, cap);
        exit(2);
    }
}

const char *vu_test_base(void)
{
    /*
     * Where fixtures live, from the PASSWORD DATABASE rather than $HOME.
     *
     * Three reasons, in ascending order of how much they matter:
     *
     *  1. $HOME is caller-controlled and pw_dir is not. For a corpus whose whole
     *     subject is code that must not trust its environment, reading the
     *     environment to decide where to write is the wrong instinct.
     *
     *  2. t/test_adversarial.c's test_environment() DELIBERATELY clobbers HOME,
     *     to prove it does not survive into the exec'd process. The first version
     *     of that test broke every fixture created after it, and needed strdup'd
     *     save/restore to stop doing so. A corpus that never reads $HOME cannot
     *     have that failure mode at all - the restore is now hygiene rather than
     *     load-bearing.
     *
     *  3. It removes the taint source behind CodeQL's cpp/system-data-exposure
     *     (CWE-497), which fired on every fixture message that prints its path.
     *     That was a false positive - a test writing to its own stderr is not a
     *     service leaking to a remote user - but the first two reasons stand on
     *     their own, and a fix that is correct for independent reasons is better
     *     than an annotation.
     *
     * The fallback is "." rather than $HOME: tests run from helper/, which is
     * writable, and falling back to the environment would put the caller-
     * controlled value back on a path this function exists to keep off it.
     * getpwuid can legitimately return NULL in a container whose uid is not in
     * /etc/passwd.
     */
    static char base[1024];
    if (base[0]) return base;

    const struct passwd *pw = getpwuid(getuid());
    const char *dir = (pw && pw->pw_dir && pw->pw_dir[0]) ? pw->pw_dir : ".";
    vu_path(base, sizeof base, "%s", dir);

    /* A trailing slash would produce "//" in every fixture path below it. */
    size_t n = strlen(base);
    while (n > 1 && base[n - 1] == '/') base[--n] = '\0';
    return base;
}
