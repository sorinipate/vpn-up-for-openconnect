#include "harness.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
