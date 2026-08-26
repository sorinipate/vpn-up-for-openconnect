/* closure.c — the trusted execution closure walk (§11.4, §16 step 10). */

#include "vu_closure.h"
#include "vu_elf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void vu_closure_spec_default(vu_closure_spec *s, const char *openconnect,
                             const char *script, uid_t owner)
{
    if (!s) return;
    memset(s, 0, sizeof *s);
    s->openconnect   = openconnect;
    s->script        = script;
    s->shell         = "/bin/sh";
    s->path_env      = VU_HELPER_PATH;
    s->hooks_root    = "/etc/vpnc";
    s->ldso_preload  = VU_LDSO_PRELOAD;
    s->ldso_conf     = VU_LDSO_CONF;
    s->ldso_conf_dir = VU_LDSO_CONF_DIR;
    s->owner         = owner;
    /*
     * NOT owner. The probe asks "can the CALLER write this despite the mode
     * bits", so it needs the calling user's uid - SUDO_UID - and owner is 0 in
     * production. Defaulting it to owner is the bug that shipped in step 10 and
     * failed the first time anything ran as root. Callers that enable the probe
     * must set this; vu_closure_check refuses the combination otherwise.
     */
    s->probe_uid     = 0;
    s->probe         = false;
}

/* ------------------------------------------------------------------ report */

static vu_closure_item *slot(vu_closure_report *r, const char *role, const char *path)
{
    if (r->n >= VU_CLOSURE_MAX) { r->truncated = true; return NULL; }
    vu_closure_item *it = &r->items[r->n++];
    memset(it, 0, sizeof *it);
    it->role = role;
    snprintf(it->path, sizeof it->path, "%s", path);
    return it;
}

static void record(vu_closure_report *r, const char *role, const char *path,
                   bool ok, bool checked, const char *reason)
{
    vu_closure_item *it = slot(r, role, path);
    if (!it) return;
    it->ok = ok;
    it->checked = checked;
    if (!ok) {
        r->n_failed++;
        snprintf(it->reason, sizeof it->reason, "%s", reason ? reason : "refused");
    }
}

/* A file that must be trusted. want_exec distinguishes "root runs this" from
 * "root sources this" — a sourced hook needs no execute bit, which is exactly
 * why directory ownership is what protects the hook directories. */
static void check_file(vu_closure_report *r, const char *role, const char *path,
                       uid_t owner, bool want_exec)
{
    vu_err e; vu_err_clear(&e);
    bool ok = vu_path_trusted(path, owner, want_exec, &e);
    record(r, role, path, ok, true, e.msg);
}

static void check_dir(vu_closure_report *r, const char *role, const char *path, uid_t owner)
{
    vu_err e; vu_err_clear(&e);
    bool ok = vu_dir_trusted(path, owner, &e);
    record(r, role, path, ok, true, e.msg);
}

static bool exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* --------------------------------------------------------------- interpreter */

/*
 * The script's shebang, if it has one.
 *
 * OpenConnect runs vpnc-script through execl("/bin/sh", "-c", ...), so /bin/sh
 * is the interpreter that matters and is checked unconditionally. The shebang is
 * checked as well because it is what runs if the script is ever executed
 * directly, and because a shebang naming something in a user-writable prefix is
 * a clear signal about the installation regardless of who invokes it.
 */
static void check_shebang(vu_closure_report *r, const char *script, uid_t owner)
{
    int fd = open(script, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;                     /* the script itself is checked separately */
    char head[256];
    ssize_t got = read(fd, head, sizeof head - 1);
    close(fd);
    if (got < 3) return;
    head[got] = '\0';
    if (head[0] != '#' || head[1] != '!') return;

    char *p = head + 2;
    while (*p == ' ' || *p == '\t') p++;
    char *end = p;
    while (*end && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') end++;
    *end = '\0';
    if (p[0] != '/') return;                /* relative interpreter: not ours to resolve */

    check_file(r, "script interpreter (shebang)", p, owner, true);
}

/* ----------------------------------------------------------- sourced hooks */

/*
 * The hook root and its per-event hook directories.
 *
 * run_hooks() in the shipped vpnc-script SOURCES every file in the matching
 * hook directory — `. $script`, not an exec — which was verified by reading the
 * installed script, not assumed. Two consequences, and both are why this is a
 * separate check rather than a variation on the file checks above:
 *
 *   - the execute bit is irrelevant, so a hook does not have to look runnable
 *     to run;
 *   - DIRECTORY writability is the control. A user who can create a file in one
 *     of these directories gets root on the next connect, without touching any
 *     file that already exists.
 *
 * Existing hooks are checked too, since a writable hook file is the same hole
 * reached a different way. Absent is fine and common: most installations have
 * no hooks at all.
 */
static void check_hooks(vu_closure_report *r, const char *root, uid_t owner)
{
    if (!exists(root)) {
        record(r, "hook root (absent, nothing sourced)", root, true, true, NULL);
        return;
    }
    check_dir(r, "hook root (contents are SOURCED as root)", root, owner);

    DIR *d = opendir(root);
    if (!d) {
        record(r, "hook root", root, false, false, strerror(errno));
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        size_t len = strlen(ent->d_name);
        if (len < 3 || strcmp(ent->d_name + len - 2, ".d") != 0) continue;

        char sub[VU_PATH_MAX];
        if (snprintf(sub, sizeof sub, "%s/%s", root, ent->d_name) >= (int)sizeof sub) {
            record(r, "hook directory", ent->d_name, false, false, "path too long");
            continue;
        }
        struct stat st;
        if (lstat(sub, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        check_dir(r, "hook directory (contents are SOURCED as root)", sub, owner);

        DIR *hd = opendir(sub);
        if (!hd) continue;
        struct dirent *h;
        while ((h = readdir(hd)) != NULL) {
            if (h->d_name[0] == '.') continue;
            char hook[VU_PATH_MAX];
            if (snprintf(hook, sizeof hook, "%s/%s", sub, h->d_name) >= (int)sizeof hook) continue;
            /* want_exec = false: these are sourced, not executed. */
            check_file(r, "sourced hook", hook, owner, false);
        }
        closedir(hd);
    }
    closedir(d);
}

/* ------------------------------------------------------------- PATH entries */

static void check_path_entries(vu_closure_report *r, const char *path_env, uid_t owner)
{
    if (!path_env || !*path_env) {
        record(r, "PATH", "(empty)", false, true,
               "an empty PATH becomes a trailing colon in vpnc-script, which means the cwd");
        return;
    }
    const char *p = path_env;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t len = colon ? (size_t)(colon - p) : strlen(p);
        char dir[VU_PATH_MAX];
        if (len == 0) {
            record(r, "PATH entry", "(empty)", false, true,
                   "an empty PATH entry means the current directory");
        } else if (len + 1 > sizeof dir) {
            record(r, "PATH entry", "(too long)", false, false, "path too long");
        } else {
            memcpy(dir, p, len);
            dir[len] = '\0';
            if (dir[0] != '/') {
                record(r, "PATH entry", dir, false, true, "relative PATH entry");
            } else if (!exists(dir)) {
                /* A PATH entry that does not exist cannot be searched, but it
                 * CAN be created later by whoever owns its parent — so the
                 * parent chain still has to be trustworthy. */
                vu_err e; vu_err_clear(&e);
                char parent[VU_PATH_MAX];
                snprintf(parent, sizeof parent, "%s", dir);
                char *slash = strrchr(parent, '/');
                if (slash && slash != parent) *slash = '\0';
                bool ok = vu_dir_trusted(parent, owner, &e);
                record(r, "PATH entry (absent; parent checked)", dir, ok, true, e.msg);
            } else {
                check_dir(r, "PATH entry (vpnc-script resolves tools here)", dir, owner);
            }
        }
        if (!colon) break;
        p = colon + 1;
    }
}

/* ------------------------------------------------- library closure (Linux) */

/*
 * Read a newline-separated list of paths from a root-owned config file, ignoring
 * comments and blank lines. Used for /etc/ld.so.preload and ld.so.conf.
 * `include` directives in ld.so.conf are reported rather than followed: they are
 * globs, and a glob we do not expand is a set of directories we cannot claim to
 * have verified.
 */
#if VU_LIBRARY_CLOSURE_ELF
/* ELF/ld.so-only, like its callers: guarded so a build without that path does
 * not carry an unused function (and -Werror does not reject it). */
static void check_ldso_list(vu_closure_report *r, const char *file, uid_t owner,
                            bool entries_are_files, const char *role,
                            const char *entry_role)
{
    if (!exists(file)) {
        record(r, role, file, true, true, NULL);      /* absent is the good case */
        return;
    }
    check_file(r, role, file, owner, false);

    FILE *f = fopen(file, "r");
    if (!f) {
        record(r, role, file, false, false, strerror(errno));
        return;
    }
    char line[VU_PATH_MAX];
    while (fgets(line, sizeof line, f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        char *nl = strpbrk(s, "\r\n");
        if (nl) *nl = '\0';
        if (!*s || *s == '#') continue;

        if (strncmp(s, "include", 7) == 0 && (s[7] == ' ' || s[7] == '\t')) {
            /* Not followed: see above. Recorded so the report is honest about
             * what it did not check. */
            record(r, "ld.so.conf include (not expanded by this check)", s, true, false, NULL);
            continue;
        }
        if (*s != '/') {
            record(r, entry_role, s, false, true, "not an absolute path");
            continue;
        }
        if (!exists(s)) continue;                     /* nothing to load from */
        if (entries_are_files) check_file(r, entry_role, s, owner, false);
        else                   check_dir(r, entry_role, s, owner);
    }
    fclose(f);
}
#endif /* VU_LIBRARY_CLOSURE_ELF */

static void check_libraries(vu_closure_report *r, const vu_closure_spec *s)
{
#if VU_LIBRARY_CLOSURE_ELF
    /*
     * The property being established is NOT "every library is trusted" by
     * enumeration — it is "every directory the loader will search is trusted".
     * With LD_LIBRARY_PATH and LD_PRELOAD stripped by vu_clean_env, a library can
     * only come from DT_RPATH/DT_RUNPATH, /etc/ld.so.preload, or the
     * ld.so.conf-configured and default directories. Verify that set and every
     * library that CAN be loaded is covered, including ones this code has never
     * heard of and anything dlopen'd at runtime.
     */
    vu_elf_info info;
    vu_err e; vu_err_clear(&e);
    if (!vu_elf_dynamic(s->openconnect, &info, &e)) {
        record(r, "library closure", s->openconnect, false, false, e.msg);
        return;
    }
    if (!info.is_elf) {
        record(r, "library closure", s->openconnect, false, true,
               "the pinned openconnect is not an ELF binary");
        return;
    }
    if (info.truncated) {
        record(r, "library closure", s->openconnect, false, true,
               "more libraries or search paths than this check can enumerate");
    }

    /* RPATH/RUNPATH first: these are searched before the system directories, so
     * a writable entry here beats everything else. */
    for (size_t i = 0; i < info.n_rpath; ++i) {
        if (!exists(info.rpath[i])) continue;
        check_dir(r, info.had_runpath ? "DT_RUNPATH library directory"
                                      : "DT_RPATH library directory",
                  info.rpath[i], s->owner);
    }

    check_ldso_list(r, s->ldso_preload, s->owner, true,
                    "/etc/ld.so.preload (loaded into every process)",
                    "preloaded library");
    check_ldso_list(r, s->ldso_conf, s->owner, false,
                    "ld.so.conf", "configured library directory");

    if (exists(s->ldso_conf_dir)) {
        /* The directory itself matters as much as its contents: a user who can
         * add a .conf file there adds a library search directory. */
        check_dir(r, "ld.so.conf.d (adds library search directories)", s->ldso_conf_dir, s->owner);
        DIR *d = opendir(s->ldso_conf_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char conf[VU_PATH_MAX];
                if (snprintf(conf, sizeof conf, "%s/%s", s->ldso_conf_dir, ent->d_name)
                        >= (int)sizeof conf) continue;
                check_ldso_list(r, conf, s->owner, false,
                                "ld.so.conf.d entry", "configured library directory");
            }
            closedir(d);
        }
    }

    /* The loader's built-in directories. Only those that exist; the list covers
     * the multiarch layouts Debian and Fedora use. */
    static const char *const builtin_libdirs[] = {
        "/lib", "/usr/lib", "/lib64", "/usr/lib64",
        "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
    };
    const char *const *libdirs = builtin_libdirs;
    size_t n_libdirs = sizeof builtin_libdirs / sizeof *builtin_libdirs;
    if (s->no_default_libdirs) { libdirs = NULL; n_libdirs = 0; }
    else if (s->default_libdirs) { libdirs = s->default_libdirs; n_libdirs = s->n_default_libdirs; }

    for (size_t i = 0; i < n_libdirs; ++i)
        if (exists(libdirs[i]))
            check_dir(r, "default library directory", libdirs[i], s->owner);

    /* Informational: the concrete list of what is being trusted. A person
     * reading a refusal wants to see this. */
    for (size_t i = 0; i < info.n_needed; ++i)
        record(r, "linked library (resolved from the directories above)",
               info.needed[i], true, false, NULL);
#else
    /*
     * §11.7: macOS helper mode is unavailable until this exists, and it fails
     * CLOSED rather than being weakened. The work is step 13 — Mach-O
     * LC_LOAD_DYLIB, the dyld shared cache, and the DYLD_* search rules are a
     * different mechanism from ELF and ld.so, not a port of it.
     */
    record(r, "library closure", s->openconnect, false, false,
           "trusted OpenConnect execution closure could not be established: "
           "the macOS dynamic library closure is not implemented yet (design step 13)");
#endif
}

/* --------------------------------------------------------- ACL probe (§11.5) */

/*
 * Ownership plus mode bits do not prove non-writability: a file can be
 * root:wheel 0755 while an ACL grants the invoking user write access. For the
 * two or three FIXED objects, ask the kernel by dropping privilege and testing.
 *
 * TOCTOU, and therefore defence-in-depth detection rather than enforcement —
 * the primary protection remains that the parents are root-owned. Never called
 * on a caller-supplied path.
 */
static void check_acls(vu_closure_report *r, const vu_closure_spec *s)
{
    const char *fixed[] = { s->openconnect, s->script, s->shell };
    for (size_t i = 0; i < sizeof fixed / sizeof *fixed; ++i) {
        if (!fixed[i] || !exists(fixed[i])) continue;
        bool writable = false;
        vu_err e; vu_err_clear(&e);
        if (!vu_writable_by(fixed[i], s->probe_uid, &writable, &e)) {
            record(r, "effective-writability probe", fixed[i], false, false, e.msg);
            continue;
        }
        if (writable) {
            char why[VU_ERR_MAX];
            snprintf(why, sizeof why,
                     "uid %lu can write this despite its mode bits (an ACL, most likely)",
                     (unsigned long)s->probe_uid);
            record(r, "effective-writability probe", fixed[i], false, true, why);
        } else {
            record(r, "effective-writability probe", fixed[i], true, true, NULL);
        }
    }
}

/* --------------------------------------------------------------------- walk */

bool vu_closure_check(const vu_closure_spec *s, vu_closure_report *out, vu_err *e)
{
    if (!s || !out) { vu_err_set(e, "closure: null argument"); return false; }
    memset(out, 0, sizeof *out);

    if (!s->openconnect || !s->script || !s->shell) {
        vu_err_set(e, "closure: spec is incomplete");
        return false;
    }
    /* Fail fast and legibly rather than in a forked child four frames down. */
    if (s->probe && s->probe_uid == 0) {
        vu_err_set(e, "closure: the effective-writability probe needs the calling "
                      "user's uid, not 0");
        return false;
    }

    check_file(out, "openconnect binary (executed as root)", s->openconnect, s->owner, true);
    check_libraries(out, s);
    check_file(out, "/bin/sh (OpenConnect runs the script through it)", s->shell, s->owner, true);
    check_file(out, "vpnc-script (executed as root on every connect)", s->script, s->owner, true);
    check_shebang(out, s->script, s->owner);
    check_hooks(out, s->hooks_root, s->owner);
    check_path_entries(out, s->path_env, s->owner);
    if (s->probe) check_acls(out, s);

    if (out->truncated) {
        vu_err_set(e, "closure: more objects than the report can hold (%d); "
                      "refusing rather than reporting a partial verdict", VU_CLOSURE_MAX);
        return false;
    }
    if (out->n_failed > 0) {
        vu_err_set(e, "closure: %zu of %zu objects in the privileged execution path "
                      "are not trustworthy", out->n_failed, out->n);
        return false;
    }
    return true;
}

void vu_closure_print(const vu_closure_report *r, FILE *to)
{
    if (!r || !to) return;

    /* Failures first: on a machine where this refuses, that is the only part
     * anyone needs to read. */
    for (size_t pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i < r->n; ++i) {
            const vu_closure_item *it = &r->items[i];
            bool bad = !it->ok;
            if ((pass == 0) != bad) continue;
            if (bad)
                fprintf(to, "  [!!] %-52s %s\n       %s\n", it->role, it->path, it->reason);
            else if (it->checked)
                fprintf(to, "  [OK] %-52s %s\n", it->role, it->path);
            else
                fprintf(to, "  [..] %-52s %s\n", it->role, it->path);
        }
    }
    if (r->truncated)
        fprintf(to, "  [!!] the closure has more objects than this report can hold\n");
}
