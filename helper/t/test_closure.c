/*
 * test_closure.c — the trusted execution closure (§11.4), step 10 of §16.
 *
 * Two halves, and they need different techniques:
 *
 *  1. The ELF reader. Pure byte parsing, so it is tested against ELF images
 *     BUILT HERE, byte by byte, rather than against whatever binary happens to
 *     be installed. That is not a workaround for having no Linux toolchain on
 *     the development machine (though it is also that): a synthesised image is
 *     the only way to test a truncated header, a string table pointing outside
 *     the file, a big-endian ELF32, or a DT_RUNPATH of "$ORIGIN/../lib" on
 *     demand and deterministically.
 *
 *  2. The closure walk. Fixture trees, with the expected owner and every root
 *     as parameters, exactly as steps 5 to 7 do it.
 *
 * The §18 checklist this implements: a user-owned binary, a group-writable
 * parent, a symlink component, a user-writable hook directory, a user-writable
 * PATH entry, and a Homebrew-shaped installation must each be refused. Plus the
 * ACL case, which is genuinely testable on macOS with chmod +a.
 */

#include "harness.h"
#include "vu_closure.h"
#include "vu_elf.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_base[VU_PATH_MAX];

static void make_base(const char *tag)
{
    vu_path(g_base, sizeof g_base, "%s/.vpn-up-closure-%s-%ld",
            vu_test_base(), tag, (long)getpid());
    vu_rm_rf(g_base);
    CHECK(mkdir(g_base, 0700) == 0, "cannot create %s: %s", g_base, strerror(errno));
}

static void drop_base(void) { vu_rm_rf(g_base); }

/*
 * Fixture creation, with the mode set through the DESCRIPTOR rather than the
 * path.
 *
 * The mode has to be set explicitly at all, rather than passed to open() or
 * mkdir(), because the umask masks the creation mode — a fixture that means to be
 * group-writable is otherwise silently created 0750, which was a real false pass
 * in step 5.
 *
 * Setting it with fchmod() rather than chmod() closes a time-of-check /
 * time-of-use gap: chmod() re-resolves the pathname, so between creating the
 * file and setting its mode the name could refer to something else. In a fixture
 * tree under $HOME with a pid in its name that is not a realistic attack, and it
 * is still the wrong way to write it here — this corpus exists to verify code
 * whose whole discipline is openat, O_NOFOLLOW and fstat-on-the-descriptor
 * instead of stat-on-the-path. A test that verifies that property while not
 * practising it invites the reader to think the distinction is pedantic.
 *
 * fchmod is also immune to the umask, so it replaces the old chmod rather than
 * joining it. Flagged by CodeQL; the suggested patch added the fchmod and left
 * the chmod in place, which would have kept the gap it was closing.
 */
static void write_file(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "cannot create %s: %s", path, strerror(errno));
    if (fd < 0) return;
    size_t len = strlen(text);
    CHECK(len == 0 || write(fd, text, len) == (ssize_t)len, "write %s: %s", path, strerror(errno));
    CHECK(fchmod(fd, mode) == 0, "fchmod %s: %s", path, strerror(errno));
    close(fd);
}

static void make_dir(const char *path, mode_t mode)
{
    CHECK(mkdir(path, 0700) == 0, "mkdir %s: %s", path, strerror(errno));
    /* O_NOFOLLOW on the leaf, which is also the production policy for a
     * directory this program just created (design §11.4, as amended in step 5). */
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0, "cannot open %s: %s", path, strerror(errno));
    if (fd < 0) return;
    CHECK(fchmod(fd, mode) == 0, "fchmod %s: %s", path, strerror(errno));
    close(fd);
}

/* ------------------------------------------------------------------------- */
/* A synthetic ELF image.                                                    */
/* ------------------------------------------------------------------------- */

/*
 * Layout, chosen so one PT_LOAD covers everything and file offsets equal
 * virtual addresses only where that is deliberate:
 *
 *   0x0000  ELF header
 *   0x0040  program headers: PT_LOAD, PT_DYNAMIC
 *   0x0100  dynamic section
 *   0x0200  string table
 *
 * The PT_LOAD segment is given a non-zero p_vaddr on purpose, so DT_STRTAB (a
 * VIRTUAL ADDRESS) does not coincide with its file offset. A parser that
 * confuses the two passes on most real binaries — where the first segment maps
 * at 0 and they happen to be equal — and reads garbage on the rest. This fixture
 * fails such a parser immediately.
 */
#define ELF_VBASE 0x400000u
#define OFF_PH    0x40u
#define OFF_DYN   0x100u
#define OFF_STR   0x200u

typedef struct {
    unsigned char b[0x400];
    size_t n;
    bool   is64, le;
} elf_build;

static void put16(elf_build *m, size_t off, uint16_t v)
{
    if (m->le) { m->b[off] = (unsigned char)(v & 0xff); m->b[off + 1] = (unsigned char)(v >> 8); }
    else       { m->b[off + 1] = (unsigned char)(v & 0xff); m->b[off] = (unsigned char)(v >> 8); }
}

static void put32(elf_build *m, size_t off, uint32_t v)
{
    for (size_t i = 0; i < 4; ++i) {
        unsigned char byte = (unsigned char)((v >> (8 * i)) & 0xff);
        m->b[off + (m->le ? i : 3 - i)] = byte;
    }
}

static void put64(elf_build *m, size_t off, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i) {
        unsigned char byte = (unsigned char)((v >> (8 * i)) & 0xff);
        m->b[off + (m->le ? i : 7 - i)] = byte;
    }
}

static void putword(elf_build *m, size_t off, uint64_t v)
{
    if (m->is64) put64(m, off, v);
    else         put32(m, off, (uint32_t)v);
}

/* strings: NUL-separated blob; returns the offset of each as it is appended. */
typedef struct { char blob[512]; size_t len; } strtab;

static uint32_t str_add(strtab *t, const char *s)
{
    uint32_t at = (uint32_t)t->len;
    size_t n = strlen(s) + 1;
    CHECK(t->len + n <= sizeof t->blob, "fixture string table full");
    memcpy(t->blob + t->len, s, n);
    t->len += n;
    return at;
}

typedef struct { uint64_t tag, val; } dynent;

static void build_elf(elf_build *m, bool is64, bool le,
                      const dynent *dyn, size_t ndyn, const strtab *st)
{
    memset(m, 0, sizeof *m);
    m->is64 = is64;
    m->le = le;
    m->n = sizeof m->b;

    memcpy(m->b, "\177ELF", 4);
    m->b[4] = is64 ? 2 : 1;
    m->b[5] = le ? 1 : 2;
    m->b[6] = 1;                                   /* EI_VERSION */

    uint16_t phentsize = is64 ? 56 : 32;
    if (is64) {
        put16(m, 16, 2);                           /* e_type = ET_EXEC */
        put16(m, 18, 62);                          /* e_machine */
        putword(m, 32, OFF_PH);                    /* e_phoff */
        put16(m, 54, phentsize);
        put16(m, 56, 2);                           /* e_phnum */
    } else {
        put16(m, 16, 2);
        put16(m, 18, 3);
        putword(m, 28, OFF_PH);
        put16(m, 42, phentsize);
        put16(m, 44, 2);
    }

    /* PT_LOAD covering the whole image, mapped at ELF_VBASE. */
    size_t ph0 = OFF_PH;
    put32(m, ph0, 1);                              /* p_type = PT_LOAD */
    if (is64) {
        putword(m, ph0 + 8,  0);                   /* p_offset */
        putword(m, ph0 + 16, ELF_VBASE);           /* p_vaddr  */
        putword(m, ph0 + 32, sizeof m->b);         /* p_filesz */
    } else {
        putword(m, ph0 + 4,  0);
        putword(m, ph0 + 8,  ELF_VBASE);
        putword(m, ph0 + 16, sizeof m->b);
    }

    /* PT_DYNAMIC. */
    size_t ph1 = OFF_PH + phentsize;
    size_t entsz = is64 ? 16u : 8u;
    put32(m, ph1, 2);                              /* p_type = PT_DYNAMIC */
    if (is64) {
        putword(m, ph1 + 8,  OFF_DYN);
        putword(m, ph1 + 16, ELF_VBASE + OFF_DYN);
        putword(m, ph1 + 32, (ndyn + 1) * entsz);
    } else {
        putword(m, ph1 + 4,  OFF_DYN);
        putword(m, ph1 + 8,  ELF_VBASE + OFF_DYN);
        putword(m, ph1 + 16, (ndyn + 1) * entsz);
    }

    for (size_t i = 0; i < ndyn; ++i) {
        size_t at = OFF_DYN + i * entsz;
        putword(m, at, dyn[i].tag);
        putword(m, at + entsz / 2, dyn[i].val);
    }
    /* DT_NULL terminator. */
    putword(m, OFF_DYN + ndyn * entsz, 0);
    putword(m, OFF_DYN + ndyn * entsz + entsz / 2, 0);

    memcpy(m->b + OFF_STR, st->blob, st->len);
}

static void write_elf(const char *path, const elf_build *m, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "cannot create %s: %s", path, strerror(errno));
    if (fd < 0) return;
    CHECK(write(fd, m->b, m->n) == (ssize_t)m->n, "write elf: %s", strerror(errno));
    CHECK(fchmod(fd, mode) == 0, "fchmod %s: %s", path, strerror(errno));
    close(fd);
}

static void test_elf_reader(void)
{
    make_base("elf");
    char path[VU_PATH_MAX];
    vu_path(path, sizeof path, "%s/openconnect", g_base);
    vu_err e;

    /* Both classes and both byte orders. A parser that assumes the host's
     * layout passes half of this. */
    for (int class64 = 0; class64 <= 1; ++class64) {
        for (int little = 0; little <= 1; ++little) {
            strtab st; memset(&st, 0, sizeof st);
            (void)str_add(&st, "");                     /* index 0 is empty */
            uint32_t s_ssl  = str_add(&st, "libssl.so.3");
            uint32_t s_xml  = str_add(&st, "libxml2.so.2");
            uint32_t s_rp   = str_add(&st, "/opt/vpn/lib:/usr/local/lib");

            dynent dyn[] = {
                { 5,  ELF_VBASE + OFF_STR },            /* DT_STRTAB (a VADDR) */
                { 10, st.len },                          /* DT_STRSZ           */
                { 1,  s_ssl },                           /* DT_NEEDED          */
                { 1,  s_xml },
                { 29, s_rp },                            /* DT_RUNPATH         */
            };
            elf_build m;
            build_elf(&m, class64 == 1, little == 1, dyn, sizeof dyn / sizeof *dyn, &st);
            write_elf(path, &m, 0755);

            vu_elf_info info;
            vu_err_clear(&e);
            CHECK(vu_elf_dynamic(path, &info, &e),
                  "ELF%d %s-endian must parse: %s", class64 ? 64 : 32,
                  little ? "little" : "big", e.msg);
            CHECK(info.is_elf, "must be recognised as ELF");
            CHECK(info.is_64 == (class64 == 1), "class misdetected");
            CHECK(info.is_le == (little == 1), "byte order misdetected");
            CHECK(info.n_needed == 2, "expected 2 DT_NEEDED, got %zu", info.n_needed);
            if (info.n_needed == 2) {
                CHECK(strcmp(info.needed[0], "libssl.so.3") == 0, "got %s", info.needed[0]);
                CHECK(strcmp(info.needed[1], "libxml2.so.2") == 0, "got %s", info.needed[1]);
            }
            CHECK(info.had_runpath, "DT_RUNPATH must be distinguished from DT_RPATH");
            CHECK(info.n_rpath == 2, "expected 2 rpath entries, got %zu", info.n_rpath);
            if (info.n_rpath == 2) {
                CHECK(strcmp(info.rpath[0], "/opt/vpn/lib") == 0, "got %s", info.rpath[0]);
                CHECK(strcmp(info.rpath[1], "/usr/local/lib") == 0, "got %s", info.rpath[1]);
            }
        }
    }

    /* $ORIGIN expands to the directory holding the binary — which is the whole
     * reason a RUNPATH can be user-writable while looking absolute. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        uint32_t s_rp = str_add(&st, "$ORIGIN/../lib");
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len }, { 29, s_rp } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(path, &m, 0755);

        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(vu_elf_dynamic(path, &info, &e), "$ORIGIN must parse: %s", e.msg);
        CHECK(info.n_rpath == 1, "one entry expected, got %zu", info.n_rpath);
        if (info.n_rpath == 1) {
            char want[VU_PATH_MAX];
            vu_path(want, sizeof want, "%s/../lib", g_base);
            CHECK(strcmp(info.rpath[0], want) == 0,
                  "$ORIGIN must expand to the binary's directory: got %s, want %s",
                  info.rpath[0], want);
        }
    }

    /* ${ORIGIN} braced form. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        uint32_t s_rp = str_add(&st, "${ORIGIN}/lib");
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len }, { 15, s_rp } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(path, &m, 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(vu_elf_dynamic(path, &info, &e), "${ORIGIN} must parse: %s", e.msg);
        CHECK(!info.had_runpath, "DT_RPATH must not be reported as DT_RUNPATH");
        CHECK(info.n_rpath == 1 && strstr(info.rpath[0], g_base) != NULL,
              "braced ORIGIN must expand: %s", info.n_rpath ? info.rpath[0] : "(none)");
    }

    /* $LIB and $PLATFORM are refused, not guessed: a search path we cannot
     * resolve is one we must not claim to have verified. */
    for (int which = 0; which < 2; ++which) {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        uint32_t s_rp = str_add(&st, which ? "/usr/$PLATFORM/lib" : "/usr/$LIB");
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len }, { 29, s_rp } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(path, &m, 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(!vu_elf_dynamic(path, &info, &e),
              "a loader substitution we cannot resolve must be refused");
        CHECK(strstr(e.msg, "cannot resolve") != NULL, "say why: %s", e.msg);
    }

    /* A string table address that is in no loaded segment. This is the case a
     * parser that treats DT_STRTAB as a file offset gets wrong. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        (void)str_add(&st, "libc.so.6");
        dynent dyn[] = { { 5, 0xdeadbeef }, { 10, st.len }, { 1, 1 } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(path, &m, 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(!vu_elf_dynamic(path, &info, &e), "an unmapped string table must be refused");
        CHECK(strstr(e.msg, "loaded segment") != NULL, "say why: %s", e.msg);
    }

    /* A DT_NEEDED index past the end of the string table. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        (void)str_add(&st, "libc.so.6");
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len }, { 1, 9999 } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(path, &m, 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(!vu_elf_dynamic(path, &info, &e), "an out-of-range name must be refused");
    }

    /* No string table at all. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        dynent dyn[] = { { 1, 0 } };
        elf_build m;
        build_elf(&m, true, true, dyn, 1, &st);
        write_elf(path, &m, 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(!vu_elf_dynamic(path, &info, &e), "a dynamic section with no strtab must be refused");
    }

    /* Not ELF at all: NOT an error. A vpnc-script is a shell script, and the
     * closure walk wants its interpreter rather than its libraries. */
    {
        write_file(path, "#!/bin/sh\necho hello\n", 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(vu_elf_dynamic(path, &info, &e), "a non-ELF file is a verdict, not an error: %s", e.msg);
        CHECK(!info.is_elf, "a shell script must not be reported as ELF");
        CHECK(info.n_needed == 0 && info.n_rpath == 0, "nothing to report for a script");
    }

    /* Garbage that starts like ELF. */
    {
        write_file(path, "\177ELFtruncated", 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        /* Too short to be ELF: reported as not-ELF rather than as a parse error,
         * because 13 bytes cannot be a binary and saying "not ELF" is true. */
        CHECK(vu_elf_dynamic(path, &info, &e) && !info.is_elf,
              "a truncated stub must not be treated as a parseable ELF");
    }

    /* A bad class or encoding byte is a refusal: we cannot know the layout. */
    {
        elf_build m; memset(&m, 0, sizeof m);
        m.n = sizeof m.b; m.le = true; m.is64 = true;
        memcpy(m.b, "\177ELF", 4);
        m.b[4] = 7; m.b[5] = 1;
        write_elf(path, &m, 0755);
        vu_elf_info info;
        vu_err_clear(&e);
        CHECK(!vu_elf_dynamic(path, &info, &e), "an unknown ELF class must be refused");
    }

    /* A directory is not a file. */
    {
        vu_err_clear(&e);
        vu_elf_info info;
        CHECK(!vu_elf_dynamic(g_base, &info, &e), "a directory must be refused");
    }

    drop_base();
}

/* ------------------------------------------------------------------------- */
/* The closure walk.                                                         */
/* ------------------------------------------------------------------------- */

/* A fixture install that passes: binary, script, hooks, and a PATH of its own. */
typedef struct {
    char root[VU_PATH_MAX];
    char sbin[VU_PATH_MAX];
    char openconnect[VU_PATH_MAX];
    char script[VU_PATH_MAX];
    char shell[VU_PATH_MAX];
    char hooks[VU_PATH_MAX];
    char path_env[VU_PATH_MAX * 2];
} fixture;

static void build_fixture(fixture *f)
{
    vu_path(f->root, sizeof f->root, "%s/opt", g_base);
    make_dir(f->root, 0755);
    vu_path(f->sbin, sizeof f->sbin, "%s/sbin", f->root);
    make_dir(f->sbin, 0755);

    vu_path(f->openconnect, sizeof f->openconnect, "%s/openconnect", f->sbin);
    /* A minimal valid ELF with no libraries: enough for the walk to accept the
     * library row when the ELF path is compiled in. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len } };
        elf_build m;
        build_elf(&m, true, true, dyn, 2, &st);
        write_elf(f->openconnect, &m, 0755);
    }

    vu_path(f->script, sizeof f->script, "%s/vpnc-script", f->root);
    write_file(f->script, "#!/bin/sh\n# fixture\n", 0755);

    vu_path(f->shell, sizeof f->shell, "%s/sh", f->sbin);
    write_file(f->shell, "#!/bin/sh\n", 0755);

    vu_path(f->hooks, sizeof f->hooks, "%s/vpnc", f->root);
    make_dir(f->hooks, 0755);
    char hookdir[VU_PATH_MAX];
    vu_path(hookdir, sizeof hookdir, "%s/connect.d", f->hooks);
    make_dir(hookdir, 0755);
    char hook[VU_PATH_MAX];
    vu_path(hook, sizeof hook, "%s/00-fixture", hookdir);
    /* 0644, no execute bit: these are SOURCED, so that is normal and must pass. */
    write_file(hook, "# sourced, not executed\n", 0644);

    vu_path(f->path_env, sizeof f->path_env, "%s", f->sbin);
}

static void spec_for(vu_closure_spec *s, const fixture *f)
{
    vu_closure_spec_default(s, f->openconnect, f->script, getuid());
    s->shell         = f->shell;
    s->path_env      = f->path_env;
    s->hooks_root    = f->hooks;
    /* Point the loader configuration at paths that do not exist: absent is the
     * good case, and the corpus has its own tests for the present case. */
    s->ldso_preload  = "/nonexistent/ld.so.preload";
    s->ldso_conf     = "/nonexistent/ld.so.conf";
    s->ldso_conf_dir = "/nonexistent/ld.so.conf.d";
    /* Hermetic: assertions about a fixture tree must not also depend on how the
     * host happens to own /usr/lib. The real list is exercised in production and
     * by vpn-up-admin verify-closure. */
    s->no_default_libdirs = true;
    s->probe              = false;
}

/*
 * Did the report fail specifically because of `needle`? Any refusal satisfies a
 * bare `!ok`, so a test that asserts WHICH object failed must not be
 * satisfiable by an unrelated failure.
 *
 * The reason is searched as well as the path, and that is not laziness: for a
 * symlinked object the item names the path we were GIVEN while the reason names
 * the resolved component that actually failed. Both are the answer to "what is
 * wrong", and for a Homebrew-shaped install the resolved one is the useful half.
 */
static bool failed_on(const vu_closure_report *r, const char *needle)
{
    for (size_t i = 0; i < r->n; ++i)
        if (!r->items[i].ok &&
            (strstr(r->items[i].path, needle) || strstr(r->items[i].reason, needle)))
            return true;
    return false;
}

/*
 * How many failures a correct baseline has.
 *
 * Zero where the library closure is compiled in. One where it is not, because
 * §11.7 requires the check to fail CLOSED rather than skip the row — so on a
 * default macOS build the baseline legitimately reports exactly one failure, and
 * a test that demanded zero would be demanding the wrong behaviour.
 *
 * `make test-elf-closure` builds this corpus with the ELF path forced on, so
 * both configurations are exercised on both platforms.
 */
static size_t baseline_failures(void)
{
    return VU_LIBRARY_CLOSURE_ELF ? 0u : 1u;
}

static void check_only_library_row_failed(const vu_closure_report *r)
{
    for (size_t i = 0; i < r->n; ++i) {
        if (r->items[i].ok) continue;
        CHECK(strstr(r->items[i].reason, "could not be established") != NULL,
              "the only acceptable baseline failure is the unimplemented library "
              "closure, got: %s (%s)", r->items[i].path, r->items[i].reason);
    }
}

static void test_closure_walk(void)
{
    make_base("walk");
    fixture f;
    build_fixture(&f);

    vu_closure_spec s;
    vu_closure_report rep;
    vu_err e;

    /*
     * The baseline must be clean apart from the one row §11.7 deliberately fails
     * where the library closure is not compiled in. Without this anchor, none of
     * the negative cases below would mean anything: they would all "pass" on a
     * fixture that was already refused for unrelated reasons.
     */
    spec_for(&s, &f);
    vu_err_clear(&e);
    bool ok = vu_closure_check(&s, &rep, &e);
    CHECK(ok == (baseline_failures() == 0),
          "baseline verdict was %d with %zu failures: %s", ok, rep.n_failed, e.msg);
    CHECK(rep.n_failed == baseline_failures(),
          "expected %zu baseline failures, got %zu", baseline_failures(), rep.n_failed);
    check_only_library_row_failed(&rep);
    CHECK(rep.n > 4, "the report should cover every object, got %zu", rep.n);

    /* A sourced hook with no execute bit passed above. Assert that explicitly:
     * requiring +x here would be the wrong check and would pass every real
     * installation while missing the actual hole. */
    {
        bool saw_hook = false;
        for (size_t i = 0; i < rep.n; ++i)
            if (strstr(rep.items[i].path, "00-fixture")) { saw_hook = true; CHECK(rep.items[i].ok, "a non-executable sourced hook must pass"); }
        CHECK(saw_hook, "the walk must actually visit the hook files");
    }

    /* §18: the binary is group- or world-writable. */
    CHECK(chmod(f.openconnect, 0757) == 0, "chmod: %s", strerror(errno));
    spec_for(&s, &f);
    vu_err_clear(&e);
    CHECK(!vu_closure_check(&s, &rep, &e), "a world-writable openconnect must be refused");
    CHECK(failed_on(&rep, "openconnect"), "the refusal must name the binary");
    CHECK(chmod(f.openconnect, 0755) == 0, "chmod back: %s", strerror(errno));

    /* §18: a PARENT directory is group-writable. This is the Homebrew shape:
     * the binary itself looks fine, and the directory above it does not. */
    CHECK(chmod(f.sbin, 0775) == 0, "chmod: %s", strerror(errno));
    spec_for(&s, &f);
    vu_err_clear(&e);
    CHECK(!vu_closure_check(&s, &rep, &e), "a group-writable parent must be refused");
    CHECK(chmod(f.sbin, 0755) == 0, "chmod back: %s", strerror(errno));

    /* §18: the hook DIRECTORY is user-writable while every file in it is fine.
     * This is the case the execute-bit intuition misses entirely — nothing is
     * executable, nothing is writable, and yet anyone who can add a file there
     * gets root on the next connect. */
    {
        char hookdir[VU_PATH_MAX];
        vu_path(hookdir, sizeof hookdir, "%s/connect.d", f.hooks);
        CHECK(chmod(hookdir, 0777) == 0, "chmod: %s", strerror(errno));
        spec_for(&s, &f);
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a world-writable hook directory must be refused");
        CHECK(failed_on(&rep, "connect.d"), "the refusal must name the hook directory");
        CHECK(chmod(hookdir, 0755) == 0, "chmod back: %s", strerror(errno));
    }

    /* An existing hook FILE that is writable is the same hole by another route. */
    {
        char hook[VU_PATH_MAX];
        vu_path(hook, sizeof hook, "%s/connect.d/00-fixture", f.hooks);
        CHECK(chmod(hook, 0666) == 0, "chmod: %s", strerror(errno));
        spec_for(&s, &f);
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a world-writable sourced hook must be refused");
        CHECK(chmod(hook, 0644) == 0, "chmod back: %s", strerror(errno));
    }

    /* No hook root at all: fine, and must not be reported as a failure. Most
     * installations have no hooks. */
    {
        spec_for(&s, &f);
        s.hooks_root = "/nonexistent/vpnc";
        vu_err_clear(&e);
        (void)vu_closure_check(&s, &rep, &e);
        CHECK(rep.n_failed == baseline_failures(),
              "an absent hook root must not add a failure: %s", e.msg);
        check_only_library_row_failed(&rep);
    }

    /* §18: a user-writable PATH entry. vpnc-script resolves route, ip and
     * ifconfig by name, as root. */
    {
        char bad[VU_PATH_MAX];
        vu_path(bad, sizeof bad, "%s/writable-bin", g_base);
        make_dir(bad, 0777);
        spec_for(&s, &f);
        char combined[VU_PATH_MAX * 2];
        vu_path(combined, sizeof combined, "%s:%s", f.sbin, bad);
        s.path_env = combined;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a world-writable PATH entry must be refused");
        CHECK(failed_on(&rep, "writable-bin"), "the refusal must name the PATH entry");
    }

    /* An empty PATH, and an empty ENTRY in a PATH, both mean the current
     * directory once vpnc-script prepends to it. Verified chain, not a guess. */
    {
        spec_for(&s, &f);
        s.path_env = "";
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "an empty PATH must be refused");

        char combined[VU_PATH_MAX * 2];
        vu_path(combined, sizeof combined, "%s::/bin", f.sbin);
        spec_for(&s, &f);
        s.path_env = combined;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "an empty PATH entry must be refused");

        vu_path(combined, sizeof combined, "%s:relative/bin", f.sbin);
        spec_for(&s, &f);
        s.path_env = combined;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a relative PATH entry must be refused");
    }

    /* §18: a symlink component. Resolved and then verified, per the step 5
     * amendment — so a link INTO a user-writable tree is caught on the real
     * chain's ownership rather than on the link's existence. That is the
     * Homebrew bin/openconnect -> ../Cellar shape exactly. */
    {
        char cellar[VU_PATH_MAX], link[VU_PATH_MAX], target[VU_PATH_MAX];
        vu_path(cellar, sizeof cellar, "%s/Cellar", g_base);
        make_dir(cellar, 0777);                    /* user-writable, like a Homebrew prefix */
        vu_path(target, sizeof target, "%s/openconnect", cellar);
        write_file(target, "#!/bin/sh\n", 0755);
        vu_path(link, sizeof link, "%s/oc-link", f.sbin);
        CHECK(symlink(target, link) == 0, "symlink: %s", strerror(errno));

        spec_for(&s, &f);
        s.openconnect = link;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e),
              "a link into a user-writable prefix must be refused");
        CHECK(failed_on(&rep, "Cellar"),
              "the refusal must name the RESOLVED path, which is the useful answer");
    }

    /* The script's shebang is part of the closure: it is what runs if the script
     * is executed directly. */
    {
        char badsh[VU_PATH_MAX], script2[VU_PATH_MAX];
        char wdir[VU_PATH_MAX];
        vu_path(wdir, sizeof wdir, "%s/wbin", g_base);
        make_dir(wdir, 0777);
        vu_path(badsh, sizeof badsh, "%s/sh", wdir);
        write_file(badsh, "#!/bin/sh\n", 0755);

        char shebang[VU_PATH_MAX + 16];
        vu_path(shebang, sizeof shebang, "#!%s\n# fixture\n", badsh);
        vu_path(script2, sizeof script2, "%s/vpnc-script-2", f.root);
        write_file(script2, shebang, 0755);

        spec_for(&s, &f);
        s.script = script2;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e),
              "a shebang interpreter in a writable directory must be refused");
        CHECK(failed_on(&rep, "wbin"), "the refusal must name the interpreter");
    }

    /* A missing object is a refusal, not a pass. */
    {
        spec_for(&s, &f);
        s.openconnect = "/nonexistent/openconnect";
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a missing openconnect must be refused");

        spec_for(&s, &f);
        s.script = "/nonexistent/vpnc-script";
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a missing vpnc-script must be refused");

        spec_for(&s, &f);
        s.shell = "/nonexistent/sh";
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a missing shell must be refused");
    }

    /* An incomplete spec must not be interpreted generously. */
    {
        vu_closure_spec empty;
        memset(&empty, 0, sizeof empty);
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&empty, &rep, &e), "an empty spec must be refused");
        CHECK(!vu_closure_check(&s, NULL, &e), "a null report must be refused");
    }

    /* The report is the deliverable: it must name every failing object, not
     * stop at the first. A machine that fails usually fails several rows for one
     * underlying reason, and seeing them together is what identifies it. */
    {
        char hookdir[VU_PATH_MAX];
        vu_path(hookdir, sizeof hookdir, "%s/connect.d", f.hooks);
        CHECK(chmod(f.openconnect, 0757) == 0, "chmod: %s", strerror(errno));
        CHECK(chmod(hookdir, 0777) == 0, "chmod: %s", strerror(errno));
        spec_for(&s, &f);
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "must refuse");
        CHECK(rep.n_failed >= 2, "every failing object must be reported, got %zu", rep.n_failed);
        CHECK(failed_on(&rep, "openconnect") && failed_on(&rep, "connect.d"),
              "both failures must appear");
        CHECK(chmod(f.openconnect, 0755) == 0, "chmod back: %s", strerror(errno));
        CHECK(chmod(hookdir, 0755) == 0, "chmod back: %s", strerror(errno));
    }

    drop_base();
}

/* ------------------------------------------------------------------------- */
/* The loader configuration (only when the ELF path is compiled in).         */
/* ------------------------------------------------------------------------- */

static void test_loader_config(void)
{
#if VU_LIBRARY_CLOSURE_ELF
    make_base("ldso");
    fixture f;
    build_fixture(&f);

    vu_closure_spec s;
    vu_closure_report rep;
    vu_err e;

    char preload[VU_PATH_MAX], conf[VU_PATH_MAX], confd[VU_PATH_MAX];
    vu_path(preload, sizeof preload, "%s/ld.so.preload", g_base);
    vu_path(conf, sizeof conf, "%s/ld.so.conf", g_base);
    vu_path(confd, sizeof confd, "%s/ld.so.conf.d", g_base);

    /* A trusted library directory, and a writable one. */
    char goodlib[VU_PATH_MAX], badlib[VU_PATH_MAX];
    vu_path(goodlib, sizeof goodlib, "%s/lib", f.root);
    make_dir(goodlib, 0755);
    vu_path(badlib, sizeof badlib, "%s/badlib", g_base);
    make_dir(badlib, 0777);

    /* ld.so.conf naming a trusted directory: passes. */
    {
        char body[VU_PATH_MAX * 2];
        vu_path(body, sizeof body, "# a comment\n\n%s\n", goodlib);
        write_file(conf, body, 0644);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        bool ok = vu_closure_check(&s, &rep, &e);
        CHECK(ok, "a trusted configured library directory must pass: %s", e.msg);
        if (!ok) vu_closure_print(&rep, stderr);
    }

    /* ld.so.conf naming a WRITABLE directory: refused. Anything the loader
     * finds there is loaded into a root process. */
    {
        char body[VU_PATH_MAX * 2];
        vu_path(body, sizeof body, "%s\n", badlib);
        write_file(conf, body, 0644);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e),
              "a world-writable configured library directory must be refused");
        CHECK(failed_on(&rep, "badlib"), "the refusal must name the directory");
    }

    /* A writable ld.so.conf itself is a refusal: whoever can write it chooses
     * where root's loader searches. */
    {
        char body[VU_PATH_MAX * 2];
        vu_path(body, sizeof body, "%s\n", goodlib);
        write_file(conf, body, 0666);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a writable ld.so.conf must be refused");
        CHECK(chmod(conf, 0644) == 0, "chmod back: %s", strerror(errno));
    }

    /* An `include` line is reported as unexpanded rather than silently ignored:
     * it is a glob, and a set of directories we do not enumerate is one we must
     * not claim to have checked. */
    {
        write_file(conf, "include /etc/ld.so.conf.d/*.conf\n", 0644);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        CHECK(vu_closure_check(&s, &rep, &e), "an include line must not fail the walk: %s", e.msg);
        bool saw = false;
        for (size_t i = 0; i < rep.n; ++i)
            if (strstr(rep.items[i].role, "not expanded")) saw = true;
        CHECK(saw, "the report must say the include was not expanded");
    }

    /* ld.so.preload is the sharpest case: every path in it is loaded into every
     * process, as root. */
    {
        char lib[VU_PATH_MAX];
        vu_path(lib, sizeof lib, "%s/libhook.so", badlib);
        write_file(lib, "not really a library\n", 0644);
        char body[VU_PATH_MAX * 2];
        vu_path(body, sizeof body, "%s\n", lib);
        write_file(preload, body, 0644);

        spec_for(&s, &f);
        s.ldso_preload = preload;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e),
              "a preloaded library in a writable directory must be refused");
        CHECK(failed_on(&rep, "libhook.so"), "the refusal must name the library");
    }

    /* A writable ld.so.conf.d is a refusal even when every file in it is fine:
     * adding a file there adds a library search directory. */
    {
        write_file(conf, "# nothing\n", 0644);
        make_dir(confd, 0777);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        s.ldso_conf_dir = confd;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a writable ld.so.conf.d must be refused");
        CHECK(chmod(confd, 0755) == 0, "chmod back: %s", strerror(errno));
    }

    /* DT_RUNPATH pointing at a writable directory: refused. This is the row
     * that makes the whole ELF reader worth having — the binary is root-owned
     * and correct, and it will still load a library the caller wrote. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        uint32_t s_rp = str_add(&st, badlib);
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len }, { 29, s_rp } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(f.openconnect, &m, 0755);

        write_file(conf, "# nothing\n", 0644);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e),
              "a DT_RUNPATH into a writable directory must be refused");
        CHECK(failed_on(&rep, "badlib"), "the refusal must name the RUNPATH directory");
    }

    /* And the same binary with a trusted RUNPATH passes, so the check is
     * discriminating rather than simply hostile to RUNPATH. */
    {
        strtab st; memset(&st, 0, sizeof st);
        (void)str_add(&st, "");
        uint32_t s_rp = str_add(&st, goodlib);
        dynent dyn[] = { { 5, ELF_VBASE + OFF_STR }, { 10, st.len }, { 29, s_rp } };
        elf_build m;
        build_elf(&m, true, true, dyn, 3, &st);
        write_elf(f.openconnect, &m, 0755);

        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        bool ok = vu_closure_check(&s, &rep, &e);
        CHECK(ok, "a trusted DT_RUNPATH must pass: %s", e.msg);
        if (!ok) vu_closure_print(&rep, stderr);
    }

    /* A non-ELF openconnect is refused when the ELF closure is in force: we
     * cannot enumerate the search paths of something we cannot parse. */
    {
        write_file(f.openconnect, "#!/bin/sh\necho not openconnect\n", 0755);
        spec_for(&s, &f);
        s.ldso_conf = conf;
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&s, &rep, &e), "a non-ELF openconnect must be refused");
    }

    drop_base();
#else
    /*
     * The macOS default. §11.7 requires helper mode to be UNAVAILABLE rather
     * than weakened until the dyld closure exists (step 13), and this asserts
     * that the code actually does that instead of the document merely saying so.
     */
    make_base("closed");
    fixture f;
    build_fixture(&f);

    vu_closure_spec s;
    vu_closure_report rep;
    vu_err e;
    spec_for(&s, &f);
    vu_err_clear(&e);
    CHECK(!vu_closure_check(&s, &rep, &e),
          "without the library closure, the check must fail closed");
    bool explained = false;
    for (size_t i = 0; i < rep.n; ++i)
        if (!rep.items[i].ok && strstr(rep.items[i].reason, "could not be established"))
            explained = true;
    CHECK(explained, "the refusal must use the wording section 11.7 specifies");
    drop_base();
#endif
}

/* ------------------------------------------------------------------------- */
/* ACLs: mode bits are not the whole story (§11.5).                          */
/* ------------------------------------------------------------------------- */

static void test_acl_detection(void)
{
    make_base("acl");
    char file[VU_PATH_MAX];
    vu_path(file, sizeof file, "%s/openconnect", g_base);
    write_file(file, "#!/bin/sh\n", 0755);

    vu_err e; vu_err_clear(&e);

    /*
     * The probe only means something for another uid when running as root, since
     * dropping privilege is the mechanism. Unprivileged, it answers honestly for
     * our own uid and refuses to guess about anyone else's — which is itself
     * worth asserting, because "returns false, meaning not writable" would be a
     * dangerous way to fail.
     */
    bool writable = false;
    CHECK(vu_writable_by(file, getuid(), &writable, &e),
          "probing our own uid must work unprivileged: %s", e.msg);
    CHECK(writable, "we own this file 0755, so we can write it");

    vu_err_clear(&e);
    CHECK(!vu_writable_by(file, getuid() + 1, &writable, &e),
          "probing another uid without root must refuse, not answer");
    CHECK(strstr(e.msg, "requires root") != NULL, "say why: %s", e.msg);

    /*
     * Probing uid 0 must be REFUSED, not attempted.
     *
     * This is the assertion that was missing, and its absence let a real bug ship
     * in step 10: the closure spec defaulted probe_uid to `owner`, which is 0 in
     * production, so the probe was asked to drop privilege to root and then verify
     * it could not regain root. It "succeeded" at dropping, regained root
     * trivially, and reported could-not-drop-privilege - a failure that reads as a
     * broken sandbox and is actually a caller passing the wrong uid. It went
     * unnoticed because the probe only runs as root, and nothing ran as root until
     * the step 11 integration script did.
     */
    vu_err_clear(&e);
    CHECK(!vu_writable_by(file, 0, &writable, &e),
          "probing uid 0 is meaningless and must be refused, not attempted");
    CHECK(strstr(e.msg, "uid 0") != NULL, "say why: %s", e.msg);

    /* And the spec-level guard, so the mistake cannot be made through the
     * closure check either. */
    {
        vu_closure_spec spec;
        vu_closure_report rep;
        vu_closure_spec_default(&spec, file, file, getuid());
        spec.shell = file;
        spec.probe = true;
        spec.probe_uid = 0;                  /* the step 10 bug, exactly */
        vu_err_clear(&e);
        CHECK(!vu_closure_check(&spec, &rep, &e),
              "a probe with no caller uid must be refused up front");
        CHECK(strstr(e.msg, "calling user's uid") != NULL, "explain: %s", e.msg);

        /*
         * The default must not adopt the OWNER as the probe uid, which is the
         * exact shape of the step 10 bug.
         *
         * A non-zero owner is essential here: the first version of this
         * assertion passed owner 0, so `probe_uid = owner` and `probe_uid = 0`
         * were indistinguishable and the test could not fail. Caught by
         * restoring the bug and watching the corpus stay green.
         */
        vu_closure_spec fresh;
        vu_closure_spec_default(&fresh, file, file, (uid_t)4242);
        CHECK(!fresh.probe, "the default spec must leave the probe off");
        CHECK(fresh.probe_uid != (uid_t)4242,
              "the default must not adopt the owner as the probe uid: the probe "
              "asks about the CALLER, and owner is 0 in production");
    }

    /*
     * The case §11.5 exists for: mode bits say no, an ACL says yes.
     *
     * Testable for real on macOS with chmod +a. The file is made read-only for
     * everyone including its owner (0444), so mode bits alone would say "not
     * writable" — and then an ACL grants this user write access. A check that
     * only read st_mode reports the wrong answer here, which is the entire point
     * of the effective probe.
     */
#if defined(__APPLE__)
    {
        char cmd[VU_PATH_MAX * 2];
        CHECK(chmod(file, 0444) == 0, "chmod: %s", strerror(errno));

        vu_err_clear(&e);
        writable = true;
        CHECK(vu_writable_by(file, getuid(), &writable, &e), "probe: %s", e.msg);
        CHECK(!writable, "0444 with no ACL must not be writable");

        /* Add the ACL. Skipped rather than failed if the filesystem does not
         * support ACLs — a tmpfs or an exFAT volume legitimately does not. */
        vu_path(cmd, sizeof cmd, "/bin/chmod +a# 0 \"everyone allow write\" '%s'", file);
        int rc = system(cmd);
        if (rc == 0) {
            vu_err_clear(&e);
            writable = false;
            CHECK(vu_writable_by(file, getuid(), &writable, &e), "probe with ACL: %s", e.msg);
            CHECK(writable,
                  "an ACL granting write must be detected even though the mode bits are 0444 — "
                  "this is exactly the case ownership-and-mode checking misses");
        } else {
            fprintf(stderr, "note: ACLs unavailable on this filesystem; ACL case not exercised\n");
        }
        CHECK(chmod(file, 0755) == 0, "chmod back: %s", strerror(errno));
    }
#endif

    drop_base();
}

void vu_test_closure(void)
{
    test_elf_reader();
    test_closure_walk();
    test_loader_config();
    test_acl_detection();
}
