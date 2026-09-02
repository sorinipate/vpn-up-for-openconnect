/*
 * macho.c — Mach-O load commands, and nothing else. See vu_macho.h for why
 * the API differs from elf.c's, and PRIVILEGED-HELPER-DESIGN.md §17.1 for the
 * real install this was checked against before being written.
 *
 * Hand-rolled rather than <mach-o/loader.h>, same reasoning as elf.c: bounds-
 * checked against the file size, byte-order handled explicitly rather than
 * assumed, testable with hand-built fixtures on either platform without a
 * working native toolchain for the "other" one.
 */

#include "vu_macho.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Two different bounds, not one — unlike elf.c, this parser is not only ever
 * pointed at openconnect itself: closure.c recurses it into every dependency
 * in the graph, and a real one is not always small. Confirmed directly
 * against a real MacPorts install (design doc §17.1): openconnect's own
 * dependency graph includes libicudata, routinely 30+ MB (it embeds Unicode
 * locale data) — an 8 MB whole-file cap (elf.c's, and an earlier version of
 * this file's) refuses it outright, which is not a security property, just a
 * parser that cannot see load commands past a size a real, legitimate
 * library exceeds.
 *
 * MACHO_MAX_FILE_SIZE bounds the FILE itself — generous, but still finite
 * against a genuinely implausible or adversarial size.
 *
 * MACHO_READ_CAP bounds what actually gets read into memory, and is what
 * matters for the "is this too large" question: Mach-O load commands always
 * live in a small region right after the header, however large the rest of
 * the file (debug info, locale tables, code) is — so reading a bounded
 * prefix is both correct and cheap. 256 KiB is far beyond any real binary's
 * load-command region (thousands of commands would be needed to approach
 * it), while never allocating anywhere near MACHO_MAX_FILE_SIZE regardless
 * of how large the file on disk actually is.
 */
#define MACHO_MAX_FILE_SIZE (512ull * 1024ull * 1024ull)
#define MACHO_READ_CAP (256u * 1024u)

/* --- Mach-O constants, spelled out rather than <mach-o/loader.h> --- */
#define MH_MAGIC          0xfeedfaceu
#define MH_CIGAM          0xcefaedfeu
#define MH_MAGIC_64       0xfeedfacfu
#define MH_CIGAM_64       0xcffaedfeu
#define FAT_MAGIC_BE0     0xcau
#define FAT_MAGIC_BE1     0xfeu
#define FAT_MAGIC_BE2     0xbau
#define FAT_MAGIC_BE3     0xbeu

#define LC_REQ_DYLD          0x80000000u
#define LC_LOAD_DYLIB         0x0cu
#define LC_LOAD_WEAK_DYLIB   (0x18u | LC_REQ_DYLD)
#define LC_RPATH             (0x1cu | LC_REQ_DYLD)
#define LC_REEXPORT_DYLIB    (0x1fu | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB (0x23u | LC_REQ_DYLD)

#define CPU_TYPE_X86_64  0x01000007u
#define CPU_TYPE_ARM64   0x0100000cu

#if defined(__x86_64__) || defined(__amd64__)
#  define VU_HOST_CPU_TYPE CPU_TYPE_X86_64
#elif defined(__aarch64__) || defined(__arm64__)
#  define VU_HOST_CPU_TYPE CPU_TYPE_ARM64
#else
/* Unknown host: fine for a thin Mach-O (arch doesn't matter to parse it), and
 * handled as a runtime failure only if a fat binary is actually encountered
 * (see vu_macho_dylibs) — never a build-time #error, since this file compiles
 * unconditionally on every platform (macho.c is in SRC like elf.c is), even
 * where VU_LIBRARY_CLOSURE_MACHO is off. */
#  define VU_HOST_CPU_TYPE 0u
#endif

typedef struct {
    const unsigned char *b;
    size_t               n;
    bool                 is64, le;
} img;

static bool rd32(const img *m, size_t off, uint32_t *out)
{
    if (off + 4 > m->n) return false;
    const unsigned char *p = m->b + off;
    *out = m->le ? (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24
                 : (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
    return true;
}

/* The fat header and every fat_arch entry are always stored big-endian on
 * disk, regardless of host or slice byte order — an Apple toolchain
 * convention, not something this parser infers from a magic byte, so this
 * reads big-endian unconditionally rather than going through `img.le`. */
static bool be32_at(const unsigned char *b, size_t n, size_t off, uint32_t *out)
{
    if (off + 4 > n) return false;
    *out = (uint32_t)b[off] << 24 | (uint32_t)b[off + 1] << 16 |
           (uint32_t)b[off + 2] << 8 | (uint32_t)b[off + 3];
    return true;
}

/* A NUL-terminated string embedded directly in a load command (Mach-O has no
 * separate string table the way ELF's DT_STRTAB is one — lc_str is an offset
 * into the SAME load command), bounded by that command's own cmdsize. */
static bool lcstr_get(const img *m, size_t lc_off, uint32_t cmdsize,
                      uint32_t str_off, char *out, size_t cap)
{
    if (str_off >= cmdsize) return false;
    size_t at = lc_off + str_off;
    size_t limit = lc_off + cmdsize;
    if (limit > m->n) limit = m->n;
    if (at >= limit) return false;

    size_t len = 0;
    while (at + len < limit && m->b[at + len] != '\0') len++;
    if (len + 1 > cap) return false;
    memcpy(out, m->b + at, len);
    out[len] = '\0';
    return true;
}

/* The directory holding `path`, for @loader_path — identical purpose to
 * elf.c's dirname_of. */
static bool dirname_of(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    if (!slash) return false;
    size_t len = (size_t)(slash - path);
    if (len == 0) len = 1;
    if (len + 1 > cap) return false;
    memcpy(out, path, len);
    out[len] = '\0';
    return true;
}

/* Expand a leading @loader_path or @executable_path token. Anything else
 * (an absolute path, or a still-unresolved @rpath/... entry) is passed
 * through unchanged — @rpath is deliberately left for the caller, see
 * vu_macho.h point 2. */
static bool expand_token(const char *value, const char *file_path,
                         const char *exe_path, char *out, size_t cap)
{
    const char *rest = NULL;
    const char *base = NULL;

    if (strncmp(value, "@loader_path", 12) == 0 &&
        (value[12] == '/' || value[12] == '\0')) {
        rest = value + 12;
        base = file_path;
    } else if (strncmp(value, "@executable_path", 16) == 0 &&
              (value[16] == '/' || value[16] == '\0')) {
        rest = value + 16;
        base = exe_path;
    }

    if (!rest) {
        if (snprintf(out, cap, "%s", value) >= (int)cap) return false;
        return true;
    }

    char dir[VU_PATH_MAX];
    if (!base || !dirname_of(base, dir, sizeof dir)) return false;
    if (snprintf(out, cap, "%s%s", dir, rest) >= (int)cap) return false;
    return true;
}

/* Select the fat_arch slice matching the host architecture. Returns the
 * slice's own byte offset/size within the file via slice_off/slice_len. */
/*
 * `hdr_n` bounds what's available to PARSE the fat_header/fat_arch table
 * itself (the initial bounded read); `filesz` is the REAL total file size,
 * used only to validate a selected slice's offset/size are within the actual
 * file — the slice's own bytes are read separately, afterwards, starting
 * from its offset (see vu_macho_dylibs), never assumed to already be in `b`.
 */
static bool select_fat_slice(const unsigned char *b, size_t hdr_n, uint64_t filesz,
                             size_t *slice_off, size_t *slice_len, vu_err *e)
{
    uint32_t nfat;
    if (!be32_at(b, hdr_n, 4, &nfat)) { vu_err_set(e, "macho: truncated fat header"); return false; }
    if (nfat == 0 || nfat > 64) { vu_err_set(e, "macho: implausible fat_arch count"); return false; }
    if (VU_HOST_CPU_TYPE == 0) {
        vu_err_set(e, "macho: fat binary on an unrecognized host architecture; "
                      "cannot tell which slice would actually run");
        return false;
    }

    size_t at = 8;
    for (uint32_t i = 0; i < nfat; ++i, at += 20) {
        uint32_t cputype, offset, size;
        if (!be32_at(b, hdr_n, at, &cputype) ||
            !be32_at(b, hdr_n, at + 8, &offset) ||
            !be32_at(b, hdr_n, at + 12, &size)) {
            vu_err_set(e, "macho: truncated fat_arch entry"); return false;
        }
        if (cputype != VU_HOST_CPU_TYPE) continue;
        if ((uint64_t)offset + size > filesz) {
            vu_err_set(e, "macho: fat_arch slice extends past end of file"); return false;
        }
        *slice_off = offset;
        *slice_len = size;
        return true;
    }
    vu_err_set(e, "macho: no fat_arch slice matches this host's architecture");
    return false;
}

bool vu_macho_dylibs(const char *path, const char *exe_path, vu_macho_info *out, vu_err *e)
{
    if (!path || !exe_path || !out) { vu_err_set(e, "macho: null argument"); return false; }
    memset(out, 0, sizeof *out);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { vu_err_set(e, "macho: cannot open '%s': %s", path, strerror(errno)); return false; }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        vu_err_set(e, "macho: cannot stat '%s': %s", path, strerror(errno));
        close(fd); return false;
    }
    if (!S_ISREG(st.st_mode)) {
        vu_err_set(e, "macho: '%s' is not a regular file", path);
        close(fd); return false;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > MACHO_MAX_FILE_SIZE) {
        vu_err_set(e, "macho: '%s' is implausibly large", path);
        close(fd); return false;
    }
    uint64_t filesz = (uint64_t)st.st_size;

    static unsigned char buf[MACHO_READ_CAP];
    size_t want = filesz < MACHO_READ_CAP ? (size_t)filesz : MACHO_READ_CAP;
    size_t got = 0;
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            vu_err_set(e, "macho: cannot read '%s': %s", path, strerror(errno));
            close(fd); return false;
        }
        if (r == 0) break;
        got += (size_t)r;
    }

    if (got < 4) { close(fd); return true; }   /* not an error: e.g. an empty/tiny file */

    /*
     * Fat/universal binary: select one slice, then re-read from ITS OWN
     * offset — never assumed to already be inside the initial bounded read
     * above, which only ever needs to cover the (small) fat_header/fat_arch
     * table, not any slice's own content. A slice can start well past
     * MACHO_READ_CAP into a large file, and its own header/load-command
     * region is what actually gets parsed below, read fresh starting there.
     */
    size_t base_len;
    if (buf[0] == FAT_MAGIC_BE0 && buf[1] == FAT_MAGIC_BE1 &&
        buf[2] == FAT_MAGIC_BE2 && buf[3] == FAT_MAGIC_BE3) {
        out->is_fat = true;
        size_t slice_off = 0, slice_len = 0;
        if (!select_fat_slice(buf, got, filesz, &slice_off, &slice_len, e)) {
            close(fd); return false;
        }
        if (lseek(fd, (off_t)slice_off, SEEK_SET) == (off_t)-1) {
            vu_err_set(e, "macho: cannot seek to fat slice in '%s': %s", path, strerror(errno));
            close(fd); return false;
        }
        size_t want2 = slice_len < MACHO_READ_CAP ? slice_len : MACHO_READ_CAP;
        size_t got2 = 0;
        while (got2 < want2) {
            ssize_t r = read(fd, buf + got2, want2 - got2);
            if (r < 0) {
                if (errno == EINTR) continue;
                vu_err_set(e, "macho: cannot read fat slice of '%s': %s", path, strerror(errno));
                close(fd); return false;
            }
            if (r == 0) break;
            got2 += (size_t)r;
        }
        base_len = got2;
    } else {
        base_len = got;
    }
    close(fd);

    if (base_len < 28) return true;   /* too small to be Mach-O: not an error */

    uint32_t magic;
    /*
     * Magic is read big-endian-composed here purely as a fixed way to turn 4
     * raw bytes into one comparable number — it does NOT mean "this file is
     * big-endian". Verified directly (not just reasoned about) against a
     * real 64-bit little-endian Mach-O binary: its on-disk magic bytes are
     * cf fa ed fe (`xxd`), which read as big-endian compose to 0xcffaedfe —
     * MH_CIGAM_64, the "swapped" constant — even though the file is little-
     * endian. The CIGAM forms are what a genuinely LITTLE-endian file's
     * bytes compose to under a big-endian read; the plain MAGIC forms are
     * what a genuinely BIG-endian file's bytes compose to. Getting this
     * backwards (an earlier version of this function did) makes every real
     * binary on every real Mac fail to parse at all, caught by the reader
     * corpus's little-endian cases the moment they were run rather than
     * merely reasoned through.
     */
    if (!be32_at(buf, base_len, 0, &magic)) return true;

    bool is64, le;
    if (magic == MH_MAGIC)          { is64 = false; le = false; }
    else if (magic == MH_CIGAM)     { is64 = false; le = true;  }
    else if (magic == MH_MAGIC_64)  { is64 = true;  le = false; }
    else if (magic == MH_CIGAM_64)  { is64 = true;  le = true;  }
    else return true;   /* not Mach-O: e.g. the vpnc-script shell interpreter */

    img m = { buf, base_len, is64, le };
    out->is_macho = true;
    out->is_64 = is64;
    out->is_le = le;

    uint32_t ncmds, sizeofcmds;
    if (!rd32(&m, 16, &ncmds) || !rd32(&m, 20, &sizeofcmds)) {
        vu_err_set(e, "macho: truncated mach_header"); return false;
    }
    size_t hdr_size = is64 ? 32 : 28;
    if ((uint64_t)hdr_size + sizeofcmds > m.n) {
        vu_err_set(e, "macho: load commands extend past end of file"); return false;
    }

    size_t off = hdr_size;
    for (uint32_t i = 0; i < ncmds; ++i) {
        if (off + 8 > m.n) { vu_err_set(e, "macho: truncated load command"); return false; }
        uint32_t cmd, cmdsize;
        if (!rd32(&m, off, &cmd) || !rd32(&m, off + 4, &cmdsize)) {
            vu_err_set(e, "macho: truncated load command"); return false;
        }
        if (cmdsize < 8 || off + cmdsize > m.n) {
            vu_err_set(e, "macho: load command size out of bounds"); return false;
        }

        bool is_dylib = (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB ||
                         cmd == LC_REEXPORT_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB);
        bool is_rpath = (cmd == LC_RPATH);

        if (is_dylib || is_rpath) {
            uint32_t str_off;
            if (!rd32(&m, off + 8, &str_off)) {
                vu_err_set(e, "macho: truncated dylib/rpath command"); return false;
            }
            char raw[VU_PATH_MAX];
            if (!lcstr_get(&m, off, cmdsize, str_off, raw, sizeof raw)) {
                vu_err_set(e, "macho: load command string is outside its own command"); return false;
            }
            char expanded[VU_PATH_MAX];
            if (!expand_token(raw, path, exe_path, expanded, sizeof expanded)) {
                vu_err_set(e, "macho: expanded load-command path too long"); return false;
            }
            if (is_dylib) {
                if (out->n_dylib >= VU_MACHO_DYLIB_MAX) out->truncated = true;
                else {
                    memcpy(out->dylib[out->n_dylib], expanded, strlen(expanded) + 1);
                    out->n_dylib++;
                }
            } else {
                if (out->n_rpath >= VU_MACHO_RPATH_MAX) out->truncated = true;
                else {
                    memcpy(out->rpath[out->n_rpath], expanded, strlen(expanded) + 1);
                    out->n_rpath++;
                }
            }
        }

        off += cmdsize;
    }
    return true;
}
