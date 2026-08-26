/*
 * elf.c — the dynamic section of an ELF file, and nothing else.
 *
 * Deliberately hand-rolled rather than using <elf.h>: this parses a file whose
 * class and byte order may differ from the machine doing the parsing (the test
 * fixtures do exactly that on purpose), and every field access is bounds-checked
 * against the file size. libelf would be a dependency, and elf.h's structs
 * assume native layout.
 *
 * Everything here is read-only, allocation-free above a single buffer, and total:
 * any byte string in, a verdict out.
 */

#include "vu_elf.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A privileged program has no business reading an arbitrarily large file into
 * memory. openconnect is ~1MB; 8MB is far beyond any real binary and still
 * bounded. */
#define ELF_MAX_FILE (8u * 1024u * 1024u)

/* --- the handful of constants we need, spelled out rather than #included --- */
#define PT_LOAD     1
#define PT_DYNAMIC  2
#define DT_NULL     0
#define DT_NEEDED   1
#define DT_STRTAB   5
#define DT_STRSZ    10
#define DT_RPATH    15
#define DT_RUNPATH  29

typedef struct {
    const unsigned char *b;
    size_t               n;
    bool                 is64, le;
} img;

/*
 * Bounds-checked little/big-endian reads. Every caller checks the return.
 *
 * The cast is OUTSIDE the ternary, and that placement is the whole point. A
 * conditional expression whose two operands are both uint16_t has type INT: the
 * usual arithmetic conversions promote both operands, after any cast inside them.
 * So the previous version, which cast each branch to uint16_t separately, still
 * assigned an int to a uint16_t - and GCC's -Wconversion rejected it, because it
 * does not propagate value ranges across a conditional and so cannot prove the
 * result fits.
 *
 * Confirmed with _Generic rather than read off the standard:
 *
 *     _Generic((le ? x : y), int: ..., uint16_t: ...)        ->  int
 *     _Generic((uint16_t)(x | y), int: ..., uint16_t: ...)   ->  uint16_t
 *
 * Clang does not implement this warning at all, not even under -Weverything, so
 * the class is invisible on a macOS development machine and appears only in the
 * GCC leg of CI. See helper/t/README.
 */
static bool rd16(const img *m, size_t off, uint16_t *out)
{
    if (off + 2 > m->n) return false;
    /* Wider temporaries so the shifts happen in an unsigned type of known width,
     * then exactly one narrowing cast, on the assignment. */
    uint32_t lo = m->b[off], hi = m->b[off + 1];
    *out = (uint16_t)(m->le ? (lo | hi << 8) : (lo << 8 | hi));
    return true;
}

static bool rd32(const img *m, size_t off, uint32_t *out)
{
    if (off + 4 > m->n) return false;
    const unsigned char *p = m->b + off;
    *out = m->le ? (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24
                 : (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
    return true;
}

static bool rd64(const img *m, size_t off, uint64_t *out)
{
    if (off + 8 > m->n) return false;
    uint32_t lo, hi;
    if (m->le) {
        if (!rd32(m, off, &lo) || !rd32(m, off + 4, &hi)) return false;
    } else {
        if (!rd32(m, off, &hi) || !rd32(m, off + 4, &lo)) return false;
    }
    *out = (uint64_t)hi << 32 | lo;
    return true;
}

/* A word: 8 bytes on ELF64, 4 on ELF32. Most of the parser is width-agnostic
 * once reads go through here. */
static bool rdword(const img *m, size_t off, uint64_t *out)
{
    if (m->is64) return rd64(m, off, out);
    uint32_t v;
    if (!rd32(m, off, &v)) return false;
    *out = v;
    return true;
}

/*
 * Translate a virtual address to a file offset using the PT_LOAD segments.
 *
 * DT_STRTAB is a VADDR, not an offset — a detail that is easy to miss and
 * produces a parser that works on some binaries and reads garbage from others,
 * because for many executables the two happen to coincide in the first segment.
 */
static bool vaddr_to_off(const img *m, uint64_t phoff, uint16_t phentsize,
                         uint16_t phnum, uint64_t vaddr, uint64_t *out_off)
{
    for (uint16_t i = 0; i < phnum; ++i) {
        size_t ph = (size_t)phoff + (size_t)i * phentsize;
        uint32_t type;
        if (!rd32(m, ph, &type)) return false;
        if (type != PT_LOAD) continue;

        /* Field order differs between ELF32 and ELF64 headers. */
        uint64_t p_offset, p_vaddr, p_filesz;
        if (m->is64) {
            if (!rdword(m, ph + 8,  &p_offset) ||
                !rdword(m, ph + 16, &p_vaddr)  ||
                !rdword(m, ph + 32, &p_filesz)) return false;
        } else {
            if (!rdword(m, ph + 4,  &p_offset) ||
                !rdword(m, ph + 8,  &p_vaddr)  ||
                !rdword(m, ph + 16, &p_filesz)) return false;
        }
        if (vaddr >= p_vaddr && vaddr - p_vaddr < p_filesz) {
            *out_off = p_offset + (vaddr - p_vaddr);
            return true;
        }
    }
    return false;
}

/* A NUL-terminated string inside the dynamic string table, with the table's own
 * bounds enforced as well as the file's. */
static bool strtab_get(const img *m, uint64_t stroff, uint64_t strsz,
                       uint64_t idx, char *out, size_t cap)
{
    if (idx >= strsz) return false;
    size_t at = (size_t)(stroff + idx);
    if (at >= m->n) return false;
    size_t limit = (size_t)(stroff + strsz);
    if (limit > m->n) limit = m->n;

    size_t len = 0;
    while (at + len < limit && m->b[at + len] != '\0') len++;
    if (at + len >= limit) return false;          /* unterminated */
    if (len + 1 > cap) return false;
    memcpy(out, m->b + at, len);
    out[len] = '\0';
    return true;
}

/* The directory holding `path`, for $ORIGIN. */
static bool dirname_of(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    if (!slash) return false;
    size_t len = (size_t)(slash - path);
    if (len == 0) len = 1;                        /* "/x" -> "/" */
    if (len + 1 > cap) return false;
    memcpy(out, path, len);
    out[len] = '\0';
    return true;
}

/*
 * Split a colon-separated search path and expand $ORIGIN.
 *
 * $LIB and $PLATFORM are refused. Expanding them needs the loader's own notion
 * of the machine (lib vs lib64, x86_64 vs aarch64), and a search directory we
 * cannot resolve is one we cannot verify — which for a closure check means we
 * must not claim to have verified it.
 */
static bool split_rpath(const char *value, const char *binary,
                        vu_elf_info *out, vu_err *e)
{
    char origin[VU_PATH_MAX];
    bool have_origin = dirname_of(binary, origin, sizeof origin);

    const char *p = value;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t len = colon ? (size_t)(colon - p) : strlen(p);

        if (len > 0) {
            char item[VU_PATH_MAX];
            if (len + 1 > sizeof item) { vu_err_set(e, "elf: rpath entry too long"); return false; }
            memcpy(item, p, len);
            item[len] = '\0';

            if (strstr(item, "$LIB") || strstr(item, "${LIB}") ||
                strstr(item, "$PLATFORM") || strstr(item, "${PLATFORM}")) {
                vu_err_set(e, "elf: rpath '%s' uses a loader substitution this check "
                              "cannot resolve", item);
                return false;
            }

            char expanded[VU_PATH_MAX];
            const char *dollar = strstr(item, "$ORIGIN");
            size_t tok = 7;
            if (!dollar) { dollar = strstr(item, "${ORIGIN}"); tok = 9; }
            if (dollar) {
                if (!have_origin) {
                    vu_err_set(e, "elf: $ORIGIN in rpath but '%s' has no directory", binary);
                    return false;
                }
                size_t pre = (size_t)(dollar - item);
                int n = snprintf(expanded, sizeof expanded, "%.*s%s%s",
                                 (int)pre, item, origin, dollar + tok);
                if (n < 0 || (size_t)n >= sizeof expanded) {
                    vu_err_set(e, "elf: expanded rpath too long"); return false;
                }
            } else if (snprintf(expanded, sizeof expanded, "%s", item) >= (int)sizeof expanded) {
                vu_err_set(e, "elf: rpath entry too long"); return false;
            }

            if (out->n_rpath >= VU_ELF_RPATH_MAX) {
                out->truncated = true;
            } else {
                memcpy(out->rpath[out->n_rpath], expanded, strlen(expanded) + 1);
                out->n_rpath++;
            }
        }
        if (!colon) break;
        p = colon + 1;
    }
    return true;
}

bool vu_elf_dynamic(const char *path, vu_elf_info *out, vu_err *e)
{
    if (!path || !out) { vu_err_set(e, "elf: null argument"); return false; }
    memset(out, 0, sizeof *out);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { vu_err_set(e, "elf: cannot open '%s': %s", path, strerror(errno)); return false; }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        vu_err_set(e, "elf: cannot stat '%s': %s", path, strerror(errno));
        close(fd); return false;
    }
    if (!S_ISREG(st.st_mode)) {
        vu_err_set(e, "elf: '%s' is not a regular file", path);
        close(fd); return false;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > ELF_MAX_FILE) {
        vu_err_set(e, "elf: '%s' is implausibly large", path);
        close(fd); return false;
    }

    static unsigned char buf[ELF_MAX_FILE];
    size_t want = (size_t)st.st_size, got = 0;
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            vu_err_set(e, "elf: cannot read '%s': %s", path, strerror(errno));
            close(fd); return false;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);

    img m = { buf, got, false, true };

    /* Not ELF is not an error: a vpnc-script is a shell script, and the closure
     * walk wants its interpreter rather than its libraries. */
    if (got < 64 || memcmp(buf, "\177ELF", 4) != 0) return true;

    unsigned char cls = buf[4], data = buf[5];
    if (cls != 1 && cls != 2) { vu_err_set(e, "elf: unknown ELF class %u", cls); return false; }
    if (data != 1 && data != 2) { vu_err_set(e, "elf: unknown ELF data encoding %u", data); return false; }
    m.is64 = (cls == 2);
    m.le   = (data == 1);
    out->is_elf = true;
    out->is_64  = m.is64;
    out->is_le  = m.le;

    /* e_phoff / e_phentsize / e_phnum, at different offsets per class. */
    uint64_t phoff;
    uint16_t phentsize, phnum;
    if (m.is64) {
        if (!rdword(&m, 32, &phoff) || !rd16(&m, 54, &phentsize) || !rd16(&m, 56, &phnum)) {
            vu_err_set(e, "elf: truncated ELF64 header"); return false;
        }
    } else {
        if (!rdword(&m, 28, &phoff) || !rd16(&m, 42, &phentsize) || !rd16(&m, 44, &phnum)) {
            vu_err_set(e, "elf: truncated ELF32 header"); return false;
        }
    }
    if (phentsize < (m.is64 ? 56 : 32) || phnum == 0) {
        vu_err_set(e, "elf: implausible program header table"); return false;
    }
    if (phoff + (uint64_t)phentsize * phnum > got) {
        vu_err_set(e, "elf: program header table extends past end of file"); return false;
    }

    /* PT_DYNAMIC. A static binary has none, which is a legitimate answer: there
     * is no library closure to check. */
    uint64_t dynoff = 0, dynsz = 0;
    bool have_dyn = false;
    for (uint16_t i = 0; i < phnum; ++i) {
        size_t ph = (size_t)phoff + (size_t)i * phentsize;
        uint32_t type;
        if (!rd32(&m, ph, &type)) { vu_err_set(e, "elf: truncated program header"); return false; }
        if (type != PT_DYNAMIC) continue;
        if (m.is64) {
            if (!rdword(&m, ph + 8, &dynoff) || !rdword(&m, ph + 32, &dynsz)) {
                vu_err_set(e, "elf: truncated PT_DYNAMIC"); return false;
            }
        } else {
            if (!rdword(&m, ph + 4, &dynoff) || !rdword(&m, ph + 16, &dynsz)) {
                vu_err_set(e, "elf: truncated PT_DYNAMIC"); return false;
            }
        }
        have_dyn = true;
        break;
    }
    if (!have_dyn) return true;
    if (dynoff + dynsz > got) {
        vu_err_set(e, "elf: dynamic section extends past end of file"); return false;
    }

    size_t entsz = m.is64 ? 16u : 8u;

    /* Two passes. The string table has to be located before any DT_NEEDED or
     * DT_RPATH value can be read, and nothing guarantees DT_STRTAB comes first. */
    uint64_t strvaddr = 0, strsz = 0;
    bool have_strtab = false, have_strsz = false;
    for (uint64_t at = dynoff; at + entsz <= dynoff + dynsz; at += entsz) {
        uint64_t tag, val;
        if (!rdword(&m, (size_t)at, &tag) || !rdword(&m, (size_t)at + entsz / 2, &val)) {
            vu_err_set(e, "elf: truncated dynamic entry"); return false;
        }
        if (tag == DT_NULL) break;
        if (tag == DT_STRTAB) { strvaddr = val; have_strtab = true; }
        if (tag == DT_STRSZ)  { strsz    = val; have_strsz = true; }
    }
    if (!have_strtab || !have_strsz) {
        vu_err_set(e, "elf: dynamic section has no string table"); return false;
    }

    uint64_t stroff = 0;
    if (!vaddr_to_off(&m, phoff, phentsize, phnum, strvaddr, &stroff)) {
        vu_err_set(e, "elf: dynamic string table address is not in any loaded segment");
        return false;
    }
    if (stroff + strsz > got) {
        vu_err_set(e, "elf: dynamic string table extends past end of file"); return false;
    }

    for (uint64_t at = dynoff; at + entsz <= dynoff + dynsz; at += entsz) {
        uint64_t tag, val;
        if (!rdword(&m, (size_t)at, &tag) || !rdword(&m, (size_t)at + entsz / 2, &val)) {
            vu_err_set(e, "elf: truncated dynamic entry"); return false;
        }
        if (tag == DT_NULL) break;

        if (tag == DT_NEEDED) {
            char name[VU_ELF_NAME_MAX];
            if (!strtab_get(&m, stroff, strsz, val, name, sizeof name)) {
                vu_err_set(e, "elf: DT_NEEDED name is outside the string table"); return false;
            }
            if (out->n_needed >= VU_ELF_NEEDED_MAX) out->truncated = true;
            else {
                memcpy(out->needed[out->n_needed], name, strlen(name) + 1);
                out->n_needed++;
            }
        } else if (tag == DT_RPATH || tag == DT_RUNPATH) {
            char value[VU_PATH_MAX];
            if (!strtab_get(&m, stroff, strsz, val, value, sizeof value)) {
                vu_err_set(e, "elf: rpath value is outside the string table"); return false;
            }
            if (tag == DT_RUNPATH) out->had_runpath = true;
            if (!split_rpath(value, path, out, e)) return false;
        }
    }
    return true;
}
