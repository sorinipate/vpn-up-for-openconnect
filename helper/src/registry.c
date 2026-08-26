/* registry.c — persistent, root-owned Model B approval records. */

#define _GNU_SOURCE

#include "vu_registry.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* --------------------------------------------------------------- path layout */

bool vu_registry_paths_in(const char *root, uid_t uid, const char *profile_id,
                          vu_registry_paths *out, vu_err *e)
{
    if (!root || !out) { vu_err_set(e, "registry: null argument"); return false; }
    memset(out, 0, sizeof *out);

    if (snprintf(out->approvals, sizeof out->approvals, "%s/%s",
                 root, VU_APPROVALS_DIR) >= (int)sizeof out->approvals) {
        vu_err_set(e, "registry: approvals path too long"); return false;
    }
    if (snprintf(out->uid_dir, sizeof out->uid_dir, "%s/%lu",
                 out->approvals, (unsigned long)uid) >= (int)sizeof out->uid_dir) {
        vu_err_set(e, "registry: uid path too long"); return false;
    }

    /* A record path is only built for a specific profile; list() works from the
     * uid directory alone. */
    if (profile_id) {
        if (!*profile_id) { vu_err_set(e, "registry: empty profile id"); return false; }
        /* The caller is expected to have canonicalised this. Refuse the shapes
         * that would escape the directory regardless, because a path built from
         * an uncanonicalised id must fail loudly rather than land elsewhere. */
        if (strchr(profile_id, '/') || strcmp(profile_id, ".") == 0 ||
            strcmp(profile_id, "..") == 0) {
            vu_err_set(e, "registry: profile id is not canonical");
            return false;
        }
        if (snprintf(out->record, sizeof out->record, "%s/%s",
                     out->uid_dir, profile_id) >= (int)sizeof out->record) {
            vu_err_set(e, "registry: record path too long"); return false;
        }
    }
    return true;
}

bool vu_registry_paths_for(uid_t uid, const char *profile_id,
                           vu_registry_paths *out, vu_err *e)
{
    return vu_registry_paths_in(VU_REGISTRY_ROOT, uid, profile_id, out, e);
}

/* ------------------------------------------------------------ serialisation */

bool vu_approval_serialise(const vu_approval *a, char *out, size_t cap, vu_err *e)
{
    if (!a || !out) { vu_err_set(e, "approval: null argument"); return false; }

    /* Fixed key order and one trailing newline per line, so re-approving an
     * unchanged capability rewrites an identical file. */
    int n = snprintf(out, cap,
                     "version=%d\n"
                     "profile_id=%s\n"
                     "protocol=%s\n"
                     "origin=%s\n"
                     "fingerprint=%s\n"
                     "proxy=%s\n",
                     VU_APPROVAL_VERSION,
                     a->profile_id, a->protocol, a->origin, a->fingerprint,
                     a->proxy[0] ? a->proxy : "NONE");
    if (n < 0 || (size_t)n >= cap) {
        vu_err_set(e, "approval: record does not fit");
        return false;
    }
    return true;
}

bool vu_approval_parse(const char *text, vu_approval *out, vu_err *e)
{
    if (!text || !out) { vu_err_set(e, "approval: null argument"); return false; }
    memset(out, 0, sizeof *out);

    bool have_version = false, have_id = false, have_proto = false;
    bool have_origin = false, have_fpr = false, have_proxy = false;

    const char *p = text;
    size_t lineno = 0;

    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        lineno++;

        if (len == 0) {
            /* A single trailing newline ends the record; a blank line inside it
             * means the file is not what it claims to be. */
            if (nl && *(nl + 1) == '\0') break;
            vu_err_set(e, "approval: blank line %zu", lineno);
            return false;
        }

        const char *eq = memchr(p, '=', len);
        if (!eq) {
            vu_err_set(e, "approval: line %zu is not key=value", lineno);
            return false;
        }
        size_t klen = (size_t)(eq - p);
        const char *val = eq + 1;
        size_t vlen = len - klen - 1;

        char value[VU_URL_MAX];
        if (vlen + 1 > sizeof value) {
            vu_err_set(e, "approval: value on line %zu too long", lineno);
            return false;
        }
        memcpy(value, val, vlen);
        value[vlen] = '\0';
        for (size_t i = 0; i < vlen; ++i) {
            unsigned char c = (unsigned char)value[i];
            if (c < 0x20 || c == 0x7f) {
                vu_err_set(e, "approval: control byte on line %zu", lineno);
                return false;
            }
        }

        struct { const char *key; char *dst; size_t cap; bool *seen; } f[] = {
            { "profile_id",  out->profile_id,  sizeof out->profile_id,  &have_id     },
            { "protocol",    out->protocol,    sizeof out->protocol,    &have_proto  },
            { "origin",      out->origin,      sizeof out->origin,      &have_origin },
            { "fingerprint", out->fingerprint, sizeof out->fingerprint, &have_fpr    },
        };

        if (klen == 7 && memcmp(p, "version", 7) == 0) {
            if (have_version) { vu_err_set(e, "approval: duplicate version"); return false; }
            int32_t v;
            if (!vu_parse_i32(value, 1, 1000000, &v, e) || v != VU_APPROVAL_VERSION) {
                vu_err_set(e, "approval: unsupported record version '%s'", value);
                return false;
            }
            have_version = true;
        } else if (klen == 5 && memcmp(p, "proxy", 5) == 0) {
            if (have_proxy) { vu_err_set(e, "approval: duplicate proxy"); return false; }
            /* "NONE" is the explicit spelling for no proxy, so an empty value
             * cannot be mistaken for a deliberate one. */
            if (strcmp(value, "NONE") == 0) {
                out->proxy[0] = '\0';
            } else if (strlen(value) + 1 > sizeof out->proxy) {
                vu_err_set(e, "approval: proxy too long"); return false;
            } else {
                memcpy(out->proxy, value, strlen(value) + 1);
            }
            have_proxy = true;
        } else {
            bool matched = false;
            for (size_t i = 0; i < sizeof f / sizeof *f; ++i) {
                if (strlen(f[i].key) == klen && memcmp(p, f[i].key, klen) == 0) {
                    if (*f[i].seen) {
                        vu_err_set(e, "approval: duplicate %s", f[i].key);
                        return false;
                    }
                    if (strlen(value) + 1 > f[i].cap) {
                        vu_err_set(e, "approval: %s too long", f[i].key);
                        return false;
                    }
                    memcpy(f[i].dst, value, strlen(value) + 1);
                    *f[i].seen = true;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                /* Unknown keys are refused, not ignored: a record we do not
                 * fully understand must never be used to authorise a tunnel. */
                vu_err_set(e, "approval: unrecognised key on line %zu", lineno);
                return false;
            }
        }

        if (!nl) break;
        p = nl + 1;
    }

    if (!have_version || !have_id || !have_proto || !have_origin || !have_fpr || !have_proxy) {
        vu_err_set(e, "approval: record is incomplete");
        return false;
    }

    /*
     * Re-validate every field through the same engine that validated it on the
     * way in. The file was written by root, but "root wrote it" is not evidence
     * that it is still well-formed: it may have been hand-edited, truncated by a
     * full disk, or restored from an older format.
     */
    char scratch[VU_URL_MAX];
    if (!vu_canon_profile_id(out->profile_id, scratch, sizeof scratch, e)) return false;
    if (strcmp(scratch, out->profile_id) != 0) {
        vu_err_set(e, "approval: profile_id is not in canonical form");
        return false;
    }
    if (!vu_valid_protocol(out->protocol, e)) return false;
    {
        vu_url u;
        if (!vu_parse_url(out->origin, &u, e)) {
            vu_err_set(e, "approval: origin is not a valid https URL");
            return false;
        }
        if (strcmp(u.origin, out->origin) != 0) {
            vu_err_set(e, "approval: origin is not in canonical form");
            return false;
        }
    }
    if (!vu_canon_fingerprint(out->fingerprint, scratch, sizeof scratch, e)) return false;
    if (strcmp(scratch, out->fingerprint) != 0) {
        vu_err_set(e, "approval: fingerprint is not in canonical form");
        return false;
    }
    if (out->proxy[0]) {
        if (!vu_canon_proxy(out->proxy, scratch, sizeof scratch, e)) return false;
        if (strcmp(scratch, out->proxy) != 0) {
            vu_err_set(e, "approval: proxy is not in canonical form");
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------- file plumbing */

static bool ensure_chain(const char *root, uid_t owner, const vu_registry_paths *rp, vu_err *e)
{
    /* One owned directory per call, as vu_dir_ensure requires. 0700 throughout:
     * the registry says which VPNs this machine will establish without a
     * password, and that is nobody's business but root's. */
    if (!vu_dir_ensure(root,           owner, 0700, e)) return false;
    if (!vu_dir_ensure(rp->approvals,  owner, 0700, e)) return false;
    if (!vu_dir_ensure(rp->uid_dir,    owner, 0700, e)) return false;
    return true;
}

static bool write_record(const char *path, const char *text, vu_err *e)
{
    char tmp[VU_PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        vu_err_set(e, "registry: temp path too long"); return false;
    }
    /* O_NOFOLLOW so a symlink planted at the record path cannot redirect a
     * root-owned write, and 0600 because only root reads approvals. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        vu_err_set(e, "registry: cannot write record: %s", strerror(errno));
        return false;
    }
    size_t len = strlen(text);
    ssize_t w = write(fd, text, len);
    if (w < 0 || (size_t)w != len) {
        vu_err_set(e, "registry: short write");
        close(fd); unlink(tmp);
        return false;
    }
    /* An approval that survives a crash only sometimes is worse than one that
     * fails to be written at all, so this fsync is checked. */
    if (fsync(fd) != 0) {
        vu_err_set(e, "registry: cannot flush record: %s", strerror(errno));
        close(fd); unlink(tmp);
        return false;
    }
    if (close(fd) != 0) {
        vu_err_set(e, "registry: cannot close record: %s", strerror(errno));
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        vu_err_set(e, "registry: cannot install record: %s", strerror(errno));
        unlink(tmp);
        return false;
    }
    return true;
}

static bool read_record(const char *path, uid_t owner, char *out, size_t cap,
                        bool *found, vu_err *e)
{
    *found = false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return true;              /* absent is a normal answer */
        vu_err_set(e, "registry: cannot read record: %s%s", strerror(errno),
                   (errno == ELOOP || errno == ENOTDIR) ? " (symlink refused)" : "");
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        vu_err_set(e, "registry: cannot stat record: %s", strerror(errno));
        close(fd); return false;
    }
    if (!S_ISREG(st.st_mode)) {
        vu_err_set(e, "registry: record is not a regular file");
        close(fd); return false;
    }
    if (st.st_uid != owner) {
        vu_err_set(e, "registry: record owned by uid %lu, expected %lu",
                   (unsigned long)st.st_uid, (unsigned long)owner);
        close(fd); return false;
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        vu_err_set(e, "registry: record grants group or other access (mode %04o)",
                   (unsigned)(st.st_mode & 07777));
        close(fd); return false;
    }

    ssize_t r = read(fd, out, cap - 1);
    close(fd);
    if (r < 0) { vu_err_set(e, "registry: cannot read record: %s", strerror(errno)); return false; }
    if ((size_t)r >= cap - 1) { vu_err_set(e, "registry: record too large"); return false; }
    out[r] = '\0';
    *found = true;
    return true;
}

/* --------------------------------------------------------------- operations */

bool vu_registry_put(const char *root, uid_t owner, uid_t uid,
                     const vu_approval *a, vu_err *e)
{
    if (!root || !a) { vu_err_set(e, "registry: null argument"); return false; }

    /* Never store something we would refuse to read back. Round-tripping the
     * record through the parser before it is installed means a malformed
     * approval cannot exist on disk at all. */
    char text[VU_URL_MAX];
    if (!vu_approval_serialise(a, text, sizeof text, e)) return false;
    vu_approval check;
    if (!vu_approval_parse(text, &check, e)) {
        vu_err_set(e, "registry: refusing to store a record that will not parse");
        return false;
    }

    vu_registry_paths rp;
    if (!vu_registry_paths_in(root, uid, a->profile_id, &rp, e)) return false;
    if (!ensure_chain(root, owner, &rp, e)) return false;
    return write_record(rp.record, text, e);
}

bool vu_registry_get(const char *root, uid_t owner, uid_t uid, const char *profile_id,
                     vu_approval *out, bool *found, vu_err *e)
{
    if (!root || !profile_id || !out || !found) {
        vu_err_set(e, "registry: null argument"); return false;
    }
    *found = false;

    vu_registry_paths rp;
    if (!vu_registry_paths_in(root, uid, profile_id, &rp, e)) return false;

    char text[VU_URL_MAX];
    bool present = false;
    if (!read_record(rp.record, owner, text, sizeof text, &present, e)) return false;
    if (!present) return true;

    if (!vu_approval_parse(text, out, e)) return false;

    /* The filename is the profile id; a record whose contents disagree has been
     * moved or tampered with, and must not authorise anything. */
    if (strcmp(out->profile_id, profile_id) != 0) {
        vu_err_set(e, "registry: record contents do not match its filename");
        return false;
    }
    *found = true;
    return true;
}

bool vu_registry_delete(const char *root, uid_t owner, uid_t uid, const char *profile_id,
                        bool *removed, vu_err *e)
{
    if (!root || !profile_id || !removed) { vu_err_set(e, "registry: null argument"); return false; }
    /* owner is unused here deliberately: unlink removes the name, not whatever a
     * symlink points at, and the containing directory is already required to be
     * owner-only 0700, so nothing but the owner could have created the entry.
     * Kept in the signature for symmetry with get/put/list. */
    (void)owner;
    *removed = false;

    vu_registry_paths rp;
    if (!vu_registry_paths_in(root, uid, profile_id, &rp, e)) return false;

    if (unlink(rp.record) != 0) {
        if (errno == ENOENT) return true;              /* revoking nothing is not an error */
        vu_err_set(e, "registry: cannot revoke: %s", strerror(errno));
        return false;
    }
    *removed = true;
    return true;
}

bool vu_registry_list(const char *root, uid_t owner, uid_t uid,
                      vu_approval *out, size_t cap, size_t *count, vu_err *e)
{
    if (!root || !out || !count) { vu_err_set(e, "registry: null argument"); return false; }
    *count = 0;

    vu_registry_paths rp;
    if (!vu_registry_paths_in(root, uid, NULL, &rp, e)) return false;

    DIR *d = opendir(rp.uid_dir);
    if (!d) {
        if (errno == ENOENT) return true;              /* nothing approved yet */
        vu_err_set(e, "registry: cannot list: %s", strerror(errno));
        return false;
    }

    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;                    /* . .. and hidden */
        size_t nlen = strlen(ent->d_name);
        if (nlen > 4 && strcmp(ent->d_name + nlen - 4, ".tmp") == 0) continue;

        if (*count >= cap) {
            /* Never silently truncate a security listing: a user who cannot see
             * an approval cannot revoke it. */
            vu_err_set(e, "registry: more than %zu approvals; listing truncated", cap);
            ok = false;
            break;
        }

        bool found = false;
        vu_err sub; vu_err_clear(&sub);
        if (!vu_registry_get(root, owner, uid, ent->d_name, &out[*count], &found, &sub)) {
            /* One unreadable record must not hide the rest, but it must be
             * reported rather than skipped in silence. */
            vu_err_set(e, "registry: skipping unreadable record '%s': %s",
                       ent->d_name, sub.msg);
            ok = false;
            continue;
        }
        if (found) (*count)++;
    }
    closedir(d);
    return ok;
}

bool vu_admin_require_root(vu_err *e)
{
    if (geteuid() != 0) {
        vu_err_set(e, "vpn-up-admin must be run through sudo (it writes root-owned policy)");
        return false;
    }
    return true;
}
