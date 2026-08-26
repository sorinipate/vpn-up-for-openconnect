/*
 * test_registry.c — corpus for the Model B approval registry (§16 step 6).
 *
 * Unprivileged, using the same two parameters that make step 5 testable: an
 * explicit root and an explicit expected owner. So the ownership and symlink
 * checks under test are the ones that will run as root.
 */

#include "vu_registry.h"
#include "harness.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[VU_PATH_MAX];
static uid_t g_me;
static const uid_t UID_A = 4001;
static const uid_t UID_B = 4002;

static const char *ID_A = "a7d1bb99-538c-4db4-b357-0123456789ab";
static const char *ID_B = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";

static void make_root(void)
{
    vu_path(g_root, sizeof g_root, "%s/vu-reg-test-XXXXXX", vu_test_base());
    if (!mkdtemp(g_root)) {
        fprintf(stderr, "cannot create temp registry root: %s\n", strerror(errno));
        exit(2);
    }
    chmod(g_root, 0700);
    g_me = geteuid();
}

static vu_approval sample(const char *id)
{
    vu_approval a;
    memset(&a, 0, sizeof a);
    snprintf(a.profile_id, sizeof a.profile_id, "%s", id);
    snprintf(a.protocol, sizeof a.protocol, "anyconnect");
    snprintf(a.origin, sizeof a.origin, "https://vpn.example.com:443");
    snprintf(a.fingerprint, sizeof a.fingerprint,
             "sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42");
    a.proxy[0] = '\0';
    return a;
}

/* ------------------------------------------------------------ serialisation */

static void test_serialise(void)
{
    vu_err e;
    vu_approval a = sample(ID_A);
    char text[VU_URL_MAX], text2[VU_URL_MAX];

    vu_err_clear(&e);
    CHECK(vu_approval_serialise(&a, text, sizeof text, &e), "serialise: %s", e.msg);
    CHECK(strstr(text, "version=1\n") != NULL, "record carries a version");
    CHECK(strstr(text, "proxy=NONE\n") != NULL, "no proxy is spelled NONE explicitly");

    /* Byte-identical on re-serialisation, so re-approving an unchanged
     * capability does not churn the file. */
    CHECK(vu_approval_serialise(&a, text2, sizeof text2, &e), "serialise again");
    CHECK(strcmp(text, text2) == 0, "serialisation is canonical");

    vu_approval back;
    vu_err_clear(&e);
    CHECK(vu_approval_parse(text, &back, &e), "round-trips: %s", e.msg);
    CHECK(strcmp(back.profile_id, a.profile_id) == 0, "id survives");
    CHECK(strcmp(back.origin, a.origin) == 0, "origin survives");
    CHECK(back.proxy[0] == '\0', "NONE parses back to no proxy");

    /* A proxy round-trips too. */
    snprintf(a.proxy, sizeof a.proxy, "socks5://127.0.0.1:1080");
    vu_err_clear(&e);
    CHECK(vu_approval_serialise(&a, text, sizeof text, &e), "serialise with proxy");
    CHECK(vu_approval_parse(text, &back, &e), "parse with proxy: %s", e.msg);
    CHECK(strcmp(back.proxy, a.proxy) == 0, "proxy survives");
}

static bool parse_rejected(const char *text)
{
    vu_approval a; vu_err e; vu_err_clear(&e);
    return !vu_approval_parse(text, &a, &e);
}

static void test_parse_strictness(void)
{
    static const char good[] =
        "version=1\n"
        "profile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\n"
        "origin=https://vpn.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\n"
        "proxy=NONE\n";
    vu_approval a; vu_err e; vu_err_clear(&e);
    CHECK(vu_approval_parse(good, &a, &e), "reference record parses: %s", e.msg);

    /* "root wrote it" is not evidence the file is still well-formed: it can be
     * hand-edited, truncated by a full disk, or left over from an older format.
     * So every field is re-validated on the way in. */
    CHECK(parse_rejected("version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"),
          "incomplete record refused");
    CHECK(parse_rejected(""), "empty record refused");
    CHECK(parse_rejected(
        "version=2\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=https://vpn.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "unknown record version refused");
    CHECK(parse_rejected(
        "version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=https://vpn.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"
        "extra=whatever\n"),
        "unrecognised key refused, not ignored");
    CHECK(parse_rejected(
        "version=1\nversion=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=https://vpn.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "duplicate key refused");

    /* A truncated fingerprint in a record must be refused for exactly the same
     * reason it is refused on the command line: --servercert would accept it as
     * a partial match and pin almost nothing. */
    CHECK(parse_rejected(
        "version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=https://vpn.example.com:443\n"
        "fingerprint=sha256:abcd\nproxy=NONE\n"),
        "partial fingerprint in a record refused");

    /* Non-canonical values are refused rather than silently normalised: a record
     * that does not round-trip is a record nobody can reason about. */
    CHECK(parse_rejected(
        "version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=https://VPN.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "non-canonical origin refused");
    CHECK(parse_rejected(
        "version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=https://vpn.example.com\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "origin without an explicit port is not canonical");
    CHECK(parse_rejected(
        "version=1\nprofile_id=A7D1BB99-538C-4DB4-B357-0123456789AB\n"
        "protocol=anyconnect\norigin=https://vpn.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "uppercase profile id is not canonical");
    CHECK(parse_rejected(
        "version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=http\norigin=https://vpn.example.com:443\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "protocol outside the closed set refused");
    CHECK(parse_rejected(
        "version=1\nprofile_id=a7d1bb99-538c-4db4-b357-0123456789ab\n"
        "protocol=anyconnect\norigin=http://vpn.example.com:80\n"
        "fingerprint=sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42\nproxy=NONE\n"),
        "non-https origin refused");
}

/* --------------------------------------------------------------- operations */

static void test_operations(void)
{
    vu_err e;
    vu_approval a = sample(ID_A), got;
    bool found = false, removed = false;

    vu_err_clear(&e);
    CHECK(vu_registry_get(g_root, g_me, UID_A, ID_A, &got, &found, &e),
          "get on an empty registry succeeds: %s", e.msg);
    CHECK(!found, "and reports not-found rather than erroring");

    vu_err_clear(&e);
    CHECK(vu_registry_put(g_root, g_me, UID_A, &a, &e), "put: %s", e.msg);

    /* The record and its directories are 0700/0600 and owned by us. */
    vu_registry_paths rp;
    vu_err_clear(&e);
    CHECK(vu_registry_paths_in(g_root, UID_A, ID_A, &rp, &e), "paths");
    struct stat st;
    CHECK(stat(rp.record, &st) == 0, "record exists");
    CHECK((st.st_mode & 07777) == 0600, "record is 0600, got %04o", (unsigned)(st.st_mode & 07777));
    CHECK(stat(rp.uid_dir, &st) == 0 && (st.st_mode & 07777) == 0700, "uid dir is 0700");

    vu_err_clear(&e);
    CHECK(vu_registry_get(g_root, g_me, UID_A, ID_A, &got, &found, &e) && found,
          "get after put: %s", e.msg);
    CHECK(strcmp(got.origin, a.origin) == 0, "origin round-trips through the file");

    /* Approvals are per-uid: this is what stops one user addressing another's
     * identically-named profile. */
    vu_err_clear(&e);
    CHECK(vu_registry_get(g_root, g_me, UID_B, ID_A, &got, &found, &e), "get for another uid");
    CHECK(!found, "another uid does not see this approval");

    /* Re-approving is idempotent. */
    vu_err_clear(&e);
    CHECK(vu_registry_put(g_root, g_me, UID_A, &a, &e), "re-put: %s", e.msg);

    /* A second profile coexists, and list shows both. */
    vu_approval b = sample(ID_B);
    snprintf(b.origin, sizeof b.origin, "https://other.example.com:8443");
    vu_err_clear(&e);
    CHECK(vu_registry_put(g_root, g_me, UID_A, &b, &e), "put second: %s", e.msg);

    vu_approval items[8];
    size_t n = 0;
    vu_err_clear(&e);
    CHECK(vu_registry_list(g_root, g_me, UID_A, items, 8, &n, &e), "list: %s", e.msg);
    CHECK(n == 2, "list found both approvals, got %zu", n);

    /* A stray .tmp left by an interrupted write must not appear as an approval. */
    {
        char tmp[VU_PATH_MAX];
        vu_path(tmp, sizeof tmp, "%s.tmp", rp.record);
        int fd = open(tmp, O_CREAT | O_WRONLY, 0600);
        CHECK(fd >= 0, "made a stray temp file");
        close(fd);
        n = 0;
        vu_err_clear(&e);
        CHECK(vu_registry_list(g_root, g_me, UID_A, items, 8, &n, &e), "list ignores .tmp: %s", e.msg);
        CHECK(n == 2, "still two approvals, got %zu", n);
        unlink(tmp);
    }

    /* Truncation must be reported, never silent: an approval you cannot see is
     * an approval you cannot revoke. */
    n = 0;
    vu_err_clear(&e);
    CHECK(!vu_registry_list(g_root, g_me, UID_A, items, 1, &n, &e),
          "a listing that does not fit fails rather than truncating silently");
    CHECK(strstr(e.msg, "truncated") != NULL, "and says so: '%s'", e.msg);

    /* Revoke. */
    vu_err_clear(&e);
    CHECK(vu_registry_delete(g_root, g_me, UID_A, ID_A, &removed, &e) && removed,
          "revoke: %s", e.msg);
    vu_err_clear(&e);
    CHECK(vu_registry_get(g_root, g_me, UID_A, ID_A, &got, &found, &e) && !found,
          "revoked approval is gone");
    vu_err_clear(&e);
    CHECK(vu_registry_delete(g_root, g_me, UID_A, ID_A, &removed, &e) && !removed,
          "revoking again is not an error");
}

static void test_tampering(void)
{
    vu_err e;
    vu_approval a = sample(ID_A), got;
    bool found = false;

    vu_err_clear(&e);
    CHECK(vu_registry_put(g_root, g_me, UID_A, &a, &e), "put: %s", e.msg);

    vu_registry_paths rp;
    vu_err_clear(&e);
    CHECK(vu_registry_paths_in(g_root, UID_A, ID_A, &rp, &e), "paths");

    /* A record whose contents name a different profile than its filename has
     * been moved or edited, and must not authorise anything. */
    {
        vu_approval other = sample(ID_B);
        char text[VU_URL_MAX];
        vu_err_clear(&e);
        CHECK(vu_approval_serialise(&other, text, sizeof text, &e), "serialise other");
        FILE *f = fopen(rp.record, "w");
        CHECK(f != NULL, "open record for tampering");
        if (f) { fputs(text, f); fclose(f); }
        vu_err_clear(&e);
        CHECK(!vu_registry_get(g_root, g_me, UID_A, ID_A, &got, &found, &e),
              "filename/content mismatch refused");
        CHECK(strstr(e.msg, "filename") != NULL, "refusal names the reason: '%s'", e.msg);
    }

    /* A loosened record is refused: 0644 means someone else can read which VPNs
     * this machine will establish without a password. */
    vu_err_clear(&e);
    CHECK(vu_registry_put(g_root, g_me, UID_A, &a, &e), "restore record");
    CHECK(chmod(rp.record, 0644) == 0, "loosen record mode");
    vu_err_clear(&e);
    CHECK(!vu_registry_get(g_root, g_me, UID_A, ID_A, &got, &found, &e),
          "group/other-readable record refused");

    /* Wrong owner is refused. We cannot chown without privilege, so assert by
     * expecting an owner we are not. */
    CHECK(chmod(rp.record, 0600) == 0, "restore record mode");
    vu_err_clear(&e);
    CHECK(!vu_registry_get(g_root, g_me + 1, UID_A, ID_A, &got, &found, &e),
          "record owned by the wrong uid refused");

    /* A symlinked record path must not be followed: reading through it would let
     * an attacker choose what root treats as policy. */
    {
        char decoy[VU_PATH_MAX];
        vu_path(decoy, sizeof decoy, "%s/decoy", g_root);
        char text[VU_URL_MAX];
        vu_approval other = sample(ID_A);
        snprintf(other.origin, sizeof other.origin, "https://attacker.example.com:443");
        vu_err_clear(&e);
        CHECK(vu_approval_serialise(&other, text, sizeof text, &e), "serialise decoy");
        FILE *f = fopen(decoy, "w");
        if (f) { fputs(text, f); fclose(f); }
        chmod(decoy, 0600);

        unlink(rp.record);
        CHECK(symlink(decoy, rp.record) == 0, "symlink the record path");
        vu_err_clear(&e);
        CHECK(!vu_registry_get(g_root, g_me, UID_A, ID_A, &got, &found, &e),
              "symlinked record refused");
        unlink(rp.record);
    }

    /* Directory permissions are contract too. */
    vu_err_clear(&e);
    CHECK(vu_registry_put(g_root, g_me, UID_A, &a, &e), "restore record");
    CHECK(chmod(rp.uid_dir, 0755) == 0, "loosen uid dir");
    vu_err_clear(&e);
    CHECK(!vu_registry_put(g_root, g_me, UID_A, &a, &e),
          "put into a group-readable uid dir refused");
    CHECK(chmod(rp.uid_dir, 0700) == 0, "restore uid dir");
}

static void test_admin_gate(void)
{
    vu_err e; vu_err_clear(&e);
    if (geteuid() != 0) {
        CHECK(!vu_admin_require_root(&e), "vpn-up-admin refuses to run unprivileged");
        CHECK(strstr(e.msg, "sudo") != NULL, "and says how to run it: '%s'", e.msg);
    } else {
        CHECK(vu_admin_require_root(&e), "root passes the gate");
    }
}

void vu_test_registry(void)
{
    make_root();
    test_serialise();
    test_parse_strictness();
    test_operations();
    test_tampering();
    test_admin_gate();
    vu_rm_rf(g_root);
}
