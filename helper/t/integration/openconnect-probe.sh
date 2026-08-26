#!/usr/bin/env bash
# openconnect-probe.sh — questions only the real OpenConnect can answer.
#
# Step 11 of PRIVILEGED-HELPER-DESIGN.md §16. Two of the design's open questions
# and one of §18's "integration test, not source inspection" items are about what
# OpenConnect itself does, not about what this project does. Reading its source
# would answer them for one version; asking the installed binary answers them for
# the version that will actually run.
#
# Kept as a script rather than a one-time investigation because both answers are
# version-dependent: §17.5 says add https:// to the proxy schema IF an
# integration test proves OpenConnect handles it, so the day that changes we want
# a test to notice rather than a memory to fail.
#
# Needs openconnect on PATH and a compiler. Makes no VPN connection: it uses an
# unroutable TEST-NET-1 address and a closed local port, so nothing leaves the
# machine except a TCP SYN to a documentation-reserved address.
set -uo pipefail

fail=0
note() { printf '  %s\n' "$*"; }
ok()   { printf '  [OK] %s\n' "$*"; }
bad()  { printf '  [!!] %s\n' "$*"; fail=1; }

command -v openconnect >/dev/null 2>&1 || {
  echo "openconnect not installed; nothing to probe"
  exit 0
}

echo "=== OpenConnect facts this design depends on ==="
openconnect --version 2>&1 | head -1 | sed 's/^/  /'

# --------------------------------------------------------------------------
# Design section 17.5: does --proxy accept https://?
#
# The v1 schema accepts http:// and socks5:// only, and section 17.5 left adding
# https:// open pending exactly this test. The answer decides whether the
# validator is conservative or simply correct.
# --------------------------------------------------------------------------
echo
echo "Proxy schemes (design section 17.5):"
probe_scheme() {
  local scheme="$1"
  # A closed local port: OpenConnect parses and validates the proxy before it
  # tries to use it, so a connection failure means the scheme was ACCEPTED.
  openconnect --protocol=anyconnect --proxy="${scheme}://127.0.0.1:9" \
              --authenticate --non-inter vpn.invalid 2>&1 | head -5
}

for scheme in http socks5; do
  out="$(probe_scheme "$scheme")"
  if printf '%s' "$out" | grep -qi 'proxies supported\|Failed to parse proxy'; then
    bad "${scheme}:// is REJECTED by this OpenConnect, but the helper accepts it"
    note "    $(printf '%s' "$out" | head -1)"
  else
    ok "${scheme}:// accepted (reached the connection attempt)"
  fi
done

for scheme in https socks4; do
  out="$(probe_scheme "$scheme")"
  if printf '%s' "$out" | grep -qi 'proxies supported\|Failed to parse proxy'; then
    ok "${scheme}:// is rejected by OpenConnect itself — the schema is correct to omit it"
    note "    $(printf '%s' "$out" | grep -i 'proxies supported\|Failed to parse' | head -1)"
  else
    # Not a failure: it is the trigger for a design decision.
    bad "${scheme}:// is now ACCEPTED by OpenConnect. Section 17.5 says to consider"
    note "    adding it to the proxy schema, which needs a design review first."
  fi
done

# --------------------------------------------------------------------------
# Section 18: "confirm OpenConnect does not close inherited descriptors it does
# not own."
#
# The per-profile lock is held by a descriptor with FD_CLOEXEC cleared, so it
# survives the execve and the kernel releases it when OpenConnect exits. That is
# what makes "one tunnel per profile" work with no reaper and no pid file. It
# depends on OpenConnect leaving a descriptor it knows nothing about alone.
# --------------------------------------------------------------------------
echo
echo "Inherited descriptors (design section 6, section 18):"
probe_src="$(mktemp -t vu-fdprobe-XXXXXX).c"
probe_bin="${probe_src%.c}"
trap 'rm -f "$probe_src" "$probe_bin"' EXIT

cat > "$probe_src" <<'PROBE'
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    char lockpath[512];
    snprintf(lockpath, sizeof lockpath, "%s/.vu-fdprobe-%ld", getenv("HOME"), (long)getpid());
    int fd = open(lockpath, O_RDWR | O_CREAT, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0) return 1;
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC);
    if (fd != 3) { dup2(fd, 3); fcntl(3, F_SETFD, 0); }

    pid_t child = fork();
    if (child == 0) {
        int dn = open("/dev/null", O_RDWR);
        dup2(dn, 1); dup2(dn, 2);
        /* 192.0.2.1 is TEST-NET-1: reserved for documentation and never answers,
         * so the connect hangs and leaves a window to inspect the descriptor. */
        char *args[] = { argv[1], (char *)"--protocol=anyconnect",
                         (char *)"--authenticate", (char *)"--non-inter",
                         (char *)"192.0.2.1", NULL };
        execv(argv[1], args);
        _exit(127);
    }
    struct timespec ts = { 2, 0 };
    nanosleep(&ts, NULL);

    /* A SEPARATE open file description, so flock genuinely contends. */
    int probe = open(lockpath, O_RDWR);
    int held = flock(probe, LOCK_EX | LOCK_NB) != 0;
    if (!held) flock(probe, LOCK_UN);
    close(probe);

    kill(child, SIGKILL);
    int st; waitpid(child, &st, 0);
    /* Drop our own copies before asking again, or we measure ourselves. */
    close(fd);
    if (fd != 3) close(3);

    probe = open(lockpath, O_RDWR);
    int after = flock(probe, LOCK_EX | LOCK_NB) != 0;
    close(probe);
    unlink(lockpath);
    printf("held_while_running=%d held_after_exit=%d\n", held, after);
    return 0;
}
PROBE

# The same platform feature macro the Makefile uses, for the same reason: with
# -std=c99 and no macro, glibc hides nanosleep and struct timespec and this will
# not compile. It has to differ by platform - on Darwin _POSIX_C_SOURCE would
# restrict the namespace rather than widen it. See helper/t/README.
case "$(uname)" in
  Darwin) feature=-D_DARWIN_C_SOURCE ;;
  *)      feature=-D_GNU_SOURCE ;;
esac

if ! cc -std=c99 "$feature" -o "$probe_bin" "$probe_src" 2>/dev/null; then
  note "[..] no working compiler; descriptor probe skipped"
else
  result="$("$probe_bin" "$(command -v openconnect)")"
  case "$result" in
    *"held_while_running=1"*) ok "OpenConnect keeps an inherited locked descriptor while it runs" ;;
    *) bad "OpenConnect CLOSED the inherited descriptor. The per-profile lock would"
       note "    be released while the tunnel is still up, so a second connect could start."
       note "    Result: $result" ;;
  esac
  case "$result" in
    *"held_after_exit=0"*) ok "the kernel releases the lock when OpenConnect exits" ;;
    *) bad "the lock outlived OpenConnect: stale state would not self-heal ($result)" ;;
  esac
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "All OpenConnect assumptions hold for this version."
else
  echo "At least one assumption does NOT hold. See above; this needs a design decision."
fi
exit "$fail"
