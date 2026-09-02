#!/usr/bin/env bash
# shellcheck disable=SC2024
#   "sudo doesn't affect redirects" - correct, and intended. Every redirect here
#   is deliberately performed by THIS shell, not by root: the output files live in
#   /tmp and belong to the invoking user, so a root-owned file is never created
#   outside $PREFIX. Having sudo do the redirect would be the bug.
# shellcheck disable=SC2009
#   Reading ps output is the point, not an accident: the claim under test is that
#   the cookie is not visible in ps, and pgrep cannot answer that. Note that the
#   check does NOT pipe ps into grep - see the comment at the check itself for
#   why that shape reports a false leak.
# run.sh — the real vpn-up-helper binary, as root, end to end.
#
# Step 11 of PRIVILEGED-HELPER-DESIGN.md §16. t/test_integration.c already
# exercises the privileged SEQUENCE unprivileged, using the same functions in the
# same order — which covers §18's locking and cookie claims. What it cannot cover
# is the binary itself: the root check, SUDO_UID handling, the registry lookup,
# the closure check against a real installed path, and the argv that a real sudo
# invocation produces.
#
# So this runs the actual binaries under sudo against a stand-in OpenConnect.
#
# WHAT IT DOES TO THE MACHINE, stated plainly because it runs as root:
#   creates  $PREFIX (default /opt/vpn-up-integration), root-owned 0755
#   inside it: a stand-in openconnect, a stand-in vpnc-script, a state root and
#   a registry root, all root-owned
#   removes  $PREFIX entirely on exit, including on failure
# It touches nothing else. No system sudoers file, no /etc/vpnc, no real
# openconnect, no network.
#
# Opt-in on purpose: set VPN_UP_INTEGRATION=1. A test that quietly does
# privileged things because it was in the default target is a test that will
# eventually surprise someone.
set -euo pipefail


# Where the fixture install goes. Chosen at run time from candidates whose parent
# is root-owned and not group- or world-writable, because the closure check walks
# parents and will (correctly) refuse a prefix under a world-writable directory.
# Some CI images ship /opt as mode 0777, which is exactly that case.
#
# The alternative would be to chmod the parent, and that is worse: it mutates a
# system directory to make a test pass, and it hides a real signal - a
# world-writable /opt IS a finding on a machine that intends to run helper mode.
PREFIX_CANDIDATES="/usr/lib /opt /usr/local/lib"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # helper/
PROFILE_ID="11111111-2222-3333-4444-555555555555"
ENDPOINT="https://vpn.example.com:443"
FPR="sha256:1111111111111111111111111111111111111111111111111111111111111111"
MARKER="vu-cookie-must-never-be-visible-anywhere"

checks=0
fails=0
failed_list=""
ok()   { checks=$((checks+1)); printf '  [OK] %s\n' "$*"; }
# Failures are echoed where they happen AND collected, because the useful line is
# easy to lose in a long log - the first CI report of a failure here quoted the
# summary count and not the message, which cost a round trip to find out which of
# twenty-seven checks had failed.
bad()  { checks=$((checks+1)); fails=$((fails+1))
         printf '  [!!] %s\n' "$*"
         failed_list="${failed_list}
  - $*" ; }
note() { printf '       %s\n' "$*"; }
assert() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }

# ---------------------------------------------------------------- preconditions

skip() { printf 'SKIPPED: %s\n' "$*"; exit 0; }

[ "${VPN_UP_INTEGRATION:-0}" = 1 ] || \
  skip "set VPN_UP_INTEGRATION=1 to run the privileged end-to-end test"

# macOS is not a gap in this script: §11.7 makes helper mode fail closed there
# until the dyld closure work (step 13), so `connect` refuses by design and there
# is nothing to test end to end yet.
[ "$(uname)" = Linux ] || \
  skip "helper mode fails closed on $(uname) until the macOS closure work (design step 13)"

command -v sudo >/dev/null 2>&1 || skip "sudo not available"
sudo -n true 2>/dev/null || skip "sudo needs a password; this test must run unattended"

# Is this directory root-owned with no group or other write bit? The same
# question vu_dir_trusted asks in C, asked here with stat so the script can pick a
# location the closure check will accept instead of failing inside it.
parent_is_trustworthy() {
  local d owner mode
  # RESOLVE first, then check - the same policy as vu_path_trusted in C. Without
  # this, `stat` on a symlink reports the LINK's mode: /tmp on macOS is a
  # root-owned 0755 symlink to a 1777 directory, and the naive check called it
  # trustworthy.
  d=$(cd "$1" 2>/dev/null && pwd -P) || return 1
  [ -d "$d" ] || return 1
  if [ "$(uname)" = Darwin ]; then
    owner=$(stat -f '%u' "$d") ; mode=$(stat -f '%Lp' "$d")
  else
    owner=$(stat -c '%u' "$d") ; mode=$(stat -c '%a' "$d")
  fi
  [ "$owner" = 0 ] || return 1
  # No group-write (020) and no other-write (002).
  [ $(( 8#$mode & 8#22 )) -eq 0 ]
}

if [ -n "${VPN_UP_INTEGRATION_PREFIX:-}" ]; then
  PREFIX="$VPN_UP_INTEGRATION_PREFIX"
else
  PREFIX=""
  for cand in $PREFIX_CANDIDATES; do
    if parent_is_trustworthy "$cand"; then
      PREFIX="$cand/vpn-up-integration"
      break
    fi
  done
  [ -n "$PREFIX" ] || skip "no candidate directory ($PREFIX_CANDIDATES) is root-owned
         and free of group/other write, so any fixture install would be refused by
         the closure check for a reason that is about this machine rather than
         about the code"
fi

echo "=== vpn-up-helper end-to-end (as root, stand-in OpenConnect) ==="
echo "prefix: $PREFIX"

cleanup() { sudo rm -rf -- "$PREFIX"; }
trap cleanup EXIT

sudo rm -rf -- "$PREFIX"
# `install -d` sets owner and mode as it creates each directory, the same way the
# file installs below do. The alternative - mkdir, then chown -R, then chmod -
# needs three passes over a privileged path, and a recursive chown in a root
# script is the kind of line a reviewer has to stop and think about.
for d in "$PREFIX" "$PREFIX/bin" "$PREFIX/etc"; do
  sudo install -d -o 0 -g 0 -m 0755 -- "$d"
done

# ------------------------------------------------------------------- the pieces

# The stand-in has to be a compiled ELF binary: the closure check parses the
# pinned binary's dynamic section, and a script is refused as "not an ELF binary".
#
# Built through the MAKEFILE rather than with a cc command written here. The first
# version invoked `cc -std=c99` directly and broke the Linux build: -std=c99
# defines __STRICT_ANSI__, glibc then hides nanosleep and struct timespec behind a
# feature macro, and the compile fails. The Makefile already knows the macro, and
# knows it has to differ by platform - _GNU_SOURCE on glibc, _DARWIN_C_SOURCE on
# Darwin, where _POSIX_C_SOURCE would RESTRICT the namespace instead of widening
# it. Duplicating that knowledge here was the defect; deleting the duplicate is
# the fix. See helper/t/README.
#
# Clean first, because the pinned build below reuses this build directory.
make -C "$HERE" --no-print-directory clean >/dev/null
make -C "$HERE" --no-print-directory build/fake-openconnect >/dev/null
sudo install -o 0 -g 0 -m 0755 "$HERE/build/fake-openconnect" "$PREFIX/bin/openconnect"

printf '#!/bin/sh\n# stand-in vpnc-script\nexit 0\n' > /tmp/vu-fake-script
sudo install -o 0 -g 0 -m 0755 /tmp/vu-fake-script "$PREFIX/etc/vpnc-script"
rm -f /tmp/vu-fake-script

# VU_VPNC_SCRIPT_REAL — the third-party vpnc-script the wrapper delegates to —
# is a SEPARATE pin from VU_VPNC_SCRIPT above, and the closure check walks it
# too (vu_closure_check, not just vu_wrapper_precheck). Left unpinned, the
# build falls back to the compiled-in host default (/etc/vpnc/vpnc-script),
# which does not exist on a CI runner, so the closure check fails on a path
# this test never claimed to touch. Give it its own fixture stand-in.
printf '#!/bin/sh\n# stand-in REAL vpnc-script\nexit 0\n' > /tmp/vu-fake-script-real
sudo install -o 0 -g 0 -m 0755 /tmp/vu-fake-script-real "$PREFIX/etc/vpnc-script-real"
rm -f /tmp/vu-fake-script-real

# Build the binaries with their compile-time pins pointed at the fixture. That
# the roots are compile-time constants rather than environment variables is the
# whole reason this is safe to do: a test build cannot become a runtime override.
# No clean here: the stand-in above lives in the same build directory.
# The loader configuration the closure check validates is the TEST's, not the
# host's. Ubuntu's /etc/ld.so.conf.d lists /usr/local/lib, which on some CI images
# is writable by the unprivileged runner user - so the closure check refuses, and
# it is RIGHT to: a writable library directory means root loads what that user
# put there. But that is a finding about the image, not about this code, and an
# integration test whose verdict depends on the host's loader configuration cannot
# distinguish the two.
#
# So the test supplies its own: an empty ld.so.conf, an empty conf.d, and no
# preload file. The real paths are still what production uses, and the closure
# logic itself is exercised against hostile fixtures by t/test_closure.c - which
# covers a writable configured directory, a writable ld.so.conf, a writable
# conf.d, and a preloaded library in a writable directory.
sudo install -d -o 0 -g 0 -m 0755 -- "$PREFIX/ldso" "$PREFIX/ldso/conf.d"
printf '# empty: the integration test supplies its own loader configuration\n' > /tmp/vu-ldso.conf
sudo install -o 0 -g 0 -m 0644 /tmp/vu-ldso.conf "$PREFIX/ldso/ld.so.conf"
rm -f /tmp/vu-ldso.conf

make -C "$HERE" --no-print-directory build/vpn-up-helper build/vpn-up-admin \
  OPT="-O1 -DVU_OPENCONNECT='\"$PREFIX/bin/openconnect\"' \
       -DVU_VPNC_SCRIPT='\"$PREFIX/etc/vpnc-script\"' \
       -DVU_VPNC_SCRIPT_REAL='\"$PREFIX/etc/vpnc-script-real\"' \
       -DVU_STATE_ROOT='\"$PREFIX/run\"' \
       -DVU_REGISTRY_ROOT='\"$PREFIX/registry\"' \
       -DVU_LDSO_PRELOAD='\"$PREFIX/ldso/ld.so.preload\"' \
       -DVU_LDSO_CONF='\"$PREFIX/ldso/ld.so.conf\"' \
       -DVU_LDSO_CONF_DIR='\"$PREFIX/ldso/conf.d\"'" >/dev/null

sudo install -o 0 -g 0 -m 0755 "$HERE/build/vpn-up-helper" "$PREFIX/bin/vpn-up-helper"
sudo install -o 0 -g 0 -m 0755 "$HERE/build/vpn-up-admin"  "$PREFIX/bin/vpn-up-admin"

HELPER="$PREFIX/bin/vpn-up-helper"
ADMIN="$PREFIX/bin/vpn-up-admin"
UID_NOW="$(id -u)"

# ------------------------------------------------------------------ the closure

echo
echo "Closure check against the fixture install:"
if sudo -n "$ADMIN" verify-closure >/tmp/vu-closure.txt 2>&1; then
  ok "the fixture install passes the trusted execution closure"
else
  bad "the fixture install does not pass its own closure check"
  sed 's/^/       /' /tmp/vu-closure.txt
fi
rm -f /tmp/vu-closure.txt

# ------------------------------------------------------------- refuse first

echo
echo "Refusals before anything is approved:"
if sudo -n SUDO_UID="$UID_NOW" "$HELPER" connect \
     --profile-id "$PROFILE_ID" --protocol anyconnect \
     --connect-url "$ENDPOINT/portal" </dev/null >/tmp/vu-out.txt 2>&1; then
  bad "connect succeeded with no approval in the registry"
else
  if grep -q 'not approved' /tmp/vu-out.txt; then
    ok "an unapproved profile is refused, and says how to approve it"
  else
    bad "refused, but not for the expected reason"
    sed 's/^/       /' /tmp/vu-out.txt
  fi
fi

# SUDO_UID is the only thing that says whose approvals apply.
if sudo -n env -u SUDO_UID "$HELPER" connect --profile-id "$PROFILE_ID" \
     --protocol anyconnect --connect-url "$ENDPOINT/portal" </dev/null >/tmp/vu-out.txt 2>&1; then
  bad "connect succeeded with no SUDO_UID"
else
  if grep -q 'SUDO_UID' /tmp/vu-out.txt; then
    ok "a missing SUDO_UID is refused"
  else
    bad "refused, but not because of SUDO_UID"
    sed 's/^/       /' /tmp/vu-out.txt
  fi
fi

# The approval registry must be unreachable from the passwordless binary.
for sub in approve revoke list verify-closure; do
  if sudo -n SUDO_UID="$UID_NOW" "$HELPER" "$sub" >/dev/null 2>&1; then
    bad "vpn-up-helper accepted '$sub' — it must never be able to grant approvals"
  else
    ok "vpn-up-helper refuses '$sub'"
  fi
done

# --------------------------------------------------------------- approve, connect

echo
echo "Approve, then connect:"
sudo -n SUDO_UID="$UID_NOW" "$ADMIN" approve \
  --profile-id "$PROFILE_ID" --protocol anyconnect \
  --endpoint "$ENDPOINT" --fingerprint "$FPR" --no-proxy >/dev/null
ok "vpn-up-admin recorded the approval"

# A cookie larger than every buffer in the project, with the marker in the
# MIDDLE. Not near either end on purpose: the stand-in reports the first and last
# 16 bytes as hex, so a marker there could appear in the report legitimately and
# the "never visible" assertion would be unfalsifiable.
#
# Built with head/tr so the test carries no interpreter dependency it does not
# otherwise need.
{ head -c 50000 /dev/zero | tr '\0' 'a'
  printf '%s' "$MARKER"
  head -c 50000 /dev/zero | tr '\0' 'b'
} > /tmp/vu-cookie
COOKIE_LEN=$(wc -c < /tmp/vu-cookie | tr -d ' ')

# The stand-in writes its report to stdout and then waits for SIGTERM.
sudo -n SUDO_UID="$UID_NOW" "$HELPER" connect \
  --profile-id "$PROFILE_ID" --protocol anyconnect \
  --connect-url "$ENDPOINT/portal" --tunable no-dtls --tunable mtu=1400 \
  < /tmp/vu-cookie > /tmp/vu-report.txt 2>/tmp/vu-err.txt &
HELPER_PID=$!

# Wait for the report rather than sleeping a fixed time.
for _ in $(seq 1 100); do
  grep -q 'FAKE-REPORT-END' /tmp/vu-report.txt 2>/dev/null && break
  sleep 0.1
done

if grep -q 'FAKE-REPORT-END' /tmp/vu-report.txt 2>/dev/null; then
  ok "the helper execve'd the stand-in and it reported"
else
  bad "no report from the stand-in"
  sed 's/^/       /' /tmp/vu-err.txt 2>/dev/null | head -20
fi

# ----------------------------------------------------------------- assertions

echo
echo "What crossed the boundary:"

grep -q "^stdin_bytes=${COOKIE_LEN}$" /tmp/vu-report.txt
assert $? "the whole ${COOKIE_LEN}-byte cookie arrived on stdin, unbuffered by us"

if grep -q -- "$MARKER" /tmp/vu-report.txt; then
  bad "the cookie appeared in argv, the environment, or /proc/self/cmdline"
else
  ok "the cookie is nowhere in argv, the environment, or the process table"
fi

# ps is what a person would actually look at, so it is worth checking directly
# rather than trusting /proc/self/cmdline alone.
#
# SEQUENCED, not piped, and the pattern comes from a FILE. Both matter, and the
# first version got it wrong in a way that produced a false alarm in CI:
#
#     ps -ww -eo args | grep -q -- "$MARKER"     # always FOUND
#
# ps and grep in a pipeline run CONCURRENTLY, so ps snapshots the process table
# while the grep is in it - and that grep's own argv contains the marker. The
# check detected itself and reported the cookie as leaked while the adjacent
# check, reading the stand-in's own /proc/self/cmdline, correctly said it had not.
#
# Taking the snapshot first fixes it, because the snapshot predates the grep.
# Reading the pattern from a file as well means the marker never appears in ANY
# argv, so the check stays correct even if someone reintroduces a pipeline.
# Verified both ways with a standalone probe: pipelined FOUND, sequenced did not.
ps_snapshot="/tmp/vu-ps-snapshot.txt"
ps_pattern="/tmp/vu-ps-pattern.txt"
ps -ww -eo args > "$ps_snapshot" 2>/dev/null || true
printf '%s\n' "$MARKER" > "$ps_pattern"

if [ ! -s "$ps_snapshot" ]; then
  # A failed ps would make the grep below find nothing, and the check would
  # "pass" without having looked at anything.
  bad "could not read the process table, so the ps check proved nothing"
elif grep -q -f "$ps_pattern" "$ps_snapshot"; then
  bad "the cookie is visible in ps output"
else
  ok "the cookie is not visible in ps"
fi
rm -f "$ps_snapshot" "$ps_pattern"

grep -q '^cwd=/$' /tmp/vu-report.txt
assert $? "the exec'd process runs from /"

grep -q '^umask=0077$' /tmp/vu-report.txt
assert $? "umask is 077"

# Stale as of the connection-state telemetry work: the helper used to hand the
# child PATH and nothing else (env_count=1). It now also sets the four VUP_*
# variables the vpnc-script wrapper needs to find its state leaf (proc.c,
# vu_clean_env) — env_count=5, and the values are worth checking, not just the
# count, since a wrong profile id or uid here would misattribute telemetry to
# the wrong tunnel.
grep -q '^env_count=5$' /tmp/vu-report.txt
assert $? "the environment is PATH plus the four VUP_* telemetry variables, and nothing else"

grep -q -- "^env=VUP_PROFILE_ID=${PROFILE_ID}\$" /tmp/vu-report.txt
assert $? "VUP_PROFILE_ID matches the connecting profile"

grep -q -- "^env=VUP_STATE_UID=${UID_NOW}\$" /tmp/vu-report.txt
assert $? "VUP_STATE_UID matches the invoking uid"

grep -qE -- '^env=VUP_SESSION_ID=[0-9a-f]{32}$' /tmp/vu-report.txt
assert $? "VUP_SESSION_ID is a fresh 32-hex-char id"

grep -q -- '^env=VUP_REQUEST_ID=' /tmp/vu-report.txt
assert $? "VUP_REQUEST_ID is present (empty when the client supplied none)"

grep -q -- '^argv\[.*\]=--cookie-on-stdin$' /tmp/vu-report.txt
assert $? "--cookie-on-stdin is present"

grep -q -- '^argv\[.*\]=--non-inter$' /tmp/vu-report.txt
assert $? "--non-inter is present"

grep -q -- "^argv\[.*\]=--servercert=$FPR\$" /tmp/vu-report.txt
assert $? "--servercert came from the registry, not the command line"

grep -q -- '^argv\[.*\]=--no-proxy$' /tmp/vu-report.txt
assert $? "--no-proxy is explicit when the approval has no proxy"

grep -q -- '^argv\[.*\]=--mtu=1400$' /tmp/vu-report.txt
assert $? "a translated tunable reached OpenConnect"

if grep -qE -- '^argv\[.*\]=(--script-tun|--csd-wrapper|--config|--xmlconfig|--background|--pid-file)' /tmp/vu-report.txt; then
  bad "a forbidden flag reached the command line"
else
  ok "no forbidden flag reached the command line"
fi

# ------------------------------------------------------------------- the lock

echo
echo "One tunnel per profile:"
if sudo -n SUDO_UID="$UID_NOW" "$HELPER" connect \
     --profile-id "$PROFILE_ID" --protocol anyconnect \
     --connect-url "$ENDPOINT/portal" </dev/null >/tmp/vu-out.txt 2>&1; then
  bad "a second connect succeeded while the first was still running"
else
  if grep -q 'already has a tunnel' /tmp/vu-out.txt; then
    ok "a second connect for the same profile is refused while one is running"
  else
    bad "refused, but not because of the lock"
    sed 's/^/       /' /tmp/vu-out.txt
  fi
fi

# ------------------------------------------------------------------- stop

echo
echo "Stop:"
sudo -n SUDO_UID="$UID_NOW" "$HELPER" stop --profile-id "$PROFILE_ID" >/tmp/vu-out.txt 2>&1
if grep -q '^stopped ' /tmp/vu-out.txt; then
  ok "stop signalled the recorded process and reported it stopped"
else
  bad "stop did not report a stop"
  sed 's/^/       /' /tmp/vu-out.txt
fi

wait "$HELPER_PID" 2>/dev/null || true

# The lock must be gone now, so a fresh connect can take it.
: > /tmp/vu-report2.txt
sudo -n SUDO_UID="$UID_NOW" "$HELPER" connect \
  --profile-id "$PROFILE_ID" --protocol anyconnect \
  --connect-url "$ENDPOINT/portal" </dev/null >/tmp/vu-report2.txt 2>&1 &
NEW_PID=$!
for _ in $(seq 1 100); do
  grep -q 'FAKE-REPORT-END' /tmp/vu-report2.txt 2>/dev/null && break
  sleep 0.1
done
if grep -q 'FAKE-REPORT-END' /tmp/vu-report2.txt 2>/dev/null; then
  ok "after the first tunnel stops, a new connect takes the lock"
else
  bad "a new connect could not take the lock after the first tunnel stopped"
  sed 's/^/       /' /tmp/vu-report2.txt | head -10
fi
sudo -n SUDO_UID="$UID_NOW" "$HELPER" stop --profile-id "$PROFILE_ID" >/dev/null 2>&1 || true
wait "$NEW_PID" 2>/dev/null || true

# stop with nothing running is a normal answer, not an error.
sudo -n SUDO_UID="$UID_NOW" "$HELPER" stop --profile-id "$PROFILE_ID" >/tmp/vu-out.txt 2>&1
grep -q 'no tunnel recorded' /tmp/vu-out.txt
assert $? "stop with nothing running says so and succeeds"

# ------------------------------------------------------------------- revoke

echo
echo "Revoke:"
sudo -n SUDO_UID="$UID_NOW" "$ADMIN" revoke --profile-id "$PROFILE_ID" >/dev/null
if sudo -n SUDO_UID="$UID_NOW" "$HELPER" connect \
     --profile-id "$PROFILE_ID" --protocol anyconnect \
     --connect-url "$ENDPOINT/portal" </dev/null >/tmp/vu-out.txt 2>&1; then
  bad "connect succeeded after the approval was revoked"
else
  ok "a revoked approval stops working immediately"
fi

# ------------------------------------------------- 11.1: the self-path check
#
# The unprivileged corpus can only assert the REFUSAL (it runs from a user-owned
# build tree). The accept case needs a root-owned install, which is exactly what
# this script has - so both halves are proven, and neither test is one that could
# only pass.

echo
echo "Install-path self-check (§11.1):"
# Accept: everything above already ran the installed binaries as root, so a
# root-gated command working at all is the positive case. Assert it explicitly
# anyway, because it is what the refusal below is being contrasted with. `list`
# is used rather than `version`: version sits ABOVE the root gate and therefore
# never performs the walk.
if sudo -n SUDO_UID="$UID_NOW" "$ADMIN" list >/dev/null 2>&1; then
  ok "the installed vpn-up-admin accepts its own install path"
else
  bad "the installed vpn-up-admin refused its own install path"
fi

# Refuse: the SAME binary, run as root from the user-owned build directory.
if sudo -n SUDO_UID="$UID_NOW" "$HERE/build/vpn-up-admin" list >/tmp/vu-out.txt 2>&1; then
  bad "a root-gated command succeeded from a user-writable build directory"
else
  if grep -q 'untrusted path' /tmp/vu-out.txt; then
    ok "the same binary is refused when run as root from the build directory"
  else
    bad "refused from the build directory, but not by the self-path check"
    sed 's/^/       /' /tmp/vu-out.txt
  fi
fi

# `version` must stay exempt, or doctor could not report on a machine with no
# installation and the passwordless probe would conflate two different questions.
if sudo -n "$HERE/build/vpn-up-admin" version >/dev/null 2>&1; then
  ok "version still runs from anywhere (the documented diagnostic exemption)"
else
  bad "version is no longer runnable from a build tree; doctor depends on it"
fi

# ------------------------------------- sudo timestamp cache versus real policy
#
# The property: "passwordless" is a question about POLICY, and `sudo -n` answers
# a question about the CACHE. Only a real sudo can show the difference, so this
# cannot be an argv assertion.
#
# It must prove it can fail before it means anything. On a runner where the user
# holds NOPASSWD: ALL - which is how this script can use `sudo -n` at all in CI -
# `sudo -k -n <anything>` succeeds too, so every "must fail" leg below is
# unassertable. Detect that and skip loudly rather than reporting a pass.

echo
echo "Passwordless probes ignore the credential cache:"
if sudo -k -n /usr/bin/true >/dev/null 2>&1; then
  echo "  [..] SKIPPED: this account can run anything passwordless (NOPASSWD: ALL),"
  echo "       so 'must fail' cannot be distinguished from 'must succeed' here."
  echo "       Run in a container or VM with ordinary sudoers to exercise it."
else
  # A warm cache: this script has been running sudo throughout, so plain -n
  # succeeds for a command no rule names.
  if sudo -n "$ADMIN" version >/dev/null 2>&1; then
    ok "sudo -n succeeds on the warm timestamp, with no rule naming this binary"
  else
    bad "expected sudo -n to succeed on a warm timestamp"
  fi
  if sudo -k -n "$ADMIN" version >/dev/null 2>&1; then
    bad "sudo -k -n succeeded with no rule naming the binary: the cache leaked in"
  else
    ok "sudo -k -n refuses the same command: it reports policy, not the cache"
  fi
fi

rm -f /tmp/vu-cookie /tmp/vu-report.txt /tmp/vu-report2.txt /tmp/vu-err.txt /tmp/vu-out.txt

echo
if [ "$fails" -ne 0 ]; then
  echo "FAILED CHECKS:$failed_list"
  echo
fi
echo "$checks checks, $fails failures"
[ "$fails" -eq 0 ]
