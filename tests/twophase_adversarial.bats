#!/usr/bin/env bats
# Step 9 of PRIVILEGED-HELPER-DESIGN.md §16: the adversarial pass over the
# UNPRIVILEGED half of helper mode.
#
# tests/twophase.bats tests that the two-phase path does what it is supposed to.
# This file tries to make it do something else. The C corpus
# (helper/t/test_adversarial.c) does the same for the privileged half; both are
# organised by attack rather than by function.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_DIRNAME/.."
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  print_warning() { printf -- "$1" "${@:2}"; }
  print_danger()  { printf -- "$1" "${@:2}" >&2; }
  print_success() { printf -- "$1" "${@:2}"; }
  print_primary() { printf -- "$1" "${@:2}"; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
  source "$BATS_TEST_DIRNAME/../twophase.sh"
  source "$BATS_TEST_DIRNAME/../dependencies.sh"
}

# --- the shared fixture set ------------------------------------------------
#
# One format, two decoders: parse_auth_output() here and vu_parse_auth() in C.
# The production one is this shell function; the C one has the harder corpus.
# Both read the SAME fixture files, so a divergence shows up as a test failure
# rather than as a difference nobody notices.
# See helper/t/fixtures/auth/README for why the shared scope is format-only.

@test "shared fixtures: the shell decoder agrees with the reference on every one" {
  local dir="$BATS_TEST_DIRNAME/../helper/t/fixtures/auth"
  [ -d "$dir" ]
  local seen=0 f name
  for f in "$dir"/accept-* "$dir"/refuse-*; do
    [ -e "$f" ] || continue
    name="$(basename "$f")"
    seen=$((seen + 1))
    if [ "${name#accept-}" != "$name" ]; then
      run parse_auth_output < "$f"
      [ "$status" -eq 0 ] || { echo "expected accept, got $status for $name: $output"; return 1; }
    else
      run parse_auth_output < "$f"
      [ "$status" -ne 0 ] || { echo "expected refuse, got 0 for $name"; return 1; }
      [ -n "$output" ] || { echo "$name was refused without a message"; return 1; }
    fi
  done
  # A loop over nothing passes; assert the set was actually there.
  [ "$seen" -ge 20 ]
}

@test "shared fixtures: the C reference agrees too, and both were run" {
  # Skipped rather than failed when there is no compiler: this asserts agreement
  # between two implementations, and with only one present there is nothing to
  # compare. The shell half above still runs.
  command -v cc >/dev/null 2>&1 || skip "no C compiler"
  ( cd "$BATS_TEST_DIRNAME/../helper" && make -s all >/dev/null 2>&1 && ./build/vu-test >/dev/null 2>&1 )
}

# --- extraArgs: the flags that made this whole exercise necessary ----------
#
# The original finding was that NOPASSWD openconnect plus arbitrary extraArgs
# plus --script is arbitrary root execution. In helper mode nothing reaches
# OpenConnect that did not come from the closed schema, and translation is where
# that is enforced on the shell side.

@test "extraArgs: every flag that can name a program to run is refused" {
  local flag
  for flag in --script --script-tun --csd-wrapper --csd-user --config --xmlconfig \
              --external-browser --pid-file --cookie --cookie-on-stdin \
              --key-password --token-secret --certificate --sslkey --servercert \
              --resolve --proxy --no-proxy --background --interface --syslog \
              --route --split-tunnel -s -S -b -x -C -c -q -i ; do
    run translate_extra_args "$flag /tmp/evil"
    [ "$status" -ne 0 ] || { echo "$flag was accepted by translation"; return 1; }
    # The refusal must name the flag and point at the escape hatch, or the user
    # cannot tell what to do about it.
    [[ "$output" == *"$flag"* ]] || { echo "refusal did not name $flag: $output"; return 1; }
    [[ "$output" == *"prompt mode"* ]] || { echo "refusal did not offer prompt mode: $output"; return 1; }
  done
}

@test "extraArgs: --flag=value forms are refused too, not just --flag value" {
  run translate_extra_args "--script=/tmp/evil"
  [ "$status" -ne 0 ]
  run translate_extra_args "--csd-wrapper=/tmp/evil"
  [ "$status" -ne 0 ]
  run translate_extra_args "--config=/tmp/evil.conf"
  [ "$status" -ne 0 ]
}

@test "extraArgs: a shell metacharacter in a value cannot reach a shell" {
  # Nothing here is eval'd, so these are refused as unknown flags or carried as
  # opaque values — never executed. The marker file is the assertion.
  local marker="$BATS_TEST_TMPDIR/executed"
  run translate_extra_args "--os=linux; touch $marker"
  [ ! -e "$marker" ]
  run translate_extra_args "--mtu=\$(touch $marker)"
  [ ! -e "$marker" ]
  run translate_extra_args "\`touch $marker\`"
  [ ! -e "$marker" ]
  run translate_extra_args "--useragent='; touch $marker'"
  [ ! -e "$marker" ]
}

@test "extraArgs: a bad tunable value is refused by translation or by the helper" {
  # Translation does not re-implement the integer ranges; it passes the value to
  # --tunable, and the C validator refuses it. Assert the composition: whatever
  # translation emits, the value is never silently corrected.
  # Called directly, not through `run`: `run` uses a subshell, so the arrays the
  # function sets would not be visible here.
  local rc=0
  translate_extra_args "--mtu abc" || rc=$?
  if [ "$rc" -eq 0 ]; then
    [[ "${HELPER_TUNABLES[*]}" == *"mtu=abc"* ]] || { echo "value was altered: ${HELPER_TUNABLES[*]}"; return 1; }
  fi
  run translate_extra_args "--mtu"
  [ "$status" -ne 0 ]
}

@test "extraArgs: benign flags still translate, so existing profiles keep working" {
  translate_extra_args "--no-dtls --mtu 1400 --disable-ipv6"
  [ "${HELPER_TUNABLES[*]}" = "--tunable no-dtls --tunable mtu=1400 --tunable disable-ipv6" ]
}

@test "extraArgs: malformed quoting is refused rather than half-parsed" {
  run translate_extra_args "--useragent 'unterminated"
  [ "$status" -ne 0 ]
}

# --- helper mode availability ---------------------------------------------

@test "helper mode is unavailable when the binary is missing" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/nowhere"
  run helper_mode_available
  [ "$status" -ne 0 ]
}

@test "helper mode is unavailable when sudo would prompt" {
  # Both halves must hold: an installed binary that still needs a password is no
  # use to a login service and would hang it.
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR"
  printf '#!/bin/sh\nexit 0\n' > "$VPN_UP_HELPER_DIR/vpn-up-helper"
  chmod +x "$VPN_UP_HELPER_DIR/vpn-up-helper"

  # A sudo that refuses -n, the way a password-required rule behaves.
  mkdir -p "$BATS_TEST_TMPDIR/stub"
  printf '#!/bin/sh\necho "sudo: a password is required" >&2\nexit 1\n' > "$BATS_TEST_TMPDIR/stub/sudo"
  chmod +x "$BATS_TEST_TMPDIR/stub/sudo"
  PATH="$BATS_TEST_TMPDIR/stub:$PATH" run helper_mode_available
  [ "$status" -ne 0 ]
}

@test "helper mode does not pick up a vpn-up-helper found on PATH" {
  # The path is pinned. A decoy earlier on PATH must be irrelevant, because what
  # is asked of sudo is an absolute path and sudoers names an absolute path.
  mkdir -p "$BATS_TEST_TMPDIR/decoy"
  printf '#!/bin/sh\nexit 0\n' > "$BATS_TEST_TMPDIR/decoy/vpn-up-helper"
  chmod +x "$BATS_TEST_TMPDIR/decoy/vpn-up-helper"
  unset VPN_UP_HELPER_DIR
  run helper_bin
  [ "$status" -eq 0 ]
  [[ "$output" == /* ]]
  [[ "$output" != *"$BATS_TEST_TMPDIR"* ]]
}

# --- the privilege boundary doctor reports on -----------------------------

@test "doctor fails when vpn-up-admin is reachable without a password" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR" "$BATS_TEST_TMPDIR/stub"
  # A sudo that says "yes, passwordless" for anything asked of it — which is
  # exactly the misconfiguration this check exists to find.
  printf '#!/bin/sh\nexit 0\n' > "$BATS_TEST_TMPDIR/stub/sudo"
  chmod +x "$BATS_TEST_TMPDIR/stub/sudo"

  PATH="$BATS_TEST_TMPDIR/stub:$PATH" run doctor_privilege_boundary
  [ "$status" -ne 0 ]
  [[ "$output" == *"vpn-up-admin IS REACHABLE WITHOUT A PASSWORD"* ]]
  [[ "$output" == *"approval boundary"* ]]
}

@test "doctor passes when vpn-up-admin needs a password" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR" "$BATS_TEST_TMPDIR/stub"
  printf '#!/bin/sh\nexit 0\n' > "$VPN_UP_HELPER_DIR/vpn-up-helper"
  chmod +x "$VPN_UP_HELPER_DIR/vpn-up-helper"

  # Passwordless for the helper, password required for the admin tool: the
  # intended configuration.
  cat > "$BATS_TEST_TMPDIR/stub/sudo" <<'STUB'
#!/bin/sh
for a in "$@"; do
  case "$a" in
    *vpn-up-admin) echo "sudo: a password is required" >&2; exit 1 ;;
  esac
done
exit 0
STUB
  chmod +x "$BATS_TEST_TMPDIR/stub/sudo"

  PATH="$BATS_TEST_TMPDIR/stub:$PATH" run doctor_privilege_boundary
  [ "$status" -eq 0 ]
  [[ "$output" == *"vpn-up-admin is not reachable without a password"* ]]
}

@test "doctor accepts vpn-up-admin in an authenticated rule" {
  # Appearing in an ordinary `user ALL=(root) /path/vpn-up-admin` rule is
  # legitimate administrator policy. The check is about PASSWORDLESS
  # reachability, not about being mentioned in sudoers.
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR" "$BATS_TEST_TMPDIR/stub"
  cat > "$BATS_TEST_TMPDIR/stub/sudo" <<'STUB'
#!/bin/sh
# `sudo -n -l <cmd>` fails for a rule that requires a password, even though the
# command is permitted. That distinction is the whole point.
for a in "$@"; do
  case "$a" in
    *vpn-up-admin) echo "sudo: a password is required" >&2; exit 1 ;;
  esac
done
exit 0
STUB
  chmod +x "$BATS_TEST_TMPDIR/stub/sudo"
  PATH="$BATS_TEST_TMPDIR/stub:$PATH" run doctor_privilege_boundary
  [ "$status" -eq 0 ]
}

@test "doctor reports cleanly when sudo is absent" {
  mkdir -p "$BATS_TEST_TMPDIR/empty"
  PATH="$BATS_TEST_TMPDIR/empty" run doctor_privilege_boundary
  [ "$status" -eq 0 ]
  [[ "$output" == *"sudo not found"* ]]
}

# --- what crosses the boundary -------------------------------------------

@test "stop never passes a pid to the helper" {
  # The pid comes from root-owned state and is verified before it is signalled.
  # `sudo kill "$pid"` with a pid from a user-writable file is the hole this
  # replaces, so a pid on this command line would reintroduce it.
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR" "$BATS_TEST_TMPDIR/stub"
  printf '#!/bin/sh\nprintf "%%s\\n" "$@" > %s/argv\n' "$BATS_TEST_TMPDIR" > "$BATS_TEST_TMPDIR/stub/sudo"
  chmod +x "$BATS_TEST_TMPDIR/stub/sudo"

  VPN_PROFILE_ID="11111111-2222-3333-4444-555555555555"
  PATH="$BATS_TEST_TMPDIR/stub:$PATH" run stop_via_helper
  [ -f "$BATS_TEST_TMPDIR/argv" ]
  run grep -cE '^-n$|^stop$|^--profile-id$' "$BATS_TEST_TMPDIR/argv"
  # No numeric argument other than the profile UUID may appear.
  run grep -E '^[0-9]+$' "$BATS_TEST_TMPDIR/argv"
  [ "$status" -ne 0 ]
  run grep -c 'pid' "$BATS_TEST_TMPDIR/argv"
  [ "$output" = "0" ]
}
