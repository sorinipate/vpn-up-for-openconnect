#!/usr/bin/env bats
# Two-phase OpenConnect: the phase-one output decoder, extraArgs translation,
# and the phase-two command line. See PRIVILEGED-HELPER-DESIGN.md §4, §8, §10.

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
  source "$BATS_TEST_DIRNAME/../outcome.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
  source "$BATS_TEST_DIRNAME/../twophase.sh"
}

# --- the phase-one decoder -------------------------------------------------
#
# Upstream emits KEY='VALUE' so it can be eval'd. These assert that we neither
# eval it nor accept anything outside the small language it actually emits.

AUTH_GOOD="COOKIE='3311180634@13561856@1339425499@B315A0E29D16C6FD92EE'
HOST='10.0.0.1'
CONNECT_URL='https://vpnserver.example.com'
FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'
RESOLVE='vpnserver.example.com:10.0.0.1'"

@test "decoder accepts upstream's documented output" {
  parse_auth_output <<< "$AUTH_GOOD"
  [ "$AUTH_COOKIE" = "3311180634@13561856@1339425499@B315A0E29D16C6FD92EE" ]
  [ "$AUTH_CONNECT_URL" = "https://vpnserver.example.com" ]
  [ "$AUTH_FINGERPRINT" = "469bb424ec8835944d30bc77c77e8fc1d8e23a42" ]
  [ "$AUTH_RESOLVE" = "vpnserver.example.com:10.0.0.1" ]
}

@test "decoder never executes what it reads" {
  # If any of these were eval'd or word-split into a command, the marker file
  # would exist. The point of the test is the absence of that file.
  marker="$BATS_TEST_TMPDIR/executed"
  run parse_auth_output <<< "COOKIE='\$(touch $marker)'"
  [ ! -e "$marker" ]

  run parse_auth_output <<< "COOKIE='\`touch $marker\`'"
  [ ! -e "$marker" ]

  run parse_auth_output <<< "COOKIE='x'; touch $marker"
  [ ! -e "$marker" ]

  run parse_auth_output <<< "COOKIE='x' && touch $marker"
  [ ! -e "$marker" ]
}

@test "decoder preserves a substitution-looking value verbatim" {
  # It must be data, not a command: kept exactly as sent.
  parse_auth_output <<< "COOKIE='\$(id)'
CONNECT_URL='https://vpn.example.com'
FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'"
  [ "$AUTH_COOKIE" = '$(id)' ]
}

@test "decoder keeps a backslash literal (no escape processing)" {
  parse_auth_output <<< "COOKIE='a\\nb'
CONNECT_URL='https://vpn.example.com'
FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'"
  [ "$AUTH_COOKIE" = 'a\nb' ]
}

@test "decoder refuses unquoted, unterminated and quote-bearing values" {
  run parse_auth_output <<< "COOKIE=abc"
  [ "$status" -ne 0 ]
  run parse_auth_output <<< "COOKIE='abc"
  [ "$status" -ne 0 ]
  run parse_auth_output <<< "COOKIE='ab'c'"
  [ "$status" -ne 0 ]
}

@test "decoder refuses unknown keys rather than skipping them" {
  # A future OpenConnect emitting something we do not understand must be
  # visible, not silently dropped.
  run parse_auth_output <<< "EVIL='x'
COOKIE='abc'"
  [ "$status" -ne 0 ]
  [[ "$output" == *"unrecognised key"* ]]
}

@test "decoder refuses duplicates, blank lines and no output at all" {
  run parse_auth_output <<< "COOKIE='a'
COOKIE='b'"
  [ "$status" -ne 0 ]

  run parse_auth_output <<< "COOKIE='a'

HOST='h'"
  [ "$status" -ne 0 ]

  run parse_auth_output < /dev/null
  [ "$status" -ne 0 ]
}

@test "helper contract requires CONNECT_URL, not just HOST" {
  # Model B binds an origin; a numeric HOST discards what is being bound. This
  # detects the output contract instead of guessing an OpenConnect version.
  parse_auth_output <<< "COOKIE='abc'
HOST='10.0.0.1'
FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'"
  run require_helper_auth_contract
  [ "$status" -ne 0 ]
  [[ "$output" == *"too old"* ]]

  parse_auth_output <<< "$AUTH_GOOD"
  run require_helper_auth_contract
  [ "$status" -eq 0 ]
}

@test "helper contract requires a cookie and a fingerprint" {
  parse_auth_output <<< "CONNECT_URL='https://vpn.example.com'
FINGERPRINT='469bb424ec8835944d30bc77c77e8fc1d8e23a42'"
  run require_helper_auth_contract
  [ "$status" -ne 0 ]

  parse_auth_output <<< "COOKIE='abc'
CONNECT_URL='https://vpn.example.com'"
  run require_helper_auth_contract
  [ "$status" -ne 0 ]
}

# --- phase one: PKCS#11 PIN, shared with the prompt-mode path (round 6) ----
#
# An earlier version of phase_one_authenticate built --certificate directly
# from VPN_CLIENT_CERT with no PIN handling at all, unlike run_openconnect's
# prompt-mode path (core.sh), which already fed a stored PKCS#11 PIN via a
# pin-source file. A service using a PKCS#11 certificate through helper mode
# -- the preferred, documented path -- could never supply a stored PIN, so
# it would be left waiting on an interactive PIN prompt with no tty to answer
# it, contradicting the documented unattended-service PKCS#11 feature. The
# fetch itself now happens once in run_admitted_connection
# (_prepare_pkcs11_pin, core.sh) and is shared via _VPN_PIN_FILE; these tests
# cover phase_one_authenticate's own half of that contract, matching how
# clientcert.bats covers run_openconnect's half.

@test "phase_one_authenticate attaches a pre-fetched PKCS#11 PIN via pin-source" {
  VPN_USER="alice"; PROTOCOL="anyconnect"; VPN_HOST="p.example.com"
  VPN_PASSWD="s3cret"; VPN_CLIENT_CERT="pkcs11:manufacturer=piv_II;id=%01"
  local pin="918273"
  _VPN_PIN_FILE="$BATS_TEST_TMPDIR/staged.pin"
  ( umask 077; printf '%s' "$pin" > "$_VPN_PIN_FILE" )
  local argv="$BATS_TEST_TMPDIR/argv"
  openconnect() { printf '%s\n' "$@" > "$argv"; cat >/dev/null; echo "$AUTH_GOOD"; return 0; }

  run phase_one_authenticate
  [ "$status" -eq 0 ]
  grep -qF -- "--certificate=pkcs11:manufacturer=piv_II;id=%01?pin-source=file:${_VPN_PIN_FILE}" "$argv"
  if grep -qF -- "$pin" "$argv"; then false; fi   # never on argv, only referenced by path
}

@test "phase_one_authenticate omits pin-source when _VPN_PIN_FILE is unset" {
  VPN_USER="alice"; PROTOCOL="anyconnect"; VPN_HOST="p.example.com"
  VPN_PASSWD="s3cret"; VPN_CLIENT_CERT="pkcs11:manufacturer=piv_II;id=%01"
  _VPN_PIN_FILE=""
  local argv="$BATS_TEST_TMPDIR/argv"
  openconnect() { printf '%s\n' "$@" > "$argv"; cat >/dev/null; echo "$AUTH_GOOD"; return 0; }

  run phase_one_authenticate
  [ "$status" -eq 0 ]
  grep -qF -- "--certificate=pkcs11:manufacturer=piv_II;id=%01" "$argv"
  if grep -qF -- "pin-source=file:" "$argv"; then false; fi
}

# --- extraArgs translation -------------------------------------------------

@test "benign extraArgs translate into tunables, both spellings" {
  translate_extra_args "--no-dtls --mtu 1400 --reconnect-timeout=30"
  [ "${HELPER_TUNABLES[0]}" = "--tunable" ]
  [ "${HELPER_TUNABLES[1]}" = "no-dtls" ]
  [[ " ${HELPER_TUNABLES[*]} " == *" mtu=1400 "* ]]
  [[ " ${HELPER_TUNABLES[*]} " == *" reconnect-timeout=30 "* ]]
}

@test "--os and --useragent route to phase one rather than being refused" {
  translate_extra_args "--os=win --useragent 'AnyConnect Windows 4.10.06079'"
  [[ " ${PHASE1_EXTRA[*]} " == *"--os=win"* ]]
  [ "$HELPER_USERAGENT" = "AnyConnect Windows 4.10.06079" ]
  # useragent goes to BOTH phases: upstream documents servers that need it to
  # authenticate *or* connect.
  [[ " ${PHASE1_EXTRA[*]} " == *"--useragent=AnyConnect Windows 4.10.06079"* ]]
}

@test "extraArgs that can name a program to run are refused in helper mode" {
  for flag in --script --script-tun --csd-wrapper --csd-user --config --xmlconfig -s -x; do
    run translate_extra_args "$flag /tmp/evil"
    [ "$status" -ne 0 ] || { echo "accepted $flag"; return 1; }
    [[ "$output" == *"prompt mode"* ]] || { echo "no guidance for $flag"; return 1; }
  done
}

@test "unknown extraArgs are refused, not forwarded" {
  run translate_extra_args "--some-future-flag"
  [ "$status" -ne 0 ]
  run translate_extra_args "--mtu"
  [ "$status" -ne 0 ]
}

@test "empty extraArgs translate to nothing" {
  translate_extra_args ""
  [ "${#HELPER_TUNABLES[@]}" -eq 0 ]
  [ "${#PHASE1_EXTRA[@]}" -eq 0 ]
}

# --- the phase-two command line -------------------------------------------

_write_profile() {
  cat > "$PROFILES_FILE" <<XML
<VPNs>
  <VPN><name>Helper VPN</name><protocol>anyconnect</protocol><host>vpn.example.com</host><authGroup></authGroup><user>alice</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode></tokenMode><extraArgs>${1:-}</extraArgs><clientCertificate></clientCertificate><clientKey></clientKey><proxy>${2:-}</proxy><profileId>a7d1bb99-538c-4db4-b357-0123456789ab</profileId></VPN>
</VPNs>
XML
}

@test "profileId is read from the profile" {
  _write_profile
  load_profile_fields "Helper VPN"
  [ "$VPN_PROFILE_ID" = "a7d1bb99-538c-4db4-b357-0123456789ab" ]
}

@test "profile_id_ensure generates and persists an id when absent" {
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>No Id</name><protocol>anyconnect</protocol><host>h.example.com</host><user>u</user><password></password></VPN>
</VPNs>
XML
  load_profile_fields "No Id"
  [ -z "$VPN_PROFILE_ID" ]
  run profile_id_ensure "No Id"
  [ "$status" -eq 0 ]
  [ -n "$output" ]

  # Persisted, and stable across reloads: an approval must not be invalidated
  # by simply using the profile again.
  load_profile_fields "No Id"
  [ "$VPN_PROFILE_ID" = "$output" ]
  first="$VPN_PROFILE_ID"
  profile_id_ensure "No Id" >/dev/null
  load_profile_fields "No Id"
  [ "$VPN_PROFILE_ID" = "$first" ]
}

@test "phase two passes the cookie on stdin and never on the command line" {
  _write_profile
  load_profile_fields "Helper VPN"
  translate_extra_args ""
  AUTH_CONNECT_URL="https://vpn.example.com/portal?s=1"
  AUTH_RESOLVE="vpn.example.com:10.0.0.1"
  AUTH_COOKIE="SUPERSECRETCOOKIE"
  QUIET=FALSE
  set_profile_paths "Helper VPN"

  ARGV="$BATS_TEST_TMPDIR/argv"; STDIN="$BATS_TEST_TMPDIR/stdin"
  # Records sudo's WHOLE argv, flags included. The stub used to `shift` first,
  # which discarded exactly the thing that later turned out to be wrong.
  sudo() { printf '%s\n' "$@" > "$ARGV"; cat > "$STDIN"; return 0; }
  write_connection_state() { :; }
  run_hooks() { :; }

  run run_openconnect_helper
  [ "$status" -eq 0 ]

  # The cookie arrives on stdin...
  grep -qx "SUPERSECRETCOOKIE" "$STDIN"
  # ...and appears nowhere in the process table.
  if grep -q "SUPERSECRETCOOKIE" "$ARGV"; then false; fi

  grep -qx -- "connect" "$ARGV"
  grep -qx -- "--profile-id" "$ARGV"
  grep -qx -- "a7d1bb99-538c-4db4-b357-0123456789ab" "$ARGV"
  grep -qx -- "--connect-url" "$ARGV"
  grep -qx -- "https://vpn.example.com/portal?s=1" "$ARGV"
  grep -qx -- "--resolve" "$ARGV"
}

@test "phase two never passes a fingerprint: the helper reads it from the registry" {
  _write_profile
  load_profile_fields "Helper VPN"
  translate_extra_args ""
  AUTH_CONNECT_URL="https://vpn.example.com"
  AUTH_FINGERPRINT="sha1:469bb424ec8835944d30bc77c77e8fc1d8e23a42"
  AUTH_COOKIE="c"
  AUTH_RESOLVE=""
  QUIET=FALSE
  set_profile_paths "Helper VPN"

  ARGV="$BATS_TEST_TMPDIR/argv"
  sudo() { printf '%s\n' "$@" > "$ARGV"; cat >/dev/null; return 0; }
  write_connection_state() { :; }
  run_hooks() { :; }

  run run_openconnect_helper
  # A caller-supplied fingerprint is exactly what Model B refuses to trust, so
  # it must not be on the command line at all.
  if grep -q -- "--servercert" "$ARGV"; then false; fi
  if grep -q -- "--fingerprint" "$ARGV"; then false; fi
  if grep -q -- "469bb424" "$ARGV"; then false; fi
}

@test "phase two forwards an approved proxy and the translated tunables" {
  _write_profile "--no-dtls --mtu 1400" "socks5://127.0.0.1:1080"
  load_profile_fields "Helper VPN"
  translate_extra_args "$VPN_EXTRA_ARGS"
  AUTH_CONNECT_URL="https://vpn.example.com"
  AUTH_COOKIE="c"; AUTH_RESOLVE=""
  QUIET=TRUE
  set_profile_paths "Helper VPN"

  ARGV="$BATS_TEST_TMPDIR/argv"
  sudo() { printf '%s\n' "$@" > "$ARGV"; cat >/dev/null; return 0; }
  write_connection_state() { :; }
  run_hooks() { :; }

  run run_openconnect_helper
  grep -qx -- "--proxy" "$ARGV"
  grep -qx -- "socks5://127.0.0.1:1080" "$ARGV"
  grep -qx -- "--tunable" "$ARGV"
  grep -qx -- "no-dtls" "$ARGV"
  grep -qx -- "mtu=1400" "$ARGV"
  grep -qx -- "--quiet" "$ARGV"
}

# --- mode selection --------------------------------------------------------

@test "helper mode is refused when the binary is missing" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/nowhere"
  run helper_mode_available
  [ "$status" -ne 0 ]
}

@test "helper mode requires passwordless sudo, not merely the binary" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR"
  printf '#!/bin/sh\nexit 0\n' > "$VPN_UP_HELPER_DIR/vpn-up-helper"
  chmod 755 "$VPN_UP_HELPER_DIR/vpn-up-helper"

  # sudo -n fails when no passwordless rule covers the command. A rule that
  # still prompts is useless to a login service and would hang it.
  sudo() { return 1; }
  run helper_mode_available
  [ "$status" -ne 0 ]

  sudo() { return 0; }
  run helper_mode_available
  [ "$status" -eq 0 ]
}

# --- how the privileged step is invoked ------------------------------------
#
# The tier split (helper_mode_installed / helper_mode_available) decides WHETHER
# helper mode is used; these decide what actually reaches sudo. They exist
# because the split shipped without them: `install-helper` made helper mode
# reachable without a passwordless rule, while connect and stop still passed
# `sudo -n`, so the interactive tier could not work at all.
#
# It failed intermittently rather than always, which is why nothing noticed: a
# warm sudo credential cache makes `-n` succeed, and the installer leaves one
# warm. Assert on argv, not on behaviour, or the cache decides the verdict.

_helper_argv_setup() {
  _write_profile
  load_profile_fields "Helper VPN"
  translate_extra_args ""
  AUTH_CONNECT_URL="https://vpn.example.com"
  AUTH_COOKIE="c"; AUTH_RESOLVE=""
  QUIET=FALSE
  set_profile_paths "Helper VPN"
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  ARGV="$BATS_TEST_TMPDIR/argv"
  write_connection_state() { :; }
  run_hooks() { :; }
}

@test "connect asks sudo interactively: no -n, and it names the helper" {
  _helper_argv_setup
  sudo() { printf '%s\n' "$@" > "$ARGV"; cat >/dev/null; return 0; }

  run run_openconnect_helper
  [ "$status" -eq 0 ]

  # -n here means "fail instead of prompting", which is exactly wrong on a
  # machine whose passwordless rule was never installed - and the failure lands
  # AFTER phase one has spent the user's password and second factor.
  if grep -qx -- "-n" "$ARGV"; then false; fi
  grep -qx -- "$BATS_TEST_TMPDIR/bin/vpn-up-helper" "$ARGV"
  # The first word must be the helper: no flag may precede it.
  [ "$(head -n 1 "$ARGV")" = "$BATS_TEST_TMPDIR/bin/vpn-up-helper" ]
}

@test "connect_via_helper removes a staged PKCS#11 PIN file as soon as the cookie is obtained" {
  # Once phase_one_authenticate returns, run_openconnect_helper hands the
  # cookie to the privileged helper and never touches the certificate/key/PIN
  # again -- so a staged PIN file (core.sh, _prepare_pkcs11_pin) has finished
  # its job right here, rather than needing to survive for the whole,
  # possibly hours-long tunnel session the way it does in prompt mode (review
  # round 8, HIGH #2). This asserts the file is gone by the time
  # run_openconnect_helper -- the only thing left to run -- is even reached.
  _helper_argv_setup
  _VPN_PIN_FILE="$BATS_TEST_TMPDIR/pinfile"
  printf '1234' > "$_VPN_PIN_FILE"
  phase_one_authenticate() { return 0; }
  local seen="$BATS_TEST_TMPDIR/seen-at-dispatch"
  run_openconnect_helper() {
    if [ -e "$_VPN_PIN_FILE" ]; then echo "still-present" > "$seen"; else echo "gone" > "$seen"; fi
    return 0
  }

  connect_via_helper
  [ "$(cat "$seen")" = "gone" ]
  [ -z "$_VPN_PIN_FILE" ]
  [ ! -e "$BATS_TEST_TMPDIR/pinfile" ]
}

@test "stop asks sudo interactively too" {
  # A `-n` here could not stop a tunnel this same session started, and stop's
  # caller then falls through to the pid-file path - which never finds a
  # helper-mode tunnel, because the helper keeps its pid in root-owned state.
  _helper_argv_setup
  sudo() { printf '%s\n' "$@" > "$ARGV"; return 0; }

  run stop_via_helper
  [ "$status" -eq 0 ]
  if grep -qx -- "-n" "$ARGV"; then false; fi
  [ "$(head -n 1 "$ARGV")" = "$BATS_TEST_TMPDIR/bin/vpn-up-helper" ]
  grep -qx -- "stop" "$ARGV"
}

@test "the passwordless probe still carries -k, and connect still does not" {
  # Two different questions. The probe asks about POLICY and must ignore the
  # credential cache; the connect asks sudo to do the work and must be willing
  # to prompt. One file, opposite requirements.
  _helper_argv_setup
  mkdir -p "$VPN_UP_HELPER_DIR"
  printf '#!/bin/sh\nexit 0\n' > "$VPN_UP_HELPER_DIR/vpn-up-helper"
  chmod 755 "$VPN_UP_HELPER_DIR/vpn-up-helper"

  PROBE="$BATS_TEST_TMPDIR/probe"
  sudo() { printf '%s\n' "$@" > "$PROBE"; return 0; }
  run helper_mode_available
  [ "$status" -eq 0 ]
  grep -qx -- "-k" "$PROBE"
  grep -qx -- "-n" "$PROBE"
}

@test "sudo is authorized before phase one, not after it" {
  # Ordering is the whole point: a Duo push cannot be recalled, so discovering
  # that sudo will not authorize the helper must happen first. This is now
  # run_admitted_connection's responsibility (core.sh), not
  # connect_via_helper's -- the interactive sudo -v call moved out to phase 4
  # per the design's privilege-split correction (see CHANGELOG).
  _helper_argv_setup
  ORDER="$BATS_TEST_TMPDIR/order"
  : > "$ORDER"
  _VPN_CONNECT_MODE="helper"
  helper_mode_available() { return 1; }             # interactive tier
  sudo() { echo "sudo $1" >> "$ORDER"; return 0; }
  migrate_or_fetch_password() { return 0; }
  phase_one_authenticate() { echo "phase-one" >> "$ORDER"; return 1; }

  run run_admitted_connection "Helper VPN" INTERACTIVE
  [ "$status" -ne 0 ]
  [ "$(head -n 1 "$ORDER")" = "sudo -v" ]
  grep -qx -- "phase-one" "$ORDER"
}

@test "a refused sudo aborts before phase one spends a second factor" {
  _helper_argv_setup
  _VPN_CONNECT_MODE="helper"
  helper_mode_available() { return 1; }
  sudo() { return 1; }                              # user cancelled or failed
  migrate_or_fetch_password() { return 0; }
  RAN="$BATS_TEST_TMPDIR/ran"
  phase_one_authenticate() { : > "$RAN"; return 0; }

  run run_admitted_connection "Helper VPN" INTERACTIVE
  [ "$status" -ne 0 ]
  [ ! -e "$RAN" ]
}

@test "a passwordless machine is not prompted for nothing" {
  # `sudo -v` validates the user in general, so on a machine whose only rule is
  # NOPASSWD for the helper it would prompt - for a password not needed.
  _helper_argv_setup
  helper_mode_available() { return 0; }
  CALLED="$BATS_TEST_TMPDIR/called"
  sudo() { : > "$CALLED"; return 0; }

  run helper_sudo_prepare
  [ "$status" -eq 0 ]
  [ ! -e "$CALLED" ]
}

# --- a refusal is not a disconnection --------------------------------------

@test "a sudo refusal does not fire the disconnected hooks" {
  # The tunnel never existed. Announcing a disconnection runs the user's
  # `disconnected` hook for a connection that never happened.
  _helper_argv_setup
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  sudo() { echo "sudo: a password is required" >&2; cat >/dev/null; return 1; }

  run run_openconnect_helper
  [ "$status" -ne 0 ]
  [ ! -e "$HOOKS" ]
}

@test "a helper refusal does not fire the disconnected hooks either" {
  # The helper execs OpenConnect on success, so a line under its own name can
  # only have come from a refusal before that exec.
  _helper_argv_setup
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  sudo() {
    echo "vpn-up-helper: profile a7d1bb99 is not approved for this user."
    cat >/dev/null; return 1
  }

  run run_openconnect_helper
  [ "$status" -ne 0 ]
  [ ! -e "$HOOKS" ]
}

@test "a tunnel that ran still reports its disconnection" {
  # The narrowing must not swallow the real case, or `disconnected` hooks stop
  # firing altogether and nothing downstream ever cleans up.
  _helper_argv_setup
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  sudo() {
    echo "Connected as 10.0.0.2, using SSL"
    echo "Session terminated by server"
    cat >/dev/null; return 1
  }

  run run_openconnect_helper
  [ "$status" -ne 0 ]
  grep -qx -- "disconnected" "$HOOKS"
}

@test "a silent run is treated as a tunnel, not as a refusal" {
  # --quiet is supported, so no output is ambiguous. Ambiguity keeps the old
  # behaviour rather than inventing a verdict.
  _helper_argv_setup
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  sudo() { cat >/dev/null; return 0; }

  run run_openconnect_helper
  [ "$status" -eq 0 ]
  grep -qx -- "disconnected" "$HOOKS"
}

@test "an earlier session in the log does not decide this run's verdict" {
  # The check reads only what THIS run appended, from the byte offset taken
  # before it. The log is append-only across sessions, so a successful tunnel
  # yesterday would otherwise supply the non-refusal line that makes today's
  # refusal look like a disconnection - and every later run in that log would
  # inherit the wrong answer permanently.
  _helper_argv_setup
  mkdir -p "$(dirname "$LOG_FILE_PATH")"
  cat > "$LOG_FILE_PATH" <<'OLD'
Connected as 10.0.0.2, using SSL
Session terminated by server
OLD
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  sudo() { echo "sudo: a password is required" >&2; cat >/dev/null; return 1; }

  run run_openconnect_helper
  [ "$status" -ne 0 ]
  [ ! -e "$HOOKS" ]
}

# --- connection-state telemetry (connection-state design plan §2) ----------

@test "helper_supports_event_status detects the marker in a new helper's version output" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR"
  cat > "$VPN_UP_HELPER_DIR/vpn-up-helper" <<'EOF'
#!/bin/sh
echo "vpn-up-helper (policy engine 1)"
echo "  features        event-status-v1"
EOF
  chmod 755 "$VPN_UP_HELPER_DIR/vpn-up-helper"
  run helper_supports_event_status
  [ "$status" -eq 0 ]
}

@test "helper_supports_event_status reports false for an old helper with no marker" {
  export VPN_UP_HELPER_DIR="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$VPN_UP_HELPER_DIR"
  printf '#!/bin/sh\necho "vpn-up-helper (policy engine 1)"\n' > "$VPN_UP_HELPER_DIR/vpn-up-helper"
  chmod 755 "$VPN_UP_HELPER_DIR/vpn-up-helper"
  run helper_supports_event_status
  [ "$status" -ne 0 ]
}

@test "generate_request_id produces exactly 32 lowercase hex characters, and does not repeat" {
  local a b
  a="$(generate_request_id)"
  b="$(generate_request_id)"
  [ "${#a}" -eq 32 ]
  [[ "$a" =~ ^[0-9a-f]{32}$ ]]
  [ "$a" != "$b" ]
}

@test "the capability check and request-id generation happen before phase_one_authenticate spends anything" {
  # Constraint 8 / round 4 item 6: phase_one_authenticate spends a real
  # credential, so anything that must run "before any credential is spent"
  # cannot live inside run_openconnect_helper, reached only after that
  # credential is already gone.
  ORDER="$BATS_TEST_TMPDIR/order"
  : > "$ORDER"
  helper_supports_event_status() { echo capability_check >> "$ORDER"; return 0; }
  generate_request_id() { echo generate_request_id >> "$ORDER"; printf '%s' "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }
  phase_one_authenticate() { echo phase_one >> "$ORDER"; return 1; }

  run connect_via_helper
  [ "$status" -eq "$VPN_RC_PREAUTH" ]
  [ "$(sed -n '1p' "$ORDER")" = "capability_check" ]
  [ "$(sed -n '2p' "$ORDER")" = "generate_request_id" ]
  [ "$(sed -n '3p' "$ORDER")" = "phase_one" ]
}

@test "an old helper (capability check fails) never calls generate_request_id and never passes --request-id" {
  ORDER="$BATS_TEST_TMPDIR/order"
  : > "$ORDER"
  helper_supports_event_status() { return 1; }
  generate_request_id() { echo generate_request_id >> "$ORDER"; return 1; }
  phase_one_authenticate() { return 1; }

  run connect_via_helper
  [ ! -s "$ORDER" ]
}

@test "poll_helper_event ignores a reading whose request_id does not match this invocation's own" {
  _helper_argv_setup
  HOOKS="$BATS_TEST_TMPDIR/hooks"; NOTIFIES="$BATS_TEST_TMPDIR/notifies"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  notify() { printf '%s\n' "$2" >> "$NOTIFIES"; }
  sleep() { :; }   # the loop must not block a bounded test on real time

  # A concurrent, unrelated generation's own verified session - never this
  # invocation's to claim (round 3 item 3).
  sudo() {
    cat >/dev/null 2>&1
    printf 'session=ffffffffffffffffffffffffffffffff\n'
    printf 'request_id=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n'
    printf 'last_connected_epoch=1700000000\n'
    printf 'current_verified=1\n'
    printf 'last_reason=connect\n'
    printf 'last_event_epoch=1700000000\n'
    printf 'pid=9999\n'
  }

  run poll_helper_event "cccccccccccccccccccccccccccccccc" "${VPN_PROFILE_ID}" "$(helper_bin)"
  [ "$status" -ne 0 ]                # bounded, exhausted, never matched
  [ ! -e "$PID_FILE_PATH" ]
  [ ! -e "$HOOKS" ]
  [ ! -e "$NOTIFIES" ]
}

@test "poll_helper_event publishes evidence once it observes a matching, verified record" {
  # _helper_argv_setup stubs write_connection_state to a no-op for tests that
  # do not care about it; this one specifically asserts on what it writes, so
  # the real definition (still the one core.sh sourced, at this point in the
  # test) is captured first and restored after.
  eval "_real_write_connection_state() $(declare -f write_connection_state | tail -n +2)"
  _helper_argv_setup
  write_connection_state() { _real_write_connection_state "$@"; }
  HOOKS="$BATS_TEST_TMPDIR/hooks"; NOTIFIES="$BATS_TEST_TMPDIR/notifies"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  notify() { printf '%s\n' "$2" >> "$NOTIFIES"; }
  local req="cccccccccccccccccccccccccccccccc"
  sudo() {
    cat >/dev/null 2>&1
    printf 'session=dddddddddddddddddddddddddddddddd\n'
    printf 'request_id=%s\n' "$req"
    printf 'last_connected_epoch=1700000000\n'
    printf 'current_verified=1\n'
    printf 'last_reason=connect\n'
    printf 'last_event_epoch=1700000000\n'
    printf 'pid=4242\n'
  }

  run poll_helper_event "$req" "${VPN_PROFILE_ID}" "$(helper_bin)"
  [ "$status" -eq 0 ]
  [ "$(cat "$PID_FILE_PATH")" = "4242" ]
  grep -q "evidence=verified" "$STATE_FILE_PATH"
  grep -q "connected_at_epoch=1700000000" "$STATE_FILE_PATH"
  grep -qx -- "connected" "$HOOKS"
  grep -qx -- "Connected to Helper VPN" "$NOTIFIES"
}

@test "_helper_final_event_had_tunnel confirms a genuine disconnect only for a matching, once-verified record" {
  _helper_argv_setup
  local req="cccccccccccccccccccccccccccccccc"
  sudo() {
    cat >/dev/null 2>&1
    printf 'session=dddddddddddddddddddddddddddddddd\n'
    printf 'request_id=%s\n' "$req"
    printf 'last_connected_epoch=1700000000\n'
    printf 'current_verified=0\n'
    printf 'last_reason=disconnect\n'
    printf 'last_event_epoch=1700000100\n'
    printf 'pid=0\n'
  }
  run _helper_final_event_had_tunnel "$req" "${VPN_PROFILE_ID}" "$(helper_bin)"
  [ "$status" -eq 0 ]
}

@test "_helper_final_event_had_tunnel is inconclusive on a request-id mismatch, falling back to the heuristic" {
  _helper_argv_setup
  sudo() {
    cat >/dev/null 2>&1
    printf 'session=dddddddddddddddddddddddddddddddd\n'
    printf 'request_id=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n'
    printf 'last_connected_epoch=1700000000\n'
    printf 'current_verified=0\n'
    printf 'last_reason=disconnect\n'
    printf 'last_event_epoch=1700000100\n'
    printf 'pid=0\n'
  }
  run _helper_final_event_had_tunnel "cccccccccccccccccccccccccccccccc" "${VPN_PROFILE_ID}" "$(helper_bin)"
  [ "$status" -ne 0 ]
}

@test "_helper_final_event_had_tunnel is inconclusive when the profile never connected (epoch 0)" {
  _helper_argv_setup
  local req="cccccccccccccccccccccccccccccccc"
  sudo() {
    cat >/dev/null 2>&1
    printf 'session=dddddddddddddddddddddddddddddddd\n'
    printf 'request_id=%s\n' "$req"
    printf 'last_connected_epoch=0\n'
    printf 'current_verified=0\n'
    printf 'last_reason=\n'
    printf 'last_event_epoch=0\n'
    printf 'pid=0\n'
  }
  run _helper_final_event_had_tunnel "$req" "${VPN_PROFILE_ID}" "$(helper_bin)"
  [ "$status" -ne 0 ]
}

@test "an old client (no request id) still connects and falls back to the heuristic unchanged" {
  # Round 4 item 5: a rolled-back or older vpn-up talking to an already-
  # upgraded helper must still work, with no telemetry correlation rather
  # than an error.
  _helper_argv_setup
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  sudo() {
    printf '%s\n' "$@" > "$ARGV"
    echo "Connected as 10.0.0.2, using SSL"
    echo "Session terminated by server"
    cat >/dev/null
    return 0
  }
  run run_openconnect_helper ""
  [ "$status" -eq 0 ]
  if grep -qx -- "--request-id" "$ARGV"; then false; fi
  grep -qx -- "disconnected" "$HOOKS"
}

@test "run_openconnect_helper: the poller's verified evidence reaches vpn-up status through the real, unmodified command" {
  eval "_real_write_connection_state() $(declare -f write_connection_state | tail -n +2)"
  _helper_argv_setup
  write_connection_state() { _real_write_connection_state "$@"; }
  is_openconnect_pid() { return 0; }     # the recorded (fake) pid is treated as a live process
  local req="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  HOOKS="$BATS_TEST_TMPDIR/hooks"
  NOTIFIES="$BATS_TEST_TMPDIR/notifies"
  STATUS_OUT="$BATS_TEST_TMPDIR/status-out"
  run_hooks() { echo "$1" >> "$HOOKS"; }
  notify() { printf '%s\n' "$2" >> "$NOTIFIES"; }

  sudo() {
    case "$1" in
      -k)
        cat >/dev/null 2>&1
        printf 'session=dddddddddddddddddddddddddddddddd\n'
        printf 'request_id=%s\n' "$req"
        printf 'last_connected_epoch=1700000000\n'
        printf 'current_verified=1\n'
        printf 'last_reason=connect\n'
        printf 'last_event_epoch=1700000000\n'
        printf 'pid=4242\n'
        ;;
      *)
        cat >/dev/null
        # Deterministic synchronisation without a stubbed sleep: the main
        # connect call does not return until the backgrounded poller has
        # actually finished ALL of its work, so this proves the real
        # ordering rather than winning a race by luck. Waiting on HOOKS
        # rather than PID_FILE_PATH matters: PID_FILE_PATH is the FIRST
        # thing poll_helper_event writes (part 1's ordering rule), so
        # releasing the main pipeline - and with it run_openconnect_helper's
        # own kill of the poller - the moment it appears could still SIGTERM
        # the poller mid-flight, before its own notify/run_hooks calls ever
        # run. HOOKS is the LAST thing it writes. Bounded to 5s so a genuine
        # bug (the poller never finishing) fails the test instead of hanging
        # it.
        local waited=0
        while [ ! -f "$HOOKS" ] && [ "$waited" -lt 500 ]; do
          command sleep 0.01
          waited=$((waited + 1))
        done
        # Captured HERE, before run_openconnect_helper's own end-of-run
        # cleanup removes these files - the direct proof that the ordinary,
        # completely unmodified `status` command reaches the poller's
        # evidence through the command a user actually runs.
        status > "$STATUS_OUT" 2>&1
        echo "Connected as 10.0.0.2, using SSL"
        return 0
        ;;
    esac
  }

  run run_openconnect_helper "$req"
  [ "$status" -eq 0 ]
  grep -qx -- "connected" "$HOOKS"
  grep -qx -- "Connected to Helper VPN" "$NOTIFIES"
  grep -q "VPN is running" "$STATUS_OUT"
  grep -q "verified: OpenConnect connect event observed for this session" "$STATUS_OUT"
}

@test "run_openconnect_helper joins the poller before its own final decision (no late Connected after Disconnected)" {
  eval "_real_write_connection_state() $(declare -f write_connection_state | tail -n +2)"
  _helper_argv_setup
  write_connection_state() { _real_write_connection_state "$@"; }
  ORDER="$BATS_TEST_TMPDIR/order"
  : > "$ORDER"
  local req="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  notify() { printf '%s\n' "$2" >> "$ORDER"; }
  run_hooks() { printf '%s\n' "$1" >> "$ORDER"; }

  sudo() {
    case "$1" in
      -k)
        cat >/dev/null 2>&1
        printf 'session=dddddddddddddddddddddddddddddddd\n'
        printf 'request_id=%s\n' "$req"
        printf 'last_connected_epoch=1700000000\n'
        printf 'current_verified=1\n'
        printf 'last_reason=connect\n'
        printf 'last_event_epoch=1700000000\n'
        printf 'pid=4242\n'
        ;;
      *)
        cat >/dev/null
        # Wait for BOTH of the poller's writes to ORDER (notify, then
        # run_hooks - the last thing it does), not merely its first side
        # effect: releasing the main pipeline (and with it
        # run_openconnect_helper's kill of the poller) any earlier could
        # SIGTERM it mid-flight, before run_hooks ever fires.
        local waited=0
        while [ "$(wc -l < "$ORDER" 2>/dev/null || echo 0)" -lt 2 ] && [ "$waited" -lt 500 ]; do
          command sleep 0.01
          waited=$((waited + 1))
        done
        echo "Connected as 10.0.0.2, using SSL"
        return 0
        ;;
    esac
  }

  run run_openconnect_helper "$req"
  [ "$status" -eq 0 ]
  # "connected" (from the poller) must be recorded strictly before
  # "disconnected" (from the parent's own final decision) - never the reverse.
  [ "$(sed -n '1p' "$ORDER")" = "Connected to Helper VPN" ]
  [ "$(sed -n '2p' "$ORDER")" = "connected" ]
  [ "$(sed -n '3p' "$ORDER")" = "Disconnected from Helper VPN" ]
  [ "$(sed -n '4p' "$ORDER")" = "disconnected" ]
}
