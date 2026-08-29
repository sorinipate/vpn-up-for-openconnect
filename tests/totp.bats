#!/usr/bin/env bats
# Tests for TOTP authenticator-app 2FA (tokenMode=totp).

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  print_warning() { printf -- "$1" "${@:2}"; }
  print_danger()  { printf -- "$1" "${@:2}"; }
  print_success() { printf -- "$1" "${@:2}"; }
  print_primary() { printf -- "$1" "${@:2}"; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../outcome.sh"
  source "$BATS_TEST_DIRNAME/../dependencies.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
}

_write_profiles() {
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Token VPN</name><protocol>anyconnect</protocol><host>t.example.com</host><authGroup></authGroup><user>alice</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode>totp</tokenMode></VPN>
  <VPN><name>Duo VPN</name><protocol>anyconnect</protocol><host>d.example.com</host><authGroup></authGroup><user>bob</user><password></password><duo2FAMethod>push</duo2FAMethod><serverCertificate></serverCertificate></VPN>
</VPNs>
XML
}

# --- schema ---

@test "load_profile_fields reads tokenMode=totp and leaves earlier fields intact" {
  _write_profiles
  load_profile_fields "Token VPN"
  [ "$VPN_NAME" = "Token VPN" ]
  [ "$VPN_USER" = "alice" ]
  [ "$VPN_AUTH_MODE" = "password" ]
  [ "$VPN_TOKEN_MODE" = "totp" ]
}

@test "load_profile_fields leaves tokenMode empty when the tag is absent" {
  _write_profiles
  load_profile_fields "Duo VPN"
  [ -z "$VPN_TOKEN_MODE" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
}

# --- generation + dependency gate ---

@test "generate_totp returns the oathtool output" {
  oathtool() { echo "654321"; }
  [ "$(generate_totp JBSWY3DPEHPK3PXP)" = "654321" ]
}

@test "generate_totp passes the seed on stdin, never on argv" {
  # Capture both what oathtool received as arguments and what it read on stdin.
  oathtool() { printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/argv"; cat > "$BATS_TEST_TMPDIR/stdin"; echo "654321"; }
  [ "$(generate_totp JBSWY3DPEHPK3PXP)" = "654321" ]

  # The seed must not appear anywhere in the process table.
  if grep -q "JBSWY3DPEHPK3PXP" "$BATS_TEST_TMPDIR/argv"; then false; fi
  # It must arrive on stdin instead, and '-' must be the key argument.
  grep -qx -- "JBSWY3DPEHPK3PXP" "$BATS_TEST_TMPDIR/stdin"
  grep -qx -- "-" "$BATS_TEST_TMPDIR/argv"
  grep -qx -- "--totp" "$BATS_TEST_TMPDIR/argv"
  grep -qx -- "-b" "$BATS_TEST_TMPDIR/argv"
}

@test "generate_totp matches the real oathtool for a known seed (stdin form)" {
  command -v oathtool >/dev/null 2>&1 || skip "oathtool not installed"
  # Same time step, so the stdin form and the legacy argv form must agree.
  [ "$(generate_totp JBSWY3DPEHPK3PXP)" = "$(oathtool --totp -b JBSWY3DPEHPK3PXP)" ]
}

@test "require_oathtool succeeds when oathtool is present" {
  oathtool() { :; }   # a function makes `command -v oathtool` resolve
  run require_oathtool
  [ "$status" -eq 0 ]
}

@test "require_oathtool fails when oathtool is absent" {
  local saved="$PATH"
  PATH="/nonexistent"               # no oathtool on PATH, and no stub function
  run require_oathtool
  PATH="$saved"
  [ "$status" -ne 0 ]
}

# --- the security-critical path: code on stdin, seed never on argv ---

@test "run_openconnect feeds the generated code on stdin and never puts the seed/token flags on argv" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv" stdin="$BATS_TEST_TMPDIR/stdin"
  sudo() {
    if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat > "$stdin"; return 0; fi
    return 0
  }
  load_profile_fields "Token VPN"
  VPN_PASSWD="s3cret"
  # Generating the code from the seed is now run_admitted_connection's job
  # (core.sh), not run_openconnect's; this test is specifically about
  # run_openconnect's own stdin/argv construction, so the already-generated
  # code is supplied directly, exactly as run_admitted_connection would.
  VPN_SECOND_FACTOR="424242"
  SERVER_CERTIFICATE="pin-sha256:abc"   # skip trust-store lookup
  QUIET=FALSE; BACKGROUND=TRUE          # use the background branch (no tee/sleep)

  run_openconnect

  # stdin: line 1 = password, line 2 = the generated TOTP code
  [ "$(sed -n 1p "$stdin")" = "s3cret" ]
  [ "$(sed -n 2p "$stdin")" = "424242" ]
  # argv: password-on-stdin, but NEVER the token flags or a seed
  grep -qF -- "--passwd-on-stdin" "$argv"
  if grep -qiE -- "--token-(secret|mode)" "$argv"; then false; fi
  if grep -qF -- "JBSWY3DPEHPK3PXP" "$argv"; then false; fi
}

# --- precedence: SSO wins over token (token branch is skipped) ---

@test "run_admitted_connection (sso + totp) takes the SSO path and never generates a TOTP code" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  export VPN_UP_NO_TOTP_WAIT=1
  require_openconnect_sso() { return 0; }
  fetch_server_pin() { echo "pin-sha256:abc"; }   # avoid a real network call
  # twophase.sh isn't sourced in this file; force prompt mode so the test
  # exercises run_openconnect's dispatch (what it actually cares about) via
  # the stubbed `sudo`, not the unrelated helper-mode path.
  helper_mode_usable() { return 1; }
  oathtool() { touch "$BATS_TEST_TMPDIR/oathtool-called"; echo "000000"; }
  sleep() { :; }
  tee() { cat >/dev/null; }
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; return 0; fi; return 0; }
  load_profile_fields "Token VPN"
  VPN_AUTH_MODE=sso                      # force SSO on top of tokenMode=totp
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=FALSE
  VPN_UP_EXTERNAL_BROWSER="my-opener"

  # _VPN_CONNECT_MODE is left unset (defaults to the prompt-mode dispatch,
  # exactly as connection_preflight would leave it after the SSO/TOTP
  # precedence checks below run) -- this test is specifically about that
  # precedence, which now lives in connection_preflight + run_admitted_connection
  # rather than a single connect() function.
  connection_preflight INTERACTIVE
  run_admitted_connection "Token VPN" INTERACTIVE

  grep -qF -- "--external-browser=my-opener" "$argv"
  if grep -qF -- "--passwd-on-stdin" "$argv"; then false; fi
  [ ! -e "$BATS_TEST_TMPDIR/oathtool-called" ]   # token branch was skipped
}

# --- service mode ---

@test "service preflight allows a TOTP profile with a stored secret, rejects it without one" {
  _write_profiles
  source "$BATS_TEST_DIRNAME/../service.sh"
  sudo() { return 0; }
  oathtool() { :; }

  secrets_get() { echo "JBSWY3DPEHPK3PXP"; }   # seed present
  run _service_preflight "Token VPN"
  [ "$status" -eq 0 ]

  secrets_get() { echo ""; }                   # seed missing
  run _service_preflight "Token VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no stored secret"* || "$output" == *"set-secret"* ]]
}
