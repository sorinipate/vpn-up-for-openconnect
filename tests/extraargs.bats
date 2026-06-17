#!/usr/bin/env bats
# Tests for the per-profile extraArgs openconnect passthrough.

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
  source "$BATS_TEST_DIRNAME/../dependencies.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
}

# Profile XML with an extraArgs value (quoting included to test tokenization).
_write_profiles() {
  local extra="$1"
  cat > "$PROFILES_FILE" <<XML
<VPNs>
  <VPN><name>Extra VPN</name><protocol>anyconnect</protocol><host>x.example.com</host><authGroup></authGroup><user>alice</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode></tokenMode><extraArgs>${extra}</extraArgs></VPN>
</VPNs>
XML
}

# Run run_openconnect (background branch) capturing the openconnect argv.
_capture_argv() {
  ARGV_FILE="$BATS_TEST_TMPDIR/argv"
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$ARGV_FILE"; return 0; fi; return 0; }
  VPN_PASSWD="pw"; SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=TRUE
  run_openconnect
}

# --- schema ---

@test "load_profile_fields reads extraArgs (index 10); earlier fields intact" {
  _write_profiles "--no-dtls"
  load_profile_fields "Extra VPN"
  [ "$VPN_NAME" = "Extra VPN" ]
  [ "$VPN_AUTH_MODE" = "password" ]
  [ -z "$VPN_TOKEN_MODE" ]
  [ "$VPN_EXTRA_ARGS" = "--no-dtls" ]
}

# --- tokenization & placement ---

@test "extraArgs are tokenized (quotes respected) and appended before the host" {
  _write_profiles '--no-dtls --os=win &quot;--csd-wrapper=/a b&quot;'
  load_profile_fields "Extra VPN"
  _capture_argv

  grep -qx -- "--no-dtls" "$ARGV_FILE"
  grep -qx -- "--os=win" "$ARGV_FILE"
  grep -qx -- "--csd-wrapper=/a b" "$ARGV_FILE"   # quoted value stays one element
  # extra args come before the host positional
  local n_csd n_host
  n_csd="$(grep -nx -- "--csd-wrapper=/a b" "$ARGV_FILE" | cut -d: -f1)"
  n_host="$(grep -nx -- "x.example.com" "$ARGV_FILE" | cut -d: -f1)"
  [ "$n_csd" -lt "$n_host" ]
}

@test "empty extraArgs adds no stray argument" {
  _write_profiles ""
  load_profile_fields "Extra VPN"
  _capture_argv
  # no empty line in the captured argv
  ! grep -qx -- "" "$ARGV_FILE"
  grep -qx -- "x.example.com" "$ARGV_FILE"
}

# --- collision warning (warn, but still pass) ---

@test "a managed flag in extraArgs warns but is still passed" {
  _write_profiles "--pid-file /tmp/x"
  load_profile_fields "Extra VPN"
  ARGV_FILE="$BATS_TEST_TMPDIR/argv"
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$ARGV_FILE"; return 0; fi; return 0; }
  VPN_PASSWD="pw"; SERVER_CERTIFICATE="pin-sha256:abc"; QUIET=FALSE; BACKGROUND=TRUE
  run run_openconnect
  [[ "$output" == *"vpn-up already manages"* ]]
  grep -qx -- "--pid-file" "$ARGV_FILE"     # still passed through
}

@test "_warn_extra_arg_collisions flags managed flags and ignores others" {
  run _warn_extra_arg_collisions --no-dtls --user=bob --reconnect-timeout 30
  [[ "$output" == *"--user"* ]]
  [[ "$output" != *"--no-dtls"* ]]
  [[ "$output" != *"--reconnect-timeout"* ]]
}
