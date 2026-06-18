#!/usr/bin/env bats
# Tests for the first-class HTTP/SOCKS proxy field (<proxy>): it maps to
# openconnect's --proxy and is appended only when set.

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

_write_profiles() {
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Proxy VPN</name><protocol>anyconnect</protocol><host>p.example.com</host><authGroup></authGroup><user>alice</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode></tokenMode><extraArgs></extraArgs><clientCertificate></clientCertificate><clientKey></clientKey><proxy>socks5://127.0.0.1:1080</proxy></VPN>
  <VPN><name>Plain VPN</name><protocol>anyconnect</protocol><host>x.example.com</host><authGroup></authGroup><user>bob</user><password></password><duo2FAMethod>push</duo2FAMethod></VPN>
</VPNs>
XML
}

# --- schema ---

@test "load_profile_fields reads proxy and leaves earlier fields intact" {
  _write_profiles
  load_profile_fields "Proxy VPN"
  [ "$VPN_NAME" = "Proxy VPN" ]
  [ "$VPN_USER" = "alice" ]
  [ "$VPN_PROXY" = "socks5://127.0.0.1:1080" ]
}

@test "load_profile_fields leaves proxy empty when the tag is absent" {
  _write_profiles
  load_profile_fields "Plain VPN"
  [ -z "$VPN_PROXY" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
}

# --- argv: --proxy present only when set ---

@test "run_openconnect passes --proxy when the profile has one" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat >/dev/null; return 0; fi; return 0; }
  load_profile_fields "Proxy VPN"
  VPN_PASSWD="s3cret"
  SERVER_CERTIFICATE="pin-sha256:abc"   # skip trust-store lookup
  QUIET=FALSE; BACKGROUND=TRUE          # background branch (no tee/sleep)

  connect

  grep -qF -- "--proxy=socks5://127.0.0.1:1080" "$argv"
}

@test "run_openconnect omits --proxy when the profile has none" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat >/dev/null; return 0; fi; return 0; }
  load_profile_fields "Plain VPN"
  VPN_DUO2FAMETHOD=""                   # avoid the interactive passcode branch
  VPN_PASSWD="s3cret"
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=TRUE

  connect

  ! grep -qF -- "--proxy" "$argv"
}

# --- collision warning ---

@test "_warn_extra_arg_collisions warns when extraArgs duplicates --proxy" {
  run _warn_extra_arg_collisions "--proxy=http://x:8080"
  [[ "$output" == *"--proxy"* ]]
}
