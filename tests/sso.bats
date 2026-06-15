#!/usr/bin/env bats
# Tests for SAML/SSO external-browser authentication (authMode=sso).

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
  <VPN><name>SSO VPN</name><protocol>anyconnect</protocol><host>sso.example.com</host><authGroup></authGroup><user>alice</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>sso</authMode></VPN>
  <VPN><name>Pwd VPN</name><protocol>anyconnect</protocol><host>pwd.example.com</host><authGroup></authGroup><user>bob</user><password></password><duo2FAMethod>push</duo2FAMethod><serverCertificate></serverCertificate></VPN>
</VPNs>
XML
}

# --- schema: authMode is loaded and defaults to password ---

@test "load_profile_fields reads authMode=sso and leaves earlier fields intact" {
  _write_profiles
  load_profile_fields "SSO VPN"
  [ "$VPN_NAME" = "SSO VPN" ]
  [ "$PROTOCOL" = "anyconnect" ]
  [ "$VPN_HOST" = "sso.example.com" ]
  [ "$VPN_USER" = "alice" ]
  [ "$VPN_AUTH_MODE" = "sso" ]
}

@test "load_profile_fields defaults authMode to password when the tag is absent" {
  _write_profiles
  load_profile_fields "Pwd VPN"
  [ "$VPN_AUTH_MODE" = "password" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
}

# --- resolve_external_browser ---

@test "resolve_external_browser honors the override, else a platform default" {
  VPN_UP_EXTERNAL_BROWSER="/opt/my-browser" run resolve_external_browser
  [ "$output" = "/opt/my-browser" ]
  unset VPN_UP_EXTERNAL_BROWSER
  run resolve_external_browser
  case "$output" in open|xdg-open|openconnect-external-browser) : ;; *) false ;; esac
}

# --- run_openconnect argv: external-browser, no password on stdin ---

@test "run_openconnect (sso) passes --external-browser and never --passwd-on-stdin" {
  local cap="$BATS_TEST_TMPDIR/argv"
  # Capture only the openconnect invocation; succeed for sudo -v / -n -v.
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$cap"; return 0; fi; return 0; }
  sleep() { :; }                      # don't linger on the 3s PID-capture subshell
  tee()  { cat >/dev/null; }          # swallow logged output

  VPN_NAME="SSO VPN"; PROTOCOL="anyconnect"; VPN_HOST="sso.example.com"
  VPN_USER="alice"; VPN_GROUP=""; VPN_PASSWD=""; VPN_DUO2FAMETHOD=""
  SERVER_CERTIFICATE=""; VPN_AUTH_MODE="sso"
  QUIET=FALSE; BACKGROUND=TRUE        # BACKGROUND must be ignored for SSO
  VPN_UP_EXTERNAL_BROWSER="my-opener"
  PID_FILE_PATH="$DATA_DIR/pids/${PROGRAM_NAME}.SSO.pid"
  STATE_FILE_PATH="$DATA_DIR/pids/${PROGRAM_NAME}.SSO.state"
  LOG_FILE_PATH="$DATA_DIR/logs/${PROGRAM_NAME}.SSO.log"

  run_openconnect
  grep -qF -- "--external-browser=my-opener" "$cap"
  ! grep -qF -- "--passwd-on-stdin" "$cap"
  ! grep -qF -- "--background" "$cap"   # forced foreground
}

@test "run_openconnect (password) still passes --passwd-on-stdin and no external-browser" {
  local cap="$BATS_TEST_TMPDIR/argv"
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$cap"; return 0; fi; return 0; }
  sleep() { :; }
  tee()  { cat >/dev/null; }

  VPN_NAME="Pwd VPN"; PROTOCOL="anyconnect"; VPN_HOST="pwd.example.com"
  VPN_USER="bob"; VPN_GROUP=""; VPN_PASSWD="s3cret"; VPN_DUO2FAMETHOD="push"
  SERVER_CERTIFICATE=""; VPN_AUTH_MODE="password"
  QUIET=FALSE; BACKGROUND=FALSE
  PID_FILE_PATH="$DATA_DIR/pids/${PROGRAM_NAME}.Pwd.pid"
  STATE_FILE_PATH="$DATA_DIR/pids/${PROGRAM_NAME}.Pwd.state"
  LOG_FILE_PATH="$DATA_DIR/logs/${PROGRAM_NAME}.Pwd.log"

  run_openconnect
  grep -qF -- "--passwd-on-stdin" "$cap"
  ! grep -qF -- "--external-browser" "$cap"
}

# --- version gate ---

@test "require_openconnect_sso accepts v9+, rejects v8, is lenient when unknown" {
  openconnect() { echo "OpenConnect version v9.12"; }
  run require_openconnect_sso; [ "$status" -eq 0 ]
  openconnect() { echo "OpenConnect version v8.10"; }
  run require_openconnect_sso; [ "$status" -ne 0 ]
  openconnect() { echo ""; }
  run require_openconnect_sso; [ "$status" -eq 0 ]
}

@test "openconnect_major parses with and without the leading v" {
  openconnect() { echo "OpenConnect version v9.12"; }
  [ "$(openconnect_major)" = "9" ]
  openconnect() { echo "OpenConnect version 8.20"; }
  [ "$(openconnect_major)" = "8" ]
}

# --- connect()/service guards for SSO ---

@test "connect refuses SSO in service mode and for the nc protocol" {
  _write_profiles
  set_profile_paths() { PID_FILE_PATH=x; LOG_FILE_PATH=y; STATE_FILE_PATH=z; }
  require_openconnect_sso() { return 0; }
  load_profile_fields "SSO VPN"

  VPN_UP_SERVICE=1 run connect
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot run as a service"* ]]

  PROTOCOL="nc" run connect
  [ "$status" -ne 0 ]
  [[ "$output" == *"not supported for the 'nc' protocol"* ]]
}

@test "service preflight rejects an SSO profile" {
  _write_profiles
  source "$BATS_TEST_DIRNAME/../service.sh"
  sudo() { return 0; }
  secrets_get() { echo ""; }
  run _service_preflight "SSO VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot run as a login service"* ]]
}
