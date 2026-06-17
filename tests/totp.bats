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

@test "connect (totp) feeds the generated code on stdin and never puts the seed/token flags on argv" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv" stdin="$BATS_TEST_TMPDIR/stdin"
  oathtool() { echo "424242"; }                       # fixed code
  secrets_get() { echo "JBSWY3DPEHPK3PXP"; }           # stored seed
  sudo() {
    if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat > "$stdin"; return 0; fi
    return 0   # sudo -v
  }
  load_profile_fields "Token VPN"
  VPN_PASSWD="s3cret"
  SERVER_CERTIFICATE="pin-sha256:abc"   # skip trust-store lookup
  QUIET=FALSE; BACKGROUND=TRUE          # use the background branch (no tee/sleep)

  connect

  # stdin: line 1 = password, line 2 = the generated TOTP code
  [ "$(sed -n 1p "$stdin")" = "s3cret" ]
  [ "$(sed -n 2p "$stdin")" = "424242" ]
  # argv: password-on-stdin, but NEVER the token flags or the seed
  grep -qF -- "--passwd-on-stdin" "$argv"
  ! grep -qiE -- "--token-(secret|mode)" "$argv"
  ! grep -qF -- "JBSWY3DPEHPK3PXP" "$argv"
}

# --- precedence: SSO wins over token (token branch is skipped) ---

@test "connect (sso + totp) takes the SSO path and never generates a TOTP code" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  require_openconnect_sso() { return 0; }
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

  connect

  grep -qF -- "--external-browser=my-opener" "$argv"
  ! grep -qF -- "--passwd-on-stdin" "$argv"
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
