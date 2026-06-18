#!/usr/bin/env bats
# Tests for client-certificate authentication (clientCertificate / clientKey),
# including the PKCS#11 (smartcard / YubiKey-PIV) PIN path. The security-critical
# invariant: the cert/key path or URI may appear on argv, but a key passphrase /
# PKCS#11 PIN must NEVER reach argv.

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
  <VPN><name>Cert VPN</name><protocol>anyconnect</protocol><host>c.example.com</host><authGroup></authGroup><user>alice</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode></tokenMode><extraArgs></extraArgs><clientCertificate>/etc/vpn/me.pem</clientCertificate><clientKey>/etc/vpn/me.key</clientKey></VPN>
  <VPN><name>PKCS VPN</name><protocol>anyconnect</protocol><host>p.example.com</host><authGroup></authGroup><user>bob</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode></tokenMode><extraArgs></extraArgs><clientCertificate>pkcs11:manufacturer=piv_II;id=%01</clientCertificate></VPN>
  <VPN><name>Plain VPN</name><protocol>anyconnect</protocol><host>x.example.com</host><authGroup></authGroup><user>carol</user><password></password><duo2FAMethod>push</duo2FAMethod></VPN>
</VPNs>
XML
}

# --- schema ---

@test "load_profile_fields reads clientCertificate/clientKey and leaves earlier fields intact" {
  _write_profiles
  load_profile_fields "Cert VPN"
  [ "$VPN_NAME" = "Cert VPN" ]
  [ "$VPN_USER" = "alice" ]
  [ "$VPN_AUTH_MODE" = "password" ]
  [ "$VPN_CLIENT_CERT" = "/etc/vpn/me.pem" ]
  [ "$VPN_CLIENT_KEY" = "/etc/vpn/me.key" ]
}

@test "load_profile_fields leaves cert fields empty when the tags are absent" {
  _write_profiles
  load_profile_fields "Plain VPN"
  [ -z "$VPN_CLIENT_CERT" ]
  [ -z "$VPN_CLIENT_KEY" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
}

# --- cert-only auth: no password is required or prompted ---

@test "migrate_or_fetch_password does not require/prompt a password for a cert-only profile" {
  _write_profiles
  secrets_get() { echo ""; }            # nothing stored
  load_profile_fields "Cert VPN"        # has a client cert, no password
  run migrate_or_fetch_password
  [ "$status" -eq 0 ]
}

# --- argv: cert/key flags present; path is fine on argv ---

@test "run_openconnect passes --certificate/--sslkey for a file-based client cert" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat >/dev/null; return 0; fi; return 0; }
  load_profile_fields "Cert VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"   # skip trust-store lookup
  QUIET=FALSE; BACKGROUND=TRUE          # background branch (no tee/sleep)

  connect

  grep -qF -- "--certificate=/etc/vpn/me.pem" "$argv"
  grep -qF -- "--sslkey=/etc/vpn/me.key" "$argv"
}

# --- the security-critical path: PKCS#11 PIN via pin-source file, NEVER on argv ---

@test "run_openconnect feeds a PKCS#11 PIN via a 0600 pin-source file and never on argv" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  local PIN="918273"
  secrets_get() { [ "$2" = key_password ] && echo "$PIN"; }   # stored PKCS#11 PIN
  sudo() {
    if [ "$1" = openconnect ]; then
      shift; printf '%s\n' "$@" > "$argv"
      local a p
      for a in "$@"; do
        case "$a" in
          --certificate=pkcs11:*pin-source=file:*)
            p="${a#*pin-source=file:}"
            ls -l "$p" | cut -c1-10 > "$BATS_TEST_TMPDIR/pinperms"
            cat "$p" > "$BATS_TEST_TMPDIR/pincontents"
            ;;
        esac
      done
      cat >/dev/null
      return 0
    fi
    return 0
  }
  load_profile_fields "PKCS VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=TRUE

  connect

  # argv references the PIN file, but never the PIN value itself
  grep -qF -- "pin-source=file:" "$argv"
  grep -qF -- "pkcs11:manufacturer=piv_II;id=%01" "$argv"
  ! grep -qF -- "$PIN" "$argv"
  # the PIN actually lived in a 0600 file (read back inside the stub)
  [ "$(cat "$BATS_TEST_TMPDIR/pincontents")" = "$PIN" ]
  [[ "$(cat "$BATS_TEST_TMPDIR/pinperms")" == -rw------* ]]
  # and the transient file is shredded after the session
  [ ! -e "${DATA_DIR}/pids/.${PROGRAM_NAME}.$(profile_slug "PKCS VPN").pin" ]
}

@test "run_openconnect omits pin-source when no PKCS#11 PIN is stored (interactive prompt)" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  secrets_get() { echo ""; }            # no stored PIN
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat >/dev/null; return 0; fi; return 0; }
  load_profile_fields "PKCS VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=TRUE

  connect

  grep -qF -- "--certificate=pkcs11:manufacturer=piv_II;id=%01" "$argv"
  ! grep -qF -- "pin-source=file:" "$argv"
}

# --- collision warning includes the cert flags ---

@test "_warn_extra_arg_collisions warns when extraArgs duplicates a cert flag" {
  run _warn_extra_arg_collisions "--certificate=/tmp/x.pem"
  [[ "$output" == *"--certificate"* ]]
}

# --- service mode ---

@test "service preflight: cert-only profile does not warn about a missing password" {
  _write_profiles
  source "$BATS_TEST_DIRNAME/../service.sh"
  sudo() { return 0; }
  secrets_get() { echo ""; }
  run _service_preflight "Cert VPN"
  [ "$status" -eq 0 ]
  [[ "$output" != *"No stored password"* ]]
}

@test "service preflight: PKCS#11 cert without a stored PIN warns to store key_password" {
  _write_profiles
  source "$BATS_TEST_DIRNAME/../service.sh"
  sudo() { return 0; }
  secrets_get() { echo ""; }            # no stored PIN
  run _service_preflight "PKCS VPN"
  [ "$status" -eq 0 ]
  [[ "$output" == *"key_password"* ]]
}
