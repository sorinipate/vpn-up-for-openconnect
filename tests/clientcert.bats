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
  source "$BATS_TEST_DIRNAME/../outcome.sh"
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

  run_openconnect
  grep -qF -- "--certificate=/etc/vpn/me.pem" "$argv"
  grep -qF -- "--sslkey=/etc/vpn/me.key" "$argv"
}

# --- the security-critical path: PKCS#11 PIN via pin-source file, NEVER on argv ---

@test "run_openconnect feeds a pre-fetched PKCS#11 PIN via a 0600 pin-source file and never on argv" {
  # run_openconnect no longer fetches key_password itself -- that fetch is
  # now centralized in run_admitted_connection's _prepare_pkcs11_pin (review
  # round 6, finding #3), shared with the helper dispatch path (see
  # twophase.bats). This test covers run_openconnect's own half of the
  # contract in isolation: given _VPN_PIN_FILE already staged, it must
  # reference that file via pin-source and never put the PIN itself on argv.
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  local PIN="918273"
  _VPN_PIN_FILE="$BATS_TEST_TMPDIR/staged.pin"
  ( umask 077; printf '%s' "$PIN" > "$_VPN_PIN_FILE" )
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

  run_openconnect
  # argv references the PIN file, but never the PIN value itself
  grep -qF -- "pin-source=file:" "$argv"
  grep -qF -- "pkcs11:manufacturer=piv_II;id=%01" "$argv"
  if grep -qF -- "$PIN" "$argv"; then false; fi
  # the PIN actually lived in a 0600 file (read back inside the stub)
  [ "$(cat "$BATS_TEST_TMPDIR/pincontents")" = "$PIN" ]
  [[ "$(cat "$BATS_TEST_TMPDIR/pinperms")" == -rw------* ]]
}

@test "run_openconnect omits pin-source when _VPN_PIN_FILE is unset (interactive prompt)" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv"
  _VPN_PIN_FILE=""
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat >/dev/null; return 0; fi; return 0; }
  load_profile_fields "PKCS VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=TRUE

  run_openconnect
  grep -qF -- "--certificate=pkcs11:manufacturer=piv_II;id=%01" "$argv"
  if grep -qF -- "pin-source=file:" "$argv"; then false; fi
}

# --- the full phase-4 lifecycle: fetch once, shred once, shared by both modes ---

@test "run_admitted_connection fetches the PKCS#11 PIN once and shreds it once, in prompt mode" {
  _write_profiles
  local argv="$BATS_TEST_TMPDIR/argv" fetches="$BATS_TEST_TMPDIR/fetches"
  : > "$fetches"
  load_profile_fields "PKCS VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE; BACKGROUND=TRUE
  secrets_get() {
    case "$2" in
      key_password) echo "call" >> "$fetches"; echo "918273"; return 0 ;;
      password) echo "s3cret"; return 0 ;;
      *) echo ""; return 0 ;;
    esac
  }
  sudo() { if [ "$1" = openconnect ]; then shift; printf '%s\n' "$@" > "$argv"; cat >/dev/null; return 0; fi; return 0; }

  run_admitted_connection "PKCS VPN" SERVICE
  grep -qF -- "pin-source=file:" "$argv"
  [ "$(wc -l < "$fetches")" -eq 1 ]   # fetched exactly once
  # The PIN file is now a uniquely-named mktemp path (review round 7, finding
  # #1), not a deterministic profile_slug()-based name -- assert no PIN file
  # of any name is left behind in pids/, rather than checking one specific
  # (now-nonexistent-by-construction) path.
  local leftover; leftover="$(find "${DATA_DIR}/pids" -maxdepth 1 -name ".${PROGRAM_NAME}.pin.*" 2>/dev/null)"
  [ -z "$leftover" ]
}

@test "a service with a PKCS#11 certificate and no stored PIN is CONFIG, never prompts" {
  _write_profiles
  load_profile_fields "PKCS VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  # password fetch must succeed cleanly so the PIN check is what's under test
  secrets_get() {
    [ "$2" = password ] && { echo "s3cret"; return 0; }
    echo ""; return 0   # no stored PIN
  }
  run run_admitted_connection "PKCS VPN" SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

# --- a PIN-file write that fails must never be reported as success (review round 7, BLOCKER #1) ---
#
# An earlier version of _prepare_pkcs11_pin wrote the PIN to a fixed,
# deterministic path and never checked whether the write (or the mkdir before
# it) actually succeeded -- reproduced directly by replacing
# ${DATA_DIR}/pids with a plain file, which made `printf ... > "$_VPN_PIN_FILE"`
# fail silently while the function still returned 0 with _VPN_PIN_FILE set to
# a path that was never created. Any failure here must be reported as
# SECRETS_UNAVAILABLE (a service can retry) in SERVICE mode -- never rc=0 with
# a dangling reference to a file that doesn't exist -- and dispatch must never
# be reached.

@test "a PIN-file write failure is SECRETS_UNAVAILABLE, not a false success, and dispatch never runs" {
  _write_profiles
  load_profile_fields "PKCS VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  secrets_get() {
    [ "$2" = password ] && { echo "s3cret"; return 0; }
    echo "918273"; return 0   # PIN IS stored -- the write itself is what fails
  }
  rm -rf "${DATA_DIR}/pids"
  : > "${DATA_DIR}/pids"   # a plain file where the pids DIRECTORY must be -- mkdir/mktemp inside it can't succeed
  local dispatched="$BATS_TEST_TMPDIR/dispatched"
  run_openconnect() { touch "$dispatched"; return 0; }
  connect_via_helper() { touch "$dispatched"; return 0; }

  run run_admitted_connection "PKCS VPN" SERVICE
  [ "$status" -eq "$VPN_RC_SECRETS_UNAVAILABLE" ]
  [ ! -e "$dispatched" ]
  [ -z "${_VPN_PIN_FILE:-}" ]
}

@test "an INTERACTIVE PIN-file write failure falls back to the interactive prompt instead of refusing" {
  # A human is present in INTERACTIVE mode, so a local filesystem hiccup
  # staging the PIN should degrade to openconnect's own interactive PIN
  # prompt (same as "no PIN stored") rather than block the whole connection --
  # only a SERVICE, which has no TTY to fall back to, needs to refuse.
  _write_profiles
  load_profile_fields "PKCS VPN"
  VPN_PASSWD="s3cret"
  SERVER_CERTIFICATE="pin-sha256:abc"
  secrets_get() {
    [ "$2" = password ] && { echo "s3cret"; return 0; }
    echo "918273"; return 0
  }
  rm -rf "${DATA_DIR}/pids"
  : > "${DATA_DIR}/pids"
  sudo() { if [ "$1" = openconnect ]; then shift; cat >/dev/null; return 0; fi; return 0; }

  run run_admitted_connection "PKCS VPN" INTERACTIVE
  [ "$status" -eq 0 ]
  [ -z "${_VPN_PIN_FILE:-}" ]
}

# --- PKCS#11 PIN staging happens before the one-time value, not after (review round 7, HIGH #3) ---
#
# _prepare_pkcs11_pin can call out to Keychain/Secret Service/the vault and do
# filesystem I/O -- none of it instant. An earlier version of
# run_admitted_connection ran it AFTER TOTP generation, so a TOTP code could be
# produced and then sit idle while PIN staging ran, exactly the kind of
# staleness totp_wait_for_fresh_step exists to prevent. Recorded call order
# must show the PIN staged before the TOTP code is generated.

@test "PKCS#11 PIN staging happens before TOTP generation, not after" {
  _write_profiles
  # PKCS VPN has no tokenMode in its fixture XML; force it to totp for this
  # ordering check without needing a second fixture profile.
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>PKCS TOTP VPN</name><protocol>anyconnect</protocol><host>p.example.com</host><authGroup></authGroup><user>bob</user><password></password><duo2FAMethod></duo2FAMethod><serverCertificate></serverCertificate><authMode>password</authMode><tokenMode>totp</tokenMode><extraArgs></extraArgs><clientCertificate>pkcs11:manufacturer=piv_II;id=%01</clientCertificate></VPN>
</VPNs>
XML
  load_profile_fields "PKCS TOTP VPN"
  VPN_PASSWD=""
  SERVER_CERTIFICATE="pin-sha256:abc"
  local order="$BATS_TEST_TMPDIR/order"
  secrets_get() {
    case "$2" in
      key_password) echo "918273"; return 0 ;;
      password) echo "s3cret"; return 0 ;;
      token_secret) echo "JBSWY3DPEHPK3PXP"; return 0 ;;
      *) echo ""; return 0 ;;
    esac
  }
  # totp_wait_for_fresh_step isn't stubbed for its own logic -- it's the probe
  # point: at the moment TOTP reservation begins, has the PKCS#11 PIN already
  # been staged to disk? If PIN staging still ran AFTER TOTP/Duo entry (the
  # pre-fix order), no PIN file would exist yet when this runs.
  totp_wait_for_fresh_step() {
    local pinfile; pinfile="$(find "${DATA_DIR}/pids" -maxdepth 1 -name ".${PROGRAM_NAME}.pin.*" 2>/dev/null)"
    if [ -n "$pinfile" ]; then echo "staged-before-totp" > "$order"; else echo "NOT-staged-before-totp" > "$order"; fi
    return 0
  }
  generate_totp() { echo "123456"; }
  run_openconnect() { return 0; }

  run_admitted_connection "PKCS TOTP VPN" SERVICE
  [ "$(cat "$order")" = "staged-before-totp" ]
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

# --- _append_pkcs11_pin_source (pure URI builder) ---

@test "_append_pkcs11_pin_source returns non-pkcs11 URIs and file paths unchanged" {
  run _append_pkcs11_pin_source "/etc/vpn/me.key" "/run/pin"
  [ "$status" -eq 0 ]
  [ "$output" = "/etc/vpn/me.key" ]
}

@test "_append_pkcs11_pin_source appends pin-source with '?' when the URI has no query" {
  run _append_pkcs11_pin_source "pkcs11:manufacturer=piv_II;id=%01" "/run/pin"
  [ "$status" -eq 0 ]
  [ "$output" = "pkcs11:manufacturer=piv_II;id=%01?pin-source=file:/run/pin" ]
}

@test "_append_pkcs11_pin_source appends pin-source with '&' when the URI already has a query" {
  run _append_pkcs11_pin_source "pkcs11:id=%01?type=cert" "/run/pin"
  [ "$status" -eq 0 ]
  [ "$output" = "pkcs11:id=%01?type=cert&pin-source=file:/run/pin" ]
}
