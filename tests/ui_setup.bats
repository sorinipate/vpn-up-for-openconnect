#!/usr/bin/env bats
# Tests for ui.sh (banner/notify gating) and setup.sh (bool parsing, config template).

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR"
  export CONFIGURATION_FILE="$DATA_DIR/${PROGRAM_NAME}.config"
  print_warning() { :; }; print_danger() { :; }; print_success() { :; }; print_primary() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../ui.sh"
  source "$BATS_TEST_DIRNAME/../setup.sh"
}

# --- notify ---

_stub_notifiers() {
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  for tool in osascript notify-send; do
    cat > "$BATS_TEST_TMPDIR/bin/$tool" <<EOF
#!/bin/sh
echo "\$@" >> "$BATS_TEST_TMPDIR/notify-out"
EOF
    chmod 755 "$BATS_TEST_TMPDIR/bin/$tool"
  done
  PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "notify fires when NOTIFICATIONS=TRUE (default) and is silent when FALSE" {
  _stub_notifiers
  NOTIFICATIONS=TRUE notify "Title" "Message"
  [ -f "$BATS_TEST_TMPDIR/notify-out" ]
  grep -q "Message" "$BATS_TEST_TMPDIR/notify-out"
  rm -f "$BATS_TEST_TMPDIR/notify-out"
  NOTIFICATIONS=FALSE notify "Title" "Message"
  [ ! -f "$BATS_TEST_TMPDIR/notify-out" ]
}

@test "show_banner is silent and successful when stdout is not a tty" {
  SHOW_BANNER=TRUE
  out="$(show_banner)"
  [ -z "$out" ]
}

# --- _bool_default ---

@test "_bool_default normalizes truthy/falsy inputs and applies defaults" {
  [ "$(_bool_default "true" FALSE)" = "TRUE" ]
  [ "$(_bool_default "Y" FALSE)" = "TRUE" ]
  [ "$(_bool_default "1" FALSE)" = "TRUE" ]
  [ "$(_bool_default "no" TRUE)" = "FALSE" ]
  [ "$(_bool_default "F" TRUE)" = "FALSE" ]
  [ "$(_bool_default "0" TRUE)" = "FALSE" ]
  [ "$(_bool_default "" TRUE)" = "TRUE" ]
  [ "$(_bool_default "garbage" FALSE)" = "FALSE" ]
}

# --- save_configuration ---

@test "save_configuration writes all wizard values with 600 perms" {
  __WZ_BACKGROUND=FALSE __WZ_QUIET=TRUE __WZ_SHOW_BANNER=FALSE __WZ_NOTIFICATIONS=TRUE
  save_configuration
  [ "$(file_mode "$CONFIGURATION_FILE")" = "600" ]
  grep -q '^readonly BACKGROUND=FALSE$' "$CONFIGURATION_FILE"
  grep -q '^readonly QUIET=TRUE$' "$CONFIGURATION_FILE"
  grep -q '^readonly SHOW_BANNER=FALSE$' "$CONFIGURATION_FILE"
  grep -q '^readonly NOTIFICATIONS=TRUE$' "$CONFIGURATION_FILE"
  # no template placeholders left behind
  if grep -q '__' "$CONFIGURATION_FILE"; then false; fi
}

# --- add_profile_wizard: PKCS#11 PIN offer (review round 7, finding #4) ---
#
# Checking only the certificate for a pkcs11: URI (an earlier version of this
# wizard) missed the equally valid, documented case of a file-path
# certificate paired with a PKCS#11 private key: it printed the
# "passphrase-protected" warning for a profile that actually needed a stored
# PIN, and never offered to store one. _pkcs11_pin_needed (core.sh) checks
# both the certificate and the key.

_wizard_stubs() {
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
  export PROFILES_FILE="$BATS_TEST_TMPDIR/profiles.xml"
  profiles_xml_ok() { return 0; }
  profile_exists() { return 1; }
  append_profile() { return 0; }
  pin_save() { return 0; }
  SECRETS_SET_CALLS="$BATS_TEST_TMPDIR/secrets_set-calls"; : > "$SECRETS_SET_CALLS"
  secrets_set() { printf '%s\n' "$2" >> "$SECRETS_SET_CALLS"; return 0; }
  WARNINGS="$BATS_TEST_TMPDIR/warnings"; : > "$WARNINGS"
  print_warning() { printf -- "$1" "${@:2}" >> "$WARNINGS"; }
  DANGERS="$BATS_TEST_TMPDIR/dangers"; : > "$DANGERS"
  print_danger() { printf -- "$1" "${@:2}" >> "$DANGERS"; }
  print_success() { :; }
}

@test "add_profile_wizard offers and stores a PKCS#11 PIN for a file certificate paired with a pkcs11: key" {
  _wizard_stubs
  add_profile_wizard <<'EOF'
FileKeyPKCS11
anyconnect
h.example.com

user
n
n
/tmp/cert.pem
pkcs11:id=%02
y
1234


n
n
EOF
  grep -qF "key_password" "$SECRETS_SET_CALLS"
  if grep -qF "passphrase-protected" "$WARNINGS"; then false; fi
}

@test "add_profile_wizard refuses a client certificate URI that embeds a PIN directly" {
  # Reproduced directly against this codebase before this fix: a profile
  # created with clientCertificate="pkcs11:id=%01?pin-value=918273" stored
  # the PIN in the clear in profiles.xml (review round 9, BLOCKER #1). The
  # wizard must refuse this rather than silently accepting it, so a profile
  # can never be CREATED this way in the first place -- clearing both cert
  # and key fields, same as if neither had been entered.
  _wizard_stubs
  APPENDED_CERT="$BATS_TEST_TMPDIR/appended-cert"; : > "$APPENDED_CERT"
  APPENDED_KEY="$BATS_TEST_TMPDIR/appended-key"; : > "$APPENDED_KEY"
  append_profile() { printf '%s' "${10}" > "$APPENDED_CERT"; printf '%s' "${11}" > "$APPENDED_KEY"; return 0; }
  add_profile_wizard <<'EOF'
LeakyPin
anyconnect
h.example.com

user
n
n
pkcs11:id=%01?pin-value=918273



n
n
EOF
  [[ "$(cat "$DANGERS")" == *"pin-value"* || "$(cat "$DANGERS")" == *"PIN"* ]]
  [ -z "$(cat "$APPENDED_CERT")" ]
  [ -z "$(cat "$APPENDED_KEY")" ]
  if grep -qF "918273" "$APPENDED_CERT" "$APPENDED_KEY" "$SECRETS_SET_CALLS"; then false; fi
}

# --- add_profile_wizard: SSO protocol gate (protocol_supports_sso, profiles.sh) ---
#
# nc and pulse both use password/Duo flows per docs/protocols.md; only
# anyconnect and gp support browser SSO. Was two independent denylists
# (setup.sh, core.sh) naming only 'nc' -- pulse silently passed both, and
# neither had wizard-level test coverage at all.

@test "add_profile_wizard refuses SSO for the nc protocol" {
  _wizard_stubs
  run add_profile_wizard <<'EOF'
NcSso
nc
h.example.com

user
y
EOF
  [ "$status" -ne 0 ]
  grep -qF "not supported for the 'nc' protocol" "$DANGERS"
}

@test "add_profile_wizard refuses SSO for the pulse protocol" {
  _wizard_stubs
  run add_profile_wizard <<'EOF'
PulseSso
pulse
h.example.com

user
y
EOF
  [ "$status" -ne 0 ]
  grep -qF "not supported for the 'pulse' protocol" "$DANGERS"
}

@test "add_profile_wizard does not offer a PKCS#11 PIN for a plain file certificate and key" {
  _wizard_stubs
  add_profile_wizard <<'EOF'
FileKeyOnly
anyconnect
h.example.com

user
n
n
/tmp/cert.pem
/tmp/cert.key


n
n
EOF
  if grep -qF "key_password" "$SECRETS_SET_CALLS"; then false; fi
  grep -qF "passphrase-protected" "$WARNINGS"
}

# --- add_profile_wizard: advanced TOTP options (algorithm/digits/time step) ---

@test "add_profile_wizard offers advanced TOTP options behind an opt-in gate and passes them to append_profile" {
  command -v oathtool >/dev/null 2>&1 || skip "oathtool not installed"
  _wizard_stubs
  APPENDED_TOTP="$BATS_TEST_TMPDIR/appended-totp"
  append_profile() { printf '%s %s %s\n' "${13}" "${14}" "${15}" > "$APPENDED_TOTP"; return 0; }
  add_profile_wizard <<'EOF'
TotpAdvanced
anyconnect
h.example.com

user
n
t
JBSWY3DPEHPK3PXP
y
sha256
8
60



n
n
EOF
  grep -qF "token_secret" "$SECRETS_SET_CALLS"
  [ "$(cat "$APPENDED_TOTP")" = "SHA256 8 60" ]
}

@test "add_profile_wizard leaves TOTP algorithm/digits/step blank when the advanced gate is declined" {
  command -v oathtool >/dev/null 2>&1 || skip "oathtool not installed"
  _wizard_stubs
  APPENDED_TOTP="$BATS_TEST_TMPDIR/appended-totp"
  append_profile() { printf '%s %s %s\n' "${13}" "${14}" "${15}" > "$APPENDED_TOTP"; return 0; }
  add_profile_wizard <<'EOF'
TotpDefault
anyconnect
h.example.com

user
n
t
JBSWY3DPEHPK3PXP
n



n
n
EOF
  grep -qF "token_secret" "$SECRETS_SET_CALLS"
  [ "$(cat "$APPENDED_TOTP")" = "  " ]
}
