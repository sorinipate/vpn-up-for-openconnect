#!/usr/bin/env bats
# Tests for profile parsing, XPath escaping, and password scrubbing.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Test's VPN</name><protocol>anyconnect</protocol><host>h.example.com</host><authGroup>G1</authGroup><user>u1</user><password>sekrit</password><duo2FAMethod>push</duo2FAMethod><serverCertificate>pin-sha256:abc</serverCertificate></VPN>
  <VPN><name>Other VPN</name><protocol>gp</protocol><host>g.example.com</host><authGroup/><user>u2</user><password>keepme</password><duo2FAMethod/><serverCertificate/></VPN>
</VPNs>
XML
  print_warning() { :; }
  print_danger() { :; }
  source "$BATS_TEST_DIRNAME/../profiles.sh"
}

@test "xpath_literal: plain names quoted, quotes handled via concat" {
  [ "$(xpath_literal "Plain VPN")" = "'Plain VPN'" ]
  [ "$(xpath_literal "Test's VPN")" = "concat('Test', \"'\", 's VPN')" ]
}

@test "load_profile_fields: extracts all fields for quoted name" {
  load_profile_fields "Test's VPN"
  [ "$VPN_NAME" = "Test's VPN" ]
  [ "$PROTOCOL" = "anyconnect" ]
  [ "$VPN_HOST" = "h.example.com" ]
  [ "$VPN_GROUP" = "G1" ]
  [ "$VPN_USER" = "u1" ]
  [ "$VPN_PASSWD" = "sekrit" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
  [ "$SERVER_CERTIFICATE" = "pin-sha256:abc" ]
}

@test "load_profile_fields: empty fields do not shift later fields" {
  # Regression: `read` with IFS collapsed consecutive newlines, so an empty
  # <password> shifted the Duo method into VPN_PASSWD (and it then got
  # migrated into the keychain as the "password").
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Blanked</name><protocol>anyconnect</protocol><host>h.example.com</host><authGroup/><user>u1</user><password></password><duo2FAMethod>push</duo2FAMethod><serverCertificate>pin-sha256:abc</serverCertificate></VPN>
</VPNs>
XML
  load_profile_fields "Blanked"
  [ "$VPN_GROUP" = "" ]
  [ "$VPN_PASSWD" = "" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
  [ "$SERVER_CERTIFICATE" = "pin-sha256:abc" ]
}

@test "scrub_profile_password: blanks only the targeted profile" {
  scrub_profile_password "Test's VPN"
  run xmlstarlet sel -t -m "//VPN[name='Other VPN']" -v password "$PROFILES_FILE"
  [ "$output" = "keepme" ]
  run xmlstarlet sel -t -m "//VPN[name=$(xpath_literal "Test's VPN")]" -v password "$PROFILES_FILE"
  [ -z "$output" ]
}

@test "list_profile_names includes all profiles plus Quit" {
  run list_profile_names
  [ "${lines[0]}" = "Test's VPN" ]
  [ "${lines[1]}" = "Other VPN" ]
  [ "${lines[2]}" = "Quit" ]
}

@test "profile_exists: true for real profiles (incl. quotes), false otherwise" {
  profile_exists "Test's VPN"
  profile_exists "Other VPN"
  run profile_exists "Ghost VPN"
  [ "$status" -ne 0 ]
}

@test "profile_names_raw lists bare names without Quit" {
  run profile_names_raw
  [ "${lines[0]}" = "Test's VPN" ]
  [ "${lines[1]}" = "Other VPN" ]
  [ "${#lines[@]}" -eq 2 ]
}

@test "append_profile adds a well-formed selectable profile" {
  print_success() { :; }
  _bool_default() { echo FALSE; }
  source "$BATS_TEST_DIRNAME/../setup.sh"
  append_profile "Berlin VPN" gp "berlin.example.com:8443" Staff sorin push
  xmlstarlet val -q "$PROFILES_FILE"
  profile_exists "Berlin VPN"
  load_profile_fields "Berlin VPN"
  [ "$PROTOCOL" = "gp" ]
  [ "$VPN_HOST" = "berlin.example.com:8443" ]
  [ "$VPN_GROUP" = "Staff" ]
  [ "$VPN_USER" = "sorin" ]
  [ "$VPN_PASSWD" = "" ]
  [ "$VPN_DUO2FAMETHOD" = "push" ]
}

@test "profile_slug produces filesystem-safe names" {
  source "$BATS_TEST_DIRNAME/../logging.sh"
  [ "$(profile_slug "Frankfurt VPN")" = "Frankfurt_VPN" ]
  [ "$(profile_slug "a/b:c d")" = "a_b_c_d" ]
  [ "$(profile_slug "safe-name_1.2")" = "safe-name_1.2" ]
}

@test "list_profiles prints a header and one row per profile" {
  check_file_existence() { :; }
  run list_profiles
  [[ "${lines[0]}" == NAME* ]]
  [[ "${lines[1]}" == "Test's VPN"* ]]
  [[ "${lines[2]}" == "Other VPN"* ]]
  [ "${#lines[@]}" -eq 3 ]
}
