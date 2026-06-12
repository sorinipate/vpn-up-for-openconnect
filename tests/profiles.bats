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
