#!/usr/bin/env bats
# Tests for pin_save (network calls stubbed).

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>With Cert</name><protocol>anyconnect</protocol><host>a.example.com</host><serverCertificate>old-pin</serverCertificate></VPN>
  <VPN><name>Without Cert</name><protocol>gp</protocol><host>b.example.com</host></VPN>
  <VPN><name>No Host</name><protocol>gp</protocol><host></host></VPN>
</VPNs>
XML
  print_warning() { :; }
  print_danger() { :; }
  print_primary() { :; }
  print_success() { :; }
  check_file_existence() { :; }
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../network.sh"
  # stub the network
  fetch_server_pin() { echo "pin-sha256:STUBBED="; }
  verify_gateway_cert() { return 0; }
}

@test "pin_save updates an existing serverCertificate element" {
  pin_save "With Cert"
  run xmlstarlet sel -t -m "//VPN[name='With Cert']" -v serverCertificate "$PROFILES_FILE"
  [ "$output" = "pin-sha256:STUBBED=" ]
}

@test "pin_save creates serverCertificate when missing" {
  pin_save "Without Cert"
  run xmlstarlet sel -t -m "//VPN[name='Without Cert']" -v serverCertificate "$PROFILES_FILE"
  [ "$output" = "pin-sha256:STUBBED=" ]
}

@test "pin_save leaves other profiles untouched" {
  pin_save "Without Cert"
  run xmlstarlet sel -t -m "//VPN[name='With Cert']" -v serverCertificate "$PROFILES_FILE"
  [ "$output" = "old-pin" ]
}

@test "pin_save fails on unknown profile and on missing host" {
  run pin_save "Ghost"
  [ "$status" -ne 0 ]
  run pin_save "No Host"
  [ "$status" -ne 0 ]
}

@test "_host_only and _port_only split host:port with a 443 default" {
  [ "$(_host_only "vpn.example.com")" = "vpn.example.com" ]
  [ "$(_port_only "vpn.example.com")" = "443" ]
  [ "$(_host_only "vpn.example.com:8443")" = "vpn.example.com" ]
  [ "$(_port_only "vpn.example.com:8443")" = "8443" ]
}
