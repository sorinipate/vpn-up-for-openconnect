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

# --------------------------------------- fetch_server_pin: the REAL function
#
# Every other test in this file stubs fetch_server_pin, which is exactly how
# a real review finding went unnoticed: an unreachable gateway used to make
# the s_client/x509/pkey/dgst pipeline hash EMPTY input and produce a
# perfectly plausible-looking (and entirely bogus) pin -- SHA-256 of the
# empty string. These call the real thing.

@test "fetch_server_pin fails (does not return a bogus pin) against an unreachable port" {
  # setup() stubs fetch_server_pin for the pin_save tests above -- undo that
  # here to exercise the real implementation.
  source "$BATS_TEST_DIRNAME/../network.sh"
  run fetch_server_pin "127.0.0.1:1"
  [ "$status" -ne 0 ]
  [ -z "$output" ]
  # the specific bogus value a broken implementation produces: SHA-256 of
  # the empty string, base64-encoded -- must never appear here.
  [[ "$output" != *"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="* ]]
}

@test "gateway_tls_reachable is false against an unreachable port" {
  run gateway_tls_reachable "127.0.0.1:1"
  [ "$status" -ne 0 ]
}

@test "fetch_server_pin fails cleanly if SPKI/DER extraction fails after a valid certificate" {
  # Regression test: a valid certificate was obtained (the earlier fix's own
  # check passes), but the pubkey->DER conversion stage itself then fails --
  # the pre-fix pipeline would still feed that empty output into `dgst` and
  # produce the same bogus SHA-256(empty) pin the cert-existence check was
  # added to rule out, just one stage later.
  source "$BATS_TEST_DIRNAME/../network.sh"
  openssl() {
    case "$1" in
      s_client) printf -- '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n' ;;
      x509)
        case "$*" in
          *-pubkey*) printf -- '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n' ;;
          *) return 0 ;;   # -noout validity check
        esac ;;
      pkey) return 1 ;;   # the extraction stage that fails
      dgst) echo "SHOULD NOT BE REACHED" ;;
    esac
  }
  run fetch_server_pin "gw.example.test:443"
  [ "$status" -ne 0 ]
  [ -z "$output" ]
  [[ "$output" != *"SHOULD NOT BE REACHED"* ]]
  # no leaked temp file from the DER extraction stage
  [ -z "$(ls "${TMPDIR:-/tmp}"/vpn-up-pin.* 2>/dev/null)" ]
}

@test "verify_gateway_cert asks openssl to verify the hostname for a DNS gateway" {
  source "$BATS_TEST_DIRNAME/../network.sh"
  local argsfile="$BATS_TEST_TMPDIR/openssl-args"
  openssl() { printf '%s\n' "$*" >> "$argsfile"; return 0; }
  verify_gateway_cert "vpn.example.com:443"
  grep -q -- '-verify_hostname vpn.example.com' "$argsfile"
  ! grep -q -- '-verify_ip' "$argsfile"
}

@test "verify_gateway_cert asks openssl to verify the IP for an IP-literal gateway" {
  source "$BATS_TEST_DIRNAME/../network.sh"
  local argsfile="$BATS_TEST_TMPDIR/openssl-args"
  openssl() { printf '%s\n' "$*" >> "$argsfile"; return 0; }
  verify_gateway_cert "203.0.113.5:443"
  grep -q -- '-verify_ip 203.0.113.5' "$argsfile"
  ! grep -q -- '-verify_hostname' "$argsfile"
}
