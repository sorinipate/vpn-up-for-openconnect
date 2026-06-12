# network.sh - gateway certificate helpers

_host_only() { printf '%s' "${1%%:*}"; }
_port_only() { local hp="$1"; case "$hp" in *:*) printf '%s' "${hp##*:}" ;; *) printf '443' ;; esac; }

# Compute the RFC 7469 public-key pin (pin-sha256:...) for a gateway.
fetch_server_pin() {
  local host port
  host="$(_host_only "$1")"; port="$(_port_only "$1")"
  local pin
  pin="$(openssl s_client -connect "${host}:${port}" -servername "${host}" </dev/null 2>/dev/null \
    | openssl x509 -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | base64)"
  [ -n "$pin" ] || return 1
  printf 'pin-sha256:%s\n' "$pin"
}

# True if the gateway's certificate chain validates against the system trust
# store. Used to fail closed when no pin is configured.
verify_gateway_cert() {
  local host port
  host="$(_host_only "$1")"; port="$(_port_only "$1")"
  openssl s_client -connect "${host}:${port}" -servername "${host}" -verify_return_error \
    </dev/null >/dev/null 2>&1
}

print_pin_instructions() {
  local host="$1"
  print_warning "To pin this gateway's certificate, run:\n"
  print_warning "  %s pin %s\n" "${PROGRAM_NAME}" "${host}"
  print_warning "then put the printed pin-sha256:... value in <serverCertificate> for this profile.\n"
  print_warning "Only do this if you have verified the certificate is the gateway's real one.\n"
}
