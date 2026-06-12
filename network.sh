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

# Fetch a profile's gateway pin and write it into <serverCertificate>.
pin_save() {
  local profile="$1"
  check_file_existence "$PROFILES_FILE" "Profiles"
  if ! profile_exists "$profile"; then
    print_danger "Unknown profile '%s'.\n" "$profile"
    return 1
  fi
  local name_lit; name_lit="$(xpath_literal "$profile")"
  local host; host="$(xmlstarlet sel -t -m "//VPN[name=${name_lit}]" -v host "${PROFILES_FILE}")"
  if [ -z "$host" ]; then
    print_danger "Profile '%s' has no <host> configured.\n" "$profile"
    return 1
  fi
  local pin
  if ! pin="$(fetch_server_pin "$host")"; then
    print_danger "Could not retrieve certificate from %s\n" "$host"
    return 1
  fi
  local tmp="${PROFILES_FILE}.tmp"
  if [ -n "$(xmlstarlet sel -t -m "//VPN[name=${name_lit}]/serverCertificate" -o yes "${PROFILES_FILE}" 2>/dev/null)" ]; then
    xmlstarlet ed -u "//VPN[name=${name_lit}]/serverCertificate" -v "$pin" "${PROFILES_FILE}" > "${tmp}"
  else
    xmlstarlet ed -s "//VPN[name=${name_lit}]" -t elem -n serverCertificate -v "$pin" "${PROFILES_FILE}" > "${tmp}"
  fi
  mv "${tmp}" "${PROFILES_FILE}"
  chmod 600 "${PROFILES_FILE}" 2>/dev/null || true
  print_success "Saved %s to profile '%s'.\n" "$pin" "$profile"
  if verify_gateway_cert "$host"; then
    print_primary "Certificate also validates against the system trust store.\n"
  else
    print_warning "Certificate does NOT chain-validate; verify this pin out-of-band with your VPN administrator.\n"
  fi
}

print_pin_instructions() {
  local host="$1"
  print_warning "To pin this gateway's certificate, run:\n"
  print_warning "  %s pin %s\n" "${DISPLAY_NAME}" "${host}"
  print_warning "then put the printed pin-sha256:... value in <serverCertificate> for this profile.\n"
  print_warning "Only do this if you have verified the certificate is the gateway's real one.\n"
}
