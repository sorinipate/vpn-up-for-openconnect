# profiles.sh - load and validate VPN profiles (robust tag support)

# Render arbitrary text as an XPath string literal (single quotes need
# concat() since XPath 1.0 has no escaping).
xpath_literal() {
  local s="$1"
  if [[ "$s" != *\'* ]]; then
    printf "'%s'" "$s"
    return
  fi
  local rep="', \"'\", '"
  printf "concat('%s')" "${s//\'/${rep}}"
}

# Verify the profiles file is well-formed XML. A missing file is treated as OK
# (first-run handling and check_file_existence deal with absence separately). On
# malformed XML, print ONE clear message — never the raw libxml2 parser noise —
# and return 1, so callers can bail gracefully instead of leaking errors or
# misreading the file as "no profiles". Reused by every command that reads it.
profiles_xml_ok() {
  [ -f "$PROFILES_FILE" ] || return 0
  if ! xmlstarlet val "$PROFILES_FILE" >/dev/null 2>&1; then
    print_danger "Your profiles file isn't valid XML, so it can't be read: %s\n" "$PROFILES_FILE"
    print_warning "Edit it to fix the XML (a common cause is an XML comment containing a double hyphen), or recreate a profile with '%s add-profile'.\n" "${DISPLAY_NAME}"
    return 1
  fi
  return 0
}

# shellcheck disable=SC2034  # fields are consumed by core.sh
load_profile_fields() {
  local selection="$1"
  local name_lit; name_lit="$(xpath_literal "$selection")"
  # Extract fields using xmlstarlet; accept legacy/new tag variants.
  # mapfile (not `read` with IFS) because read collapses consecutive
  # newlines — an empty field (e.g. a blanked <password>) would shift
  # every following field up one position.
  local fields=()
  mapfile -t fields < <(
    xmlstarlet sel -t \
      -m "//VPN[name=${name_lit}]" \
      -v "name" -n \
      -v "protocol" -n \
      -v "host" -n \
      -v "group | authGroup" -n \
      -v "username | user" -n \
      -v "password" -n \
      -v "duo2FAMethod | duoMethod" -n \
      -v "serverCertificate" -n \
      -v "authMode | authmode" -n \
      -v "tokenMode | tokenmode" -n \
      -v "extraArgs | extraargs" -n \
      -v "clientCertificate | clientcertificate" -n \
      -v "clientKey | clientkey" -n \
      -v "proxy | proxyUrl" -n "${PROFILES_FILE}"
  )
  VPN_NAME="${fields[0]:-}"
  PROTOCOL="${fields[1]:-}"
  VPN_HOST="${fields[2]:-}"
  VPN_GROUP="${fields[3]:-}"
  VPN_USER="${fields[4]:-}"
  VPN_PASSWD="${fields[5]:-}"
  VPN_DUO2FAMETHOD="${fields[6]:-}"
  SERVER_CERTIFICATE="${fields[7]:-}"
  # Authentication mode: 'sso' (browser-based SAML/SSO) or 'password' (default).
  VPN_AUTH_MODE="$(printf '%s' "${fields[8]:-password}" | tr '[:upper:]' '[:lower:]')"
  if [ -z "$VPN_AUTH_MODE" ]; then VPN_AUTH_MODE=password; fi
  # Software-token 2FA: 'totp' generates the one-time code from a stored seed.
  VPN_TOKEN_MODE="$(printf '%s' "${fields[9]:-}" | tr '[:upper:]' '[:lower:]')"
  # Advanced: extra openconnect arguments passed verbatim (tokenized at connect).
  VPN_EXTRA_ARGS="${fields[10]:-}"
  # Client-certificate auth: a file path or a PKCS#11 URI (pkcs11:...) for a
  # smartcard/YubiKey-PIV. The optional key may be a separate file/URI. These are
  # identifiers, not secrets; any passphrase/PIN lives in the secrets backend.
  VPN_CLIENT_CERT="${fields[11]:-}"
  VPN_CLIENT_KEY="${fields[12]:-}"
  # Optional HTTP/SOCKS proxy URL (e.g. http://proxy:8080, socks5://127.0.0.1:1080)
  # passed to openconnect. An identifier, not a secret — avoid embedding credentials.
  VPN_PROXY="${fields[13]:-}"

  # Intentionally NOT exported: these are read only by functions in this
  # shell, and exporting would copy the password into the environment of
  # every child process (curl, ping, awk, ...).
}

# Blank the <password> element for a profile so plaintext doesn't linger in
# the XML after migration to the secrets backend.
scrub_profile_password() {
  local name="$1"
  local name_lit; name_lit="$(xpath_literal "$name")"
  local tmp="${PROFILES_FILE}.tmp"
  if xmlstarlet ed -u "//VPN[name=${name_lit}]/password" -v '' "${PROFILES_FILE}" > "${tmp}" 2>/dev/null; then
    mv "${tmp}" "${PROFILES_FILE}"
    chmod 600 "${PROFILES_FILE}" 2>/dev/null || true
    print_warning "Removed plaintext password for '%s' from %s ...\n" "${name}" "${PROFILES_FILE}"
  else
    rm -f "${tmp}"
    print_danger "Could not remove plaintext password from %s; please blank the <password> tag manually.\n" "${PROFILES_FILE}"
  fi
}

migrate_or_fetch_password() {
  # prefer stored secret; migrate plaintext if found
  local s; s="$(secrets_get "${VPN_NAME}" "password")"
  if [ -z "$s" ] && [ -n "$VPN_PASSWD" ]; then
    print_warning "Migrating plaintext password for '%s' to secure storage...\n" "${VPN_NAME}"
    secrets_set "${VPN_NAME}" "password" "${VPN_PASSWD}"
    s="${VPN_PASSWD}"
    scrub_profile_password "${VPN_NAME}"
  fi
  if [ -z "$s" ] && [ -n "${VPN_CLIENT_CERT:-}" ]; then
    # Cert-only auth: the client certificate stands in for the password. Don't
    # force a prompt or fail; a password is used only if one is actually stored
    # (cert + password gateways).
    VPN_PASSWD=""
    return 0
  fi
  if [ -z "$s" ]; then
    if [ -n "${VPN_UP_SERVICE:-}" ]; then
      print_danger "No stored password for '%s' and service mode cannot prompt. Store one first: %s set-secret '%s' password\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
      return 1
    fi
    read -r -s -p "Enter password for ${VPN_USER}@${VPN_HOST}: " s; echo
    secrets_set "${VPN_NAME}" "password" "${s}"
  fi
  VPN_PASSWD="$s"
}

list_profile_names() {
  profiles_xml_ok || return 1
  IFS=$'\n' read -d '' -r -a vpn_names < <(xmlstarlet sel -t -m "//VPN" -v "name" -n "$PROFILES_FILE" 2>/dev/null)
  vpn_names+=("Quit")
  printf "%s\n" "${vpn_names[@]}"
}

# Bare profile names, one per line (machine-readable; used by completion).
profile_names_raw() {
  [ -f "$PROFILES_FILE" ] || return 0
  xmlstarlet sel -t -m '//VPN' -v name -n "$PROFILES_FILE" 2>/dev/null
}

profile_exists() {
  local name_lit; name_lit="$(xpath_literal "$1")"
  [ -n "$(xmlstarlet sel -t -m "//VPN[name=${name_lit}]" -v name "$PROFILES_FILE" 2>/dev/null)" ]
}

# Tabular overview of all profiles (no secrets shown).
list_profiles() {
  check_file_existence "$PROFILES_FILE" "Profiles"
  profiles_xml_ok || return 1
  xmlstarlet sel -t -m '//VPN' \
      -v name -o $'\t' \
      -v protocol -o $'\t' \
      -v host -o $'\t' \
      -v 'duo2FAMethod | duoMethod' -o $'\t' \
      -v 'authMode | authmode' -o $'\t' \
      -v 'tokenMode | tokenmode' -n "$PROFILES_FILE" \
    | awk -F'\t' '
        BEGIN { printf "%-25s %-11s %-35s %-9s %s\n", "NAME", "PROTOCOL", "HOST", "2FA", "AUTH" }
        { twofa = ($6!="" ? $6 : ($4=="" ? "-" : $4));
          printf "%-25s %-11s %-35s %-9s %s\n", $1, ($2==""?"-":$2), ($3==""?"-":$3), twofa, ($5==""?"password":$5) }'
}

# shellcheck disable=SC2034  # description vars are consumed by core.sh
set_protocol_description() {
  case $PROTOCOL in
    anyconnect) PROTOCOL_DESCRIPTION="Cisco AnyConnect" ;;
    nc)         PROTOCOL_DESCRIPTION="Juniper Network Connect" ;;
    gp)         PROTOCOL_DESCRIPTION="Palo Alto GlobalProtect" ;;
    pulse)      PROTOCOL_DESCRIPTION="Pulse Secure" ;;
    *)          PROTOCOL_DESCRIPTION="Unknown" ;;
  esac
}

# shellcheck disable=SC2034  # description vars are consumed by core.sh
set_2fa_method_description() {
  case $VPN_DUO2FAMETHOD in
    push)  VPN_DUO2FAMETHOD_DESCRIPTION="PUSH" ;;
    phone) VPN_DUO2FAMETHOD_DESCRIPTION="PHONE" ;;
    sms)   VPN_DUO2FAMETHOD_DESCRIPTION="SMS" ;;
    "")    VPN_DUO2FAMETHOD_DESCRIPTION="NONE" ;;
    *)     if [[ "$VPN_DUO2FAMETHOD" =~ ^[0-9]{6}$ ]]; then
             VPN_DUO2FAMETHOD_DESCRIPTION="PASSCODE"
           else
             VPN_DUO2FAMETHOD_DESCRIPTION="CUSTOM"
           fi ;;
  esac
}