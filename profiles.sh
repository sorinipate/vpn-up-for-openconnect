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

load_profile_fields() {
  local selection="$1"
  local name_lit; name_lit="$(xpath_literal "$selection")"
  # Extract fields using xmlstarlet; accept legacy/new tag variants.
  # `read -d ''` exits non-zero at EOF even after populating every field,
  # so don't let that status leak to callers.
  # shellcheck disable=SC2034  # fields are consumed by core.sh
  IFS=$'\n' read -r -d '' \
    VPN_NAME \
    PROTOCOL \
    VPN_HOST \
    VPN_GROUP \
    VPN_USER \
    VPN_PASSWD \
    VPN_DUO2FAMETHOD \
    SERVER_CERTIFICATE < <(
      xmlstarlet sel -t \
        -m "//VPN[name=${name_lit}]" \
        -v "name" -o $'\n' \
        -v "protocol" -o $'\n' \
        -v "host" -o $'\n' \
        -v "group | authGroup" -o $'\n' \
        -v "username | user" -o $'\n' \
        -v "password" -o $'\n' \
        -v "duo2FAMethod | duoMethod" -o $'\n' \
        -v "serverCertificate" -n "${PROFILES_FILE}"
    ) || true

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
  if [ -z "$s" ]; then
    read -r -s -p "Enter password for ${VPN_USER}@${VPN_HOST}: " s; echo
    secrets_set "${VPN_NAME}" "password" "${s}"
  fi
  VPN_PASSWD="$s"
}

list_profile_names() {
  IFS=$'\n' read -d '' -r -a vpn_names < <(xmlstarlet sel -t -m "//VPN" -v "name" -n "$PROFILES_FILE")
  vpn_names+=("Quit")
  printf "%s\n" "${vpn_names[@]}"
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