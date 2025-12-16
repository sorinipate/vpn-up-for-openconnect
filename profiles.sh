# profiles.sh - load and validate VPN profiles (robust tag support)

load_profile_fields() {
  local selection="$1"
  # Extract fields using xmlstarlet; accept legacy/new tag variants
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
        -m "//VPN[name='${selection}']" \
        -v "name" -o $'\n' \
        -v "protocol" -o $'\n' \
        -v "host" -o $'\n' \
        -v "group | authGroup" -o $'\n' \
        -v "username | user" -o $'\n' \
        -v "password" -o $'\n' \
        -v "duo2FAMethod | duoMethod" -o $'\n' \
        -v "serverCertificate" -n "${PROFILES_FILE}"
    )

  export VPN_NAME PROTOCOL VPN_HOST VPN_GROUP VPN_USER VPN_PASSWD VPN_DUO2FAMETHOD SERVER_CERTIFICATE
}

migrate_or_fetch_password() {
  # prefer stored secret; migrate plaintext if found
  local s="$(secrets_get "${VPN_NAME}" "password")"
  if [ -z "$s" ] && [ -n "$VPN_PASSWD" ]; then
    print_warning "Migrating plaintext password for '${VPN_NAME}' to secure storage...\n"
    secrets_set "${VPN_NAME}" "password" "${VPN_PASSWD}"
    s="${VPN_PASSWD}"
  fi
  if [ -z "$s" ]; then
    read -r -s -p "Enter password for ${VPN_USER}@${VPN_HOST}: " s; echo
    secrets_set "${VPN_NAME}" "password" "${s}"
  fi
  VPN_PASSWD="$s"
  export VPN_PASSWD
}

list_profile_names() {
  IFS=$'\n' read -d '' -r -a vpn_names < <(xmlstarlet sel -t -m "//VPN" -v "name" -n "$PROFILES_FILE")
  vpn_names+=("Quit")
  printf "%s\n" "${vpn_names[@]}"
}

set_protocol_description() {
  case $PROTOCOL in
    anyconnect) PROTOCOL_DESCRIPTION="Cisco AnyConnect" ;;
    nc)         PROTOCOL_DESCRIPTION="Juniper Network Connect" ;;
    gp)         PROTOCOL_DESCRIPTION="Palo Alto GlobalProtect" ;;
    pulse)      PROTOCOL_DESCRIPTION="Pulse Secure" ;;
    *)          PROTOCOL_DESCRIPTION="Unknown" ;;
  esac
}

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