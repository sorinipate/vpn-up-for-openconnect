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
      -v "proxy | proxyUrl" -n \
      -v "profileId | profileid" -n \
      -v "totpAlgorithm | totpalgorithm" -n \
      -v "totpDigits | totpdigits" -n \
      -v "totpStepSeconds | totpstepseconds" -n "${PROFILES_FILE}"
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
  # Stable identity for the approval registry (Model B). Deliberately NOT the
  # profile name: the name is display identity and may be renamed or reused,
  # while an approval must key off something immutable. Generated on first use
  # by profile_id_ensure.
  VPN_PROFILE_ID="${fields[14]:-}"
  # RFC 6238 parameters for tokenMode=totp, all optional -- absent/empty falls
  # back to oathtool's own implicit defaults (SHA1/6 digits/30s step), so an
  # existing profile with none of these tags behaves exactly as before.
  VPN_TOTP_ALGORITHM="$(printf '%s' "${fields[15]:-}" | tr '[:lower:]' '[:upper:]')"
  VPN_TOTP_DIGITS="${fields[16]:-}"
  VPN_TOTP_STEP="${fields[17]:-}"
  # `: "${VAR:=default}"` rather than `[ -z "$VAR" ] && VAR=default` -- the
  # latter returns 1 (and, unguarded, would make THIS FUNCTION return 1) on
  # every profile that actually sets a non-default value, since it's the
  # last thing load_profile_fields does. `:` always exits 0.
  : "${VPN_TOTP_ALGORITHM:=SHA1}"
  : "${VPN_TOTP_DIGITS:=6}"
  : "${VPN_TOTP_STEP:=30}"

  # Intentionally NOT exported: these are read only by functions in this
  # shell, and exporting would copy the password into the environment of
  # every child process (curl, ping, awk, ...).
}

# Ensure a profile has an immutable profile id, generating and persisting one on
# first use. Existing profiles are migrated silently the first time they are
# used with helper mode; nothing else depends on the field, so a profile that
# never uses helper mode never grows one.
#
# The id is only an identifier: it is not secret, and it confers nothing by
# itself. What it does is name which approval record applies, so renaming a
# profile no longer silently changes which endpoint is authorised.
profile_id_ensure() {
  local name="$1"
  if [ -n "${VPN_PROFILE_ID:-}" ]; then
    printf '%s' "${VPN_PROFILE_ID}"
    return 0
  fi

  local id=""
  if command -v uuidgen >/dev/null 2>&1; then
    id="$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  fi
  if [ -z "$id" ] && [ -r /proc/sys/kernel/random/uuid ]; then
    id="$(cat /proc/sys/kernel/random/uuid 2>/dev/null)"
  fi
  if [ -z "$id" ] && command -v openssl >/dev/null 2>&1; then
    # 32 hex characters is the other form the helper accepts.
    id="$(openssl rand -hex 16 2>/dev/null)"
  fi
  if [ -z "$id" ]; then
    print_danger "Cannot generate a profile id (need uuidgen or openssl).\n"
    return 1
  fi

  local name_lit; name_lit="$(xpath_literal "$name")"
  local tmp="${PROFILES_FILE}.tmp"
  # Update if the element exists, otherwise add it.
  if xmlstarlet sel -t -v "count(//VPN[name=${name_lit}]/profileId)" "${PROFILES_FILE}" 2>/dev/null | grep -q '^[1-9]'; then
    xmlstarlet ed -u "//VPN[name=${name_lit}]/profileId" -v "$id" "${PROFILES_FILE}" > "${tmp}" || return 1
  else
    xmlstarlet ed -s "//VPN[name=${name_lit}]" -t elem -n profileId -v "$id" "${PROFILES_FILE}" > "${tmp}" || return 1
  fi
  mv "${tmp}" "${PROFILES_FILE}" || return 1
  chmod 600 "${PROFILES_FILE}" 2>/dev/null || true

  VPN_PROFILE_ID="$id"
  printf '%s' "$id"
  return 0
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
  # $1: SERVICE | INTERACTIVE. A backend read error checking the stored
  # secret does NOT bail out immediately -- a legacy plaintext <password> or
  # a client certificate are both independent of the secrets backend, so
  # either lets this proceed exactly as before this check existed. Only when
  # NEITHER fallback exists does the reason for having nothing left actually
  # matter: a backend error there is reported as VPN_RC_SECRETS_UNAVAILABLE
  # (2, for SERVICE only) rather than being folded into the terminal "no
  # password stored" case below it, which is what invariant 8's SERVICE
  # preflight already refuses for a genuinely absent secret.
  local mode="$1"
  # prefer stored secret; migrate plaintext if found
  #
  # One fetch, not check-then-fetch: _secret_check's stdout IS the value on
  # success, so a separate secrets_get() call here is not needed -- review
  # round 5 (BLOCKER #2) found the previous two-call shape left a real gap
  # where the backend could fail between the check and the fetch, and for
  # the openssl vault backend it also meant decrypting (and prompting for the
  # passphrase) twice.
  local s="" backend_err=0
  s="$(_secret_check "${VPN_NAME}" password)"
  case $? in
    0) : ;;
    2) backend_err=1; s="" ;;
  esac
  if [ -z "$s" ] && [ -n "$VPN_PASSWD" ]; then
    # Only scrub the plaintext <password> element once the migrated copy is
    # actually durable. secrets_set's result used to be ignored here: if the
    # write failed (backend unavailable, vault write-verify failure, ...),
    # scrub_profile_password ran anyway and deleted the only surviving copy
    # of the credential, leaving this run's in-memory VPN_PASSWD as the sole
    # remaining copy of a secret that had otherwise been fully migrated to
    # nowhere (review round 5, finding #3). The security posture is not
    # worsened by keeping the plaintext around a while longer on a failed
    # migration -- it was already plaintext; deleting the only copy after
    # failing to establish its replacement is the actual regression.
    print_warning "Migrating plaintext password for '%s' to secure storage...\n" "${VPN_NAME}"
    if secrets_set "${VPN_NAME}" "password" "${VPN_PASSWD}"; then
      s="${VPN_PASSWD}"
      scrub_profile_password "${VPN_NAME}"
    else
      print_warning "Could not migrate the plaintext password for '%s' to secure storage; leaving it in place until migration can succeed.\n" "${VPN_NAME}"
      s="${VPN_PASSWD}"
    fi
  fi
  if [ -z "$s" ] && [ -n "${VPN_CLIENT_CERT:-}" ]; then
    # Cert-only auth: the client certificate stands in for the password. Don't
    # force a prompt or fail; a password is used only if one is actually stored
    # (cert + password gateways).
    VPN_PASSWD=""
    return 0
  fi
  if [ -z "$s" ]; then
    if [ "$backend_err" = 1 ] && [ "$mode" = SERVICE ]; then
      print_danger "Could not read the secrets store to fetch the password for '%s'; will retry.\n" "${VPN_NAME}"
      return 2
    fi
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
  check_file_existence "$PROFILES_FILE" "Profiles" || return 1
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

# Single source of truth for which protocols support browser SSO (docs/protocols.md:
# anyconnect and gp only -- pulse and nc use password/Duo flows). Was two independent
# denylists (setup.sh, core.sh) naming only 'nc'; pulse silently passed both.
protocol_supports_sso() {
  case "$1" in
    anyconnect|gp) return 0 ;;
    *)             return 1 ;;
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