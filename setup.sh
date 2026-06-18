# setup.sh - interactive configuration

_bool_default() {
  local input="$1"; local default="$2"
  input="$(printf '%s' "$input" | tr '[:lower:]' '[:upper:]')"
  case "$input" in
    TRUE|T|YES|Y|1)  echo TRUE ;;
    FALSE|F|NO|N|0)  echo FALSE ;;
    "")              echo "${default}" ;;
    *)               echo "${default}" ;;
  esac
}

save_configuration() {
  mkdir -p "$(dirname "$CONFIGURATION_FILE")"
  local tmp="${CONFIGURATION_FILE}.tmp"
  cat > "${tmp}" <<'CFG'
# VPN-UP SETTINGS

readonly PRIMARY="\x1b[36;1m"
readonly SUCCESS="\x1b[32;1m"
readonly WARNING="\x1b[35;1m"
readonly DANGER="\x1b[31;1m"
readonly RESET="\x1b[0m"

# NOTE: openconnect runs via sudo; the sudo password is never stored anywhere.
# For passwordless operation, add a scoped sudoers rule (see README).

# OPENCONNECT OPTIONS
readonly BACKGROUND=__BACKGROUND__
#        ├ TRUE          Runs in background after startup
#        └ FALSE         Runs in foreground after startup

readonly QUIET=__QUIET__
#        ├ TRUE          Less output
#        └ FALSE         Detailed output

# UI
readonly SHOW_BANNER=__SHOW_BANNER__
#        ├ TRUE          Show the ASCII banner on start (interactive only)
#        └ FALSE         Never show the banner

readonly NOTIFICATIONS=__NOTIFICATIONS__
#        ├ TRUE          Desktop notification on connect/disconnect
#        └ FALSE         No notifications

# ENCRYPTION
readonly ENCRYPTION_ENABLED=TRUE  # Toggle affects only file fallback; keychain/keyring are preferred.
CFG
  sed -i.bak "s/__BACKGROUND__/${__WZ_BACKGROUND}/" "${tmp}"
  sed -i.bak "s/__QUIET__/${__WZ_QUIET}/" "${tmp}"
  sed -i.bak "s/__SHOW_BANNER__/${__WZ_SHOW_BANNER}/" "${tmp}"
  sed -i.bak "s/__NOTIFICATIONS__/${__WZ_NOTIFICATIONS}/" "${tmp}"
  rm -f "${tmp}.bak"
  mv "${tmp}" "${CONFIGURATION_FILE}"
  chmod 600 "${CONFIGURATION_FILE}"
  print_success "Saved configuration to %s\n" "${CONFIGURATION_FILE}"
}

# Append a <VPN> block to the profiles file (password stays empty — secrets
# belong in the secrets backend, set separately).
append_profile() {
  local name="$1" proto="$2" host="$3" group="$4" user="$5" duo="$6" authmode="${7:-password}" tokenmode="${8:-}" extraargs="${9:-}" clientcert="${10:-}" clientkey="${11:-}"
  local tmp="${PROFILES_FILE}.tmp"
  xmlstarlet ed \
    -s '/VPNs' -t elem -n VPN -v '' \
    -s '/VPNs/VPN[last()]' -t elem -n name -v "$name" \
    -s '/VPNs/VPN[last()]' -t elem -n protocol -v "$proto" \
    -s '/VPNs/VPN[last()]' -t elem -n host -v "$host" \
    -s '/VPNs/VPN[last()]' -t elem -n authGroup -v "$group" \
    -s '/VPNs/VPN[last()]' -t elem -n user -v "$user" \
    -s '/VPNs/VPN[last()]' -t elem -n password -v '' \
    -s '/VPNs/VPN[last()]' -t elem -n duo2FAMethod -v "$duo" \
    -s '/VPNs/VPN[last()]' -t elem -n serverCertificate -v '' \
    -s '/VPNs/VPN[last()]' -t elem -n authMode -v "$authmode" \
    -s '/VPNs/VPN[last()]' -t elem -n tokenMode -v "$tokenmode" \
    -s '/VPNs/VPN[last()]' -t elem -n extraArgs -v "$extraargs" \
    -s '/VPNs/VPN[last()]' -t elem -n clientCertificate -v "$clientcert" \
    -s '/VPNs/VPN[last()]' -t elem -n clientKey -v "$clientkey" \
    "${PROFILES_FILE}" > "${tmp}" && mv "${tmp}" "${PROFILES_FILE}" && chmod 600 "${PROFILES_FILE}"
}

add_profile_wizard() {
  if [ ! -f "$PROFILES_FILE" ]; then
    ( umask 077; printf '<VPNs>\n</VPNs>\n' > "$PROFILES_FILE" )
  fi
  # Don't try to append to a profiles file that isn't valid XML — xmlstarlet ed
  # would fail confusingly. Fail with a clear message instead.
  profiles_xml_ok || return 1

  local name proto host group user duo authmode tokenmode extraargs clientcert clientkey
  read -r -p "Profile name: " name
  [ -n "$name" ] || { print_danger "Profile name is required.\n"; return 1; }
  if profile_exists "$name"; then
    print_danger "Profile '%s' already exists.\n" "$name"
    return 1
  fi

  read -r -p "Protocol (anyconnect/nc/gp/pulse) [anyconnect]: " proto
  proto="${proto:-anyconnect}"
  case "$proto" in
    anyconnect|nc|gp|pulse) : ;;
    *) print_danger "Unknown protocol '%s'.\n" "$proto"; return 1 ;;
  esac

  read -r -p "Gateway host[:port]: " host
  [ -n "$host" ] || { print_danger "Gateway host is required.\n"; return 1; }
  read -r -p "Auth group (optional): " group
  read -r -p "Username: " user

  # SSO / browser-based login (Okta, Azure AD, Ping + embedded Duo). When on,
  # credentials and MFA are entered in the browser, so skip the 2FA and password
  # prompts entirely.
  authmode=password; duo=""; tokenmode=""
  local _in_sso=""
  read -r -p "Use SSO / browser-based login (Okta, Azure AD, Ping + Duo)? [y/N]: " _in_sso
  if [ "$(_bool_default "${_in_sso}" "FALSE")" = TRUE ]; then
    if [ "$proto" = nc ]; then
      print_danger "SSO (external browser) is not supported for the 'nc' protocol.\n"
      return 1
    fi
    authmode=sso
  else
    # Choose the 2FA style: Duo, a TOTP authenticator app, or none.
    local _in_2fa=""
    read -r -p "Two-factor — (d) Duo, (t) TOTP authenticator app, (n) none [d]: " _in_2fa
    case "$(printf '%s' "${_in_2fa:-d}" | tr '[:upper:]' '[:lower:]')" in
      t|totp)
        tokenmode=totp
        local _seed=""
        read -r -s -p "Enter the TOTP secret (base32, from your authenticator app): " _seed; echo
        if [ -n "$_seed" ]; then
          if command -v oathtool >/dev/null 2>&1 && [ -n "$(oathtool --totp -b "$_seed" 2>/dev/null)" ]; then
            secrets_set "$name" "token_secret" "$_seed" && print_success "TOTP secret stored securely.\n"
          else
            print_danger "That doesn't look like a valid base32 TOTP secret (or 'oathtool' is missing); not stored. Add it later with: %s set-secret '%s' token_secret\n" "${DISPLAY_NAME}" "$name"
          fi
          unset _seed
        fi
        ;;
      n|none|"") : ;;
      *) read -r -p "Duo 2FA method (push/phone/sms/passcode; empty = gateway default): " duo ;;
    esac
  fi

  # Client-certificate auth (optional): a file path or a PKCS#11 URI (smartcard /
  # YubiKey PIV). Additive — it works alongside any auth mode, including SSO.
  clientcert=""; clientkey=""
  read -r -p "Client certificate (file path or pkcs11: URI, optional): " clientcert
  if [ -n "$clientcert" ]; then
    read -r -p "Client key (file path or pkcs11: URI; empty if in the cert): " clientkey
    case "$clientcert" in
      pkcs11:*)
        local _in_pin=""
        read -r -p "Store the PKCS#11 PIN now (needed for a login service)? [y/N]: " _in_pin
        if [ "$(_bool_default "${_in_pin}" "FALSE")" = TRUE ]; then
          local _pin
          read -r -s -p "Enter the PKCS#11 PIN: " _pin; echo
          [ -n "$_pin" ] && secrets_set "$name" "key_password" "$_pin" && print_success "PKCS#11 PIN stored securely.\n"
          unset _pin
        fi
        ;;
      *)
        print_warning "If the key is passphrase-protected, openconnect will prompt for it at connect time (foreground only).\n" ;;
    esac
  fi

  # Advanced (optional): extra openconnect flags passed verbatim at connect time.
  extraargs=""
  read -r -p "Extra openconnect arguments (advanced, optional): " extraargs

  append_profile "$name" "$proto" "$host" "$group" "$user" "$duo" "$authmode" "$tokenmode" "$extraargs" "$clientcert" "$clientkey" \
    || { print_danger "Failed to update %s\n" "$PROFILES_FILE"; return 1; }
  print_success "Added profile '%s' to %s\n" "$name" "$PROFILES_FILE"

  if [ "$authmode" != sso ]; then
    # Cert-only gateways need no password, so default to "no" when a client
    # certificate is configured; otherwise default to "yes".
    local _pw_default="TRUE" _pw_hint="[Y/n]"
    if [ -n "$clientcert" ]; then _pw_default="FALSE"; _pw_hint="[y/N]"; fi
    read -r -p "Store the VPN password now? ${_pw_hint}: " _in_pw
    if [ "$(_bool_default "${_in_pw}" "${_pw_default}")" = TRUE ]; then
      local _p
      read -r -s -p "Enter password for ${user}@${host}: " _p; echo
      [ -n "$_p" ] && secrets_set "$name" "password" "$_p" && print_success "Password stored securely.\n"
    fi
  fi

  read -r -p "Fetch and save the gateway certificate pin now? [Y/n]: " _in_pin
  if [ "$(_bool_default "${_in_pin}" "TRUE")" = TRUE ]; then
    pin_save "$name" || print_warning "Pin not saved; you can retry later with: %s pin --save '%s'\n" "${DISPLAY_NAME}" "$name"
  fi
}

# Remove a profile and everything attached to it: XML block, stored secret,
# per-profile pid/state/log files, and any installed login service.
remove_profile() {
  local name="$1"
  [ -n "$name" ] || { echo "Usage: ${DISPLAY_NAME} remove-profile <profile>" >&2; return 1; }
  profiles_xml_ok || return 1
  if ! profile_exists "$name"; then
    print_danger "Unknown profile '%s'.\n" "$name"
    return 1
  fi

  local slug; slug="$(profile_slug "$name")"
  local pidfile="${DATA_DIR}/pids/${PROGRAM_NAME}.${slug}.pid"
  if [ -f "$pidfile" ] && is_openconnect_pid "$(cat "$pidfile")"; then
    print_danger "Profile '%s' is currently connected; stop it first: %s stop '%s'\n" "$name" "${DISPLAY_NAME}" "$name"
    return 1
  fi

  local _confirm=""
  read -r -p "Remove profile '${name}', its stored secret, logs, and any login service? [y/N]: " _confirm
  case "$_confirm" in y|Y|yes|YES) : ;; *) print_warning "Aborted.\n"; return 1 ;; esac

  # login service (also unloads it)
  if [ -f "$(_service_path_for "$name")" ]; then
    service_uninstall "$name"
  fi

  # stored secret
  secrets_delete "$name" "password"

  # XML block
  local name_lit; name_lit="$(xpath_literal "$name")"
  local tmp="${PROFILES_FILE}.tmp"
  if xmlstarlet ed -d "//VPN[name=${name_lit}]" "${PROFILES_FILE}" > "${tmp}"; then
    mv "${tmp}" "${PROFILES_FILE}"
    chmod 600 "${PROFILES_FILE}" 2>/dev/null || true
  else
    rm -f "${tmp}"
    print_danger "Could not update %s; profile not removed from XML.\n" "${PROFILES_FILE}"
    return 1
  fi

  # per-profile state and logs
  rm -f "$pidfile" \
        "${DATA_DIR}/pids/${PROGRAM_NAME}.${slug}.state" \
        "${DATA_DIR}/logs/${PROGRAM_NAME}.${slug}.log" \
        "${DATA_DIR}/logs/service.${slug}.log"

  print_success "Removed profile '%s' (XML, secret, state, logs, service).\n" "$name"
}

setup_wizard() {
  printf "%b\n" "${PRIMARY}Running first-time setup...${RESET}"

  read -r -p "Run in background after connect? [Y/n]: " _in_bg
  __WZ_BACKGROUND="$(_bool_default "${_in_bg}" "TRUE")"

  read -r -p "Quiet openconnect output? [Y/n]: " _in_quiet
  __WZ_QUIET="$(_bool_default "${_in_quiet}" "TRUE")"

  read -r -p "Show ASCII banner on start? [Y/n]: " _in_banner
  __WZ_SHOW_BANNER="$(_bool_default "${_in_banner}" "TRUE")"

  read -r -p "Desktop notifications on connect/disconnect? [Y/n]: " _in_notif
  __WZ_NOTIFICATIONS="$(_bool_default "${_in_notif}" "TRUE")"

  # Clean up any sudo password stored by older versions; storing it defeats
  # sudo's protection (any process running as this user could retrieve it).
  if [ -n "$(secrets_get "__GLOBAL__" "sudo_password" 2>/dev/null)" ]; then
    secrets_delete "__GLOBAL__" "sudo_password"
    print_warning "Removed stored sudo password (no longer supported). For passwordless use, see the sudoers rule in the README.\n"
  fi

  save_configuration
}