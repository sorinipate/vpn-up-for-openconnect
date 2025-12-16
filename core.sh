# core.sh - main flow (Bash >= 4; uses mapfile)

start() {
  # Ensure config exists or run wizard
  if [ ! -f "$CONFIGURATION_FILE" ]; then
    setup_wizard
  fi
  # shellcheck disable=SC1090
  source "$CONFIGURATION_FILE"
  print_warning "Loaded configuration from $CONFIGURATION_FILE ...\n"

  check_file_existence "$PROFILES_FILE" "Profiles"

  # Show banner if interactive
  show_banner

  # Network check
  if ! is_network_available; then
    print_danger "Please check your internet connection or try again later!\n"
    exit 1
  fi

  if is_vpn_running; then
    print_warning "Already connected to a VPN!\n"
    exit 1
  fi

  print_primary "Starting ${PROGRAM_NAME} ...\n"
  print_warning "Process ID (PID) stored in %s ...\n" "${PID_FILE_PATH}"
  print_warning "Logs file (LOG) stored in %s ...\n" "${LOG_FILE_PATH}"

  # Select a profile (modern Bash mapfile)
  mapfile -t vpn_names < <(list_profile_names)
  PS3=$'Choose VPN: '
  select option in "${vpn_names[@]}"; do
    if [ "$option" = "Quit" ]; then
      print_warning "You chose to close the app!\n"
      exit 0
    fi
    if printf "%s\n" "${vpn_names[@]}" | grep -qx -- "$option"; then
      load_profile_fields "$option"
      migrate_or_fetch_password
      connect
      break
    else
      print_danger "Invalid option! Please choose one of the options above...\n"
    fi
  done

  if is_vpn_running; then
    print_success "Connected to %s\n" "${VPN_NAME}"
    print_current_ip_address
  else
    print_danger "Failed to connect!\n"
  fi
}

connect() {
  if [ -z "${VPN_HOST}" ]; then
    print_danger "Variable 'VPN_HOST' is not declared! Update it in ${PROFILES_FILE} ...\n"
    return
  fi
  if [ -z "${PROTOCOL}" ]; then
    print_danger "Variable 'PROTOCOL' is not declared! Update it in ${PROFILES_FILE} ...\n"
    return
  fi

  set_protocol_description
  set_2fa_method_description

  print_primary "Starting the %s on %s using %s ...\n" "${VPN_NAME}" "${VPN_HOST}" "${PROTOCOL_DESCRIPTION}"
  if [ -z "$VPN_DUO2FAMETHOD" ]; then
    print_warning "Connecting without 2FA (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
  else
    print_primary "Connecting with Two-Factor Authentication (2FA) from Duo (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
  fi

  run_openconnect
}

status() {
  if is_vpn_running; then
    print_success "VPN is running (PID: %s)\n" "$(cat "$PID_FILE_PATH")"
  else
    print_warning "VPN is not running.\n"
  fi
}

stop() {
  if is_vpn_running; then
    kill "$(cat "$PID_FILE_PATH")"
    rm -f "$PID_FILE_PATH"
    print_success "VPN stopped.\n"
  else
    print_warning "VPN is not running.\n"
  fi
}

run_openconnect() {
  local background_flag=""
  local quiet_flag=""
  local server_cert_flag=""
  [ -n "$SERVER_CERTIFICATE" ] && server_cert_flag="--servercert=$SERVER_CERTIFICATE"

  # Warm sudo timestamp if configured and secret is available
  if [ "${SUDO:-TRUE}" = TRUE ]; then
    _SUDO_PASS="$(secrets_get "__GLOBAL__" "sudo_password")"
    if [ -n "$_SUDO_PASS" ]; then
      printf "%s
" "$_SUDO_PASS" | sudo -S -v 2>/dev/null || true
    fi
  fi

  # Build argv array (no eval)
  local args=()
  args+=(--protocol="$PROTOCOL")
  args+=(--user="$VPN_USER")
  args+=(--passwd-on-stdin)
  [ "$QUIET" = TRUE ] && args+=(-q)
  [ "$BACKGROUND" = TRUE ] && args+=(--background)
  [ -n "$SERVER_CERTIFICATE" ] && args+=("$server_cert_flag")
  [ -n "$VPN_GROUP" ] && args+=(--authgroup "$VPN_GROUP")
  args+=("$VPN_HOST")
  args+=(--pid-file "$PID_FILE_PATH")

  # Ensure dirs
  mkdir -p "${PROGRAM_PATH}/logs" "${PROGRAM_PATH}/pids"
  chmod 700 "${PROGRAM_PATH}/logs" "${PROGRAM_PATH}/pids"

  if [ -n "$VPN_DUO2FAMETHOD" ]; then
    { printf "%s
" "$VPN_PASSWD"; sleep 1; printf "%s
" "$VPN_DUO2FAMETHOD"; } \
      | sudo openconnect "${args[@]}" | sudo tee "$LOG_FILE_PATH" 2>&1
  else
    printf "%s
" "$VPN_PASSWD" \
      | sudo openconnect "${args[@]}" | sudo tee "$LOG_FILE_PATH" 2>&1
  fi
}