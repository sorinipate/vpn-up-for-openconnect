# core.sh - main flow (Bash >= 4; uses mapfile)

# The config file is executable shell code: refuse to source it unless it is
# owned by the current user and not writable by group/other.
assert_safe_to_source() {
  local f="$1" owner perms
  owner="$(stat -f '%u' "$f" 2>/dev/null || stat -c '%u' "$f" 2>/dev/null)"
  perms="$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null)"
  if [ "$owner" != "$(id -u)" ]; then
    print_danger "Refusing to load %s: not owned by the current user.\n" "$f"
    return 1
  fi
  if [ $(( 8#$perms & 8#022 )) -ne 0 ]; then
    print_danger "Refusing to load %s: writable by group/other (mode %s). Fix with: chmod 600 '%s'\n" "$f" "$perms" "$f"
    return 1
  fi
}

start() {
  # Ensure config exists or run wizard
  if [ ! -f "$CONFIGURATION_FILE" ]; then
    setup_wizard
  fi
  assert_safe_to_source "$CONFIGURATION_FILE" || exit 1
  # shellcheck disable=SC1090
  source "$CONFIGURATION_FILE"
  print_warning "Loaded configuration from %s ...\n" "$CONFIGURATION_FILE"

  # Seed the profiles template on first run, then ask the user to fill it in.
  if [ ! -f "$PROFILES_FILE" ] && [ -f "${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles.default" ]; then
    ( umask 077; cp "${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles.default" "$PROFILES_FILE" )
    print_warning "Created profile template at %s\nEdit it with your VPN details, then run start again.\n" "$PROFILES_FILE"
    exit 1
  fi
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
    print_danger "Variable 'VPN_HOST' is not declared! Update it in %s ...\n" "${PROFILES_FILE}"
    return 1
  fi
  if [ -z "${PROTOCOL}" ]; then
    print_danger "Variable 'PROTOCOL' is not declared! Update it in %s ...\n" "${PROFILES_FILE}"
    return 1
  fi

  set_protocol_description
  set_2fa_method_description

  # Fail closed on server identity: either a pin is configured, or the
  # gateway's certificate must validate against the system trust store.
  if [ -n "$SERVER_CERTIFICATE" ]; then
    case "$SERVER_CERTIFICATE" in
      pin-sha256:*) : ;;
      *) print_warning "serverCertificate uses a legacy (SHA1) pin; SHA1 is deprecated. Run '%s pin %s' to get a pin-sha256 value.\n" "${PROGRAM_NAME}" "${VPN_HOST}" ;;
    esac
  else
    if ! verify_gateway_cert "${VPN_HOST}"; then
      print_danger "The certificate of %s does NOT validate against the system trust store, and no pin is configured. Refusing to connect.\n" "${VPN_HOST}"
      print_pin_instructions "${VPN_HOST}"
      return 1
    fi
  fi

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
  if [ ! -f "$PID_FILE_PATH" ]; then
    print_warning "VPN is not running.\n"
    return 0
  fi
  local pid; pid="$(cat "$PID_FILE_PATH")"
  if ! is_openconnect_pid "$pid"; then
    print_warning "Stale PID file (no openconnect process with PID %s); cleaning up.\n" "$pid"
    rm -f "$PID_FILE_PATH"
    return 0
  fi
  # openconnect runs as root, so killing it needs sudo too.
  if ! sudo kill "$pid"; then
    print_danger "Failed to signal openconnect (PID: %s).\n" "$pid"
    return 1
  fi
  local _i
  for _i in {1..20}; do
    is_openconnect_pid "$pid" || break
    sleep 0.5
  done
  if is_openconnect_pid "$pid"; then
    print_warning "openconnect did not exit gracefully; sending SIGKILL ...\n"
    sudo kill -9 "$pid" 2>/dev/null || true
    sleep 1
  fi
  if is_openconnect_pid "$pid"; then
    print_danger "Could not stop openconnect (PID: %s); VPN may still be up!\n" "$pid"
    return 1
  fi
  rm -f "$PID_FILE_PATH"
  print_success "VPN stopped.\n"
}

run_openconnect() {
  # Validate sudo up-front on the TTY so the prompt doesn't collide with the
  # password pipe below. For passwordless use, configure a scoped sudoers rule
  # (see README) instead of storing the sudo password anywhere.
  if ! sudo -v; then
    print_danger "sudo authentication failed; cannot start openconnect.\n"
    return 1
  fi

  # Build argv array (no eval)
  local args=()
  args+=(--protocol="$PROTOCOL")
  args+=(--user="$VPN_USER")
  args+=(--passwd-on-stdin)
  [ "${QUIET:-FALSE}" = TRUE ] && args+=(-q)
  [ "${BACKGROUND:-FALSE}" = TRUE ] && args+=(--background)
  [ -n "$SERVER_CERTIFICATE" ] && args+=(--servercert="$SERVER_CERTIFICATE")
  [ -n "$VPN_GROUP" ] && args+=(--authgroup "$VPN_GROUP")
  args+=("$VPN_HOST")
  args+=(--pid-file "$PID_FILE_PATH")

  # Ensure dirs
  ( umask 077; mkdir -p "${DATA_DIR}/logs" "${DATA_DIR}/pids" )
  chmod 700 "${DATA_DIR}/logs" "${DATA_DIR}/pids"

  # Feed password (and 2FA answer, if any) on stdin. Create the log file as
  # the unprivileged user with 600 perms and capture openconnect's stderr too
  # (previously `sudo tee ... 2>&1` redirected tee's stderr, not openconnect's,
  # and left a root-owned log in the user's directory).
  local stdin_lines="$VPN_PASSWD"
  [ -n "$VPN_DUO2FAMETHOD" ] && stdin_lines+=$'\n'"$VPN_DUO2FAMETHOD"
  ( umask 077; : > "$LOG_FILE_PATH" )
  printf "%s\n" "$stdin_lines" \
    | sudo openconnect "${args[@]}" 2>&1 | tee "$LOG_FILE_PATH"

  # Drop the password from shell memory as soon as it has been piped.
  unset VPN_PASSWD stdin_lines
}