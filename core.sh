# core.sh - main flow (Bash >= 4; uses mapfile)

# The config file is executable shell code: refuse to source it unless it is
# owned by the current user and not writable by group/other.
assert_safe_to_source() {
  local f="$1" owner perms
  owner="$(file_owner_uid "$f")"
  perms="$(file_mode "$f")"
  if [ "$owner" != "$(id -u)" ]; then
    print_danger "Refusing to load %s: not owned by the current user.\n" "$f"
    return 1
  fi
  if [ -z "$perms" ]; then
    print_danger "Refusing to load %s: could not determine file permissions.\n" "$f"
    return 1
  fi
  if [ $(( 8#$perms & 8#022 )) -ne 0 ]; then
    print_danger "Refusing to load %s: writable by group/other (mode %s). Fix with: chmod 600 '%s'\n" "$f" "$perms" "$f"
    return 1
  fi
}

# Run user hook scripts for a lifecycle event (connected/disconnected) from
# ${DATA_DIR}/hooks/<event>.d/, in name order. Hooks are executable code, so
# each gets the same ownership/permission check as the config file; failures
# are reported but never abort the VPN flow. Hooks receive VPN_EVENT,
# VPN_NAME, and VPN_HOST in their environment (never the password).
run_hooks() {
  local event="$1" name="${2:-}" host="${3:-}"
  local dir="${DATA_DIR}/hooks/${event}.d" h
  [ -d "$dir" ] || return 0
  for h in "$dir"/*; do
    { [ -f "$h" ] && [ -x "$h" ]; } || continue
    if ! assert_safe_to_source "$h"; then
      print_warning "Skipping hook %s (unsafe ownership/permissions).\n" "$h"
      continue
    fi
    if ! VPN_EVENT="$event" VPN_NAME="$name" VPN_HOST="$host" "$h"; then
      print_warning "Hook %s exited non-zero.\n" "$h"
    fi
  done
  return 0
}

# Source the config (executable shell) after the safety checks. Safe to call
# from any command; no-op when the config doesn't exist yet.
load_config() {
  [ -f "$CONFIGURATION_FILE" ] || return 0
  assert_safe_to_source "$CONFIGURATION_FILE" || exit 1
  # shellcheck disable=SC1090
  source "$CONFIGURATION_FILE"
}

start() {
  local requested="${1:-}"
  # Ensure config exists or run wizard
  if [ ! -f "$CONFIGURATION_FILE" ]; then
    setup_wizard
  fi
  load_config
  print_warning "Loaded configuration from %s ...\n" "$CONFIGURATION_FILE"

  # First run with no profiles: offer the guided wizard when interactive;
  # fall back to seeding the XML template for scripts/services.
  if [ ! -f "$PROFILES_FILE" ] || [ -z "$(profile_names_raw)" ]; then
    if [ -t 0 ] && [ -z "${VPN_UP_SERVICE:-}" ]; then
      print_warning "No VPN profiles yet.\n"
      local _add=""
      read -r -p "Add your first profile now? [Y/n]: " _add
      case "$_add" in
        n|N|no|NO)
          print_warning "You can add one later with: %s add-profile\n" "${DISPLAY_NAME}"
          exit 1 ;;
        *)
          add_profile_wizard || exit 1 ;;
      esac
    else
      if [ ! -f "$PROFILES_FILE" ] && [ -f "${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles.default" ]; then
        ( umask 077; cp "${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles.default" "$PROFILES_FILE" )
        print_warning "Created profile template at %s\nEdit it with your VPN details (or run '%s add-profile'), then run start again.\n" "$PROFILES_FILE" "${DISPLAY_NAME}"
      fi
      exit 1
    fi
  fi
  check_file_existence "$PROFILES_FILE" "Profiles"

  # Show banner if interactive
  show_banner

  # Network check
  if ! is_network_available; then
    print_danger "Please check your internet connection or try again later!\n"
    exit 1
  fi

  if any_vpn_running; then
    print_warning "Already connected to a VPN! Run '%s status' or '%s stop' first.\n" "${DISPLAY_NAME}" "${DISPLAY_NAME}"
    exit 1
  fi

  print_primary "Starting ${DISPLAY_NAME} ...\n"

  if [ -n "$requested" ]; then
    # Non-interactive: profile named on the command line
    if ! profile_exists "$requested"; then
      print_danger "Unknown profile '%s'. Available profiles:\n" "$requested"
      list_profiles
      exit 1
    fi
    load_profile_fields "$requested"
    if [ "${VPN_AUTH_MODE:-password}" != sso ]; then
      migrate_or_fetch_password || exit 1
    fi
    connect
  else
    # Interactive profile selection (modern Bash mapfile)
    mapfile -t vpn_names < <(list_profile_names)
    PS3=$'Choose VPN: '
    select option in "${vpn_names[@]}"; do
      if [ "$option" = "Quit" ]; then
        print_warning "You chose to close the app!\n"
        exit 0
      fi
      if printf "%s\n" "${vpn_names[@]}" | grep -qx -- "$option"; then
        load_profile_fields "$option"
        if [ "${VPN_AUTH_MODE:-password}" != sso ]; then
          migrate_or_fetch_password || exit 1
        fi
        connect
        break
      else
        print_danger "Invalid option! Please choose one of the options above...\n"
      fi
    done
  fi

  # In foreground/service mode run_openconnect blocks for the whole session
  # and cleans up after itself; the post-connect check only makes sense when
  # openconnect daemonized.
  if [ -z "${VPN_UP_SERVICE:-}" ] && [ "${BACKGROUND:-FALSE}" = TRUE ]; then
    if is_vpn_running; then
      write_connection_state
      print_success "Connected to %s\n" "${VPN_NAME}"
      notify "VPN Up" "Connected to ${VPN_NAME}"
      run_hooks connected "${VPN_NAME}" "${VPN_HOST}"
      print_current_ip_address
    else
      print_danger "Failed to connect! Last log lines from %s:\n" "${LOG_FILE_PATH}"
      tail -n 15 "$LOG_FILE_PATH" 2>/dev/null || true
      if grep -q "Login failed" "$LOG_FILE_PATH" 2>/dev/null; then
        print_warning "If the stored password is wrong, reset it with: %s delete-secret '%s' password\n" "${DISPLAY_NAME}" "${VPN_NAME}"
      fi
      notify "VPN Up" "Failed to connect to ${VPN_NAME:-VPN}"
    fi
  fi
}

# Record which profile is connected so `status` can report it.
write_connection_state() {
  ( umask 077
    printf 'profile=%s\nhost=%s\nconnected_at=%s\n' \
      "${VPN_NAME}" "${VPN_HOST}" "$(date '+%Y-%m-%d %H:%M:%S')" > "$STATE_FILE_PATH"
  )
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

  # Each profile gets its own PID/state/log files
  set_profile_paths "${VPN_NAME}"
  print_warning "Process ID (PID) stored in %s ...\n" "${PID_FILE_PATH}"
  print_warning "Logs file (LOG) stored in %s ...\n" "${LOG_FILE_PATH}"

  # SSO / external-browser auth (Okta, Azure AD, Ping + embedded Duo): the
  # whole login happens in a browser, so there is no password or Duo answer to
  # pipe. It needs an interactive desktop session and openconnect >= 9.0.
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    if [ -n "${VPN_UP_SERVICE:-}" ]; then
      print_danger "Profile '%s' uses SSO (interactive browser); it cannot run as a service.\n" "${VPN_NAME}"
      return 1
    fi
    if [ "$PROTOCOL" = nc ]; then
      print_danger "SSO (external browser) is not supported for the 'nc' protocol.\n"
      return 1
    fi
    require_openconnect_sso || return 1
  fi

  # Duo passcodes are one-time values; never read them from the XML —
  # prompt at connect time instead. (Skipped for SSO: the browser handles MFA.)
  if [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_DUO2FAMETHOD" = "passcode" ]; then
    if [ -n "${VPN_UP_SERVICE:-}" ]; then
      print_danger "Profile '%s' uses a Duo passcode, which needs interactive input; it cannot run as a service. Use push/phone/sms instead.\n" "${VPN_NAME}"
      return 1
    fi
    read -r -p "Enter Duo passcode for ${VPN_NAME}: " VPN_DUO2FAMETHOD
    if [ -z "$VPN_DUO2FAMETHOD" ]; then
      print_danger "No passcode entered; aborting.\n"
      return 1
    fi
  fi

  set_protocol_description
  set_2fa_method_description

  # Fail closed on server identity: either a pin is configured, or the
  # gateway's certificate must validate against the system trust store.
  if [ -n "$SERVER_CERTIFICATE" ]; then
    case "$SERVER_CERTIFICATE" in
      pin-sha256:*) : ;;
      *) print_warning "serverCertificate uses a legacy (SHA1) pin; SHA1 is deprecated. Run '%s pin %s' to get a pin-sha256 value.\n" "${DISPLAY_NAME}" "${VPN_HOST}" ;;
    esac
  else
    if ! verify_gateway_cert "${VPN_HOST}"; then
      print_danger "The certificate of %s does NOT validate against the system trust store, and no pin is configured. Refusing to connect.\n" "${VPN_HOST}"
      print_pin_instructions "${VPN_HOST}"
      return 1
    fi
  fi

  print_primary "Starting the %s on %s using %s ...\n" "${VPN_NAME}" "${VPN_HOST}" "${PROTOCOL_DESCRIPTION}"
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    print_primary "Connecting via SSO (external browser) — complete the login in the window that opens ...\n"
  elif [ -z "$VPN_DUO2FAMETHOD" ]; then
    print_warning "Connecting without 2FA (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
  else
    print_primary "Connecting with Two-Factor Authentication (2FA) from Duo (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
  fi

  run_openconnect
}

_print_state_details() {
  local statefile="$1" pid="$2"
  if [ -f "$statefile" ]; then
    local profile host connected_at
    profile="$(awk -F= '$1=="profile"{print substr($0,9); exit}' "$statefile")"
    host="$(awk -F= '$1=="host"{print substr($0,6); exit}' "$statefile")"
    connected_at="$(awk -F= '$1=="connected_at"{print substr($0,14); exit}' "$statefile")"
    print_primary "  Profile : %s\n" "${profile:-unknown}"
    print_primary "  Gateway : %s\n" "${host:-unknown}"
    print_primary "  Since   : %s\n" "${connected_at:-unknown}"
  fi
  print_primary "  Uptime  : %s\n" "$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ' || echo unknown)"
}

status() {
  local found=0 f pid statefile
  for f in "${DATA_DIR}/pids/"*.pid; do
    [ -e "$f" ] || continue
    pid="$(cat "$f")"
    statefile="${f%.pid}.state"
    if is_openconnect_pid "$pid"; then
      found=1
      print_success "VPN is running (PID: %s)\n" "$pid"
      _print_state_details "$statefile" "$pid"
    else
      rm -f "$f" "$statefile"
    fi
  done
  if [ "$found" -eq 0 ]; then
    print_warning "VPN is not running.\n"
  fi
}

# Stop the connection recorded in one PID file.
_stop_by_pid_file() {
  local pidfile="$1"
  local statefile="${pidfile%.pid}.state"
  local pid; pid="$(cat "$pidfile")"
  if ! is_openconnect_pid "$pid"; then
    print_warning "Stale PID file (no openconnect process with PID %s); cleaning up.\n" "$pid"
    rm -f "$pidfile" "$statefile"
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
  local profile="" host=""
  if [ -f "$statefile" ]; then
    profile="$(awk -F= '$1=="profile"{print substr($0,9); exit}' "$statefile")"
    host="$(awk -F= '$1=="host"{print substr($0,6); exit}' "$statefile")"
  fi
  rm -f "$pidfile" "$statefile"
  print_success "VPN stopped.\n"
  notify "VPN Up" "Disconnected from ${profile:-VPN}"
  run_hooks disconnected "$profile" "$host"
}

stop() {
  local requested="${1:-}" f
  load_config
  local files=()
  if [ -n "$requested" ]; then
    f="${DATA_DIR}/pids/${PROGRAM_NAME}.$(profile_slug "$requested").pid"
    if [ ! -f "$f" ]; then
      print_warning "VPN profile '%s' is not running.\n" "$requested"
      return 0
    fi
    files=("$f")
  else
    for f in "${DATA_DIR}/pids/"*.pid; do
      [ -e "$f" ] && files+=("$f")
    done
    if [ "${#files[@]}" -eq 0 ]; then
      print_warning "VPN is not running.\n"
      return 0
    fi
  fi
  local rc=0
  for f in "${files[@]}"; do
    _stop_by_pid_file "$f" || rc=1
  done
  return "$rc"
}

# Resolve the command openconnect runs (with the SSO login URL as its argument)
# to open the external browser. openconnect itself catches the returned token on
# a localhost listener, so any URL opener works. Honor an explicit override,
# then the bundled helper, then the platform default. NOTE: openconnect runs as
# root via sudo, so on Linux a root-spawned opener may not reach the user's GUI
# session — set VPN_UP_EXTERNAL_BROWSER to a session-aware wrapper if so.
resolve_external_browser() {
  if [ -n "${VPN_UP_EXTERNAL_BROWSER:-}" ]; then printf '%s' "$VPN_UP_EXTERNAL_BROWSER"; return; fi
  if command -v openconnect-external-browser >/dev/null 2>&1; then printf 'openconnect-external-browser'; return; fi
  [ "$(uname)" = Darwin ] && printf 'open' || printf 'xdg-open'
}

run_openconnect() {
  # Validate sudo up-front on the TTY so the prompt doesn't collide with the
  # password pipe below. For passwordless use, configure a scoped sudoers rule
  # (see README) instead of storing the sudo password anywhere.
  if [ -n "${VPN_UP_SERVICE:-}" ]; then
    # Service mode (launchd/systemd): no TTY, so sudo must not prompt.
    if ! sudo -n -v 2>/dev/null; then
      print_danger "Service mode requires a passwordless sudoers rule for openconnect (see README).\n"
      return 1
    fi
  elif ! sudo -v; then
    print_danger "sudo authentication failed; cannot start openconnect.\n"
    return 1
  fi

  # Under launchd/systemd the service manager must supervise openconnect
  # itself, so force foreground; KeepAlive/Restart provides auto-reconnect.
  # SSO is interactive and always runs foreground too (BACKGROUND is ignored).
  local effective_background="${BACKGROUND:-FALSE}"
  [ -n "${VPN_UP_SERVICE:-}" ] && effective_background=FALSE
  [ "${VPN_AUTH_MODE:-password}" = sso ] && effective_background=FALSE

  # Build argv array (no eval)
  local args=()
  args+=(--protocol="$PROTOCOL")
  args+=(--user="$VPN_USER")
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    # SSO: authenticate in a browser; no password is piped on stdin.
    args+=(--external-browser="$(resolve_external_browser)")
  else
    args+=(--passwd-on-stdin)
  fi
  [ "${QUIET:-FALSE}" = TRUE ] && args+=(-q)
  [ "$effective_background" = TRUE ] && args+=(--background)
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
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    # SSO: openconnect opens a browser and needs the controlling TTY, so pipe
    # NOTHING on stdin. Always foreground; capture the PID the same way as the
    # foreground password path so status/stop work during the session.
    write_connection_state
    ( sleep 3
      _pid="$(pgrep -n -x openconnect 2>/dev/null || true)"
      if [ -n "$_pid" ]; then
        printf '%s\n' "$_pid" > "$PID_FILE_PATH"
        notify "VPN Up" "Connected to ${VPN_NAME}"
        run_hooks connected "${VPN_NAME}" "${VPN_HOST}"
      fi
    ) &
    sudo openconnect "${args[@]}" 2>&1 | tee -a "$LOG_FILE_PATH"
    rm -f "$PID_FILE_PATH" "$STATE_FILE_PATH"
    notify "VPN Up" "Disconnected from ${VPN_NAME:-VPN}"
    run_hooks disconnected "${VPN_NAME:-}" "${VPN_HOST:-}"
  elif [ "$effective_background" = TRUE ]; then
    # The daemonized child keeps stdout open, so piping through tee would
    # hang the shell forever after openconnect backgrounds itself; write
    # straight to the log instead.
    # shellcheck disable=SC2024  # intentional: log is opened (and owned) by the user; the root daemon inherits the fd
    printf "%s\n" "$stdin_lines" \
      | sudo openconnect "${args[@]}" >> "$LOG_FILE_PATH" 2>&1
  else
    # Foreground: openconnect only writes --pid-file when backgrounding, so
    # record the PID ourselves (after the tunnel has had time to come up) so
    # status/stop work during a foreground/service session.
    write_connection_state
    ( sleep 3
      _pid="$(pgrep -n -x openconnect 2>/dev/null || true)"
      if [ -n "$_pid" ]; then
        printf '%s\n' "$_pid" > "$PID_FILE_PATH"
        notify "VPN Up" "Connected to ${VPN_NAME}"
        run_hooks connected "${VPN_NAME}" "${VPN_HOST}"
      fi
    ) &
    printf "%s\n" "$stdin_lines" \
      | sudo openconnect "${args[@]}" 2>&1 | tee -a "$LOG_FILE_PATH"
    # Foreground session over (disconnect or failure): clean our records.
    rm -f "$PID_FILE_PATH" "$STATE_FILE_PATH"
    notify "VPN Up" "Disconnected from ${VPN_NAME:-VPN}"
    run_hooks disconnected "${VPN_NAME:-}" "${VPN_HOST:-}"
  fi

  # Drop the password from shell memory as soon as it has been piped.
  unset VPN_PASSWD stdin_lines
}