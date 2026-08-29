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
# from any command; no-op when the config doesn't exist yet. Returns 1 rather
# than exiting: called from start()'s call tree, which under a service must
# route every failure through the outcome/service_exit_code mapping
# (outcome.sh) rather than terminate the process directly.
load_config() {
  [ -f "$CONFIGURATION_FILE" ] || return 0
  assert_safe_to_source "$CONFIGURATION_FILE" || return 1
  # shellcheck disable=SC1090
  source "$CONFIGURATION_FILE"
}

ensure_profile_not_running() {
  set_profile_paths "$VPN_NAME"
  if profile_vpn_running "$VPN_NAME"; then
    print_warning "VPN profile '%s' is already running. Run '%s status' or '%s stop \"%s\"' first.\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
    return 1
  fi
  return 0
}

# `start` returns an outcome code (outcome.sh) rather than exiting directly.
# This is load-bearing under a service: the top-level dispatch (vpn-up.command)
# is the ONE place that maps an outcome to an exit status and actually exits,
# so nothing in this call tree may `exit` on its own — an unmapped `exit`
# bypasses service_exit_code() entirely, which is exactly the supervisor-
# contract bug this design closes (see PRIVILEGED-HELPER-DESIGN.md and the
# CHANGELOG entry for this change: require_bin()/check_file_existence() used
# to exit directly, and setup_wizard() had no VPN_UP_SERVICE guard at all).
start() {
  local requested="${1:-}"
  local mode="INTERACTIVE"
  [ -n "${VPN_UP_SERVICE:-}" ] && mode="SERVICE"

  if [ ! -f "$CONFIGURATION_FILE" ]; then
    if [ "$mode" = SERVICE ]; then
      print_danger "No configuration file yet and a service cannot run the setup wizard (no terminal). Run '%s setup' interactively first.\n" "${DISPLAY_NAME}"
      return "$VPN_RC_CONFIG"
    fi
    setup_wizard
  fi
  load_config || return "$VPN_RC_CONFIG"
  print_warning "Loaded configuration from %s ...\n" "$CONFIGURATION_FILE"

  # A malformed profiles file must fail with a clear message — not be silently
  # misread as "no profiles" (which would wrongly trigger first-run) or leak raw
  # libxml2 parser errors when we read it below.
  if [ -f "$PROFILES_FILE" ] && ! profiles_xml_ok; then
    return "$VPN_RC_CONFIG"
  fi

  # First run with no profiles: offer the guided wizard when interactive;
  # fall back to seeding the XML template for scripts/services.
  if [ ! -f "$PROFILES_FILE" ] || [ -z "$(profile_names_raw)" ]; then
    if [ -t 0 ] && [ "$mode" != SERVICE ]; then
      print_warning "No VPN profiles yet.\n"
      local _add=""
      read -r -p "Add your first profile now? [Y/n]: " _add
      case "$_add" in
        n|N|no|NO)
          print_warning "You can add one later with: %s add-profile\n" "${DISPLAY_NAME}"
          return "$VPN_RC_CONFIG" ;;
        *)
          add_profile_wizard || return "$VPN_RC_CONFIG" ;;
      esac
    else
      if [ ! -f "$PROFILES_FILE" ] && [ -f "${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles.default" ]; then
        ( umask 077; cp "${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles.default" "$PROFILES_FILE" )
        print_warning "Created profile template at %s\nEdit it with your VPN details (or run '%s add-profile'), then run start again.\n" "$PROFILES_FILE" "${DISPLAY_NAME}"
      fi
      return "$VPN_RC_CONFIG"
    fi
  fi
  check_file_existence "$PROFILES_FILE" "Profiles" || return "$VPN_RC_CONFIG"

  show_banner

  if ! is_network_available; then
    print_danger "Please check your internet connection or try again later!\n"
    return "$VPN_RC_NO_NETWORK"
  fi

  print_primary "Starting ${DISPLAY_NAME} ...\n"

  local outcome=0
  if [ -n "$requested" ]; then
    # Non-interactive: profile named on the command line
    if ! profile_exists "$requested"; then
      print_danger "Unknown profile '%s'. Available profiles:\n" "$requested"
      list_profiles
      return "$VPN_RC_CONFIG"
    fi
    load_profile_fields "$requested"
    if ! ensure_profile_not_running; then
      return "$VPN_RC_ALREADY_ACTIVE"
    fi
    if connection_preflight "$mode"; then
      admit_attempt "${VPN_NAME}" "$mode"
      case $? in
        0) run_admitted_connection "${VPN_NAME}" "$mode"; outcome=$? ;;
        2) outcome="$VPN_RC_ALREADY_ACTIVE" ;;
        *) outcome="$VPN_RC_ATTEMPT_FAILED" ;;
      esac
    else
      outcome=$?
    fi
  else
    # Interactive profile selection (modern Bash mapfile)
    mapfile -t vpn_names < <(list_profile_names)
    PS3=$'Choose VPN: '
    select option in "${vpn_names[@]}"; do
      if [ "$option" = "Quit" ]; then
        print_warning "You chose to close the app!\n"
        return 0
      fi
      if printf "%s\n" "${vpn_names[@]}" | grep -qx -- "$option"; then
        load_profile_fields "$option"
        if ! ensure_profile_not_running; then
          continue
        fi
        if connection_preflight "$mode"; then
          admit_attempt "${VPN_NAME}" "$mode"
          case $? in
            0) run_admitted_connection "${VPN_NAME}" "$mode"; outcome=$? ;;
            2) outcome="$VPN_RC_ALREADY_ACTIVE" ;;
            *) outcome="$VPN_RC_ATTEMPT_FAILED" ;;
          esac
        else
          outcome=$?
        fi
        break
      else
        print_danger "Invalid option! Please choose one of the options above...\n"
      fi
    done
  fi

  # In foreground/service mode run_openconnect blocks for the whole session
  # and cleans up after itself; the post-connect check only makes sense when
  # openconnect daemonized.
  if [ "$mode" != SERVICE ] && [ "${BACKGROUND:-FALSE}" = TRUE ]; then
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
      outcome="$VPN_RC_ATTEMPT_FAILED"
    fi
  fi
  return "$outcome"
}

# Record which profile is connected so `status` can report it.
write_connection_state() {
  ( umask 077
    printf 'profile=%s\nhost=%s\nconnected_at=%s\n' \
      "${VPN_NAME}" "${VPN_HOST}" "$(date '+%Y-%m-%d %H:%M:%S')" > "$STATE_FILE_PATH"
  )
}

# ------------------- connection_preflight / run_admitted_connection --------
#
# `connect()` used to do everything in one function, and spent a TOTP code or
# read a Duo passcode at the very top of it — before certificate validation,
# before the helper/prompt mode decision, before anything that could reject
# the connection for a reason that has nothing to do with credentials. That
# meant an unattended attempt that was always going to be refused for a
# locally-decidable reason still paid the cost of an admitted attempt. See
# the CHANGELOG entry and PRIVILEGED-HELPER-DESIGN.md's rate-limiter
# invariant 8: connection_preflight() below is everything that can be decided
# WITHOUT touching a credential or its one-time value, run BEFORE
# admit_attempt() (outcome.sh) is ever called; run_admitted_connection() runs
# only once admission has already been granted.
#
# Mode selection sets _VPN_CONNECT_MODE (helper|prompt) for
# run_admitted_connection to dispatch on, so the decision is made exactly
# once, in preflight, rather than repeated.
_VPN_CONNECT_MODE=""

connection_preflight() {
  local mode="$1"   # SERVICE | INTERACTIVE
  _VPN_CONNECT_MODE=""

  if [ -z "${VPN_HOST}" ]; then
    print_danger "Variable 'VPN_HOST' is not declared! Update it in %s ...\n" "${PROFILES_FILE}"
    return "$VPN_RC_CONFIG"
  fi
  if [ -z "${PROTOCOL}" ]; then
    print_danger "Variable 'PROTOCOL' is not declared! Update it in %s ...\n" "${PROFILES_FILE}"
    return "$VPN_RC_CONFIG"
  fi

  # Each profile gets its own PID/state/log files
  set_profile_paths "${VPN_NAME}"
  print_warning "Process ID (PID) stored in %s ...\n" "${PID_FILE_PATH}"
  print_warning "Logs file (LOG) stored in %s ...\n" "${LOG_FILE_PATH}"

  # SSO / external-browser auth (Okta, Azure AD, Ping + embedded Duo): the
  # whole login happens in a browser, so there is no password or Duo answer to
  # pipe. It needs an interactive desktop session and openconnect >= 9.0.
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    if [ "$mode" = SERVICE ]; then
      print_danger "Profile '%s' uses SSO (interactive browser); it cannot run as a service.\n" "${VPN_NAME}"
      return "$VPN_RC_CONFIG"
    fi
    if [ "$PROTOCOL" = nc ]; then
      print_danger "SSO (external browser) is not supported for the 'nc' protocol.\n"
      return "$VPN_RC_CONFIG"
    fi
    require_openconnect_sso || return "$VPN_RC_CONFIG"
  fi

  # A missing password (for a profile that isn't cert-only) is exactly as
  # locally decidable as a missing TOTP seed below, and was previously only
  # discovered inside migrate_or_fetch_password (profiles.sh) -- AFTER
  # admission, spending an unattended attempt on something preflight could
  # have caught. Existence only, matching invariant 8's carve-out: this reads
  # whether a secret is present, never a one-time value, and never the
  # password itself into anything that gets submitted here.
  if [ "${VPN_AUTH_MODE:-password}" != sso ] && [ -z "${VPN_CLIENT_CERT:-}" ] \
      && [ "$mode" = SERVICE ] && [ -z "$(secrets_get "${VPN_NAME}" password)" ] && [ -z "$VPN_PASSWD" ]; then
    print_danger "No stored password for '%s' and service mode cannot prompt. Store it first: %s set-secret '%s' password\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
    return "$VPN_RC_CONFIG"
  fi

  # TOTP eligibility only — a stored seed exists, and oathtool is present.
  # Generating the code itself happens in run_admitted_connection, as late as
  # possible: a curve delay here could let a one-time code go stale before
  # it's ever submitted (see totp_wait_for_fresh_step, outcome.sh).
  if [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" = totp ]; then
    require_oathtool || return "$VPN_RC_CONFIG"
    if [ "$mode" = SERVICE ] && [ -z "$(secrets_get "${VPN_NAME}" token_secret)" ]; then
      print_danger "No TOTP secret stored for '%s' and service mode cannot prompt. Store it first: %s set-secret '%s' token_secret\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
      return "$VPN_RC_CONFIG"
    fi
  fi

  # Duo passcodes are one-time values, entered in run_admitted_connection, as
  # late as possible — only the service-incompatibility fact is checked here.
  if [ "$mode" = SERVICE ] && [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" != totp ] && [ "$VPN_DUO2FAMETHOD" = "passcode" ]; then
    print_danger "Profile '%s' uses a Duo passcode, which needs interactive input; it cannot run as a service. Use push/phone/sms instead.\n" "${VPN_NAME}"
    return "$VPN_RC_CONFIG"
  fi

  set_protocol_description
  set_2fa_method_description

  _preflight_verify_certificate || return "$?"

  print_primary "Starting the %s on %s using %s ...\n" "${VPN_NAME}" "${VPN_HOST}" "${PROTOCOL_DESCRIPTION}"
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    print_primary "Connecting via SSO (external browser) — complete the login in the window that opens ...\n"
  elif [ "$VPN_TOKEN_MODE" = totp ]; then
    print_primary "Connecting with a TOTP authenticator code ...\n"
  elif [ -z "$VPN_DUO2FAMETHOD" ]; then
    print_warning "Connecting without 2FA (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
  else
    print_primary "Connecting with Two-Factor Authentication (2FA) from Duo (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
  fi

  # Helper mode when it is available (§16 step 8): authenticate unprivileged,
  # and let vpn-up-helper establish the tunnel from the cookie. Prompt mode
  # stays the fallback and the compatibility path — it keeps extraArgs and
  # split tunnelling working, at the cost of a sudo password.
  if [ "${VPN_UP_FORCE_PROMPT_MODE:-FALSE}" != TRUE ] && helper_mode_usable; then
    if profile_id_ensure "${VPN_NAME}" >/dev/null; then
      translate_extra_args "${VPN_EXTRA_ARGS:-}" || return "$VPN_RC_CONFIG"
      _VPN_CONNECT_MODE="helper"
      return 0
    fi
    print_warning "Could not establish a profile id; falling back to prompt mode.\n"
  fi

  # Prompt mode. For a service, prove the raw-openconnect sudo policy now,
  # cache-independently and by LISTING only (never by executing a binary that
  # may be user-writable) — rather than discovering it deep inside
  # run_openconnect after everything else has already run.
  if [ "$mode" = SERVICE ]; then
    command -v vu_legacy_grant_state >/dev/null 2>&1 || . "${PROGRAM_PATH}/helperinstall.sh"
    local oc
    if vu_tools_resolve >/dev/null 2>&1 && oc="$(command -v openconnect 2>/dev/null)" && [ -n "$oc" ] \
        && [ "$(vu_legacy_grant_state "$oc")" = yes ]; then
      : # proven passwordless
    else
      print_danger "Service mode requires a passwordless sudoers rule for openconnect (see README), and none could be proven.\n"
      return "$VPN_RC_POLICY"
    fi
  fi
  _VPN_CONNECT_MODE="prompt"
  return 0
}

# Certificate preflight (§3.0.1 of the design change): distinguishes "could
# not obtain a certificate to evaluate at all" (transient — treated like the
# network gate) from "obtained one, and it failed validation" (a real,
# human-actionable problem). Never inferred from an OpenSSL return-code
# taxonomy: the only evidence used is whether a certificate was obtained.
_preflight_verify_certificate() {
  if [ -n "$SERVER_CERTIFICATE" ]; then
    case "$SERVER_CERTIFICATE" in
      pin-sha256:*)
        if ! command -v openssl >/dev/null 2>&1; then
          print_danger "openssl is required to verify the gateway certificate.\n"
          return "$VPN_RC_CONFIG"
        fi
        local actual
        if ! actual="$(fetch_server_pin "${VPN_HOST}" 2>/dev/null)" || [ -z "$actual" ]; then
          print_danger "Could not reach %s to check its certificate.\n" "${VPN_HOST}"
          return "$VPN_RC_NO_NETWORK"
        fi
        if [ "$actual" != "$SERVER_CERTIFICATE" ]; then
          print_danger "The certificate presented by %s does not match the configured pin. Refusing to connect.\n" "${VPN_HOST}"
          return "$VPN_RC_CONFIG"
        fi
        ;;
      *)
        # Legacy (SHA-1) pin: preserved exactly as before — a warning, not a
        # preflight rejection. This project does not implement a SHA-1
        # comparison here; OpenConnect itself still honours the pin at connect.
        # A reachability check still belongs here, though: without one, a
        # legacy-pin profile with a down gateway sails through preflight and
        # only fails once admission has already spent an attempt.
        if ! command -v openssl >/dev/null 2>&1; then
          print_danger "openssl is required to verify the gateway certificate.\n"
          return "$VPN_RC_CONFIG"
        fi
        if ! gateway_tls_reachable "${VPN_HOST}"; then
          print_danger "Could not reach %s to check its certificate.\n" "${VPN_HOST}"
          return "$VPN_RC_NO_NETWORK"
        fi
        print_warning "serverCertificate uses a legacy (SHA1) pin; SHA1 is deprecated. Run '%s pin %s' to get a pin-sha256 value.\n" "${DISPLAY_NAME}" "${VPN_HOST}"
        ;;
    esac
  else
    if ! command -v openssl >/dev/null 2>&1; then
      print_danger "openssl is required to verify the gateway certificate, and no pin is configured.\n"
      return "$VPN_RC_CONFIG"
    fi
    if ! gateway_tls_reachable "${VPN_HOST}"; then
      print_danger "Could not reach %s to check its certificate.\n" "${VPN_HOST}"
      return "$VPN_RC_NO_NETWORK"
    fi
    if ! verify_gateway_cert "${VPN_HOST}"; then
      # Reachability and trust are two SEPARATE TLS transactions, so the
      # gateway could have gone away in between them -- a conservative
      # re-check keeps that ambiguous case transient rather than terminal.
      # Only a gateway that is STILL reachable right now, yet still fails
      # trust, is reported as an actual certificate problem.
      if gateway_tls_reachable "${VPN_HOST}"; then
        print_danger "The certificate of %s does NOT validate against the system trust store, and no pin is configured. Refusing to connect.\n" "${VPN_HOST}"
        print_pin_instructions "${VPN_HOST}"
        return "$VPN_RC_CONFIG"
      fi
      print_danger "Could not reach %s to check its certificate.\n" "${VPN_HOST}"
      return "$VPN_RC_NO_NETWORK"
    fi
  fi
  return 0
}

# Runs only after admit_attempt() has granted admission. A single explicit
# exit path, not a `trap ... RETURN`: a trap here would depend on `functrace`
# staying off process-wide, which nothing asserts anywhere (see
# PRIVILEGED-HELPER-DESIGN.md's rate-limiter section for why that draft was
# withdrawn). Ownership is released exactly once, right here, on every branch
# — including a signal: an external kill is deliberately NOT handled by a
# TERM/INT trap either, because a locked release there could deadlock the
# very process it's meant to clean up (see the design doc); the next
# admit_attempt call reclaims a killed process's ownership the ordinary way.
run_admitted_connection() {
  local name="$1" mode="$2" rc=0

  if [ "$_VPN_CONNECT_MODE" = helper ]; then
    if ! helper_sudo_prepare; then
      print_danger "sudo authentication failed; cannot start the tunnel.\n"
      rc="$VPN_RC_POLICY"
    fi
  elif [ "$mode" != SERVICE ]; then
    # SERVICE-mode prompt policy was already proven in connection_preflight;
    # only the interactive session needs authorizing here, immediately
    # before it's used, so a long admission wait can't leave a stale cache.
    if ! sudo -v; then
      print_danger "sudo authentication failed; cannot start openconnect.\n"
      rc="$VPN_RC_POLICY"
    fi
  fi

  VPN_SECOND_FACTOR=""
  if [ "$rc" = 0 ] && [ "${VPN_AUTH_MODE:-password}" != sso ]; then
    migrate_or_fetch_password || rc="$VPN_RC_CONFIG"
  fi

  if [ "$rc" = 0 ] && [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" = totp ]; then
    local seed; seed="$(secrets_get "${VPN_NAME}" token_secret)"
    if [ -z "$seed" ]; then
      # mode=SERVICE already refused this in connection_preflight.
      read -r -s -p "Enter the TOTP secret (base32) for ${VPN_NAME}: " seed; echo
      [ -n "$seed" ] && secrets_set "${VPN_NAME}" token_secret "$seed"
    fi
    if totp_wait_for_fresh_step "$name"; then
      VPN_SECOND_FACTOR="$(generate_totp "$seed")"
      if [ -z "$VPN_SECOND_FACTOR" ]; then
        print_danger "Could not generate a TOTP code (check the stored secret with: %s set-secret '%s' token_secret).\n" "${DISPLAY_NAME}" "${VPN_NAME}"
        rc="$VPN_RC_CONFIG"
      fi
    else
      # The reservation itself could not be made durable -- generating a
      # code anyway would spend it with no exclusivity guarantee behind it,
      # which is exactly the failure this design exists to prevent.
      print_danger "Could not safely reserve a fresh TOTP step for '%s'; refusing to generate a code.\n" "${VPN_NAME}"
      rc="$VPN_RC_CONFIG"
    fi
    unset seed
  fi

  if [ "$rc" = 0 ] && [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" != totp ] && [ "$VPN_DUO2FAMETHOD" = "passcode" ]; then
    # mode=SERVICE already refused this combination in connection_preflight.
    read -r -p "Enter Duo passcode for ${VPN_NAME}: " VPN_DUO2FAMETHOD
    if [ -z "$VPN_DUO2FAMETHOD" ]; then
      print_danger "No passcode entered; aborting.\n"
      rc="$VPN_RC_CONFIG"
    fi
  fi

  if [ "$rc" = 0 ]; then
    if [ "$_VPN_CONNECT_MODE" = helper ]; then
      connect_via_helper
    else
      run_openconnect
    fi
    rc=$?
  fi

  release_attempt_owner "$name"
  return "$rc"
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

  # A helper-mode tunnel is not tracked by a pid file here: the helper keeps its
  # pid in root-owned state and verifies process identity before signalling, so
  # asking it is both the correct and the only way to stop one. Prompt-mode
  # tunnels still go through the pid-file path below.
  if [ -n "$requested" ] && [ "${VPN_UP_FORCE_PROMPT_MODE:-FALSE}" != TRUE ] && helper_mode_usable; then
    if load_profile_fields "$requested" 2>/dev/null && [ -n "${VPN_PROFILE_ID:-}" ]; then
      local out
      if out="$(stop_via_helper 2>&1)"; then
        printf '%s\n' "$out"
        # "no tunnel recorded" means there was nothing of ours running; fall
        # through so a prompt-mode tunnel for the same profile is still stopped.
        case "$out" in
          *"no tunnel recorded"*|*"no tunnel running"*) : ;;
          *) return 0 ;;
        esac
      else
        print_warning "%s\n" "$out"
      fi
    fi
  fi

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

# Generate the current RFC 6238 TOTP code from a base32 seed. The seed comes from
# the secrets backend and never reaches openconnect — only the short-lived code
# transits (on stdin). It is fed to oathtool on STDIN rather than argv: an argv
# key is visible in the process table to every user on the machine, which
# oathtool's own help calls out as "not recommended on multi-user systems".
generate_totp() {
  printf '%s\n' "$1" | oathtool --totp -b - 2>/dev/null
}

# Securely supply a PKCS#11 PIN (e.g. a YubiKey PIV smartcard) to openconnect
# WITHOUT placing it on argv: reference a transient 0600 file via the RFC 7512
# 'pin-source' URI attribute. Best-effort — if the local GnuTLS build ignores
# pin-source, openconnect simply falls back to prompting on the TTY. Non-pkcs11
# URIs (and plain file keys) are returned unchanged; those rely on openconnect's
# interactive passphrase prompt, since it offers no non-argv feed for them.
_append_pkcs11_pin_source() {
  local uri="$1" pinfile="$2" sep='?'
  case "$uri" in
    pkcs11:*) ;;
    *) printf '%s' "$uri"; return ;;
  esac
  case "$uri" in *\?*) sep='&' ;; esac
  printf '%s%spin-source=file:%s' "$uri" "$sep" "$pinfile"
}

_openconnect_pid_for_pid_file() {
  local pidfile="$1"
  { ps axww -o pid= -o command= 2>/dev/null || ps -eo pid= -o args= 2>/dev/null; } \
    | awk -v pidfile="$pidfile" '
        {
          exe = $2
          sub(/^.*\//, "", exe)
          if (exe == "openconnect" && index($0, "--pid-file") && index($0, pidfile)) {
            pid = $1
          }
        }
        END { if (pid != "") print pid }
      '
}

_record_foreground_openconnect_pid() {
  (
    sleep 3
    local _pid
    _pid="$(_openconnect_pid_for_pid_file "$PID_FILE_PATH")"
    if [ -n "$_pid" ]; then
      printf '%s\n' "$_pid" > "$PID_FILE_PATH"
      notify "VPN Up" "Connected to ${VPN_NAME}"
      run_hooks connected "${VPN_NAME}" "${VPN_HOST}"
    fi
  ) &
}

# Warn (but don't block) about user-supplied extra args. Two classes:
#
#   1. Flags that make openconnect execute another program AS ROOT. openconnect
#      runs under sudo, so --script/--script-tun/--csd-wrapper hand root to
#      whatever they name; --config/--xmlconfig can set those from a file;
#      --external-browser names an opener openconnect runs as root during SSO;
#      and --csd-user enables execution of the gateway-supplied CSD trojan
#      (--csd-user=root runs it as root). Short forms count too: -s, -S, -x.
#      They are legitimately needed (split tunnelling, CSD/trojan wrappers, a
#      session-aware browser opener), so they are passed through — but paired
#      with a passwordless sudoers rule for openconnect they are a
#      root-execution path, so say so loudly.
#      NOTE: this warning is a footgun guardrail, NOT a security boundary. A
#      NOPASSWD rule naming the openconnect binary lets anything running as this
#      user invoke openconnect directly with these same flags, bypassing vpn-up
#      entirely. The boundary has to live in sudoers (see SECURITY.md).
#   2. Flags vpn-up already manages — overriding these can break the connection
#      or status/stop.
_warn_extra_arg_privileged() {
  local tok base
  for tok in "$@"; do
    base="${tok%%=*}"
    case "$base" in
      --script|-s|--script-tun|-S|--csd-wrapper|--csd-user|--config|--xmlconfig|-x|--external-browser)
        print_danger "extraArgs contains '%s': openconnect runs as root, so this executes a program (or reads a config that can name one) WITH ROOT PRIVILEGES. Passing it anyway — only point it at something only root can write. See SECURITY.md.\n" "$base" ;;
    esac
  done
}

_warn_extra_arg_collisions() {
  local tok base
  for tok in "$@"; do
    base="${tok%%=*}"
    case "$base" in
      --protocol|-q|--user|--passwd-on-stdin|--background|--servercert|--authgroup|--pid-file|--external-browser|--token-mode|--token-secret|--certificate|-c|--sslkey|-k|--key-password|--proxy)
        print_warning "extraArgs contains '%s', which vpn-up already manages; passing it anyway (may conflict).\n" "$base" ;;
    esac
  done
}

run_openconnect() {
  # Sudo authorization for both modes now happens in run_admitted_connection,
  # before this function is ever called (SERVICE's policy proof lives even
  # earlier, in connection_preflight) — see the design's privilege-split
  # correction: putting an INTERACTIVE `sudo -v` here would leave a stale
  # credential cache if admission had to wait first.

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
  # Optional HTTP/SOCKS proxy (a URL, not a secret — safe on argv).
  [ -n "${VPN_PROXY:-}" ] && args+=(--proxy="$VPN_PROXY")
  # Client-certificate auth (X.509). The cert/key may be a file path or a PKCS#11
  # URI (smartcard / YubiKey PIV) — an identifier, not a secret, so it is safe on
  # argv. A key passphrase / PKCS#11 PIN is a secret and must NOT hit argv: for a
  # pkcs11: URI with a stored 'key_password' we feed the PIN via a transient 0600
  # file (pin-source); a file key's passphrase is prompted interactively.
  local _pin_file="" _cc="${VPN_CLIENT_CERT:-}" _ck="${VPN_CLIENT_KEY:-}"
  if [ -n "$_cc" ]; then
    case "$_cc" in
      pkcs11:*)
        local _pin; _pin="$(secrets_get "${VPN_NAME}" key_password 2>/dev/null)"
        if [ -n "$_pin" ]; then
          _pin_file="${DATA_DIR}/pids/.${PROGRAM_NAME}.$(profile_slug "$VPN_NAME").pin"
          ( umask 077; printf '%s' "$_pin" > "$_pin_file" )
          chmod 600 "$_pin_file" 2>/dev/null || true
          _cc="$(_append_pkcs11_pin_source "$_cc" "$_pin_file")"
          [ -n "$_ck" ] && _ck="$(_append_pkcs11_pin_source "$_ck" "$_pin_file")"
          unset _pin
        fi
        ;;
    esac
    args+=(--certificate="$_cc")
    [ -n "$_ck" ] && args+=(--sslkey="$_ck")
  fi
  # Extra user-supplied openconnect args (advanced). Tokenized with xargs so
  # quotes are respected without eval; appended verbatim before the host.
  if [ -n "${VPN_EXTRA_ARGS:-}" ]; then
    local _extra=() _split _rc
    _split="$(printf '%s\n' "$VPN_EXTRA_ARGS" | xargs -n1 2>/dev/null)"; _rc=$?
    if [ "$_rc" -ne 0 ]; then
      print_warning "Ignoring extraArgs for '%s' (malformed quoting).\n" "$VPN_NAME"
    else
      mapfile -t _extra <<< "$_split"
      [ "${#_extra[@]}" -eq 1 ] && [ -z "${_extra[0]}" ] && _extra=()
      if [ "${#_extra[@]}" -gt 0 ]; then
        _warn_extra_arg_privileged "${_extra[@]}"
        _warn_extra_arg_collisions "${_extra[@]}"
      fi
      [ "${#_extra[@]}" -gt 0 ] && args+=("${_extra[@]}")
    fi
  fi
  args+=("$VPN_HOST")
  args+=(--pid-file "$PID_FILE_PATH")

  # Ensure dirs
  ( umask 077; mkdir -p "${DATA_DIR}/logs" "${DATA_DIR}/pids" )
  chmod 700 "${DATA_DIR}/logs" "${DATA_DIR}/pids"

  # Feed password (and the 2FA answer, if any) on stdin. The second factor is a
  # generated TOTP code (VPN_SECOND_FACTOR) when token mode is active, otherwise
  # the Duo method/passcode. Either way it goes on stdin — never on argv. Create
  # the log file as the unprivileged user with 600 perms and capture openconnect's
  # stderr too (previously `sudo tee ... 2>&1` redirected tee's stderr, not
  # openconnect's, and left a root-owned log in the user's directory).
  local stdin_lines="$VPN_PASSWD"
  local second="${VPN_SECOND_FACTOR:-$VPN_DUO2FAMETHOD}"
  [ -n "$second" ] && stdin_lines+=$'\n'"$second"
  ( umask 077; : > "$LOG_FILE_PATH" )
  local oc_rc=0
  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    # SSO: openconnect opens a browser and needs the controlling TTY, so pipe
    # NOTHING on stdin. Always foreground; capture the PID the same way as the
    # foreground password path so status/stop work during the session.
    write_connection_state
    _record_foreground_openconnect_pid
    sudo openconnect "${args[@]}" 2>&1 | tee -a "$LOG_FILE_PATH"
    local _ps=("${PIPESTATUS[@]}"); oc_rc="${_ps[0]}"
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
    oc_rc=$?
  else
    # Foreground: openconnect only writes --pid-file when backgrounding, so
    # record the PID ourselves (after the tunnel has had time to come up) so
    # status/stop work during a foreground/service session.
    write_connection_state
    _record_foreground_openconnect_pid
    printf "%s\n" "$stdin_lines" \
      | sudo openconnect "${args[@]}" 2>&1 | tee -a "$LOG_FILE_PATH"
    local _ps=("${PIPESTATUS[@]}"); oc_rc="${_ps[1]}"
    # Foreground session over (disconnect or failure): clean our records.
    rm -f "$PID_FILE_PATH" "$STATE_FILE_PATH"
    notify "VPN Up" "Disconnected from ${VPN_NAME:-VPN}"
    run_hooks disconnected "${VPN_NAME:-}" "${VPN_HOST:-}"
  fi

  # Shred the transient PKCS#11 PIN file (openconnect has read it during auth).
  if [ -n "${_pin_file:-}" ] && [ -e "$_pin_file" ]; then
    if command -v shred >/dev/null 2>&1; then shred -u "$_pin_file" 2>/dev/null || rm -f "$_pin_file"
    else rm -f "$_pin_file"; fi
  fi

  # Drop the password and any generated 2FA code from shell memory as soon as
  # they have been piped.
  unset VPN_PASSWD stdin_lines second VPN_SECOND_FACTOR

  # Prompt mode has no refusal-marker signal (that's a helper-mode-only
  # concept, twophase.sh's _helper_run_had_tunnel), so it only ever
  # distinguishes RUN_ENDED from ATTEMPT_FAILED (§6 of the design change) —
  # had_tunnel is always passed as 1. outcome_from_run PRINTS the code and
  # returns 0 itself; it must be captured, not relied on for exit-status
  # propagation.
  local _outcome; _outcome="$(outcome_from_run "$oc_rc" 1)"
  return "$_outcome"
}
