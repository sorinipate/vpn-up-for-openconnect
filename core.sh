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
  set_profile_paths "$VPN_NAME" || return 1
  # Called directly rather than via profile_vpn_running(): that wrapper's
  # boolean return can't distinguish "not running" from "ambiguous legacy
  # state" (both come back false), and conflating them here would let a
  # profile with unresolvable legacy connection state start a second tunnel.
  if ! resolve_profile_runtime_files "$VPN_NAME"; then
    print_danger "Cannot determine whether '%s' is already running (unresolvable legacy connection state); resolve it manually before starting.\n" "${VPN_NAME}"
    return 1
  fi
  if [ -n "$RESOLVED_PID_FILE" ]; then
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

# Convert an epoch (seconds) to the local "YYYY-MM-DD HH:MM:SS" format,
# portable across BSD/macOS date (`-r <epoch>` reads epoch seconds directly)
# and GNU/Linux date (whose `-r` means "mtime of FILE", so it fails on a
# bare number and falls through to `-d @<epoch>`, which GNU understands).
_epoch_to_local() {
  local epoch="$1"
  date -r "$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null \
    || date -d "@$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null
}

# Record which profile is connected so `status` can report it.
#
# $1 (optional): the epoch this call is actually vouching for — defaults to
# now. Prompt-mode/legacy call sites only ever have "now" to offer; the
# helper-mode poller (twophase.sh) passes the real, script-confirmed
# last_connected_epoch instead, so `Since:` reflects when the tunnel was
# really established rather than when a poller happened to notice it.
# $2 (optional): "verified" or "heuristic" (default) — see status()'s
# strict, backward-compatible parsing in _print_state_details.
write_connection_state() {
  local epoch="${1:-$(date +%s)}"
  local evidence="${2:-heuristic}"
  ( umask 077
    printf 'profile=%s\nhost=%s\nconnected_at=%s\nconnected_at_epoch=%s\nevidence=%s\n' \
      "${VPN_NAME}" "${VPN_HOST}" "$(_epoch_to_local "$epoch")" "$epoch" "$evidence" > "$STATE_FILE_PATH"
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

# Set by _prepare_pkcs11_pin (below) to a transient PIN-source file's path,
# shared by run_openconnect (prompt mode) and phase_one_authenticate
# (twophase.sh, helper mode) so both dispatch paths use the one fetch
# run_admitted_connection makes, rather than each fetching (or, previously,
# one of them never fetching at all) independently.
_VPN_PIN_FILE=""

# Set by run_openconnect_helper (twophase.sh) to 1 or 0 -- did THIS admitted
# attempt reach a genuine, script-confirmed tunnel-up -- or left as "" when
# no such signal exists (prompt mode, always; helper mode with an old
# client/helper pair). Reset to "" before every dispatch below, never carried
# over from a previous attempt, since a stale "1" from an earlier connection
# read as this attempt's own verdict would be exactly the kind of false
# assurance record_attempt_verification (outcome.sh) exists to avoid.
_VPN_LAST_ATTEMPT_VERIFIED=""

# Distinguishes "this key is not stored" from "the backend itself could not
# be read" (e.g. the openssl vault failed to decrypt, or a Keychain/Secret
# Service call errored) -- a bare `[ -z "$(secrets_get ...)" ]` throws that
# signal away entirely, since command substitution only keeps the exit
# status of the FINAL command in an `if`/`[` test, not of the substitution
# itself. Reproduced directly: a faulted vault decrypt made secrets_get
# return non-zero, and the bare `-z` test still read that as "no stored
# password", permanently stopping the service (VPN_RC_CONFIG) for what was
# actually a transient backend problem -- exactly the kind of condition
# invariant 8's terminal-failure codes are not meant to cover.
#
# secrets_get()'s own exit status carries this correctly for the
# openssl/file backends (secrets_get_openssl's `_vault_decrypt() || return
# 1` really does mean "backend error"; an empty-but-zero result really does
# mean "absent") but NOT for Keychain or Linux Secret Service, which fold
# "absent" and "backend error" into overlapping exit statuses of their own
# (see _secret_check_keychain / _secret_check_secrettool, encryption.sh, for
# what each of those two actually distinguishes and how) -- so this dispatches
# on backend rather than reading secrets_get()'s status directly. Falls back
# to the generic secrets_get()-based check whenever encryption.sh hasn't been
# sourced (secrets_backend undefined) -- true of several existing unit tests
# that stub secrets_get() directly without a real backend behind it -- since
# that fallback is the openssl/file-backend logic anyway.
#
# On success (0), prints the fetched value to stdout: this is a single
# backend round-trip that both checks AND fetches, deliberately. Review
# round 5 (BLOCKER #2) found that the previous two-call shape -- this
# function to check, then a SEPARATE secrets_get() to actually read the value
# -- left a real gap between them where the backend could fail in between
# (preflight said present; the real fetch moments/an admission-wait later saw
# a transient error and had no way to distinguish that from "was never
# there"), and for the openssl vault backend the same shape was worse than a
# race: it decrypted the vault twice, prompting for the passphrase twice in
# an interactive session. Every call site now uses the value this prints
# instead of calling secrets_get() again. Preflight call sites that only need
# existence (invariant 8: never touch the value itself before admission)
# MUST redirect this to /dev/null rather than leave it on stdout, or the
# secret leaks onto the terminal/log the moment this function is called bare.
_secret_check() {
  local profile="$1" field="$2" b="" k val
  command -v secrets_backend >/dev/null 2>&1 && b="$(secrets_backend)"
  case "$b" in
    keychain)
      k="$(secrets_key "$profile" "$field")"
      _secret_check_keychain "$k"
      ;;
    secret-tool)
      k="$(secrets_key "$profile" "$field")"
      _secret_check_secrettool "$k"
      ;;
    *)
      if val="$(secrets_get "$profile" "$field")"; then
        if [ -n "$val" ]; then printf '%s' "$val"; return 0; fi
        return 1
      fi
      return 2
      ;;
  esac
}

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

  # A pkcs11: URI that embeds its own PIN (RFC 7512 pin-value/pin-source)
  # bypasses the managed key_password/_prepare_pkcs11_pin path entirely --
  # the PIN would sit in profiles.xml and on OpenConnect's argv in the
  # clear (review round 9, BLOCKER #1; see _pkcs11_uri_embeds_pin above).
  # Checked unconditionally, not just under SERVICE: unlike the
  # existence-only checks below (a human can supply a MISSING value
  # interactively), this profile is actively misconfigured, and an
  # INTERACTIVE run would put the embedded PIN on argv exactly the same
  # way. A syntax check on a locally-held string, so it costs nothing and
  # is not gated by mode.
  if _pkcs11_uri_embeds_pin "${VPN_CLIENT_CERT:-}" || _pkcs11_uri_embeds_pin "${VPN_CLIENT_KEY:-}"; then
    print_danger "Profile '%s' embeds a PIN directly in its PKCS#11 URI (pin-value/pin-source). Remove it from the URI and store the PIN instead: %s set-secret '%s' key_password\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
    return "$VPN_RC_CONFIG"
  fi

  # Each profile gets its own PID/state/log files. A fresh connection always
  # writes into the new (collision-safe) namespace, unconditionally -- never
  # touches legacy paths, which is the other half of what makes "never
  # rename a live legacy file" correct: nothing writes to the legacy
  # location again after this point.
  set_profile_paths "${VPN_NAME}" || return "$VPN_RC_CONFIG"
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
    if ! protocol_supports_sso "$PROTOCOL"; then
      print_danger "SSO (external browser) is not supported for the '%s' protocol.\n" "$PROTOCOL"
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
      && [ "$mode" = SERVICE ] && [ -z "$VPN_PASSWD" ]; then
    # >/dev/null: existence only, per invariant 8 -- _secret_check's value
    # output must never reach here, only its status.
    _secret_check "${VPN_NAME}" password >/dev/null
    case $? in
      0) : ;;
      1)
        print_danger "No stored password for '%s' and service mode cannot prompt. Store it first: %s set-secret '%s' password\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
        return "$VPN_RC_CONFIG" ;;
      2)
        print_danger "Could not read the secrets store to check for a stored password for '%s'; will retry.\n" "${VPN_NAME}"
        return "$VPN_RC_SECRETS_UNAVAILABLE" ;;
    esac
  fi

  # TOTP eligibility only — a stored seed exists, and oathtool is present.
  # Generating the code itself happens in run_admitted_connection, as late as
  # possible: a curve delay here could let a one-time code go stale before
  # it's ever submitted (see totp_wait_for_fresh_step, outcome.sh).
  if [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" = totp ]; then
    require_oathtool || return "$VPN_RC_CONFIG"
    if [ "$mode" = SERVICE ]; then
      # >/dev/null: existence only, same as the password check above.
      _secret_check "${VPN_NAME}" token_secret >/dev/null
      case $? in
        0) : ;;
        1)
          print_danger "No TOTP secret stored for '%s' and service mode cannot prompt. Store it first: %s set-secret '%s' token_secret\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
          return "$VPN_RC_CONFIG" ;;
        2)
          print_danger "Could not read the secrets store to check for a stored TOTP secret for '%s'; will retry.\n" "${VPN_NAME}"
          return "$VPN_RC_SECRETS_UNAVAILABLE" ;;
      esac
    fi
  fi

  # Duo passcodes are one-time values, entered in run_admitted_connection, as
  # late as possible — only the service-incompatibility fact is checked here.
  if [ "$mode" = SERVICE ] && [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" != totp ] && [ "$VPN_DUO2FAMETHOD" = "passcode" ]; then
    print_danger "Profile '%s' uses a Duo passcode, which needs interactive input; it cannot run as a service. Use push/phone/sms instead.\n" "${VPN_NAME}"
    return "$VPN_RC_CONFIG"
  fi

  # A PKCS#11 client certificate/key needs a stored PIN (key_password) for a
  # service to authenticate without a TTY -- exactly as locally decidable as
  # the missing-password and missing-TOTP-seed checks above, and it belongs
  # here for the same reason: discovering it only in run_admitted_connection
  # (phase 4) means admit_attempt has already charged the rate-limit budget
  # for an attempt that was always going to refuse. Reproduced directly: a
  # SERVICE-mode PKCS#11 profile with no stored key_password sailed through
  # this function with rc=0 before this check existed.
  if [ "$mode" = SERVICE ] && _pkcs11_pin_needed "${VPN_CLIENT_CERT:-}" "${VPN_CLIENT_KEY:-}"; then
    # >/dev/null: existence only, per invariant 8 -- never the PIN itself.
    _secret_check "${VPN_NAME}" key_password >/dev/null
    case $? in
      0) : ;;
      1)
        print_danger "Profile '%s' uses a PKCS#11 client certificate; a service can't enter the PIN. Store it first: %s set-secret '%s' key_password\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
        return "$VPN_RC_CONFIG" ;;
      2)
        print_danger "Could not read the secrets store to check for a stored PKCS#11 PIN for '%s'; will retry.\n" "${VPN_NAME}"
        return "$VPN_RC_SECRETS_UNAVAILABLE" ;;
    esac
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
    # Preflight only proved a secret existed at that snapshot in time
    # (invariant 8); admission may then have waited, and the backend can
    # fail in between -- migrate_or_fetch_password returns 2, distinctly
    # from 1 ("genuinely no password stored"), when the backend itself could
    # not be read, so that case reaches VPN_RC_SECRETS_UNAVAILABLE (retry)
    # rather than the terminal VPN_RC_CONFIG a real "no password" gets.
    migrate_or_fetch_password "$mode"
    case $? in
      0) : ;;
      2) rc="$VPN_RC_SECRETS_UNAVAILABLE" ;;
      *) rc="$VPN_RC_CONFIG" ;;
    esac
  fi

  # PKCS#11 PIN staging happens here, before any one-time value is touched --
  # not after, as an earlier version of this code had it. _prepare_pkcs11_pin
  # can call out to Keychain, Secret Service, or the encrypted vault and
  # perform filesystem I/O, none of which is instant. Leaving it after TOTP
  # generation or Duo-passcode entry meant a one-time value could be produced
  # and then sit idle while this ran -- exactly the class of staleness
  # totp_wait_for_fresh_step already exists to prevent, just reintroduced one
  # step later. Restoring "nothing potentially slow remains between obtaining
  # a one-time factor and submitting it" means this reusable-credential-like
  # step must come before, not after, the one-time value.
  _VPN_PIN_FILE=""
  _VPN_LAST_ATTEMPT_VERIFIED=""
  if [ "$rc" = 0 ]; then
    _prepare_pkcs11_pin "$mode"
    rc=$?
  fi

  # A staged PIN file is a plaintext credential that needs a live cleanup
  # path for as long as it exists. _prepare_pkcs11_pin (above) already
  # installed an unlocked TERM/INT trap the moment it created the file --
  # before the PIN was even written, closing the window an earlier version
  # left between staging and returning to this point (review round 9,
  # BLOCKER #2) -- so there is nothing further to install here; the trap
  # simply stays live through TOTP/Duo-passcode entry and dispatch below,
  # until this function's own epilogue tears it down after shredding the
  # file. This does not need _state_lock (only release_attempt_owner does;
  # see the design doc for why a locked signal handler was rejected there).
  # Verified empirically against real bash behaviour: a trap set on a
  # signal bash is already blocked delivering to a foreground child does not
  # run until that child itself has exited -- so this fires promptly only
  # once the tunnel process (openconnect/sudo, in the dispatch below) has
  # also been signalled, which is how both systemd's control-group kill and
  # launchd's process-group signal terminate a supervised job in practice. A
  # signal delivered to this shell alone, with the tunnel child left
  # untouched, is NOT covered here; doctor_pin_files (dependencies.sh) is
  # the diagnostic backstop for that case and for an unhandled SIGKILL.

  if [ "$rc" = 0 ] && [ "${VPN_AUTH_MODE:-password}" != sso ] && [ "$VPN_TOKEN_MODE" = totp ]; then
    local seed=""
    # One fetch, not check-then-fetch: _secret_check's stdout IS the value on
    # success, so this is the single backend round-trip that both learns the
    # status and (if present) retrieves the seed -- see _secret_check's own
    # comment (above, this file) for why the previous two-call shape was a
    # real gap, not just a style preference.
    seed="$(_secret_check "${VPN_NAME}" token_secret)"
    case $? in
      0) : ;;
      1)
        # Genuinely absent. Preflight is only a snapshot (invariant 8's own
        # wording): admit_attempt may have waited an arbitrary amount of
        # time, and the seed can be deleted (or the profile's token mode
        # changed) in that window. Assuming "SERVICE already refused this in
        # connection_preflight" and falling through to the interactive
        # prompt below was wrong -- reproduced directly: a SERVICE-mode
        # process with no tty actually invoked `read -r -s -p ...` here.
        # INTERACTIVE has no preceding preflight refusal to rely on either
        # way, so it still falls through to the prompt, unchanged.
        if [ "$mode" = SERVICE ]; then
          print_danger "No TOTP secret stored for '%s' and service mode cannot prompt. Store it first: %s set-secret '%s' token_secret\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
          rc="$VPN_RC_CONFIG"
        fi
        ;;
      2)
        if [ "$mode" = SERVICE ]; then
          print_danger "Could not read the secrets store to fetch the TOTP secret for '%s'; will retry.\n" "${VPN_NAME}"
          rc="$VPN_RC_SECRETS_UNAVAILABLE"
        fi
        ;;
    esac
    if [ "$rc" = 0 ] && [ -z "$seed" ]; then
      # mode=SERVICE already refused this in connection_preflight.
      read -r -s -p "Enter the TOTP secret (base32) for ${VPN_NAME}: " seed; echo
      [ -n "$seed" ] && secrets_set "${VPN_NAME}" token_secret "$seed"
    fi
    if [ "$rc" = 0 ]; then
      if totp_wait_for_fresh_step "$name" "$VPN_TOTP_STEP"; then
        VPN_SECOND_FACTOR="$(generate_totp "$seed" "$VPN_TOTP_ALGORITHM" "$VPN_TOTP_DIGITS" "$VPN_TOTP_STEP")"
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

  # Ninth invariant (§15.1 amendment, outcome.sh): feed the genuine tunnel-up
  # signal to the unverified-streak escalation, SERVICE only -- mirroring
  # admit_attempt()'s own "only SERVICE ever consumes rate-limit budget", the
  # escalation this streak feeds is a property of the unattended retry loop,
  # not of an interactive session sitting at a terminal. Strictly AFTER
  # dispatch returns and BEFORE release_attempt_owner, same ordering
  # constraint admit_attempt's own header describes: this can only ever
  # affect a LATER admission decision, never this one.
  if [ "$mode" = SERVICE ]; then
    record_attempt_verification "$name" "$_VPN_LAST_ATTEMPT_VERIFIED"
  fi

  # Single cleanup point for both dispatch modes: openconnect (prompt mode,
  # directly) or phase_one_authenticate (helper mode, unprivileged) has
  # already read the PIN by the time either returns, regardless of outcome.
  # (Helper mode may already have removed it earlier still -- see
  # connect_via_helper, twophase.sh -- in which case this is a harmless no-op.)
  #
  # Shred BEFORE tearing down the trap, not after (review round 9, BLOCKER
  # #2) -- reproduced directly by injecting TERM between an earlier
  # version's `trap - TERM INT` and its shred call: the trap was already
  # gone, so that TERM fell through to the default disposition and killed
  # the process with the PIN file still on disk, unshredded. With the trap
  # still live during the shred, the same signal instead re-enters
  # _shred_pin_file (idempotent -- a second attempt on an already-gone file
  # is a harmless no-op) before terminating, so no ordering of the signal
  # against this cleanup can skip it.
  _shred_pin_file "${_VPN_PIN_FILE:-}"
  trap - TERM INT
  unset _VPN_PIN_FILE

  release_attempt_owner "$name"
  return "$rc"
}

_print_state_details() {
  local statefile="$1" pid="$2"
  if [ -f "$statefile" ]; then
    local profile host connected_at evidence
    profile="$(awk -F= '$1=="profile"{print substr($0,9); exit}' "$statefile")"
    host="$(awk -F= '$1=="host"{print substr($0,6); exit}' "$statefile")"
    connected_at="$(awk -F= '$1=="connected_at"{print substr($0,14); exit}' "$statefile")"
    # Strict, backward-compatible parsing: only the exact literal "verified"
    # ever earns the stronger label. Missing, unrecognized, or malformed
    # values (an old state file, a rolled-back build) all read as heuristic
    # — never fail open into an unproven "verified" claim.
    evidence="$(awk -F= '$1=="evidence"{print substr($0,10); exit}' "$statefile")"
    local qualifier
    if [ "$evidence" = verified ]; then
      qualifier="(verified: OpenConnect connect event observed for this session)"
    else
      qualifier="(unverified: process liveness only)"
    fi
    print_primary "  Profile : %s\n" "${profile:-unknown}"
    print_primary "  Gateway : %s\n" "${host:-unknown}"
    print_primary "  Since   : %s  %s\n" "${connected_at:-unknown}" "$qualifier"
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
    if ! resolve_profile_runtime_files "$requested"; then
      print_danger "Cannot determine whether '%s' is running (unresolvable legacy connection state); resolve it manually.\n" "$requested"
      return 1
    fi
    if [ -z "$RESOLVED_PID_FILE" ]; then
      print_warning "VPN profile '%s' is not running.\n" "$requested"
      return 0
    fi
    files=("$RESOLVED_PID_FILE")
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
#
# algo/digits/step default to oathtool's own implicit defaults (SHA1/6/30s) so
# an existing profile with no <totpAlgorithm>/<totpDigits>/<totpStepSeconds>
# behaves exactly as before.
generate_totp() {
  local seed="$1" algo="${2:-SHA1}" digits="${3:-6}" step="${4:-30}"
  printf '%s\n' "$seed" | oathtool "--totp=${algo}" -b -d "$digits" -s "${step}" - 2>/dev/null
}

# Percent-encode a byte string for use as a pkcs11: URI query-attribute value
# (RFC 7512). DATA_DIR (and so the PIN file path) is configurable via
# VPN_UP_HOME/XDG_CONFIG_HOME and is not guaranteed to be URI-safe -- a space
# is not a valid pk11-qattr character, and '&' / '#' / '%' are themselves
# delimiters within the pkcs11 URI (query-attribute separator, fragment
# start, and the percent-encoding escape itself). Reproduced directly: an
# unencoded path of "/tmp/VPN Up/pin&copy#1" produced
# "pkcs11:...?pin-source=file:/tmp/VPN Up/pin&copy#1", which is not a valid
# representation of that filename -- a URI parser would read "copy#1" as a
# fragment and "Up/pin" as an unrelated, unintended query attribute. Leaves
# '/' unescaped: it is not a delimiter to the OUTER pkcs11 URI (only '&', '#'
# and '=' are, within the query component), and it must survive as the path
# separator for the nested 'file:' value to remain a usable path.
_uri_encode() {
  local LC_ALL=C
  local s="$1" i c out=""
  for (( i=0; i<${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~/-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
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
  printf '%s%spin-source=file:%s' "$uri" "$sep" "$(_uri_encode "$pinfile")"
}

# True when a stored PKCS#11 PIN (key_password) is relevant: either the
# client CERTIFICATE or the client KEY is a pkcs11: URI. Checking only the
# certificate (an earlier version of this code) missed the equally valid,
# documented configuration of a file-path certificate paired with a PKCS#11
# private key -- reproduced directly: clientCertificate=/tmp/cert.pem +
# clientKey=pkcs11:... with a stored key_password never attached the PIN,
# silently falling back to an interactive prompt a service has no TTY to
# answer. This one predicate is shared by every place that needs to know
# "does this profile need a PKCS#11 PIN" -- the setup wizard's PIN offer,
# `service install`'s diagnostics, connection_preflight, and the phase-4
# fetch below -- so there is exactly one definition of that question, not
# four subtly different ones.
_pkcs11_pin_needed() {
  local cert="$1" key="$2"
  case "$cert" in pkcs11:*) return 0 ;; esac
  case "$key"  in pkcs11:*) return 0 ;; esac
  return 1
}

# True when a pkcs11: URI's own query component embeds a PIN directly, via
# RFC 7512's 'pin-value' (the literal PIN, in the clear) or 'pin-source'
# (a path VPN Up does not control) query attribute.
#
# This is not a hypothetical: reproduced directly against this codebase --
# a profile with clientCertificate="pkcs11:id=%01?pin-value=918273" reached
# run_openconnect's argv verbatim (review round 9, BLOCKER #1), so the PIN
# ends up in profiles.xml, in OpenConnect's own process arguments, and
# visible to anything that can inspect the process table -- exactly the
# argv exposure the managed key_password/_prepare_pkcs11_pin path exists to
# avoid. RFC 7512 itself warns pin-value has security consequences and says
# a URI carrying both attributes should be refused; GnuTLS's own PKCS#11
# code checks pin-value BEFORE pin-source, so an embedded pin-value would
# also silently override VPN Up's own managed PIN (the one this project
# fetches from key_password and appends as pin-source) rather than merely
# coexisting with it.
#
# Query attributes are the substring after the URI's first '?', separated by
# '&'; each is checked by its OWN attribute name (the part before its '=')
# rather than by a blunt substring match, so a value that merely happens to
# contain the text "pin-value=" elsewhere could not produce a false
# rejection.
_pkcs11_uri_embeds_pin() {
  local uri="$1" query attr
  case "$uri" in
    pkcs11:*\?*) query="${uri#*\?}" ;;
    *) return 1 ;;
  esac
  local IFS='&'
  local -a attrs
  read -r -a attrs <<<"$query"
  for attr in "${attrs[@]}"; do
    case "${attr%%=*}" in
      pin-value|pin-source) return 0 ;;
    esac
  done
  return 1
}

# Shared by run_admitted_connection's normal cleanup and its TERM/INT trap
# below -- one definition of "how a staged PIN file is destroyed", so the two
# call sites can't drift apart on shred-vs-rm fallback behaviour.
_shred_pin_file() {
  local f="${1:-}"
  [ -n "$f" ] && [ -e "$f" ] || return 0
  if command -v shred >/dev/null 2>&1; then shred -u "$f" 2>/dev/null || rm -f "$f"
  else rm -f "$f"; fi
}

# Fetches a PKCS#11 PIN (the 'key_password' secret) for a pkcs11: client
# certificate or key (see _pkcs11_pin_needed above), and stages it in a
# transient, uniquely-named 0600 file for _append_pkcs11_pin_source above.
# Sets _VPN_PIN_FILE to that file's path only once the PIN has actually been
# written to disk and secured -- never merely attempted -- and leaves it
# empty for a profile that doesn't need one, one with no stored PIN, or (in
# INTERACTIVE mode) a backend/local-I/O error, all of which fall back to
# openconnect's own interactive PIN prompt, exactly as before this function
# existed.
#
# Centralizes what used to be two independent, inconsistent things: a raw
# secrets_get in run_openconnect (prompt mode) with no tri-state handling,
# and NO equivalent at all in the helper path's phase_one_authenticate
# (twophase.sh) -- a service using a PKCS#11 certificate through helper mode
# (the preferred, documented path) could never actually supply a stored PIN
# at all, contradicting the documented unattended-service PKCS#11 feature.
# One phase-4 fetch, shared by both dispatch modes, fixes both gaps at once.
_prepare_pkcs11_pin() {
  local mode="$1"
  _VPN_PIN_FILE=""
  _pkcs11_pin_needed "${VPN_CLIENT_CERT:-}" "${VPN_CLIENT_KEY:-}" || return 0
  local pin=""
  pin="$(_secret_check "${VPN_NAME}" key_password)"
  case $? in
    0)
      # The write is staged into a uniquely-named file (mktemp, not a
      # deterministic profile_slug()-based name -- a secret-bearing file
      # must not risk the same slug collision the state-file identity fix
      # (logging.sh's _profile_state_key) exists to avoid). Any failure
      # below is reported the same way a stored-secret backend error
      # already is: terminal for a service (nothing it can retry into
      # existence on its own), a fallback to the interactive prompt for a
      # human who is present.
      local tmp="" fail=""
      # Captured into a plain variable, NOT interpolated directly into the
      # mktemp command substitution below: $(...) forks its own subshell to
      # run the ENTIRE contained command, including argument expansion, so a
      # bare ${BASHPID} written inline there is evaluated inside THAT
      # transient, already-exiting-by-the-time-mktemp-returns subshell, not
      # the real long-lived process staging the PIN -- reproduced directly
      # while testing this exact line: "$(mktemp ".../pin.${BASHPID}.XXXXXX")"
      # embedded a pid distinct from BOTH $$ and the calling function's own
      # $BASHPID, and one that was already dead the instant mktemp returned.
      # Assigning to a plain variable FIRST freezes the value at the correct
      # scope (variables, unlike $BASHPID itself, are inherited by value into
      # a later subshell fork, not re-evaluated inside it).
      local mypid="$BASHPID"
      if ! ( umask 077; mkdir -p "${DATA_DIR}/pids" ) 2>/dev/null \
          || ! chmod 700 "${DATA_DIR}/pids" 2>/dev/null; then
        fail="create the VPN state directory"
      # $mypid ($BASHPID), not $$, is embedded ahead of mktemp's own random
      # suffix so a leftover file from an abnormal termination (review round
      # 8, HIGH #2) can still be matched to its owning process by `vpn-up
      # doctor` (doctor_pin_files, dependencies.sh) via a liveness check --
      # the same kill-0-not-age pattern already used for attempt ownership
      # (§3.5) -- rather than by guessing from age alone, which would either
      # flag a still-connected multi-hour session or silently ignore a
      # genuinely orphaned file. $$ names the ORIGINATING shell even from
      # inside a subshell, while $BASHPID is always the actual running
      # instance's own pid (review round 9, MEDIUM #3) -- using $$ here left
      # a mismatch against the TERM/INT trap below, which already (and
      # correctly) uses $BASHPID to re-raise against itself: staging inside a
      # subshell would have embedded the wrong pid, so doctor_pin_files could
      # read a genuinely dead owner as still alive via the parent's pid. In
      # vpn-up.command's normal, un-subshelled invocation $$, $BASHPID and
      # $mypid are all the same value, so this changes nothing there.
      elif ! tmp="$(mktemp "${DATA_DIR}/pids/.${PROGRAM_NAME}.pin.${mypid}.XXXXXX" 2>/dev/null)"; then
        fail="create a PIN file"
      else
        # Published as the cleanup target, and the TERM/INT trap installed,
        # the moment the file exists at all -- still empty here, before the
        # PIN is ever written to it. An earlier version did both only in
        # run_admitted_connection, AFTER this whole function had already
        # returned: reproduced directly by injecting TERM immediately after
        # the write below but before that later trap-install ran (review
        # round 9, BLOCKER #2) -- the plaintext PIN was left on disk with
        # nothing watching it. Moving both here closes that window: the
        # file is never unwatched between the instant it can hold a secret
        # and the instant this function returns.
        _VPN_PIN_FILE="$tmp"
        trap '_shred_pin_file "$_VPN_PIN_FILE"; trap - TERM INT; kill -TERM "$BASHPID"' TERM
        trap '_shred_pin_file "$_VPN_PIN_FILE"; trap - TERM INT; kill -INT  "$BASHPID"' INT
        if ! ( umask 077; printf '%s' "$pin" > "$tmp" ); then
          fail="write the PIN file"
        elif ! chmod 600 "$tmp" 2>/dev/null; then
          fail="secure the PIN file"
        fi
        if [ -n "$fail" ]; then
          _shred_pin_file "$tmp"
          _VPN_PIN_FILE=""
        fi
      fi
      unset pin
      if [ -n "$fail" ]; then
        if [ "$mode" = SERVICE ]; then
          print_danger "Could not %s for the PKCS#11 PIN for '%s'; will retry.\n" "$fail" "${VPN_NAME}"
          return "$VPN_RC_SECRETS_UNAVAILABLE"
        fi
        print_danger "Could not %s for the PKCS#11 PIN for '%s'; falling back to an interactive PIN prompt.\n" "$fail" "${VPN_NAME}"
        return 0
      fi
      ;;
    1)
      # No PIN stored. Fine for an interactive caller -- openconnect prompts
      # on the TTY, same as always. A service has no TTY to answer that
      # prompt, so this is a config problem, exactly like a missing password
      # or TOTP seed.
      if [ "$mode" = SERVICE ]; then
        print_danger "Profile '%s' uses a PKCS#11 client certificate; a service can't enter the PIN. Store it first: %s set-secret '%s' key_password\n" "${VPN_NAME}" "${DISPLAY_NAME}" "${VPN_NAME}"
        unset pin
        return "$VPN_RC_CONFIG"
      fi
      ;;
    2)
      if [ "$mode" = SERVICE ]; then
        print_danger "Could not read the secrets store to fetch the PKCS#11 PIN for '%s'; will retry.\n" "${VPN_NAME}"
        unset pin
        return "$VPN_RC_SECRETS_UNAVAILABLE"
      fi
      ;;
  esac
  unset pin
  return 0
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

# Prompt mode has no better evidence than this, ever (see constraint 2 in
# PRIVILEGED-HELPER-DESIGN.md §17.7 / the connection-state design plan): a
# process named `openconnect` still existing 3 seconds after launch. A
# process stuck at an SSO/Duo/CSD prompt at t=3s looks identical to one
# about to succeed, and no amount of additional `ps` polling changes that —
# this narrows one false-positive (the process having already exited), it
# does not and cannot prove a tunnel exists. That's why the human-facing
# notification below says "session started," never "Connected" — helper
# mode's genuine, script-confirmed `reason=connect` signal has earned that
# word (twophase.sh); this path never can.
_record_foreground_openconnect_pid() {
  (
    sleep 3
    local _pid
    _pid="$(_openconnect_pid_for_pid_file "$PID_FILE_PATH")"
    if [ -n "$_pid" ]; then
      printf '%s\n' "$_pid" > "$PID_FILE_PATH"
      write_connection_state "" heuristic
      notify "VPN Up" "VPN session started: ${VPN_NAME}"
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
  # pkcs11: URI with a stored 'key_password', run_admitted_connection has already
  # fetched it (once, before dispatch, shared with the helper path -- see
  # _prepare_pkcs11_pin) and staged it in _VPN_PIN_FILE; a file key's passphrase
  # is prompted interactively, unchanged.
  local _cc="${VPN_CLIENT_CERT:-}" _ck="${VPN_CLIENT_KEY:-}"
  if [ -n "$_cc" ]; then
    if [ -n "${_VPN_PIN_FILE:-}" ]; then
      _cc="$(_append_pkcs11_pin_source "$_cc" "$_VPN_PIN_FILE")"
      [ -n "$_ck" ] && _ck="$(_append_pkcs11_pin_source "$_ck" "$_VPN_PIN_FILE")"
    fi
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
    #
    # write_connection_state is NOT called here: it used to be, but that
    # stamped `Since:` at the moment openconnect was merely about to be
    # launched, not when anything was actually confirmed alive.
    # _record_foreground_openconnect_pid now writes it itself, only once its
    # own liveness probe succeeds.
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
    #
    # write_connection_state is NOT called here — see the SSO branch above
    # for why; _record_foreground_openconnect_pid writes it once its own
    # liveness probe succeeds.
    _record_foreground_openconnect_pid
    printf "%s\n" "$stdin_lines" \
      | sudo openconnect "${args[@]}" 2>&1 | tee -a "$LOG_FILE_PATH"
    local _ps=("${PIPESTATUS[@]}"); oc_rc="${_ps[1]}"
    # Foreground session over (disconnect or failure): clean our records.
    rm -f "$PID_FILE_PATH" "$STATE_FILE_PATH"
    notify "VPN Up" "Disconnected from ${VPN_NAME:-VPN}"
    run_hooks disconnected "${VPN_NAME:-}" "${VPN_HOST:-}"
  fi

  # The transient PKCS#11 PIN file (if any) is shredded once, centrally, by
  # run_admitted_connection's epilogue -- shared with the helper dispatch
  # path, which reads the same file from phase_one_authenticate (twophase.sh).

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
