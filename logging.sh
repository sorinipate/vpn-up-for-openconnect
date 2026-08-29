# logging.sh - simple logging helpers

# Name shown in user-facing messages and hints. PROGRAM_NAME stays the
# internal identifier (data file names, slugs, Keychain namespace) and must
# never change; brew users invoke the command as plain `vpn-up`.
DISPLAY_NAME="${DISPLAY_NAME:-${PROGRAM_NAME%.command}}"

# Legacy single-connection paths; start() switches these to per-profile
# paths via set_profile_paths once a profile is selected.
PID_FILE_PATH="${DATA_DIR}/pids/${PROGRAM_NAME}.pid"
# shellcheck disable=SC2034  # used by core.sh
LOG_FILE_PATH="${DATA_DIR}/logs/${PROGRAM_NAME}.log"
# shellcheck disable=SC2034  # used by core.sh
STATE_FILE_PATH="${DATA_DIR}/pids/${PROGRAM_NAME}.state"

# Filesystem-safe slug for a profile name (spaces etc. become '_').
profile_slug() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

# Portable stat wrappers. GNU form (-c) first: BSD stat fails on -c so the
# fallback fires, whereas GNU stat treats -f as "filesystem info" and would
# SUCCEED with garbage if tried first.
file_owner_uid() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1" 2>/dev/null; }
file_mode()      { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# Point the PID/LOG/STATE globals at a specific profile's files.
# shellcheck disable=SC2034  # globals are consumed by core.sh
set_profile_paths() {
  PID_FILE_PATH="$(profile_pid_file "$1")"
  STATE_FILE_PATH="$(profile_state_file "$1")"
  LOG_FILE_PATH="$(profile_log_file "$1")"
}

profile_pid_file() {
  local slug; slug="$(profile_slug "$1")"
  printf '%s/pids/%s.%s.pid' "$DATA_DIR" "$PROGRAM_NAME" "$slug"
}

profile_state_file() {
  local slug; slug="$(profile_slug "$1")"
  printf '%s/pids/%s.%s.state' "$DATA_DIR" "$PROGRAM_NAME" "$slug"
}

profile_log_file() {
  local slug; slug="$(profile_slug "$1")"
  printf '%s/logs/%s.%s.log' "$DATA_DIR" "$PROGRAM_NAME" "$slug"
}

# Full, normalized SHA-256 of a profile's EXACT name. Used only to key the
# rate-limiter's state file (outcome.sh): profile_slug() above is lossy — a
# tr -c that maps "Work VPN" and "Work/VPN" to the same string — so a file
# keyed on the slug alone would let two differently-named profiles corrupt
# each other's attempt-rate guard. The digest carries identity; the slug
# stays only as a human-readable filename prefix. awk normalizes each tool's
# own label format (sha256sum's trailing filename marker, openssl dgst's
# "SHA2-256(stdin)= " prefix) down to the bare hex digest.
_profile_state_key() {
  local h
  if command -v shasum >/dev/null 2>&1; then
    h="$(printf '%s' "$1" | shasum -a 256 | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    h="$(printf '%s' "$1" | sha256sum | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    h="$(printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}')"
  fi
  if [ -z "$h" ]; then
    print_danger "No sha256 tool (need shasum, sha256sum, or openssl); cannot key service state.\n"
    return 1
  fi
  printf '%s' "$h"
}

# Path to the rate-limiter's per-profile state file (outcome.sh: attempt
# history, TOTP step reservation, in-progress owner marker). NOT the same
# file as profile_state_file() above, which records an ACTIVE tunnel's
# connection details for `status` — this one lives under state/, not pids/,
# and tracks unattended-attempt admission whether or not a tunnel ever comes
# up. The slug is capped so a long profile name cannot blow past a
# filesystem's filename-component limit; the digest never is.
attempt_state_file() {
  local key; key="$(_profile_state_key "$1")" || return 1
  printf '%s/state/%s.%.48s.%s.state' "$DATA_DIR" "$PROGRAM_NAME" \
    "$(profile_slug "$1")" "$key"
}

profile_vpn_running() {
  local pidfile statefile pid
  pidfile="$(profile_pid_file "$1")"
  statefile="$(profile_state_file "$1")"
  [ -f "$pidfile" ] || return 1
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if is_openconnect_pid "$pid"; then
    return 0
  fi
  rm -f "$pidfile" "$statefile"
  return 1
}

show_logs() {
  local follow="" profile="" a file
  for a in "$@"; do
    case "$a" in
      -f) follow=1 ;;
      "") : ;;
      *)  profile="$a" ;;
    esac
  done
  if [ -n "$profile" ]; then
    file="${DATA_DIR}/logs/${PROGRAM_NAME}.$(profile_slug "$profile").log"
  else
    # most recently modified log, falling back to the legacy path
    # shellcheck disable=SC2012  # filenames are program-generated slugs (no newlines)
    file="$(ls -t "${DATA_DIR}/logs/"*.log 2>/dev/null | head -1)"
    [ -n "$file" ] || file="$LOG_FILE_PATH"
  fi
  if [ ! -f "$file" ]; then
    print_warning "No log file yet at %s\n" "$file"
    return 0
  fi
  if [ -n "$follow" ]; then
    tail -f "$file"
  else
    tail -n 50 "$file"
  fi
}

# Color codes are printed separately from the message so they never go
# through printf format processing; data must be passed as arguments to a
# literal format string (e.g. print_warning "Loaded %s\n" "$file").
# shellcheck disable=SC2059  # fmt passthrough is the point; callers pass literal formats
_print_color() { local color="$1" fmt="$2"; shift 2; printf "%b" "$color"; printf -- "$fmt" "$@"; printf "%b" "${RESET:-\x1b[0m}"; }
print_primary() { _print_color "${PRIMARY:-\x1b[36;1m}" "$@"; }
print_success() { _print_color "${SUCCESS:-\x1b[32;1m}" "$@"; }
print_warning() { _print_color "${WARNING:-\x1b[35;1m}" "$@"; }
print_danger()  { _print_color "${DANGER:-\x1b[31;1m}"  "$@"; }

# Returns 1 rather than exiting: called from start()'s call tree, which under
# a service must route every failure through the outcome/service_exit_code
# mapping (outcome.sh) rather than terminate the process directly (see the
# CHANGELOG entry for this change). Every call site checks the return value.
check_file_existence() {
  local file_path="$1"; local file_name="$2"
  if [ ! -f "$file_path" ]; then
    printf "%b%s file missing! \n%b" "${DANGER:-\x1b[31;1m}" "$file_name" "${RESET:-\x1b[0m}"
    return 1
  fi
}

# ICMP is often blocked; fall back to a plain HTTP reachability probe.
is_network_available() {
  ping -c 1 1.1.1.1 >/dev/null 2>&1 && return 0
  command -v curl >/dev/null 2>&1 \
    && curl -s --connect-timeout 4 --max-time 6 -o /dev/null "http://captive.apple.com/hotspot-detect.html"
}

# True only if the PID is numeric AND the process is actually openconnect —
# guards against PID reuse and corrupted PID files.
is_openconnect_pid() {
  local pid="$1"
  [ -n "$pid" ] || return 1
  case "$pid" in *[!0-9]*) return 1 ;; esac
  ps -p "$pid" -o comm= 2>/dev/null | grep -q 'openconnect'
}

is_vpn_running() {
  [ -f "$PID_FILE_PATH" ] && is_openconnect_pid "$(cat "$PID_FILE_PATH")"
}

print_current_ip_address() {
  local current_ip
  current_ip=$(curl -s --max-time 5 https://api.ipify.org) || current_ip="(unavailable)"
  print_primary "Current IP address: %s\n" "${current_ip:-"(unavailable)"}"
}
