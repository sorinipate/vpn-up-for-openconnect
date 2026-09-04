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

# Filesystem-safe slug for a profile name (spaces etc. become '_'). Lossy by
# design (see profile_key() below) — collapses distinct names like "Work VPN"
# and "Work/VPN" to the same string, so it's only ever a human-readable
# prefix, never used alone to build a path two different profiles could share.
profile_slug() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

# Portable stat wrappers. GNU form (-c) first: BSD stat fails on -c so the
# fallback fires, whereas GNU stat treats -f as "filesystem info" and would
# SUCCEED with garbage if tried first.
file_owner_uid() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1" 2>/dev/null; }
file_mode()      { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# Collision-safe filename stem for a profile: profile_slug()'s output
# (capped so a long name can't blow past a filesystem's filename-component
# limit) plus a full SHA-256 digest of the EXACT name -- profile_slug() alone
# is lossy; the digest is what actually guarantees two differently-named
# profiles never share a file, path, or launchd/systemd identity. Same shape
# as attempt_state_file()'s own key (below), computed independently so that
# function's already-tested, already-shipped filename scheme is untouched.
profile_key() {
  local slug key
  slug="$(profile_slug "$1")" || return 1
  key="$(_profile_state_key "$1")" || return 1
  printf '%.48s.%s' "$slug" "$key"
}

# Point the PID/LOG/STATE globals at a specific profile's files.
# shellcheck disable=SC2034  # globals are consumed by core.sh
set_profile_paths() {
  PID_FILE_PATH="$(profile_pid_file "$1")" || return 1
  STATE_FILE_PATH="$(profile_state_file "$1")" || return 1
  LOG_FILE_PATH="$(profile_log_file "$1")" || return 1
}

# profile_pid_file/profile_state_file/profile_log_file are PURE: no locking,
# no print_* output, no legacy-file awareness -- just a checked path
# computation into the new (collision-safe) namespace. Safe to call from
# anywhere, including inside command substitution: a migration diagnostic
# printed from inside one of these would land INSIDE the captured path
# string (print_warning writes to stdout), which is exactly why legacy
# resolution lives in the separate resolve_profile_runtime_files() below,
# never here.
profile_pid_file() {
  local key; key="$(profile_key "$1")" || return 1
  printf '%s/pids/%s.%s.pid' "$DATA_DIR" "$PROGRAM_NAME" "$key"
}

profile_state_file() {
  local key; key="$(profile_key "$1")" || return 1
  printf '%s/pids/%s.%s.state' "$DATA_DIR" "$PROGRAM_NAME" "$key"
}

profile_log_file() {
  local key; key="$(profile_key "$1")" || return 1
  printf '%s/logs/%s.%s.log' "$DATA_DIR" "$PROGRAM_NAME" "$key"
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

# Shared final check for resolve_profile_runtime_files, below: every path
# through it that concludes "nothing is running for this profile" routes
# through here, so a new-namespace pair that LOOKED stale (read as
# not-currently-live) but was deliberately left UNTOUCHED (see below) still
# blocks that conclusion -- `start` must never proceed as if the namespace
# were clean when this function never actually verified it's safe to treat
# as clean, even though the SAME "dirty" flag is irrelevant when the real
# answer turns out to be "a live connection exists" (those return paths
# bypass this entirely, on purpose).
_rprf_nothing_running() {
  local name="$1" new_pid="$2" new_state="$3" new_dirty="$4"
  if [ "$new_dirty" = 1 ]; then
    print_warning "Stale-looking connection state for '%s' exists (%s / %s) but was not removed here to avoid a race with a concurrent connection attempt; run '%s status' (which already cleans up dead entries) or check manually, then retry.\n" \
      "$name" "$new_pid" "$new_state" "${DISPLAY_NAME}"
    return 1
  fi
  return 0
}

# Which pid/state pair currently represents profile NAME's connection: the
# new (collision-safe) pair if it looks live, otherwise a legacy
# (pre-collision-fix, slug-only) pair -- but ONLY once verified via the
# state file's `profile=` line to belong to this EXACT profile, never merely
# a file's existence. Liveness for EITHER namespace uses is_openconnect_pid()
# on the pid file's content (the same signal this codebase has always used --
# NOT an argv-bound check against ps output, which was tried and reverted:
# ps's rendered command line is not the real argv, and is not a sound basis
# for deciding which process this code is allowed to signal). This does still
# leave PID-reuse open (a stale legacy pid number could be reused by an
# unrelated process): this function only ever READS that signal to decide
# whether to resolve/retire/refuse (never kills anything), so the failure
# mode stays conservative here -- believing "possibly still running" and
# refusing to start a duplicate. It does NOT make _stop_by_pid_file (core.sh,
# unmodified by this change) any safer at actually signalling the right
# process -- that's a real, independent, pre-existing PID-reuse gap, tracked
# separately, not something this fix closes.
#
# Existence alone still matters structurally, independent of the liveness
# method: a new-scheme file can exist but be stale (a failed or older
# connection attempt) while the profile's real connection is still tracked
# in the LEGACY namespace -- so a dead-looking new-scheme pair is left in
# place (never deleted here -- see below) and this function falls through
# to check legacy, rather than stopping at "something exists in the new
# namespace" and missing a live legacy one.
#
# Mutates the filesystem in exactly ONE place: retiring (deleting, NEVER
# renaming) a LEGACY pair once confirmed dead. A live pid file is written
# directly by openconnect itself via --pid-file (run_openconnect), a
# separate root process this shell code cannot lock or safely rename out
# from under -- renaming a possibly-live one is a real race. Deleting a
# CONFIRMED-DEAD legacy pair has no such race, because nothing writes to the
# legacy namespace ever again once every connection targets the new
# namespace. The NEW namespace gets no equivalent deletion, even for a pair
# that looks equally dead: unlike legacy, the new namespace remains actively
# written by every future connection, and there is no per-profile lifecycle
# lock preventing two overlapping `start` invocations for the same profile --
# reading a new-scheme pid file as "not currently live" and then deleting it
# could destroy a different, concurrent connection's just-written files if
# that write landed in the gap between the read and the delete.
#
# Sets RESOLVED_PID_FILE / RESOLVED_STATE_FILE (both possibly empty, meaning
# nothing live exists for this profile in either namespace -- that is
# success, not ambiguity) and returns:
#   0  resolved (including "nothing live found" and "found, but proven to
#      belong to a different profile" -- both are success: NOT this
#      profile's problem to solve)
#   1  AMBIGUOUS -- a legacy pid exists but ownership cannot be proven
#      (no state file, or one with no readable `profile=` line), a
#      confirmed-dead legacy pair could not actually be removed, OR a
#      stale-looking new-namespace pair was left in place (never deleted
#      here) with no live legacy to fall back to either. Callers MUST fail
#      closed here, never treat this the same as "not running": proceeding
#      could open a second tunnel while an unaccounted-for process keeps
#      running, or leave stale, PID-reusable state on disk.
# shellcheck disable=SC2034  # RESOLVED_PID_FILE/RESOLVED_STATE_FILE are consumed by core.sh and setup.sh
resolve_profile_runtime_files() {
  local name="$1"
  RESOLVED_PID_FILE="" RESOLVED_STATE_FILE=""
  local new_pid new_state
  new_pid="$(profile_pid_file "$name")" || return 1
  new_state="$(profile_state_file "$name")" || return 1

  local new_pid_num=""
  [ -e "$new_pid" ] && new_pid_num="$(cat "$new_pid" 2>/dev/null || true)"
  if [ -n "$new_pid_num" ] && is_openconnect_pid "$new_pid_num"; then
    RESOLVED_PID_FILE="$new_pid"; RESOLVED_STATE_FILE="$new_state"
    return 0
  fi
  # This function NEVER deletes new-namespace files, even ones that look
  # stale -- see the header comment above. Just mark it dirty and move on;
  # cleanup is left to status()'s own pre-existing, unmodified stale-pid
  # pruning, which a user can trigger on demand.
  local new_dirty=0
  { [ -e "$new_pid" ] || [ -e "$new_state" ]; } && new_dirty=1

  local slug; slug="$(profile_slug "$name")" || return 1
  local legacy_pid="${DATA_DIR}/pids/${PROGRAM_NAME}.${slug}.pid"
  local legacy_state="${DATA_DIR}/pids/${PROGRAM_NAME}.${slug}.state"
  if [ ! -e "$legacy_pid" ] && [ ! -e "$legacy_state" ]; then
    _rprf_nothing_running "$name" "$new_pid" "$new_state" "$new_dirty" || return 1
    return 0
  fi

  local owner=""
  [ -e "$legacy_state" ] && owner="$(head -n 1 "$legacy_state" 2>/dev/null | sed -n 's/^profile=//p')"
  if [ -z "$owner" ]; then
    print_warning "Legacy connection state for slug '%s' exists (%s) but there is no state file to prove which profile it belongs to; refusing to proceed until this is resolved. Check manually (e.g. 'ps') and remove it if stale.\n" \
      "$slug" "$legacy_pid"
    return 1
  fi
  if [ "$owner" != "$name" ]; then
    # Proven to belong to a different profile -- our own new-namespace
    # dirty tracking still applies, since that's about OUR stale new-scheme
    # files, unrelated to this legacy pair being someone else's.
    _rprf_nothing_running "$name" "$new_pid" "$new_state" "$new_dirty" || return 1
    return 0
  fi

  local legacy_pid_num=""
  [ -e "$legacy_pid" ] && legacy_pid_num="$(cat "$legacy_pid" 2>/dev/null || true)"
  if [ -n "$legacy_pid_num" ] && is_openconnect_pid "$legacy_pid_num"; then
    RESOLVED_PID_FILE="$legacy_pid"; RESOLVED_STATE_FILE="$legacy_state"
    return 0   # a live connection IS the answer, regardless of new_dirty
  fi

  # Confirmed dead (no live openconnect process for this pid number):
  # retire, and VERIFY the removal actually happened -- stale,
  # PID-reusable state left behind on disk is exactly what this whole check
  # exists to prevent, so a caller must not proceed as if cleanup succeeded
  # when it didn't.
  rm -f "$legacy_pid" "$legacy_state" 2>/dev/null
  if [ -e "$legacy_pid" ] || [ -e "$legacy_state" ]; then
    print_warning "Could not remove stale legacy connection state for '%s' (%s / %s); left in place.\n" "$name" "$legacy_pid" "$legacy_state"
    return 1
  fi
  _rprf_nothing_running "$name" "$new_pid" "$new_state" "$new_dirty" || return 1
  return 0
}

profile_vpn_running() {
  resolve_profile_runtime_files "$1" || return 1   # ambiguous -- caller must NOT read this as "not running"
  [ -n "$RESOLVED_PID_FILE" ]
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
    file="$(profile_log_file "$profile")" || { print_danger "Could not determine the log file path for '%s'.\n" "$profile"; return 1; }
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
