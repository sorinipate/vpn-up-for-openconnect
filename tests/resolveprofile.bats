#!/usr/bin/env bats
# Tests for resolve_profile_runtime_files (logging.sh): tri-state ownership,
# dead-legacy retirement, and the "never delete a new-namespace file" rule
# that keeps it from racing a concurrent `start` for the same profile. See
# logging.sh's own header comment on resolve_profile_runtime_files for the
# full rationale this coverage is checking.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  export DISPLAY_NAME="vpnup-test"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  print_warning() { printf -- "$1" "${@:2}"; }
  print_danger()  { printf -- "$1" "${@:2}"; }
  print_success() { printf -- "$1" "${@:2}"; }
  print_primary() { printf -- "$1" "${@:2}"; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
}

_legacy_pid_path()   { printf '%s/pids/%s.%s.pid'   "$DATA_DIR" "$PROGRAM_NAME" "$(profile_slug "$1")"; }
_legacy_state_path() { printf '%s/pids/%s.%s.state' "$DATA_DIR" "$PROGRAM_NAME" "$(profile_slug "$1")"; }

# Writes a legacy (pre-collision-fix, slug-only) pid+state pair for OWNER,
# with a pid FILE CONTENT of PIDNUM, attributed (via the state's `profile=`
# line) to ATTRIBUTED_TO (defaults to OWNER itself).
_write_legacy_pair() {
  local owner="$1" pidnum="$2" attributed_to="${3:-$1}"
  echo "$pidnum" > "$(_legacy_pid_path "$owner")"
  printf 'profile=%s\nhost=h.example.com\n' "$attributed_to" > "$(_legacy_state_path "$owner")"
}

_write_new_pair() {
  local name="$1" pidnum="$2"
  echo "$pidnum" > "$(profile_pid_file "$name")"
  touch "$(profile_state_file "$name")"
}

# --- tri-state ownership ---

@test "resolves to a live, same-profile legacy pair" {
  is_openconnect_pid() { [ "$1" = "111" ]; }
  _write_legacy_pair "Work VPN" 111
  resolve_profile_runtime_files "Work VPN"
  [ "$RESOLVED_PID_FILE" = "$(_legacy_pid_path "Work VPN")" ]
  [ "$RESOLVED_STATE_FILE" = "$(_legacy_state_path "Work VPN")" ]
}

@test "a legacy pair proven to belong to a different profile resolves to nothing, untouched" {
  is_openconnect_pid() { return 0; }   # would be "live" if it were ours
  _write_legacy_pair "Work VPN" 111 "Someone Else"
  resolve_profile_runtime_files "Work VPN"
  [ -z "$RESOLVED_PID_FILE" ]
  [ -z "$RESOLVED_STATE_FILE" ]
  # not ours -- must not be touched, retired, or otherwise acted on
  [ -e "$(_legacy_pid_path "Work VPN")" ]
  [ -e "$(_legacy_state_path "Work VPN")" ]
}

@test "a legacy pid with no state file at all is ambiguous, fails closed" {
  is_openconnect_pid() { return 0; }
  echo 111 > "$(_legacy_pid_path "Work VPN")"
  run resolve_profile_runtime_files "Work VPN"
  [ "$status" -ne 0 ]
  [ -z "$RESOLVED_PID_FILE" ]
}

@test "a legacy state file with no readable profile= line is ambiguous, fails closed" {
  is_openconnect_pid() { return 0; }
  echo 111 > "$(_legacy_pid_path "Work VPN")"
  touch "$(_legacy_state_path "Work VPN")"   # exists, but no `profile=` line
  run resolve_profile_runtime_files "Work VPN"
  [ "$status" -ne 0 ]
  [ -z "$RESOLVED_PID_FILE" ]
}

# --- dead legacy pair is retired ---

@test "a confirmed-dead, same-profile legacy pair is retired (deleted), resolves to nothing" {
  is_openconnect_pid() { return 1; }   # confirmed dead
  _write_legacy_pair "Work VPN" 111
  resolve_profile_runtime_files "Work VPN"
  [ -z "$RESOLVED_PID_FILE" ]
  [ -z "$RESOLVED_STATE_FILE" ]
  [ ! -e "$(_legacy_pid_path "Work VPN")" ]
  [ ! -e "$(_legacy_state_path "Work VPN")" ]
}

@test "legacy cleanup failure propagates as ambiguous, not silently ignored" {
  is_openconnect_pid() { return 1; }   # confirmed dead
  _write_legacy_pair "Work VPN" 111
  # Simulate an rm that reports success but doesn't actually remove (e.g. a
  # read-only mount) -- the resolver must verify by re-checking existence
  # afterward, not trust rm's own exit code.
  rm() { :; }
  run resolve_profile_runtime_files "Work VPN"
  [ "$status" -ne 0 ]
  [ -z "$RESOLVED_PID_FILE" ]
}

# --- new namespace: never deleted, never masks a live legacy connection ---

@test "a stale-looking new-scheme pair is left untouched and does not mask a live legacy connection" {
  is_openconnect_pid() { [ "$1" = "222" ]; }   # only the legacy pid (222) is "live"
  _write_new_pair "Work VPN" 999                # looks dead
  _write_legacy_pair "Work VPN" 222              # genuinely live
  resolve_profile_runtime_files "Work VPN"
  [ "$RESOLVED_PID_FILE" = "$(_legacy_pid_path "Work VPN")" ]
  # the dead-looking new-scheme pair must be byte-for-byte untouched, never rm'd
  [ -e "$(profile_pid_file "Work VPN")" ]
  [ "$(cat "$(profile_pid_file "Work VPN")")" = "999" ]
  [ -e "$(profile_state_file "Work VPN")" ]
}

@test "a live new-scheme pair wins outright, without needing to touch legacy" {
  is_openconnect_pid() { [ "$1" = "999" ]; }   # only the new-scheme pid is "live"
  _write_new_pair "Work VPN" 999
  _write_legacy_pair "Work VPN" 222
  resolve_profile_runtime_files "Work VPN"
  [ "$RESOLVED_PID_FILE" = "$(profile_pid_file "Work VPN")" ]
  [ "$RESOLVED_STATE_FILE" = "$(profile_state_file "Work VPN")" ]
  # legacy pair is irrelevant once the new one resolves live -- left as-is
  [ -e "$(_legacy_pid_path "Work VPN")" ]
  [ -e "$(_legacy_state_path "Work VPN")" ]
}

@test "a dirty new namespace with no legacy fallback fails closed" {
  is_openconnect_pid() { return 1; }   # nothing anywhere is "live"
  _write_new_pair "Work VPN" 999        # looks dead, no legacy files at all
  run resolve_profile_runtime_files "Work VPN"
  [ "$status" -ne 0 ]
  [ -z "$RESOLVED_PID_FILE" ]
  # still never deleted
  [ -e "$(profile_pid_file "Work VPN")" ]
}

@test "a dirty new namespace with only an other-profile legacy pair fails closed" {
  is_openconnect_pid() { return 1; }
  _write_new_pair "Work VPN" 999
  _write_legacy_pair "Work VPN" 111 "Someone Else"
  run resolve_profile_runtime_files "Work VPN"
  [ "$status" -ne 0 ]
  [ -z "$RESOLVED_PID_FILE" ]
  [ -e "$(profile_pid_file "Work VPN")" ]
}

@test "a dirty new namespace does not override a genuinely live legacy answer" {
  is_openconnect_pid() { [ "$1" = "222" ]; }   # only the legacy pid is "live"
  _write_new_pair "Work VPN" 999                # dirty, but irrelevant here
  _write_legacy_pair "Work VPN" 222
  resolve_profile_runtime_files "Work VPN"
  [ "$RESOLVED_PID_FILE" = "$(_legacy_pid_path "Work VPN")" ]
}

# --- nothing anywhere ---

@test "nothing running anywhere resolves cleanly, no ambiguity" {
  resolve_profile_runtime_files "Work VPN"
  [ -z "$RESOLVED_PID_FILE" ]
  [ -z "$RESOLVED_STATE_FILE" ]
}

# --- purity of the path builders ---

@test "profile_pid_file/state_file/log_file emit only the path, always into the new namespace" {
  _write_legacy_pair "Work VPN" 111
  local pid_out state_out log_out
  pid_out="$(profile_pid_file "Work VPN")"
  state_out="$(profile_state_file "Work VPN")"
  log_out="$(profile_log_file "Work VPN")"
  [[ "$pid_out" == "$DATA_DIR/pids/"* ]]
  [[ "$state_out" == "$DATA_DIR/pids/"* ]]
  [[ "$log_out" == "$DATA_DIR/logs/"* ]]
  # never the legacy (slug-only) path, regardless of what legacy files exist
  [ "$pid_out" != "$(_legacy_pid_path "Work VPN")" ]
  [ "$state_out" != "$(_legacy_state_path "Work VPN")" ]
}
