#!/usr/bin/env bats
# Tests for logging.sh: paths, pid identity, log selection, print helpers.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  source "$BATS_TEST_DIRNAME/../logging.sh"
}

@test "set_profile_paths points globals at collision-safe per-profile files" {
  local key; key="$(profile_key "My Work VPN")"
  set_profile_paths "My Work VPN"
  [ "$PID_FILE_PATH" = "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.pid" ]
  [ "$STATE_FILE_PATH" = "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.state" ]
  [ "$LOG_FILE_PATH" = "$DATA_DIR/logs/${PROGRAM_NAME}.${key}.log" ]
}

@test "profile path helpers return collision-safe per-profile files" {
  local key; key="$(profile_key "My Work VPN")"
  [ "$(profile_pid_file "My Work VPN")" = "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.pid" ]
  [ "$(profile_state_file "My Work VPN")" = "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.state" ]
  [ "$(profile_log_file "My Work VPN")" = "$DATA_DIR/logs/${PROGRAM_NAME}.${key}.log" ]
}

@test "profile_key produces distinct values for slug-colliding names" {
  [ "$(profile_key "Work VPN")" != "$(profile_key "Work/VPN")" ]
  [ "$(profile_pid_file "Work VPN")" != "$(profile_pid_file "Work/VPN")" ]
}

@test "is_openconnect_pid rejects empty, non-numeric, and non-openconnect pids" {
  run is_openconnect_pid "";        [ "$status" -ne 0 ]
  run is_openconnect_pid "12a4";    [ "$status" -ne 0 ]
  run is_openconnect_pid "evil; rm" ; [ "$status" -ne 0 ]
  # current shell is bash, not openconnect
  run is_openconnect_pid "$$";      [ "$status" -ne 0 ]
}

@test "profile_vpn_running targets one profile via the new namespace, without pruning it" {
  local key; key="$(profile_key "Work VPN")"
  echo 111 > "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.pid"
  touch "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.state"
  is_openconnect_pid() { [ "$1" = "111" ]; }
  profile_vpn_running "Work VPN"
  run profile_vpn_running "Lab VPN"
  [ "$status" -ne 0 ]

  is_openconnect_pid() { return 1; }
  run profile_vpn_running "Work VPN"
  [ "$status" -ne 0 ]
  # Unlike before this fix, a dead-looking NEW-namespace pid/state pair is
  # never pruned by profile_vpn_running itself -- that would race a
  # concurrent connect (see resolve_profile_runtime_files). Cleanup is
  # status()'s job now.
  [ -e "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.pid" ]
  [ -e "$DATA_DIR/pids/${PROGRAM_NAME}.${key}.state" ]
}

@test "file_mode and file_owner_uid report correct values" {
  f="$BATS_TEST_TMPDIR/f"; touch "$f"; chmod 640 "$f"
  [ "$(file_mode "$f")" = "640" ]
  [ "$(file_owner_uid "$f")" = "$(id -u)" ]
}

@test "show_logs warns when no log exists" {
  run show_logs
  [ "$status" -eq 0 ]
  [[ "$output" == *"No log file yet"* ]]
}

@test "show_logs picks the named profile's log, or the most recent" {
  local old_key new_key
  old_key="$(profile_key "Old VPN")"
  new_key="$(profile_key "New VPN")"
  echo "old log" > "$DATA_DIR/logs/${PROGRAM_NAME}.${old_key}.log"
  sleep 1
  echo "new log" > "$DATA_DIR/logs/${PROGRAM_NAME}.${new_key}.log"
  run show_logs "Old VPN"
  [ "$output" = "old log" ]
  run show_logs
  [ "$output" = "new log" ]
}

@test "print helpers substitute arguments into literal formats" {
  out="$(print_warning "a %s b\n" "VALUE")"
  [[ "$out" == *"a VALUE b"* ]]
  out="$(print_danger "%s-%s\n" x y)"
  [[ "$out" == *"x-y"* ]]
}

@test "check_file_existence exits non-zero for missing files" {
  run check_file_existence "$BATS_TEST_TMPDIR/nope" "Profiles"
  [ "$status" -ne 0 ]
  [[ "$output" == *"Profiles file missing"* ]]
}
