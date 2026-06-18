#!/usr/bin/env bats
# Tests for core.sh: config safety, status/stop scan logic, connection state.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  export CONFIGURATION_FILE="$DATA_DIR/cfg"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  print_warning() { printf -- "$1" "${@:2}"; }
  print_danger()  { printf -- "$1" "${@:2}"; }
  print_success() { printf -- "$1" "${@:2}"; }
  print_primary() { printf -- "$1" "${@:2}"; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
}

_write_start_test_profiles() {
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Work VPN</name><protocol>anyconnect</protocol><host>work.example.com</host><user>alice</user><password></password></VPN>
  <VPN><name>Lab VPN</name><protocol>gp</protocol><host>lab.example.com</host><user>bob</user><password></password></VPN>
</VPNs>
XML
}

_write_start_test_config() {
  cat > "$CONFIGURATION_FILE" <<'EOF'
BACKGROUND=FALSE
QUIET=TRUE
SHOW_BANNER=FALSE
NOTIFICATIONS=FALSE
EOF
  chmod 600 "$CONFIGURATION_FILE"
}

# --- assert_safe_to_source ---

@test "assert_safe_to_source accepts 600/644, rejects group/world-writable" {
  f="$BATS_TEST_TMPDIR/file"; echo x > "$f"
  chmod 600 "$f"; assert_safe_to_source "$f"
  chmod 644 "$f"; assert_safe_to_source "$f"
  chmod 664 "$f"; run assert_safe_to_source "$f"; [ "$status" -ne 0 ]
  chmod 602 "$f"; run assert_safe_to_source "$f"; [ "$status" -ne 0 ]
}

@test "assert_safe_to_source rejects missing files" {
  run assert_safe_to_source "$BATS_TEST_TMPDIR/does-not-exist"
  [ "$status" -ne 0 ]
}

# --- connection state + status ---

@test "write_connection_state records profile/host with 600 perms" {
  VPN_NAME="Test VPN"; VPN_HOST="t.example.com"
  STATE_FILE_PATH="$DATA_DIR/pids/${PROGRAM_NAME}.Test_VPN.state"
  write_connection_state
  [ "$(file_mode "$STATE_FILE_PATH")" = "600" ]
  grep -q "^profile=Test VPN$" "$STATE_FILE_PATH"
  grep -q "^host=t.example.com$" "$STATE_FILE_PATH"
  grep -q "^connected_at=" "$STATE_FILE_PATH"
}

@test "status reports running profile details from the state file" {
  echo "$$" > "$DATA_DIR/pids/${PROGRAM_NAME}.X.pid"
  printf 'profile=X VPN\nhost=x.example.com\nconnected_at=2026-06-12 10:00:00\n' > "$DATA_DIR/pids/${PROGRAM_NAME}.X.state"
  is_openconnect_pid() { return 0; }
  run status
  [[ "$output" == *"VPN is running (PID: $$)"* ]]
  [[ "$output" == *"Profile : X VPN"* ]]
  [[ "$output" == *"Gateway : x.example.com"* ]]
}

@test "status cleans stale pid/state files and reports not running" {
  echo 99999 > "$DATA_DIR/pids/${PROGRAM_NAME}.Stale.pid"
  touch "$DATA_DIR/pids/${PROGRAM_NAME}.Stale.state"
  is_openconnect_pid() { return 1; }
  run status
  [[ "$output" == *"not running"* ]]
  [ ! -e "$DATA_DIR/pids/${PROGRAM_NAME}.Stale.pid" ]
  [ ! -e "$DATA_DIR/pids/${PROGRAM_NAME}.Stale.state" ]
}

# --- start concurrency guard ---

@test "start allows a different profile while another tunnel is running" {
  _write_start_test_profiles
  _write_start_test_config
  echo 111 > "$DATA_DIR/pids/${PROGRAM_NAME}.Work_VPN.pid"
  is_openconnect_pid() { [ "$1" = "111" ]; }
  is_network_available() { return 0; }
  show_banner() { :; }
  migrate_or_fetch_password() { :; }
  connect() { printf 'connected:%s\n' "$VPN_NAME"; }

  run start "Lab VPN"
  [ "$status" -eq 0 ]
  [[ "$output" == *"connected:Lab VPN"* ]]
}

@test "start refuses a profile that is already running" {
  _write_start_test_profiles
  _write_start_test_config
  echo 111 > "$DATA_DIR/pids/${PROGRAM_NAME}.Work_VPN.pid"
  is_openconnect_pid() { [ "$1" = "111" ]; }
  is_network_available() { return 0; }
  show_banner() { :; }
  migrate_or_fetch_password() { echo "migrate-called"; }
  connect() { echo "connect-called"; }

  run start "Work VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"already running"* ]]
  [[ "$output" != *"migrate-called"* ]]
  [[ "$output" != *"connect-called"* ]]
}

@test "_openconnect_pid_for_pid_file matches the openconnect process with that pid file" {
  ps() {
    cat <<EOF
 100 openconnect --user=a --pid-file /tmp/a.pid vpn-a.example.com
 200 /usr/sbin/openconnect --user=b --pid-file /tmp/b.pid vpn-b.example.com
 300 sudo openconnect --user=b --pid-file /tmp/b.pid vpn-b.example.com
EOF
  }

  run _openconnect_pid_for_pid_file "/tmp/b.pid"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}

# --- stop ---

@test "stop kills via sudo, waits for death, removes pid and state" {
  flag="$BATS_TEST_TMPDIR/alive"; touch "$flag"
  is_openconnect_pid() { [ -e "$flag" ]; }
  sudo() { [ "$1" = "kill" ] && rm -f "$flag"; return 0; }
  load_config() { :; }
  echo 4242 > "$DATA_DIR/pids/${PROGRAM_NAME}.Y.pid"
  printf 'profile=Y\nhost=y.example.com\n' > "$DATA_DIR/pids/${PROGRAM_NAME}.Y.state"
  run_hooks_called=""
  run_hooks() { echo "$1:$2:$3" > "$BATS_TEST_TMPDIR/hookcall"; }
  stop
  [ ! -e "$DATA_DIR/pids/${PROGRAM_NAME}.Y.pid" ]
  [ ! -e "$DATA_DIR/pids/${PROGRAM_NAME}.Y.state" ]
  [ "$(cat "$BATS_TEST_TMPDIR/hookcall")" = "disconnected:Y:y.example.com" ]
}

@test "stop with profile arg targets only that profile" {
  is_openconnect_pid() { return 1; }
  load_config() { :; }
  echo 1 > "$DATA_DIR/pids/${PROGRAM_NAME}.Keep.pid"
  echo 2 > "$DATA_DIR/pids/${PROGRAM_NAME}.Gone.pid"
  stop "Gone"
  [ ! -e "$DATA_DIR/pids/${PROGRAM_NAME}.Gone.pid" ]
  [ -e "$DATA_DIR/pids/${PROGRAM_NAME}.Keep.pid" ]
}

@test "stop reports not running when no pid files exist" {
  load_config() { :; }
  run stop
  [ "$status" -eq 0 ]
  [[ "$output" == *"not running"* ]]
}

# --- load_config ---

@test "load_config sources a safe config and refuses an unsafe one" {
  echo 'MARKER=loaded' > "$CONFIGURATION_FILE"
  chmod 600 "$CONFIGURATION_FILE"
  load_config
  [ "${MARKER:-}" = "loaded" ]
  chmod 666 "$CONFIGURATION_FILE"
  run load_config
  [ "$status" -ne 0 ]
}
