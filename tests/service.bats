#!/usr/bin/env bats
# Tests for service file generation (no launchctl/systemctl calls).

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  export VPN_UP_LAUNCH_AGENT_DIR="$BATS_TEST_TMPDIR/agents"
  export VPN_UP_SYSTEMD_DIR="$BATS_TEST_TMPDIR/systemd"
  mkdir -p "$DATA_DIR"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  print_warning() { :; }; print_danger() { :; }; print_success() { :; }; print_primary() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../service.sh"
}

@test "write_launch_agent_plist produces valid plist with service env and profile" {
  run write_launch_agent_plist "My Work & VPN"
  [ "$status" -eq 0 ]
  [[ "$output" == *"<string>My Work &amp; VPN</string>"* ]]
  [[ "$output" == *"com.sorinipate.vpn-up.My_Work___VPN"* ]]
  [[ "$output" == *"<key>VPN_UP_SERVICE</key>"* ]]
  [[ "$output" == *"<key>KeepAlive</key>"* ]]
  # well-formed XML
  printf '%s\n' "$output" | xmlstarlet val -q -
}

@test "write_systemd_unit produces a unit with restart and service env" {
  run write_systemd_unit "Work VPN"
  [ "$status" -eq 0 ]
  [[ "$output" == *'ExecStart='*'start "Work VPN"'* ]]
  [[ "$output" == *"Environment=VPN_UP_SERVICE=1"* ]]
  [[ "$output" == *"Restart=always"* ]]
}

@test "_service_path_for uses slugged per-profile filenames" {
  if [ "$(uname)" = "Darwin" ]; then
    [ "$(_service_path_for "Work VPN")" = "$VPN_UP_LAUNCH_AGENT_DIR/com.sorinipate.vpn-up.Work_VPN.plist" ]
  else
    [ "$(_service_path_for "Work VPN")" = "$VPN_UP_SYSTEMD_DIR/vpn-up-Work_VPN.service" ]
  fi
}
