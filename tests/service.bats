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

@test "_xml_escape escapes &, <, > and leaves plain text untouched" {
  [ "$(_xml_escape "plain text")" = "plain text" ]
  [ "$(_xml_escape "a & b")" = "a &amp; b" ]
  [ "$(_xml_escape "1 < 2")" = "1 &lt; 2" ]
  [ "$(_xml_escape "2 > 1")" = "2 &gt; 1" ]
  [ "$(_xml_escape "<tag attr=\"x\">")" = "&lt;tag attr=\"x\"&gt;" ]
}

@test "_xml_escape escapes ampersand first so entities are not double-escaped" {
  # An input that already looks like an entity must not become &amp;lt;
  [ "$(_xml_escape "&lt;")" = "&amp;lt;" ]
  [ "$(_xml_escape "A < B & C > D")" = "A &lt; B &amp; C &gt; D" ]
}

@test "_xml_escape output for an injection-y profile name yields well-formed XML in the plist" {
  run write_launch_agent_plist 'Evil</string><key>x</key><string>& <oops>'
  [ "$status" -eq 0 ]
  printf '%s\n' "$output" | xmlstarlet val -q -
  [[ "$output" != *"<oops>"* ]]   # the literal '<' was escaped, not emitted as a tag
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

# --- install/uninstall/status flows with stubbed service managers ---

_setup_install_stubs() {
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Svc VPN</name><protocol>anyconnect</protocol><host>s.example.com</host><user>u</user><password></password><duo2FAMethod>push</duo2FAMethod></VPN>
  <VPN><name>Passcode VPN</name><protocol>anyconnect</protocol><host>p.example.com</host><user>u</user><password></password><duo2FAMethod>passcode</duo2FAMethod></VPN>
</VPNs>
XML
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  sudo() { return 0; }                 # passwordless sudo "present"
  secrets_get() { echo "stored"; }     # password "stored"
  launchctl() { echo "launchctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"; return 0; }
  systemctl() { echo "systemctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"; return 0; }
}

@test "service_install writes the service file and loads it" {
  _setup_install_stubs
  service_install "Svc VPN"
  [ -f "$(_service_path_for "Svc VPN")" ]
  grep -q "Svc" "$(_service_path_for "Svc VPN")"
  grep -qE "(launchctl load|systemctl --user enable)" "$BATS_TEST_TMPDIR/svc-calls"
}

@test "service_install refuses passcode-2FA profiles and unknown profiles" {
  _setup_install_stubs
  run service_install "Passcode VPN"
  [ "$status" -ne 0 ]
  run service_install "Ghost"
  [ "$status" -ne 0 ]
}

@test "service_uninstall unloads and removes; status lists installed services" {
  _setup_install_stubs
  service_install "Svc VPN"
  run service_status
  [[ "$output" == *"Svc_VPN"* ]]
  service_uninstall "Svc VPN"
  [ ! -e "$(_service_path_for "Svc VPN")" ]
  run service_uninstall "Svc VPN"   # idempotent
  [ "$status" -eq 0 ]
}
