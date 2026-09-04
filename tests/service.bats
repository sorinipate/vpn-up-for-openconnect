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
  # core.sh, for _secret_check/_pkcs11_pin_needed: _service_preflight now
  # routes secret existence checks through these (review round 7, finding
  # #5) instead of a raw secrets_get, the same tri-state check the runtime
  # preflight already uses.
  source "$BATS_TEST_DIRNAME/../core.sh"
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
  local key; key="$(profile_key "My Work & VPN")"
  run write_launch_agent_plist "My Work & VPN"
  [ "$status" -eq 0 ]
  [[ "$output" == *"<string>My Work &amp; VPN</string>"* ]]
  [[ "$output" == *"com.sorinipate.vpn-up.${key}"* ]]
  [[ "$output" == *"<key>VPN_UP_SERVICE</key>"* ]]
  [[ "$output" == *"<key>KeepAlive</key>"* ]]
  # well-formed XML
  printf '%s\n' "$output" | xmlstarlet val -q -
  # KeepAlive must be the SuccessfulExit=false DICTIONARY, not the bare
  # boolean: exit 0 (service_exit_code(), outcome.sh) is a permanent
  # condition and must STOP the job, not relaunch it. XPath, not a substring,
  # so a regression to the bare `<true/>` form (which also happens to
  # contain "KeepAlive" as a string) is actually caught.
  local n
  n="$(printf '%s\n' "$output" | xmlstarlet sel -t -v \
    "count(//key[.='KeepAlive']/following-sibling::dict[1]/key[.='SuccessfulExit']/following-sibling::false)")"
  [ "$n" -ge 1 ]
}

@test "write_systemd_unit produces a unit with restart and service env" {
  run write_systemd_unit "Work VPN"
  [ "$status" -eq 0 ]
  [[ "$output" == *'ExecStart='*'start "Work VPN"'* ]]
  [[ "$output" == *"Environment=VPN_UP_SERVICE=1"* ]]
  # on-failure, not always: exit 0 (service_exit_code(), outcome.sh) means a
  # permanent condition and must STOP the unit, not restart it.
  [[ "$output" == *"Restart=on-failure"* ]]
  [[ "$output" == *"StartLimitIntervalSec=300"* ]]
  [[ "$output" == *"StartLimitBurst=20"* ]]
}

@test "_service_path_for uses collision-safe per-profile filenames" {
  local key; key="$(profile_key "Work VPN")"
  if [ "$(uname)" = "Darwin" ]; then
    [ "$(_service_path_for "Work VPN")" = "$VPN_UP_LAUNCH_AGENT_DIR/com.sorinipate.vpn-up.${key}.plist" ]
  else
    [ "$(_service_path_for "Work VPN")" = "$VPN_UP_SYSTEMD_DIR/vpn-up-${key}.service" ]
  fi
}

@test "_service_path_for returns distinct paths for slug-colliding profile names" {
  [ "$(_service_path_for "Work VPN")" != "$(_service_path_for "Work/VPN")" ]
}

@test "_service_legacy_path_for uses the old slug-only formula" {
  if [ "$(uname)" = "Darwin" ]; then
    [ "$(_service_legacy_path_for "Work VPN")" = "$VPN_UP_LAUNCH_AGENT_DIR/com.sorinipate.vpn-up.Work_VPN.plist" ]
  else
    [ "$(_service_legacy_path_for "Work VPN")" = "$VPN_UP_SYSTEMD_DIR/vpn-up-Work_VPN.service" ]
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
  # launchctl list / systemctl show --property=ActiveState must report a
  # real "confirmed stopped" state on real stdout (not just a call log) --
  # _service_stop_and_verify distinguishes confirmed-inactive from
  # couldn't-query, so a bare `return 0` with no output is misread as a
  # query failure, not as "nothing is loaded/active".
  launchctl() {
    echo "launchctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    return 0   # `list` prints nothing -- nothing loaded, by default
  }
  systemctl() {
    echo "systemctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    case "$*" in
      *"show --property=ActiveState"*) echo "inactive" ;;
    esac
    return 0
  }
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
  local key; key="$(profile_key "Svc VPN")"
  run service_status
  [[ "$output" == *"${key}"* ]]
  service_uninstall "Svc VPN"
  [ ! -e "$(_service_path_for "Svc VPN")" ]
  run service_uninstall "Svc VPN"   # idempotent
  [ "$status" -eq 0 ]
}
