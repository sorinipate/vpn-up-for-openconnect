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

@test "an unresolved .old backup blocks install even when target itself is missing (interrupted-upgrade crash state)" {
  # The natural interrupted-upgrade crash state is stop -> rename target to
  # .old -> crash, which leaves $target itself missing. The check for it
  # must not be nested inside "if target exists", or this state is silently
  # treated as a fresh install and the only working copy sits ignored.
  _setup_install_stubs
  local target old_path
  target="$(_service_path_for "Svc VPN")"
  old_path="${target}.old"
  mkdir -p "$(dirname "$target")"
  echo "previous working content" > "$old_path"
  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  [ ! -e "$target" ]
  [ -e "$old_path" ]
  [ "$(cat "$old_path")" = "previous working content" ]
  [[ "$output" == *"unresolved backup"* ]]
}

@test "service_uninstall fails closed when a legacy-named file's owner can't be verified" {
  _setup_install_stubs
  local legacy; legacy="$(_service_legacy_path_for "Svc VPN")"
  mkdir -p "$(dirname "$legacy")"
  echo "not a real service definition" > "$legacy"
  run service_uninstall "Svc VPN"
  [ "$status" -ne 0 ]
  [ -e "$legacy" ]
}

@test "service_uninstall leaves a legacy-named file belonging to a different (slug-colliding) profile untouched" {
  _setup_install_stubs
  local legacy; legacy="$(_service_legacy_path_for "Svc VPN")"
  mkdir -p "$(dirname "$legacy")"
  if [ "$(uname)" = "Darwin" ]; then
    write_launch_agent_plist "Other VPN" > "$legacy"
  else
    write_systemd_unit "Other VPN" > "$legacy"
  fi
  run service_uninstall "Svc VPN"
  [ "$status" -eq 0 ]
  [ -e "$legacy" ]
}

@test "install reconciles a same-profile legacy leftover even via the upgrade branch, not just migration" {
  # Simulates a prior migration interrupted after activating the new target
  # but before retiring the legacy one -- the "target already exists"
  # (upgrade) branch never looks at the legacy path on its own, so without
  # explicit reconciliation this leftover would never be cleaned up by any
  # future run.
  _setup_install_stubs
  service_install "Svc VPN"
  local legacy; legacy="$(_service_legacy_path_for "Svc VPN")"
  if [ "$(uname)" = "Darwin" ]; then
    write_launch_agent_plist "Svc VPN" > "$legacy"
  else
    write_systemd_unit "Svc VPN" > "$legacy"
  fi
  run service_install "Svc VPN"
  [ "$status" -eq 0 ]
  [ ! -e "$legacy" ]
}

@test "install reports failure if a same-profile legacy leftover cannot actually be removed" {
  _setup_install_stubs
  service_install "Svc VPN"
  local legacy; legacy="$(_service_legacy_path_for "Svc VPN")"
  if [ "$(uname)" = "Darwin" ]; then
    write_launch_agent_plist "Svc VPN" > "$legacy"
  else
    write_systemd_unit "Svc VPN" > "$legacy"
  fi
  rm() {
    case "$*" in
      *"$legacy") : ;;   # "succeeds" without actually removing this one file
      *) command rm "$@" ;;
    esac
  }
  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"leftover legacy-named service"* ]]
  [ -f "$(_service_path_for "Svc VPN")" ]   # the actual new service is still fine
  [ -e "$legacy" ]
}

@test "service_uninstall fails if the definition file cannot actually be removed" {
  _setup_install_stubs
  service_install "Svc VPN"
  local target; target="$(_service_path_for "Svc VPN")"
  rm() { :; }   # "succeeds" but never actually removes anything
  run service_uninstall "Svc VPN"
  [ "$status" -ne 0 ]
  [ -e "$target" ]
}

@test "an unverifiable legacy-named service file blocks install, fails closed" {
  # Mirrors resolve_profile_runtime_files' own rule for an unattributable
  # legacy pid/state pair: the file could in fact be this profile's own
  # pre-collision-fix service, so an unreadable owner must refuse, not warn
  # and proceed.
  _setup_install_stubs
  local legacy; legacy="$(_service_legacy_path_for "Svc VPN")"
  mkdir -p "$(dirname "$legacy")"
  echo "not a real service definition" > "$legacy"
  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  [ ! -e "$(_service_path_for "Svc VPN")" ]
  [ -e "$legacy" ]
  [[ "$output" == *"could not be verified"* ]]
}

@test "upgrade rollback restores and verifiably reloads the previous service after a load failure" {
  _setup_install_stubs
  service_install "Svc VPN"
  local target; target="$(_service_path_for "Svc VPN")"

  # Fail only the FIRST "load"/"enable --now" call after this point (the
  # upgrade's own activation attempt) -- the baseline install above already
  # succeeded via the original stub, and the restore's reload (the second
  # call counted here) must still succeed, so this actually exercises
  # verified rollback rather than "everything fails".
  echo 0 > "$BATS_TEST_TMPDIR/load-count"
  launchctl() {
    echo "launchctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    if [ "$1" = "load" ]; then
      local n; n=$(( $(cat "$BATS_TEST_TMPDIR/load-count") + 1 )); echo "$n" > "$BATS_TEST_TMPDIR/load-count"
      [ "$n" -eq 1 ] && return 1
    fi
    return 0
  }
  systemctl() {
    echo "systemctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    case "$*" in
      *"enable --now"*)
        local n; n=$(( $(cat "$BATS_TEST_TMPDIR/load-count") + 1 )); echo "$n" > "$BATS_TEST_TMPDIR/load-count"
        [ "$n" -eq 1 ] && return 1
        ;;
      *"show --property=ActiveState"*) echo "inactive" ;;
    esac
    return 0
  }

  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"Restored the previous working service"* ]]
  [ -f "$target" ]
  local reload_calls
  reload_calls="$(grep -cE '^(launchctl load|systemctl .*enable --now)' "$BATS_TEST_TMPDIR/svc-calls")"
  [ "$reload_calls" -eq 3 ]   # baseline install + the upgrade's failed attempt + the verified restore
}

@test "rollback preserves the backup untouched when the failed replacement can't be confirmed stopped" {
  # A failed load/enable is not proof nothing was registered or started;
  # rollback must use the same verified stop as everywhere else, not a raw
  # unload/disable -- and must NOT restore/reload the previous definition
  # while the broken replacement can't be confirmed inactive, to avoid two
  # active registrations for the same VPN at once.
  _setup_install_stubs
  service_install "Svc VPN"
  local target; target="$(_service_path_for "Svc VPN")"
  local before; before="$(cat "$target")"
  local label; label="$(basename "$target" .plist)"

  # The FIRST stop-verification (step 2, confirming the currently-installed,
  # healthy target is cleanly stopped before backing it up) must still
  # succeed; only the SECOND one (step 4's rollback, confirming the broken
  # replacement is stopped) reports "still there" -- otherwise this would
  # never even reach activation/load at all.
  echo 0 > "$BATS_TEST_TMPDIR/verify-count"
  launchctl() {
    echo "launchctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    case "$1" in
      load) return 1 ;;                                # the upgrade's own activation fails
      list)
        local n; n=$(( $(cat "$BATS_TEST_TMPDIR/verify-count") + 1 )); echo "$n" > "$BATS_TEST_TMPDIR/verify-count"
        [ "$n" -gt 1 ] && printf '1234\t0\t%s\n' "$label"
        ;;
    esac
    return 0
  }
  systemctl() {
    echo "systemctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    case "$*" in
      *"enable --now"*) return 1 ;;                     # the upgrade's own activation fails
      *"show --property=ActiveState"*)
        local n; n=$(( $(cat "$BATS_TEST_TMPDIR/verify-count") + 1 )); echo "$n" > "$BATS_TEST_TMPDIR/verify-count"
        if [ "$n" -gt 1 ]; then echo "active"; else echo "inactive"; fi
        ;;
    esac
    return 0
  }

  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"leaving it in place"* ]]
  [ -f "${target}.old" ]
  [ "$(cat "${target}.old")" = "$before" ]
  if [[ "$output" == *"Restored the previous working service"* ]]; then false; fi
}

@test "a failed backup-rename still gets the already-stopped service reloaded" {
  _setup_install_stubs
  service_install "Svc VPN"
  local target; target="$(_service_path_for "Svc VPN")"

  mv() {
    case "$*" in
      *".old") return 1 ;;
    esac
    command mv "$@"
  }

  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  [[ "$output" == *"Restored the previous working service"* ]]
  [ -f "$target" ]
  local reload_calls
  reload_calls="$(grep -cE '^(launchctl load|systemctl .*enable --now)' "$BATS_TEST_TMPDIR/svc-calls")"
  [ "$reload_calls" -eq 2 ]   # baseline install + the in-place reload (no activation was ever attempted)
}

@test "a failed daemon-reload blocks enabling a possibly-stale unit (systemd)" {
  if [ "$(uname)" = "Darwin" ]; then
    skip "daemon-reload is systemd-specific"
  fi
  _setup_install_stubs
  systemctl() {
    echo "systemctl $*" >> "$BATS_TEST_TMPDIR/svc-calls"
    case "$*" in
      "--user daemon-reload") return 1 ;;
      *"show --property=ActiveState"*) echo "inactive" ;;
    esac
    return 0
  }
  run service_install "Svc VPN"
  [ "$status" -ne 0 ]
  if grep -q "enable --now" "$BATS_TEST_TMPDIR/svc-calls"; then false; fi
}
