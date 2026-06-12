#!/usr/bin/env bats
# Tests for remove-profile and the lifecycle hooks runner.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Doomed VPN</name><protocol>anyconnect</protocol><host>d.example.com</host><user>u1</user><password></password></VPN>
  <VPN><name>Keeper VPN</name><protocol>gp</protocol><host>k.example.com</host><user>u2</user><password></password></VPN>
</VPNs>
XML
  print_warning() { :; }; print_danger() { :; }; print_success() { :; }; print_primary() { :; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
  source "$BATS_TEST_DIRNAME/../setup.sh"
  # stubs for remove_profile collaborators
  _service_path_for() { echo "$BATS_TEST_TMPDIR/no-such-service"; }
  service_uninstall() { echo "uninstalled:$1" >> "$BATS_TEST_TMPDIR/calls"; }
  secrets_delete() { echo "secret-deleted:$1.$2" >> "$BATS_TEST_TMPDIR/calls"; }
  is_openconnect_pid() { return 1; }
}

@test "remove_profile deletes the block, secret, and files; keeps others" {
  touch "$DATA_DIR/pids/${PROGRAM_NAME}.Doomed_VPN.state" "$DATA_DIR/logs/${PROGRAM_NAME}.Doomed_VPN.log"
  remove_profile "Doomed VPN" <<< "y"
  ! profile_exists "Doomed VPN"
  profile_exists "Keeper VPN"
  grep -q "secret-deleted:Doomed VPN.password" "$BATS_TEST_TMPDIR/calls"
  [ ! -e "$DATA_DIR/pids/${PROGRAM_NAME}.Doomed_VPN.state" ]
  [ ! -e "$DATA_DIR/logs/${PROGRAM_NAME}.Doomed_VPN.log" ]
  xmlstarlet val -q "$PROFILES_FILE"
}

@test "remove_profile aborts without confirmation" {
  run remove_profile "Doomed VPN" <<< "n"
  [ "$status" -ne 0 ]
  profile_exists "Doomed VPN"
}

@test "remove_profile refuses while profile is connected" {
  is_openconnect_pid() { return 0; }
  echo "12345" > "$DATA_DIR/pids/${PROGRAM_NAME}.Doomed_VPN.pid"
  run remove_profile "Doomed VPN" <<< "y"
  [ "$status" -ne 0 ]
  profile_exists "Doomed VPN"
}

@test "run_hooks executes safe hooks with event env, skips unsafe ones" {
  mkdir -p "$DATA_DIR/hooks/connected.d"
  cat > "$DATA_DIR/hooks/connected.d/10-good" <<'EOF'
#!/bin/sh
echo "$VPN_EVENT/$VPN_NAME/$VPN_HOST" > "$OUT"
EOF
  cat > "$DATA_DIR/hooks/connected.d/20-unsafe" <<'EOF'
#!/bin/sh
echo "unsafe ran" >> "$OUT"
EOF
  chmod 700 "$DATA_DIR/hooks/connected.d/10-good"
  chmod 777 "$DATA_DIR/hooks/connected.d/20-unsafe"   # group/world writable -> must be skipped
  export OUT="$BATS_TEST_TMPDIR/hook-out"
  run_hooks connected "Work VPN" "w.example.com"
  [ "$(cat "$OUT")" = "connected/Work VPN/w.example.com" ]
  ! grep -q "unsafe ran" "$OUT"
}

@test "run_hooks is a no-op without a hooks dir and tolerates failing hooks" {
  run run_hooks disconnected "X" "Y"
  [ "$status" -eq 0 ]
  mkdir -p "$DATA_DIR/hooks/disconnected.d"
  printf '#!/bin/sh\nexit 7\n' > "$DATA_DIR/hooks/disconnected.d/fail"
  chmod 700 "$DATA_DIR/hooks/disconnected.d/fail"
  run run_hooks disconnected "X" "Y"
  [ "$status" -eq 0 ]
}
