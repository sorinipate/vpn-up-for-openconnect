#!/usr/bin/env bats
# End-to-end CLI dispatch tests against the real entry point in a sandbox.

setup() {
  export VPN_UP_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$VPN_UP_HOME"
  CLI="$BATS_TEST_DIRNAME/../vpn-up.command"
  cat > "$VPN_UP_HOME/vpn-up.command.profiles" <<'XML'
<VPNs>
  <VPN><name>CLI VPN</name><protocol>anyconnect</protocol><host>cli.example.com</host><user>u</user><password></password><duo2FAMethod>push</duo2FAMethod></VPN>
</VPNs>
XML
  chmod 600 "$VPN_UP_HOME/vpn-up.command.profiles"
}

@test "no arguments prints usage with the display name" {
  run "$CLI"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage: vpn-up <command>"* ]]
  [[ "$output" == *"start [profile]"* ]]
}

@test "start with no profiles, non-tty: seeds template and exits 1" {
  rm -f "$VPN_UP_HOME/vpn-up.command.profiles"
  # config present so the setup wizard doesn't interfere
  cat > "$VPN_UP_HOME/vpn-up.command.config" <<'EOF'
readonly BACKGROUND=TRUE
readonly QUIET=TRUE
readonly SHOW_BANNER=FALSE
readonly NOTIFICATIONS=FALSE
EOF
  chmod 600 "$VPN_UP_HOME/vpn-up.command.config"
  run "$CLI" start < /dev/null
  [ "$status" -eq 1 ]
  [[ "$output" == *"Created profile template"* ]]
  [ -f "$VPN_UP_HOME/vpn-up.command.profiles" ]
}

@test "unknown command prints usage" {
  run "$CLI" frobnicate
  [[ "$output" == *"Usage:"* ]]
}

@test "set-secret requires profile and field" {
  run "$CLI" set-secret
  [ "$status" -eq 1 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "set-secret refuses to store a sudo password" {
  run "$CLI" set-secret __GLOBAL__ sudo_password
  [ "$status" -eq 1 ]
  [[ "$output" == *"not supported"* ]]
}

@test "delete-secret requires profile and field" {
  run "$CLI" delete-secret onlyone
  [ "$status" -eq 1 ]
}

@test "pin requires a host or --save profile" {
  run "$CLI" pin
  [ "$status" -eq 1 ]
  run "$CLI" pin --save
  [ "$status" -eq 1 ]
}

@test "list shows seeded profile" {
  run "$CLI" list
  [ "$status" -eq 0 ]
  [[ "$output" == *"CLI VPN"* ]]
  [[ "$output" == *"cli.example.com"* ]]
}

@test "list-names emits bare names for completion" {
  run "$CLI" list-names
  [ "$output" = "CLI VPN" ]
}

@test "status reports not running in a fresh sandbox" {
  run "$CLI" status
  [ "$status" -eq 0 ]
  [[ "$output" == *"not running"* ]]
}

@test "logs warns when there is no log yet" {
  run "$CLI" logs
  [ "$status" -eq 0 ]
  [[ "$output" == *"No log file yet"* ]]
}

@test "remove-profile requires an argument and rejects unknown profiles" {
  run "$CLI" remove-profile
  [ "$status" -eq 1 ]
  run "$CLI" remove-profile "Ghost"
  [ "$status" -eq 1 ]
}

@test "service requires a valid subcommand" {
  run "$CLI" service bogus
  [ "$status" -eq 1 ]
  [[ "$output" == *"Usage:"* ]]
}
