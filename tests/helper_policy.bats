#!/usr/bin/env bats
# Bridges the C policy-engine corpus into the shell test surface, so
# `bats tests/` remains the single command that runs everything.
#
# The engine itself is pure C with no external dependencies and no privileged
# operation (PRIVILEGED-HELPER-DESIGN.md §16 step 4), so this only needs a
# compiler.

setup() {
  HELPER_DIR="$BATS_TEST_DIRNAME/../helper"
}

@test "helper policy engine: builds with warnings as errors" {
  command -v cc >/dev/null 2>&1 || skip "no C compiler available"
  run make -C "$HELPER_DIR" clean all
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "helper policy engine: hostile-input corpus passes" {
  command -v cc >/dev/null 2>&1 || skip "no C compiler available"
  run make -C "$HELPER_DIR" test
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  # Guard against a harness that silently runs nothing.
  [[ "$output" == *"0 failures"* ]]
  [[ "$output" != *"0 checks"* ]]
}

@test "vpn-up-admin refuses to run without privilege" {
  command -v cc >/dev/null 2>&1 || skip "no C compiler available"
  make -C "$HELPER_DIR" all >/dev/null
  # The registry decides which VPNs this machine will establish without a
  # password, so writing it must never be reachable unprivileged.
  run "$HELPER_DIR/build/vpn-up-admin" list
  [ "$status" -ne 0 ]
  [[ "$output" == *"sudo"* ]]
}

@test "vpn-up-helper refuses to connect without privilege" {
  command -v cc >/dev/null 2>&1 || skip "no C compiler available"
  make -C "$HELPER_DIR" all >/dev/null
  run "$HELPER_DIR/build/vpn-up-helper" connect --profile-id a7d1bb99538c4db4b3570123456789ab
  [ "$status" -ne 0 ]
  [[ "$output" == *"root"* ]]
}

@test "vpn-up-helper pins openconnect outside any user-writable prefix" {
  command -v cc >/dev/null 2>&1 || skip "no C compiler available"
  make -C "$HELPER_DIR" all >/dev/null
  run "$HELPER_DIR/build/vpn-up-helper" version
  [ "$status" -eq 0 ]
  # Field extraction, not a regex: the path itself ends in "openconnect", so a
  # greedy .*openconnect match consumes the whole line and yields nothing.
  oc="$(awk '$1 == "openconnect" { print $2 }' <<< "$output")"
  [ -n "$oc" ]
  # Homebrew's prefix is owned by the installing user, so helper mode cannot use
  # it: pinning openconnect there would hand root a replaceable binary.
  [[ "$oc" != /opt/homebrew/* ]]
  [[ "$oc" != /usr/local/* ]]
  [[ "$oc" == /* ]]
}

@test "vpn-up-admin reports its roots without needing privilege" {
  command -v cc >/dev/null 2>&1 || skip "no C compiler available"
  make -C "$HELPER_DIR" all >/dev/null
  run "$HELPER_DIR/build/vpn-up-admin" version
  [ "$status" -eq 0 ]
  # The registry must NOT live under the volatile state root: /run and /var/run
  # are cleared at boot, which would silently revoke every approval.
  [[ "$output" == *"registry root"* ]]
  [[ "$output" == *"state root"* ]]
  registry="$(sed -n 's/.*registry root *//p' <<< "$output")"
  state="$(sed -n 's/.*state root *//p' <<< "$output")"
  [ "$registry" != "$state" ]
  [[ "$state" == */run/* || "$state" == /run/* ]]
  [[ "$registry" != */run/* ]]
}
