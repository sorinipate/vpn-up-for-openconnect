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
