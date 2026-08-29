#!/usr/bin/env bats
# Tests for TOTP step reservation (outcome.sh): reserve-before-generate, the
# step-collision guard, and that the step index (never the code) is what's
# persisted. See PRIVILEGED-HELPER-DESIGN.md's rate-limiter section for why
# this exists (launchd's ThrottleInterval has no floor after a long session).

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR"
  export VPN_UP_ATTEMPT_POLL=0.05
  export VPN_UP_LOCK_POLL=0.02
  print_warning() { :; }; print_danger() { :; }; print_success() { :; }; print_primary() { :; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../outcome.sh"
}

@test "VPN_UP_NO_TOTP_WAIT=1 skips the wait entirely" {
  export VPN_UP_NO_TOTP_WAIT=1
  local f; f="$(attempt_state_file "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_TOTP_STEP=$(( $(date +%s) / TOTP_STEP_SECS ))   # already "used" this step
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  local t0 t1
  t0="$(date +%s)"
  totp_wait_for_fresh_step "Work VPN"
  t1="$(date +%s)"
  [ $((t1 - t0)) -le 1 ]
}

@test "a fresh step is reserved immediately, no wait" {
  local f; f="$(attempt_state_file "Work VPN")"
  local t0 t1
  t0="$(date +%s)"
  totp_wait_for_fresh_step "Work VPN"
  t1="$(date +%s)"
  [ $((t1 - t0)) -le 1 ]
  _state_read "$f"
  [ "$ST_TOTP_STEP" -eq $(( t0 / TOTP_STEP_SECS )) ]
}

@test "the same step is not reserved twice: the second caller waits for the next boundary" {
  local f; f="$(attempt_state_file "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_TOTP_STEP=$(( $(date +%s) / TOTP_STEP_SECS ))
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  ( totp_wait_for_fresh_step "Work VPN"; touch "$BATS_TEST_TMPDIR/reserved" ) &
  local bgpid=$!
  sleep 0.3
  # Still the same step: the caller must be waiting, not having reserved it.
  [ ! -e "$BATS_TEST_TMPDIR/reserved" ]
  kill "$bgpid" 2>/dev/null || true
  wait "$bgpid" 2>/dev/null || true
}

@test "the file records the step, never the six-digit code" {
  local f; f="$(attempt_state_file "Work VPN")"
  totp_wait_for_fresh_step "Work VPN"
  # A plausible-looking TOTP code must never appear in the state file --
  # only the step index does. Assert the file has no 6-digit run anywhere
  # except as part of a much larger epoch-derived number (last_totp_step).
  ! grep -qE '(^|[^0-9])[0-9]{6}([^0-9]|$)' "$f"
  grep -q '^last_totp_step=' "$f"
}

@test "reservation is exclusive under lock contention, not just when free" {
  # Two racing callers for the same fresh step: only one may proceed
  # immediately: prove the lock is what enforces this, not luck, by holding
  # it externally first.
  local f; f="$(attempt_state_file "Work VPN")"
  local token; token="$(_state_lock "$f")"

  ( totp_wait_for_fresh_step "Work VPN"; touch "$BATS_TEST_TMPDIR/done-while-locked" ) &
  local bgpid=$!
  sleep 0.3
  [ ! -e "$BATS_TEST_TMPDIR/done-while-locked" ]   # blocked on our external lock
  _state_unlock "$f" "$token"
  wait "$bgpid" 2>/dev/null || true
  [ -e "$BATS_TEST_TMPDIR/done-while-locked" ]      # proceeds once released
}
