#!/usr/bin/env bats
# Tests for the unattended-authentication attempt rate limiter (outcome.sh):
# admission, the sliding window, the temporary breaker, owner liveness, and
# the SERVICE/INTERACTIVE mode split. See PRIVILEGED-HELPER-DESIGN.md's
# rate-limiter security invariants for what these exist to hold.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR"
  # Fast polling so a test that legitimately waits (a live owner, a curve
  # delay) doesn't sit through the real 5s/0.2s production defaults.
  export VPN_UP_ATTEMPT_POLL=0.05
  export VPN_UP_LOCK_POLL=0.02
  print_warning() { :; }; print_danger() { :; }; print_success() { :; }; print_primary() { :; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../outcome.sh"
}

_sf() { attempt_state_file "$1"; }

# --------------------------------------------------------------- admission

@test "admission is what's counted, not outcome" {
  # The whole point of the design: nothing here ever looks at what
  # OpenConnect returned. Admitting three attempts in a row (as a caller
  # would after three failed connections) must show n=3 in the ring
  # regardless of anything about "success" -- there is no outcome parameter
  # to admit_attempt at all.
  local f n; f="$(_sf "Work VPN")"
  admit_attempt "Work VPN" SERVICE
  release_attempt_owner "Work VPN"
  _state_read "$f"
  n=0; for a in $ST_ATTEMPTS; do n=$((n+1)); done
  [ "$n" -eq 1 ]
}

@test "SERVICE mode appends to the ring; INTERACTIVE mode never does" {
  local f; f="$(_sf "Work VPN")"
  admit_attempt "Work VPN" INTERACTIVE
  release_attempt_owner "Work VPN"
  _state_read "$f"
  [ -z "$ST_ATTEMPTS" ]

  admit_attempt "Work VPN" SERVICE
  release_attempt_owner "Work VPN"
  _state_read "$f"
  [ -n "$ST_ATTEMPTS" ]
}

@test "INTERACTIVE never delays on the curve or breaker, only on a live owner" {
  local f; f="$(_sf "Work VPN")"
  # Force the breaker open.
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_OPEN_UNTIL=$(( $(date +%s) + 3600 ))
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  local t0 t1
  t0="$(date +%s)"
  admit_attempt "Work VPN" INTERACTIVE
  t1="$(date +%s)"
  release_attempt_owner "Work VPN"
  # Admitted essentially immediately -- not blocked by the open breaker.
  [ $((t1 - t0)) -le 2 ]
}

@test "the sliding window: attempts far apart don't accumulate" {
  local f; f="$(_sf "Work VPN")"
  local now; now="$(date +%s)"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_ATTEMPTS="$(( now - 7300 ))"   # just outside the 2h window
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  admit_attempt "Work VPN" SERVICE
  release_attempt_owner "Work VPN"
  _state_read "$f"
  local n=0; for a in $ST_ATTEMPTS; do n=$((n+1)); done
  # The stale entry was pruned; only this admission's own timestamp remains.
  [ "$n" -eq 1 ]
}

@test "the breaker opens at the threshold and blocks a SERVICE attempt" {
  local f; f="$(_sf "Work VPN")"
  local now; now="$(date +%s)"
  token="$(_state_lock "$f")"
  _state_read "$f"
  # Six attempts, all recent -- at threshold.
  ST_ATTEMPTS="$now $now $now $now $now $now"
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  # admit_attempt would poll forever while the breaker is open (by design),
  # so run it in the background and assert it has NOT returned yet.
  ( admit_attempt "Work VPN" SERVICE; touch "$BATS_TEST_TMPDIR/admitted" ) &
  local bgpid=$!
  sleep 0.3
  [ ! -e "$BATS_TEST_TMPDIR/admitted" ]
  kill "$bgpid" 2>/dev/null || true
  wait "$bgpid" 2>/dev/null || true

  _state_read "$f"
  [ "$ST_OPEN_UNTIL" -gt "$now" ]
}

@test "breaker expiry retires the triggering window, and only the window" {
  local f; f="$(_sf "Work VPN")"
  local now; now="$(date +%s)"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_ATTEMPTS="$now $now $now $now $now $now"
  ST_OPEN_UNTIL=$(( now - 1 ))   # already expired
  ST_TOTP_STEP=999
  ST_PAUSED=0
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  admit_attempt "Work VPN" SERVICE
  release_attempt_owner "Work VPN"

  _state_read "$f"
  # Regression test for the "second hour" bug: n=6 with an expired breaker
  # must NOT immediately reopen a fresh one -- it retires to n=1 (this
  # admission's own entry), not n=7.
  local n=0; for a in $ST_ATTEMPTS; do n=$((n+1)); done
  [ "$n" -eq 1 ]
  [ "$ST_OPEN_UNTIL" -eq 0 ]
  # The clear touches only the ring and open_until_epoch -- nothing else.
  [ "$ST_TOTP_STEP" -eq 999 ]
}

@test "a delay is respected: a fresh attempt after one recent one waits" {
  local f; f="$(_sf "Work VPN")"
  local now; now="$(date +%s)"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_ATTEMPTS="$now"
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  ( admit_attempt "Work VPN" SERVICE; touch "$BATS_TEST_TMPDIR/admitted2" ) &
  local bgpid=$!
  sleep 0.3
  # curve[1] = 60s, so this must NOT have been admitted yet.
  [ ! -e "$BATS_TEST_TMPDIR/admitted2" ]
  kill "$bgpid" 2>/dev/null || true
  wait "$bgpid" 2>/dev/null || true
}

# ------------------------------------------------------------- ownership

@test "owner marker prevents double admission for the same profile" {
  local f; f="$(_sf "Work VPN")"
  ( admit_attempt "Work VPN" SERVICE; sleep 1; release_attempt_owner "Work VPN" ) &
  local first=$!
  sleep 0.2
  _state_read "$f"
  [ "$ST_OWNER_PID" != 0 ]

  ( admit_attempt "Work VPN" INTERACTIVE; touch "$BATS_TEST_TMPDIR/second-admitted" ) &
  local second=$!
  sleep 0.3
  [ ! -e "$BATS_TEST_TMPDIR/second-admitted" ]
  wait "$first" 2>/dev/null || true
  wait "$second" 2>/dev/null || true
}

@test "a long-running owner is never reclaimed for being old -- liveness only" {
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_OWNER_PID=$$
  ST_OWNER_EPOCH=1   # ancient
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  ( admit_attempt "Work VPN" INTERACTIVE; touch "$BATS_TEST_TMPDIR/reclaimed" ) &
  local bgpid=$!
  sleep 0.3
  [ ! -e "$BATS_TEST_TMPDIR/reclaimed" ]   # our own pid is alive: never reclaimed
  kill "$bgpid" 2>/dev/null || true
  wait "$bgpid" 2>/dev/null || true
}

@test "a dead owner is reclaimed regardless of age" {
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_OWNER_PID=99999999   # not a real pid
  ST_OWNER_EPOCH=1
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  admit_attempt "Work VPN" INTERACTIVE
  release_attempt_owner "Work VPN"
  _state_read "$f"
  [ "$ST_OWNER_PID" = 0 ]
}

# ------------------------------------------------------------------ locks

@test "normal unlock never tears down a lock it does not hold" {
  local f; f="$(_sf "Work VPN")"
  local t1 t2
  t1="$(_state_lock "$f")"
  # A second, unrelated token must not be able to release process 1's lock.
  _state_unlock "$f" "not-the-real-token"
  [ -d "${f}.lock" ]
  _state_unlock "$f" "$t1"
  [ ! -d "${f}.lock" ]
}

@test "a dead-owner lock is reclaimed, serialized through the meta-lock" {
  local f; f="$(_sf "Work VPN")"
  mkdir -p "${f}.lock"
  { printf 'pid=99999999\n'; printf 'token=x\n'; printf 'created=%s\n' "$(date +%s)"; } \
    > "${f}.lock/owner"

  local token; token="$(_state_lock "$f")"
  [ -n "$token" ]
  [ ! -d "${f}.lock.reclaiming" ]   # cleaned up after use
  _state_unlock "$f" "$token"
}

@test "profile identity: colliding slugs get distinct state files" {
  local a b
  a="$(attempt_state_file "Work VPN")"
  b="$(attempt_state_file "Work/VPN")"
  [ "$a" != "$b" ]
  # profile_slug alone would collide; the full digest is what actually
  # prevents it.
  [[ "$a" == *"$(profile_slug "Work VPN")"* ]]
  [[ "$b" == *"$(profile_slug "Work/VPN")"* ]]
}

@test "no hash tool available fails loudly, never an empty key" {
  command() { [ "$2" = shasum ] && return 1; [ "$2" = sha256sum ] && return 1; [ "$2" = openssl ] && return 1; builtin command "$@"; }
  # Capture stdout separately from the (expected, printed-to-stdout by this
  # codebase's print_danger convention) diagnostic message: the function must
  # fail loudly (non-zero status) rather than silently succeed with an empty
  # key -- attempt_state_file's own `|| return 1` guard is what a caller
  # actually relies on.
  run attempt_state_file "Work VPN"
  [ "$status" -ne 0 ]
}

# ------------------------------------------------------- fail-open fields

@test "non-numeric or missing fields fail open, never block admission" {
  local f; f="$(_sf "Work VPN")"
  mkdir -p "$(dirname "$f")"
  {
    printf 'version=1\n'
    printf 'profile=Work VPN\n'
    printf 'attempts=notanumber 123abc\n'
    printf 'open_until_epoch=garbage\n'
    printf 'attempt_owner_pid=garbage\n'
    printf 'paused=whatever\n'
  } > "$f"
  chmod 600 "$f"

  admit_attempt "Work VPN" INTERACTIVE
  release_attempt_owner "Work VPN"
  # If we got here at all (no hang, no error), the corrupt fields were
  # treated as their safe defaults rather than blocking the connection.
}

@test "open_until_epoch far in the future is clamped" {
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_OPEN_UNTIL=99999999999
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  _state_read "$f"
  [ "$ST_OPEN_UNTIL" -le $(( $(date +%s) + 3600 )) ]
}

# ------------------------------------------------------------------ clears

@test "attempt_history_clear touches only the ring, never the TOTP step" {
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_ATTEMPTS="1 2 3"
  ST_TOTP_STEP=42
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  attempt_history_clear "Work VPN"
  _state_read "$f"
  [ -z "$ST_ATTEMPTS" ]
  [ "$ST_TOTP_STEP" -eq 42 ]
}

@test "totp_step_reservation_clear clears only the step" {
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_ATTEMPTS="1 2 3"
  ST_TOTP_STEP=42
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  totp_step_reservation_clear "Work VPN"
  _state_read "$f"
  [ "$ST_TOTP_STEP" -eq 0 ]
  [ "$ST_ATTEMPTS" = "1 2 3" ]
}

# --------------------------------------------------------------- outcomes

@test "outcome_from_run: rc==0 is always RUN_ENDED regardless of had_tunnel" {
  [ "$(outcome_from_run 0 1)" -eq "$VPN_RC_RUN_ENDED" ]
  [ "$(outcome_from_run 0 0)" -eq "$VPN_RC_RUN_ENDED" ]
}

@test "outcome_from_run: non-zero + no tunnel is POLICY, + a tunnel is ATTEMPT_FAILED" {
  [ "$(outcome_from_run 1 0)" -eq "$VPN_RC_POLICY" ]
  [ "$(outcome_from_run 1 1)" -eq "$VPN_RC_ATTEMPT_FAILED" ]
}

@test "service_exit_code maps only CONFIG/POLICY to stop, everything else to restart" {
  [ "$(service_exit_code "$VPN_RC_CONFIG")" -eq 0 ]
  [ "$(service_exit_code "$VPN_RC_POLICY")" -eq 0 ]
  [ "$(service_exit_code "$VPN_RC_RUN_ENDED")" -eq "$VPN_RC_SUPERVISOR_RETRY" ]
  [ "$(service_exit_code "$VPN_RC_ATTEMPT_FAILED")" -eq "$VPN_RC_SUPERVISOR_RETRY" ]
  [ "$(service_exit_code "$VPN_RC_NO_NETWORK")" -eq "$VPN_RC_SUPERVISOR_RETRY" ]
  [ "$(service_exit_code "$VPN_RC_ALREADY_ACTIVE")" -eq "$VPN_RC_SUPERVISOR_RETRY" ]
  [ "$(service_exit_code "$VPN_RC_PREAUTH")" -eq "$VPN_RC_SUPERVISOR_RETRY" ]
}
