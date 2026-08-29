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

@test "a future-dated (poisoned or clock-skewed) attempt entry is pruned, not kept forever" {
  # A naive "age <= WINDOW" test never prunes an entry whose age is
  # NEGATIVE (a future timestamp), which would otherwise inflate the
  # attempt count and keep pushing the curve delay's reference point
  # forward indefinitely.
  local f; f="$(_sf "Work VPN")"
  local future=$(( $(date +%s) + 999999 ))
  token="$(_state_lock "$f")"
  _state_read "$f"
  ST_ATTEMPTS="$future"
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  admit_attempt "Work VPN" SERVICE
  release_attempt_owner "Work VPN"
  _state_read "$f"
  local n=0; for a in $ST_ATTEMPTS; do n=$((n+1)); done
  [ "$n" -eq 1 ]   # the poisoned future entry was dropped, not kept
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

@test "the clamp is persisted, not recomputed as a moving target on every read" {
  # Regression test: an earlier version only clamped ST_OPEN_UNTIL in memory,
  # so the ON-DISK poison value survived and every subsequent read
  # recomputed "now + 3600" relative to a NEW now -- making the breaker look
  # freshly-opened forever instead of expiring within an hour.
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f" "Work VPN"
  ST_OPEN_UNTIL=99999999999
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  _state_read "$f" "Work VPN"   # first read: applies and must persist the clamp
  local raw; raw="$(_state_field open_until_epoch "$f")"
  [ "$raw" != 99999999999 ]   # the ON-DISK value itself was corrected

  local first="$raw"
  sleep 1.1
  _state_read "$f" "Work VPN"   # second read, over a second later
  local second; second="$(_state_field open_until_epoch "$f")"
  [ "$first" = "$second" ]   # stable -- not "now + 3600" recomputed each time
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

# ------------------------------------------------- persistence must not lie
#
# Regression tests for a real review finding: admit_attempt ignored
# _state_persist_current's own status and returned "admitted" even when the
# commit never landed on disk -- fault-injected below by stubbing the persist
# function directly (this codebase's established stubbing idiom), which
# isolates the commit step from lock acquisition itself.

@test "admit_attempt (INTERACTIVE) never claims admission if the commit fails" {
  _state_persist_current() { return 1; }
  run admit_attempt "Work VPN" INTERACTIVE
  [ "$status" -ne 0 ]
  local f; f="$(_sf "Work VPN")"
  [ ! -e "$f" ]   # nothing was ever durably recorded
}

@test "admit_attempt (SERVICE) retries on commit failure rather than admitting" {
  local calls=0
  _state_persist_current() { calls=$((calls + 1)); [ "$calls" -ge 3 ] && return 0; return 1; }
  admit_attempt "Work VPN" SERVICE
  [ "$calls" -ge 3 ]   # it kept retrying rather than returning success on the first failure
}

@test "totp_wait_for_fresh_step never claims a reservation if the commit fails" {
  _state_persist_current() { return 1; }
  run totp_wait_for_fresh_step "Work VPN"
  [ "$status" -ne 0 ]
}

# ---------------------------------------------- an active tunnel is checked

@test "SERVICE admission defers while the profile has a live tunnel, even with no owner recorded" {
  # Reproduces the exact gap a review finding described: run_openconnect's
  # background branch releases the owner as soon as OpenConnect finishes
  # DAEMONIZING, not when the tunnel ends -- so a live tunnel can exist with
  # attempt_owner_pid=0. profile_vpn_running must be checked independently.
  profile_vpn_running() { [ "$1" = "Work VPN" ]; }
  ( admit_attempt "Work VPN" SERVICE; touch "$BATS_TEST_TMPDIR/admitted-despite-live-tunnel" ) &
  local bgpid=$!
  sleep 0.3
  [ ! -e "$BATS_TEST_TMPDIR/admitted-despite-live-tunnel" ]
  kill "$bgpid" 2>/dev/null || true
  wait "$bgpid" 2>/dev/null || true
}

@test "INTERACTIVE admission returns ALREADY_ACTIVE (2) rather than waiting for a live tunnel" {
  profile_vpn_running() { [ "$1" = "Work VPN" ]; }
  run admit_attempt "Work VPN" INTERACTIVE
  [ "$status" -eq 2 ]
}

# ------------------------------------------------- the real _state_persist

@test "_state_persist fails atomically rather than installing a truncated file" {
  # Regression test for the release blocker: the write block's own exit
  # status used to be discarded, so a fault partway through the write (disk
  # full, a file-size limit, ...) still let a truncated temp file get mv'd
  # into place, reporting SUCCESS while silently dropping fields like
  # attempt_owner_pid to their fail-open defaults on the next read.
  local f="$DATA_DIR/state/blocker1.state"
  _state_persist "$f" "Work VPN" "111 222" "0" "5" "0" "0" "0"
  [ -e "$f" ]
  local before; before="$(cat "$f")"

  # A tiny file-size limit turns a large write into a genuine partial-write
  # fault, in a real subshell -- not a stubbed function -- exercising the
  # actual writer.
  local long_attempts; long_attempts="$(seq 1 2000 | tr '\n' ' ')"
  local status
  if ( ulimit -f 1 2>/dev/null; _state_persist "$f" "Work VPN" "$long_attempts" "1234567890" "999" "4321" "1111111111" "1" ); then
    status=0
  else
    status=$?
  fi
  [ "$status" -ne 0 ]

  local after; after="$(cat "$f")"
  [ "$after" = "$before" ]   # the previous, complete state survives a faulted write
  [ ! -e "${f}.tmp."* ]     # no leaked temp file either
}

@test "_state_lock never reports success with unpublished owner metadata" {
  # Regression test: the owner-metadata write (a tiny printf, then a rename
  # into place) used to be unchecked -- a fault there (a failed rename; disk
  # full; a permission surprise) still returned a token via _state_lock,
  # while the lock directory itself carried no readable owner file for
  # _state_unlock to ever match against later, wedging the lock permanently.
  # Faulted via a failing `mv` on the FIRST attempt only (a fault this small
  # can't be reproduced with a real file-size limit without triggering a
  # fatal SIGXFSZ instead of an ordinary, checkable failure -- confirmed
  # directly: ulimit -f 0 on a write this size kills the process outright
  # rather than returning an error).
  local f; f="$(_sf "Work VPN")"
  local lockdir="${f}.lock"
  local callfile="$BATS_TEST_TMPDIR/mv-calls"
  : > "$callfile"
  mv() {
    case "$3" in
      */owner)
        printf 'x' >> "$callfile"
        [ "$(wc -c < "$callfile")" -eq 1 ] && return 1   # fail only the first rename
        ;;
    esac
    command mv "$@"
  }

  local token; token="$(_state_lock "$f")"
  [ -n "$token" ]                    # the (retried) acquisition did succeed...
  [ -s "${lockdir}/owner" ]          # ...and it is never reported without real metadata on disk
  _state_unlock "$f" "$token"        # proves _state_unlock can find/match this metadata at all

  # The faulted first attempt actually ran, and a second attempt (the
  # retry) actually reached the same rename call again -- and did not leave
  # a wedged lock directory behind for that retry to collide with: it
  # needed no dead-pid reclaim to succeed, which this SAME still-running
  # process could never pass the liveness check for.
  [ "$(cat "$callfile")" = "xx" ]
}

# ------------------------------------------- breaker expiry doesn't spin

@test "a persistently-failing breaker-expiry persist still sleeps between retries" {
  # Regression test: the expiry-clearing branch had no sleep on its failure
  # path, so a permanently failing persist spun on lock/read/write as fast as
  # the disk allowed instead of backing off like every other wait in this
  # loop.
  local f; f="$(_sf "Work VPN")"
  token="$(_state_lock "$f")"
  _state_read "$f" "Work VPN"
  ST_ATTEMPTS="$(date +%s)"
  ST_OPEN_UNTIL=$(( $(date +%s) - 1 ))   # already expired
  _state_persist_current "$f" "Work VPN"
  _state_unlock "$f" "$token"

  # admit_attempt runs backgrounded in its OWN subshell, so shell-variable
  # counters incremented there would never be visible to this process --
  # file-based counters cross that boundary correctly. Comparing counts
  # (rather than a call rate against a wall-clock budget) keeps this
  # deterministic across machines: lock-acquisition overhead alone varies too
  # much by filesystem/hardware for a fixed "N calls in M ms" threshold to
  # reliably tell "sleeping" from "spinning" apart.
  local persistfile="$BATS_TEST_TMPDIR/persist-calls" sleepfile="$BATS_TEST_TMPDIR/sleep-calls"
  : > "$persistfile"; : > "$sleepfile"
  _state_persist_current() { printf 'x' >> "$persistfile"; return 1; }
  sleep() { printf 'x' >> "$sleepfile"; }   # no-op stub: just records the call
  ( admit_attempt "Work VPN" SERVICE ) &
  local bgpid=$!
  command sleep 0.3   # the REAL sleep -- the stub above only applies inside the backgrounded subshell
  kill "$bgpid" 2>/dev/null || true
  wait "$bgpid" 2>/dev/null || true

  local persists sleeps
  persists="$(wc -c < "$persistfile")"
  sleeps="$(wc -c < "$sleepfile")"
  [ "$persists" -gt 0 ]                 # the failure path actually ran at least once
  [ "$sleeps" -ge $((persists - 1)) ]   # every failed persist is followed by a sleep call
}

# ------------------------------------- clamp persists even with no profile=

@test "the clamp is still persisted when the state file has no profile= field at all" {
  # Regression test: _state_read used to gate the clamp write-back on
  # ST_PROFILE (read from the same same-UID-writable file), so a missing or
  # corrupt profile= field silently disabled the fix entirely -- the exact
  # moving-horizon bug this test's sibling above already covers, reopened via
  # a different missing field. The caller's own already-known profile name is
  # what must be used instead.
  local f; f="$(_sf "Work VPN")"
  mkdir -p "$(dirname "$f")"
  {
    printf 'version=1\n'
    printf 'attempts=\n'
    printf 'open_until_epoch=99999999999\n'
    printf 'last_totp_step=0\n'
    printf 'attempt_owner_pid=0\n'
    printf 'attempt_owner_epoch=0\n'
    printf 'paused=0\n'
  } > "$f"
  chmod 600 "$f"

  _state_read "$f" "Work VPN"
  local raw; raw="$(_state_field open_until_epoch "$f")"
  [ "$raw" != 99999999999 ]

  local first="$raw"
  sleep 1.1
  _state_read "$f" "Work VPN"
  local second; second="$(_state_field open_until_epoch "$f")"
  [ "$first" = "$second" ]
}
