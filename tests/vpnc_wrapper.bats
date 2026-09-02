#!/usr/bin/env bats
# Direct tests of the vpnc-script wrapper template (connection-state design
# plan §2) — the root-owned script OpenConnect actually invokes in helper
# mode, which records tunnel-event telemetry and delegates unchanged to the
# real vpnc-script.
#
# The BUILT wrapper bakes in production's REAL_VPNC_SCRIPT/STATE_ROOT as
# literals (helper/Makefile), which is exactly right for a privileged
# artefact but makes it untestable unprivileged as shipped. So these tests
# generate their OWN instance from the same template with the same `sed`
# substitution the Makefile uses, pointed at a fixture "real script" and a
# fixture state root instead — the shell equivalent of the C corpus's
# *_in()/expect_uid parameterisation (vu_state_paths_in, etc.), which exists
# for the identical reason: production pins the root, tests parameterise it,
# and the code under test must be the same either way.

setup() {
  HELPER_DIR="$BATS_TEST_DIRNAME/../helper"
  TEMPLATE="$HELPER_DIR/vpn-up-vpnc-wrapper.sh.in"
  STATE_ROOT="$BATS_TEST_TMPDIR/state"
  FAKE_REAL="$BATS_TEST_TMPDIR/fake-vpnc-script"
  WRAPPER="$BATS_TEST_TMPDIR/wrapper"
  MARKER="$BATS_TEST_TMPDIR/marker"

  sed -e "s#@VU_VPNC_SCRIPT_REAL@#$FAKE_REAL#" \
      -e "s#@VU_STATE_ROOT@#$STATE_ROOT#" "$TEMPLATE" > "$WRAPPER"
  chmod +x "$WRAPPER"

  cat > "$FAKE_REAL" <<EOF
#!/bin/sh
printf 'ran reason=%s\n' "\$reason" >> "$MARKER"
exit "\${FAKE_EXIT:-0}"
EOF
  chmod +x "$FAKE_REAL"

  UID_N=1000
  PROFILE="11111111-1111-1111-1111-111111111111"
  SESSION="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  REQUEST="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  PROFILE_DIR="$STATE_ROOT/$UID_N/$PROFILE"
  STATUS_FILE="$PROFILE_DIR/status"
  mkdir -p "$PROFILE_DIR"
}

_run_wrapper() {
  # reason and the four VUP_* are always exported by name below, per test.
  run env reason="$REASON" VUP_STATE_UID="$VUP_STATE_UID" \
      VUP_PROFILE_ID="$VUP_PROFILE_ID" VUP_SESSION_ID="$VUP_SESSION_ID" \
      VUP_REQUEST_ID="$VUP_REQUEST_ID" FAKE_EXIT="${FAKE_EXIT:-0}" "$WRAPPER"
}

status_field() { sed -n "s/^$1=//p" "$STATUS_FILE"; }

@test "vpnc wrapper: template is present and valid POSIX sh" {
  [ -f "$TEMPLATE" ]
  sh -n "$WRAPPER"
}

@test "vpnc wrapper: a successful connect records verified evidence AFTER the real script runs" {
  REASON=connect VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ -f "$MARKER" ]                      # the real script actually ran
  [ -f "$STATUS_FILE" ]
  [ "$(status_field session)" = "$SESSION" ]
  [ "$(status_field request_id)" = "$REQUEST" ]
  [ "$(status_field current_verified)" = "1" ]
  [ "$(status_field last_reason)" = "connect" ]
  [ "$(status_field last_connected_epoch)" -gt 0 ]
}

@test "vpnc wrapper: connect does NOT record verified evidence when the real script fails" {
  REASON=connect VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=1
  _run_wrapper
  [ "$status" -eq 1 ]                   # the real script's exit code, propagated
  [ ! -f "$STATUS_FILE" ]               # nothing recorded: positive evidence needs rc=0
}

@test "vpnc wrapper: disconnect records the downgrade UNCONDITIONALLY, even when the real script fails" {
  cat > "$STATUS_FILE" <<EOF
version=1
session=$SESSION
request_id=$REQUEST
last_connected_epoch=12345
current_verified=1
last_reason=connect
last_event_epoch=12345
EOF
  REASON=disconnect VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=1
  _run_wrapper
  [ "$status" -eq 1 ]                   # the real script's own failure still propagates
  [ "$(status_field current_verified)" = "0" ]
  [ "$(status_field last_reason)" = "disconnect" ]
  # sticky: a downgrade must not erase the fact that a real connect happened
  [ "$(status_field last_connected_epoch)" = "12345" ]
}

@test "vpnc wrapper: attempt-reconnect downgrades current_verified without erasing last_connected_epoch" {
  cat > "$STATUS_FILE" <<EOF
version=1
session=$SESSION
request_id=$REQUEST
last_connected_epoch=999
current_verified=1
last_reason=connect
last_event_epoch=999
EOF
  REASON=attempt-reconnect VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ "$(status_field current_verified)" = "0" ]
  [ "$(status_field last_reason)" = "attempt-reconnect" ]
  [ "$(status_field last_connected_epoch)" = "999" ]
}

@test "vpnc wrapper: a fast connect-then-disconnect is not lost" {
  REASON=connect VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ "$(status_field current_verified)" = "1" ]
  connected_epoch="$(status_field last_connected_epoch)"

  REASON=disconnect FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ "$(status_field current_verified)" = "0" ]
  [ "$(status_field last_reason)" = "disconnect" ]
  [ "$(status_field last_connected_epoch)" = "$connected_epoch" ]
}

@test "vpnc wrapper: last_connected_epoch is preserved only when the existing record's request_id matches" {
  cat > "$STATUS_FILE" <<EOF
version=1
session=cccccccccccccccccccccccccccccccc
request_id=dddddddddddddddddddddddddddddddd
last_connected_epoch=555
current_verified=1
last_reason=connect
last_event_epoch=555
EOF
  # This generation's own request id ($REQUEST) differs from the record above
  # (a prior, unrelated generation's leftovers) — its epoch must NOT survive.
  REASON=attempt-reconnect VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ "$(status_field session)" = "$SESSION" ]
  [ "$(status_field request_id)" = "$REQUEST" ]
  [ "$(status_field last_connected_epoch)" = "0" ]
}

@test "vpnc wrapper: a bare 32-hex profile id (not the canonical dashed grammar) is rejected — no telemetry, real script still runs" {
  bare_profile="11111111111111111111111111111111"    # 32 raw hex, wrapper requires dashed
  REASON=connect VUP_STATE_UID=$UID_N VUP_PROFILE_ID="$bare_profile" \
    VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ -f "$MARKER" ]                      # delegation to the real script still happens
  [ ! -f "$STATUS_FILE" ]               # but nothing was ever recorded
}

@test "vpnc wrapper: missing VUP_* variables (old client/helper) skip telemetry entirely and still delegate" {
  REASON=connect VUP_STATE_UID= VUP_PROFILE_ID= VUP_SESSION_ID= VUP_REQUEST_ID= FAKE_EXIT=0
  _run_wrapper
  [ "$status" -eq 0 ]
  [ -f "$MARKER" ]
  [ ! -f "$STATUS_FILE" ]
}

@test "vpnc wrapper: the real script's exit code always propagates, whatever the reason" {
  for r in connect disconnect reconnect attempt-reconnect; do
    rm -f "$STATUS_FILE" "$MARKER"
    REASON="$r" VUP_STATE_UID=$UID_N VUP_PROFILE_ID=$PROFILE \
      VUP_SESSION_ID=$SESSION VUP_REQUEST_ID=$REQUEST FAKE_EXIT=17
    _run_wrapper
    [ "$status" -eq 17 ]
  done
}
