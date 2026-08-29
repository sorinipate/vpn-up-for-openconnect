#!/usr/bin/env bats
# Tests for the outcome-code plumbing threaded through run_openconnect and
# start() (core.sh / outcome.sh). The regression this guards against: a lost
# PIPESTATUS capture meant run_openconnect always returned 0 regardless of
# what OpenConnect actually did, which is what let a service restart forever
# without ever being told to stop.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  export PROFILES_FILE="$DATA_DIR/profiles.xml"
  export VPN_UP_ATTEMPT_POLL=0.05
  export VPN_UP_LOCK_POLL=0.02
  print_warning() { :; }; print_danger() { :; }; print_success() { :; }; print_primary() { :; }
  notify() { :; }
  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../outcome.sh"
  source "$BATS_TEST_DIRNAME/../dependencies.sh"
  source "$BATS_TEST_DIRNAME/../profiles.sh"
  source "$BATS_TEST_DIRNAME/../core.sh"
}

_write_profile() {
  cat > "$PROFILES_FILE" <<'XML'
<VPNs>
  <VPN><name>Work VPN</name><protocol>anyconnect</protocol><host>work.example.com</host><user>alice</user><password></password><duo2FAMethod>push</duo2FAMethod></VPN>
</VPNs>
XML
}

_common_fields() {
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  SERVER_CERTIFICATE="pin-sha256:abc"
  QUIET=FALSE
}

# ----------------------------------- the six bare-call sites, regression ---

@test "run_openconnect (background) returns 0 when sudo returns 0" {
  _write_profile; _common_fields
  BACKGROUND=TRUE
  sudo() { return 0; }
  run run_openconnect
  [ "$status" -eq 0 ]
}

@test "run_openconnect (foreground) returns 0 when sudo/tee both return 0" {
  _write_profile; _common_fields
  BACKGROUND=FALSE
  sudo() { return 0; }
  tee() { cat >/dev/null; return 0; }
  sleep() { :; }
  run run_openconnect
  [ "$status" -eq 0 ]
}

@test "run_openconnect (sso) returns 0 when sudo/tee both return 0" {
  _write_profile; _common_fields
  VPN_AUTH_MODE=sso
  sudo() { return 0; }
  tee() { cat >/dev/null; return 0; }
  sleep() { :; }
  run run_openconnect
  [ "$status" -eq 0 ]
}

# ------------------------------------------ PIPESTATUS index correctness ---

@test "foreground: a failing openconnect is not masked by a succeeding tee" {
  _write_profile; _common_fields
  BACKGROUND=FALSE
  sudo() { return 7; }         # openconnect itself fails
  tee() { cat >/dev/null; return 0; }   # tee succeeds -- must not win
  sleep() { :; }
  run run_openconnect
  [ "$status" -eq "$VPN_RC_ATTEMPT_FAILED" ]
}

@test "sso: a failing openconnect is not masked by a succeeding tee" {
  _write_profile; _common_fields
  VPN_AUTH_MODE=sso
  sudo() { return 7; }
  tee() { cat >/dev/null; return 0; }
  sleep() { :; }
  run run_openconnect
  [ "$status" -eq "$VPN_RC_ATTEMPT_FAILED" ]
}

@test "background: a failing openconnect outcome is ATTEMPT_FAILED" {
  _write_profile; _common_fields
  BACKGROUND=TRUE
  sudo() { return 7; }
  run run_openconnect
  [ "$status" -eq "$VPN_RC_ATTEMPT_FAILED" ]
}

# ------------------------------------------------------- start()'s outcome -

@test "ensure_profile_not_running failing returns ALREADY_ACTIVE, not CONFIG" {
  _write_profile
  is_openconnect_pid() { return 0; }   # "already running"
  echo 12345 > "${DATA_DIR}/pids/${PROGRAM_NAME}.Work_VPN.pid"
  is_network_available() { return 0; }
  show_banner() { :; }
  local called="$BATS_TEST_TMPDIR/admit-called"
  admit_attempt() { touch "$called"; return 0; }

  export CONFIGURATION_FILE="$DATA_DIR/cfg"
  cat > "$CONFIGURATION_FILE" <<'EOF'
BACKGROUND=FALSE
QUIET=TRUE
SHOW_BANNER=FALSE
NOTIFICATIONS=FALSE
EOF
  chmod 600 "$CONFIGURATION_FILE"

  run start "Work VPN"
  [ "$status" -eq "$VPN_RC_ALREADY_ACTIVE" ]
  [ ! -e "$called" ]   # no attempt-rate budget spent on a transient condition
}

# --------------------------------------- the supervisor-contract invariant -
#
# Nothing in start's call tree may `exit` the process directly -- every
# failure must return an outcome, or a service never gets the right
# instruction (stop vs. restart) and instead sees whatever raw status an
# unmapped `exit` happened to produce.

@test "require_bin returns rather than exits" {
  command() { [ "$2" = doesnotexist123 ] && return 1; builtin command "$@"; }
  run require_bin doesnotexist123 "install it"
  [ "$status" -eq 1 ]
}

@test "check_dependencies propagates a missing dependency without exiting" {
  command() { [ "$2" = xmlstarlet ] && return 1; builtin command "$@"; }
  run check_dependencies
  [ "$status" -eq 1 ]
}

@test "check_file_existence returns rather than exits" {
  run check_file_existence "$BATS_TEST_TMPDIR/does-not-exist" "Profiles"
  [ "$status" -eq 1 ]
}

@test "a service with no configuration file returns CONFIG without calling setup_wizard" {
  export VPN_UP_SERVICE=1
  export CONFIGURATION_FILE="$DATA_DIR/does-not-exist.cfg"
  local wizard_called="$BATS_TEST_TMPDIR/wizard-called"
  setup_wizard() { touch "$wizard_called"; }
  run start ""
  [ "$status" -eq "$VPN_RC_CONFIG" ]
  [ ! -e "$wizard_called" ]
}
