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

# ---------------------------------------------------------- load_config

@test "an unsafe config makes load_config return, not exit" {
  export CONFIGURATION_FILE="$DATA_DIR/cfg"
  local marker="$BATS_TEST_TMPDIR/reached-after-load-config"
  echo "readonly BOGUS=1" > "$CONFIGURATION_FILE"
  chmod 666 "$CONFIGURATION_FILE"   # group/other-writable: unsafe to source
  local status
  if ( load_config; rc=$?; touch "$marker"; exit "$rc" ); then
    status=0
  else
    status=$?
  fi
  [ "$status" -eq 1 ]
  [ -e "$marker" ]   # code after load_config's call ran -- no exit happened
}

@test "start() maps an unsafe config to CONFIG, not an unmapped exit" {
  export CONFIGURATION_FILE="$DATA_DIR/cfg"
  echo "readonly BOGUS=1" > "$CONFIGURATION_FILE"
  chmod 666 "$CONFIGURATION_FILE"
  run start ""
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

# ------------------------------------------------- certificate preflight

@test "certificate: could not obtain one at all is NO_NETWORK, not CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  SERVER_CERTIFICATE="pin-sha256:abc"
  fetch_server_pin() { return 1; }   # unreachable -- the real function's own contract
  run _preflight_verify_certificate
  [ "$status" -eq "$VPN_RC_NO_NETWORK" ]
}

@test "certificate: a real pin mismatch is still CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  SERVER_CERTIFICATE="pin-sha256:configured"
  fetch_server_pin() { echo "pin-sha256:different"; }
  run _preflight_verify_certificate
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "unpinned: an ambiguous second-probe failure is treated as transient, not terminal" {
  # gateway_tls_reachable succeeds once (the preflight check itself), then
  # verify_gateway_cert fails, then a re-check ALSO fails -- simulating the
  # gateway vanishing between the two separate TLS transactions. Must not be
  # reported as a certificate/trust problem.
  _write_profile
  load_profile_fields "Work VPN"
  SERVER_CERTIFICATE=""
  local calls=0
  gateway_tls_reachable() { calls=$((calls + 1)); [ "$calls" -eq 1 ]; }
  verify_gateway_cert() { return 1; }
  run _preflight_verify_certificate
  [ "$status" -eq "$VPN_RC_NO_NETWORK" ]
}

@test "unpinned: a still-reachable gateway failing trust is genuinely CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  SERVER_CERTIFICATE=""
  gateway_tls_reachable() { return 0; }   # reachable both times
  verify_gateway_cert() { return 1; }     # genuinely untrusted
  run _preflight_verify_certificate
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "legacy SHA-1 pin still gets a reachability check before the warning" {
  _write_profile
  load_profile_fields "Work VPN"
  SERVER_CERTIFICATE="sha1:legacy-value"
  gateway_tls_reachable() { return 1; }   # gateway is down
  run _preflight_verify_certificate
  [ "$status" -eq "$VPN_RC_NO_NETWORK" ]
}

# ------------------------------------------------- password existence

@test "a SERVICE profile with no stored password and no client cert is CONFIG in preflight" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  secrets_get() { echo ""; }
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

# A secrets-backend read failure (vault decrypt error, keychain/secret-tool
# error, ...) must NOT be read the same way as "nothing is stored" --
# collapsing both into CONFIG permanently stops a service over what may be a
# transient backend problem (e.g. a keyring not yet unlocked at login-service
# startup). secrets_get() itself already returns non-zero for this (see
# encryption.sh's _vault_decrypt); the bug was `[ -z "$(secrets_get ...)" ]`
# discarding that exit status entirely.

@test "a secrets-backend error while checking the password is SECRETS_UNAVAILABLE, not CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  secrets_get() { return 1; }   # backend error, not "not found"
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_SECRETS_UNAVAILABLE" ]
}

@test "a secrets-backend error while checking the TOTP seed is SECRETS_UNAVAILABLE, not CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_TOKEN_MODE=totp
  require_oathtool() { return 0; }
  secrets_get() { return 1; }
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_SECRETS_UNAVAILABLE" ]
}

@test "a genuinely absent password is still CONFIG, not SECRETS_UNAVAILABLE" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  secrets_get() { echo ""; return 0; }   # read succeeded; the field is just empty
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

# --- PKCS#11 PIN existence, checked in preflight (review round 7, finding #2) ---
#
# A missing PKCS#11 PIN is just as locally decidable as a missing password or
# TOTP seed. An earlier version of connection_preflight never checked
# key_password at all: a SERVICE-mode PKCS#11 profile with no stored PIN sailed
# through preflight with rc=0, so admit_attempt charged an unattended attempt
# -- and possibly reserved/generated a TOTP step too -- for a connection that
# was always going to refuse once run_admitted_connection's own
# _prepare_pkcs11_pin got to it. These exercise preflight's existence check
# only, before admit_attempt would ever run.

@test "a SERVICE profile with a PKCS#11 client certificate and no stored PIN is CONFIG in preflight" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:manufacturer=piv_II;id=%01"
  secrets_get() { echo ""; return 0; }   # no stored key_password
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
  [[ "$output" == *"key_password"* ]]
}

@test "a SERVICE profile with a PKCS#11 client KEY (file certificate) and no stored PIN is CONFIG in preflight" {
  # The certificate alone is not the whole predicate: a file-path certificate
  # paired with a pkcs11: key needs a stored PIN too. Checking only
  # VPN_CLIENT_CERT (an earlier version of _pkcs11_pin_needed) missed this.
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="/etc/vpn/me.pem"
  VPN_CLIENT_KEY="pkcs11:manufacturer=piv_II;id=%01"
  secrets_get() { echo ""; return 0; }
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
  [[ "$output" == *"key_password"* ]]
}

# --- an embedded PIN in the PKCS#11 URI itself must be refused (review round 9, BLOCKER #1) ---
#
# RFC 7512 defines 'pin-value' (the literal PIN, in the clear) and
# 'pin-source' (a path VPN Up does not control) as query attributes a
# pkcs11: URI can carry directly. Reproduced directly against this codebase:
# clientCertificate="pkcs11:id=%01?pin-value=918273" reached run_openconnect's
# argv verbatim, bypassing the managed key_password/_prepare_pkcs11_pin path
# entirely -- the PIN ends up in profiles.xml AND on OpenConnect's own argv,
# in the clear. Checked unconditionally (not gated on SERVICE): unlike a
# merely-missing PIN, this profile is actively misconfigured, and an
# INTERACTIVE run would leak the embedded PIN onto argv exactly the same way.

@test "a cert URI containing pin-value is CONFIG before admission, in both modes" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:id=%01?pin-value=918273"
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
  [[ "$output" == *"pin-value"* || "$output" == *"PIN"* ]]
  run connection_preflight INTERACTIVE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "a key URI containing pin-value is CONFIG before admission" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="/etc/vpn/me.pem"
  VPN_CLIENT_KEY="pkcs11:id=%01?pin-value=918273"
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "a cert URI containing pin-source is CONFIG before admission" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:id=%01?pin-source=file:/tmp/attacker-controlled"
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "a key URI containing pin-source is CONFIG before admission" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="/etc/vpn/me.pem"
  VPN_CLIENT_KEY="pkcs11:id=%01?pin-source=file:/tmp/attacker-controlled"
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "a plain pkcs11 URI with no pin-value/pin-source is not rejected by the new check" {
  # The check must not false-positive on the ordinary, documented form.
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:manufacturer=piv_II;id=%01"
  secrets_get() { [ "$2" = key_password ] && { echo "1234"; return 0; }; echo "s3cret"; return 0; }
  run connection_preflight SERVICE
  [ "$status" -ne "$VPN_RC_CONFIG" ]
}

@test "a query value that merely CONTAINS the text pin-value= is not a false match" {
  # _pkcs11_uri_embeds_pin checks each attribute's OWN name (before its '='),
  # not a blunt substring search across the whole query string.
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:id=%01?object=note-says-pin-value%3D123"
  secrets_get() { [ "$2" = key_password ] && { echo "1234"; return 0; }; echo "s3cret"; return 0; }
  run connection_preflight SERVICE
  [ "$status" -ne "$VPN_RC_CONFIG" ]
}

@test "a secrets-backend error while checking the PKCS#11 PIN in preflight is SECRETS_UNAVAILABLE, not CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:manufacturer=piv_II;id=%01"
  secrets_get() { return 1; }   # backend error, not "not found"
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_SECRETS_UNAVAILABLE" ]
}

@test "connection_preflight's PKCS#11 PIN existence check never prints the PIN" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_CLIENT_CERT="pkcs11:manufacturer=piv_II;id=%01"
  secrets_get() { echo "1234-should-not-leak"; }
  run connection_preflight SERVICE
  if grep -qF "1234-should-not-leak" <<<"$output"; then false; fi
}

# --- an empty stored secret must not read as PRESENT on the real Keychain
# codepath (review round 8, BLOCKER #1) ---
#
# Every other test above stubs bare `secrets_get`, which exercises _secret_check's
# GENERIC (openssl/file) branch -- that branch already required a non-empty
# value. The actual round-8 bug lived only in the Keychain/Secret Service tri-state
# probes (encryption.sh), which this file never sources, so none of the tests
# above could have caught it. This test sources encryption.sh and forces the
# keychain branch, self-contained to this one @test (bats runs each test in its
# own process, so this cannot affect any other test in this file).
@test "connection_preflight does not bypass the TOTP-seed check on an empty Keychain value" {
  source "$BATS_TEST_DIRNAME/../encryption.sh"
  secrets_backend() { echo keychain; }
  # require_oathtool is a real dependency check (dependencies.sh) that runs
  # BEFORE the token_secret existence check this test targets -- on any
  # machine without oathtool installed (every CI runner here: neither the
  # apt nor the brew install step in ci.yml installs it), it fails FIRST
  # with an unrelated "needs oathtool" message, and this test's own
  # assertion on that message then fails for a reason that has nothing to
  # do with the actual check under test. Reproduced directly: this test
  # passed locally (oathtool happened to be installed) but failed in CI on
  # both runners, silently, since round 8 -- caught only by checking CI
  # status before merging, not by any local run. Stubbed here so this test
  # is isolated to the one thing it's actually meant to verify.
  require_oathtool() { return 0; }
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_TOKEN_MODE=totp
  # A real empty Keychain entry: `security -w ""` succeeds, and the later
  # lookup returns rc=0 with nothing on stdout -- reproduced directly against
  # the real `security` binary on this machine (see tests/secrets.bats).
  security() { printf ''; return 0; }
  run connection_preflight SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
  [[ "$output" == *"token_secret"* ]]
}

# Preflight is only a snapshot (invariant 8); admission may then wait, and the
# backend can fail in between. These exercise the ACTUAL fetch in
# run_admitted_connection, not just preflight's existence check.

@test "a secrets-backend error at the actual password FETCH (post-admission) is SECRETS_UNAVAILABLE, not CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  secrets_get() { return 1; }   # backend error, no legacy plaintext, no cert
  run run_admitted_connection "Work VPN" SERVICE
  [ "$status" -eq "$VPN_RC_SECRETS_UNAVAILABLE" ]
}

@test "a genuinely absent password at the actual FETCH is still CONFIG, not SECRETS_UNAVAILABLE" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  export VPN_UP_SERVICE=1
  secrets_get() { echo ""; return 0; }
  run run_admitted_connection "Work VPN" SERVICE
  [ "$status" -eq "$VPN_RC_CONFIG" ]
}

@test "a backend error at the password FETCH does not block a legacy plaintext fallback" {
  # A backend hiccup must not block a connection that has another,
  # backend-independent credential source available -- only when there is
  # truly nothing else to fall back on does the backend error itself matter.
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="legacy-plaintext"
  secrets_get() { return 1; }
  secrets_set() { :; }
  scrub_profile_password() { :; }
  run migrate_or_fetch_password SERVICE
  [ "$status" -eq 0 ]
}

@test "a genuinely absent TOTP seed at the actual FETCH refuses in SERVICE mode, never prompts" {
  # Review round 6, HIGH finding: preflight is only a snapshot (invariant 8's
  # own wording) -- admit_attempt may then wait an arbitrary amount of time,
  # and the seed can be deleted (or the profile's token mode changed) in that
  # window. An earlier version's phase-4 TOTP fetch assumed "SERVICE already
  # refused this in connection_preflight" for a genuinely-absent result and
  # fell through to the interactive prompt below with no mode guard at all.
  # Reproduced directly (background + bounded kill, since a real
  # `read -r -s -p` under bats' own stdin genuinely blocks rather than
  # hitting EOF): a SERVICE-mode process with no tty actually invoked `read`.
  # This must never happen for SERVICE; only INTERACTIVE may fall through to
  # the prompt.
  _write_profile
  load_profile_fields "Work VPN"
  VPN_TOKEN_MODE=totp
  secrets_get() {
    case "$2" in
      password) echo "s3cret" ;;
      token_secret) echo ""; return 0 ;;   # genuinely absent: read succeeded, field just empty
    esac
  }
  local readcalled="$BATS_TEST_TMPDIR/read-called" outfile="$BATS_TEST_TMPDIR/out" statusfile="$BATS_TEST_TMPDIR/status"
  (
    read() { touch "$readcalled"; builtin read "$@" < /dev/null; }
    # if/else, not a bare call -- bats runs test bodies (and everything a
    # backgrounded subshell of one inherits) under `set -e`; a bare
    # non-zero-returning call here would abort this subshell before the
    # following line ever ran, silently losing the status this test exists
    # to check (this exact idiom mismatch has bitten this test suite before).
    if run_admitted_connection "Work VPN" SERVICE; then rc=0; else rc=$?; fi
    echo "$rc" > "$statusfile"
  ) > "$outfile" 2>&1 &
  local bgpid=$!
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$bgpid" 2>/dev/null || break
    command sleep 0.5
  done
  if kill -0 "$bgpid" 2>/dev/null; then
    kill -9 "$bgpid" 2>/dev/null   # never expected: proves this test's own guard failed, not the code under test
  fi
  wait "$bgpid" 2>/dev/null || true

  [ ! -e "$readcalled" ]                       # the actual regression: SERVICE must never call read here
  [ "$(cat "$statusfile" 2>/dev/null)" = "$VPN_RC_CONFIG" ]
}

@test "a secrets-backend error at the actual TOTP seed FETCH (post-admission) is SECRETS_UNAVAILABLE, not CONFIG" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_TOKEN_MODE=totp
  # password fetch must succeed cleanly so the TOTP branch is what's under
  # test; only the token_secret lookup simulates the backend error.
  secrets_get() {
    case "$2" in
      password) echo "s3cret" ;;
      token_secret) return 1 ;;
    esac
  }
  run run_admitted_connection "Work VPN" SERVICE
  [ "$status" -eq "$VPN_RC_SECRETS_UNAVAILABLE" ]
}

# --- single backend round-trip, not check-then-fetch (review round 5, BLOCKER #2) ---
#
# A separate existence check followed by a separate fetch left a real gap
# where the backend could fail in between (the check said present; the fetch
# moments later saw a transient error with no way to distinguish "was never
# there" from "just broke"), and for the openssl vault backend the same
# shape was worse than a race: it decrypted the vault twice, prompting for
# the passphrase twice in an interactive session. secrets_get (the generic
# fallback _secret_check dispatches to when no real backend is sourced, as in
# these tests) must now be called exactly once per logical fetch.

@test "migrate_or_fetch_password reads a stored password with exactly one backend call" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  local calls="$BATS_TEST_TMPDIR/secrets_get-calls"
  : > "$calls"
  secrets_get() { echo "call" >> "$calls"; echo "s3cret"; }
  run migrate_or_fetch_password SERVICE
  [ "$status" -eq 0 ]
  [ "$(wc -l < "$calls")" -eq 1 ]
}

@test "the actual TOTP seed fetch reads the backend with a single call per field, not check-then-fetch" {
  _write_profile; _common_fields
  VPN_PASSWD=""
  VPN_TOKEN_MODE=totp
  export VPN_UP_NO_TOTP_WAIT=1
  BACKGROUND=TRUE
  local calls="$BATS_TEST_TMPDIR/secrets_get-calls"
  : > "$calls"
  secrets_get() {
    echo "call:$2" >> "$calls"
    case "$2" in
      password) echo "s3cret" ;;
      token_secret) echo "JBSWY3DPEHPK3PXP" ;;
    esac
  }
  oathtool() { echo "000000"; }
  sudo() { return 0; }
  run run_admitted_connection "Work VPN" SERVICE
  [ "$status" -eq 0 ]
  [ "$(grep -c '^call:password$' "$calls")" -eq 1 ]
  [ "$(grep -c '^call:token_secret$' "$calls")" -eq 1 ]
}

# --- connection_preflight must never leak the value it only checked for existence ---

@test "connection_preflight's password existence check never prints the password" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD=""
  secrets_get() { echo "s3cret-should-not-leak"; }
  run connection_preflight SERVICE
  if grep -qF "s3cret-should-not-leak" <<<"$output"; then false; fi
}

@test "connection_preflight's TOTP-seed existence check never prints the seed" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="s3cret"
  VPN_TOKEN_MODE=totp
  require_oathtool() { return 0; }
  secrets_get() { echo "JBSWY3DPEHPK3PXP-should-not-leak"; }
  run connection_preflight SERVICE
  if grep -qF "JBSWY3DPEHPK3PXP-should-not-leak" <<<"$output"; then false; fi
}

# --- a failed migration write must not destroy the only surviving copy (review round 5, finding #3) ---

@test "a failed migration write does not scrub the legacy plaintext password" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="legacy-plaintext"
  secrets_get() { return 1; }   # nothing stored yet -- migration will be attempted
  secrets_set() { return 1; }  # the migration write itself fails
  local scrubbed="$BATS_TEST_TMPDIR/scrub-called"
  scrub_profile_password() { touch "$scrubbed"; }
  run migrate_or_fetch_password SERVICE
  [ "$status" -eq 0 ]                 # the in-memory legacy password still lets this run proceed
  [ ! -e "$scrubbed" ]                # but the only durable copy must not be deleted
}

@test "a successful migration write does scrub the legacy plaintext password" {
  _write_profile
  load_profile_fields "Work VPN"
  VPN_PASSWD="legacy-plaintext"
  secrets_get() { return 1; }
  secrets_set() { return 0; }   # the migration write succeeds
  local scrubbed="$BATS_TEST_TMPDIR/scrub-called"
  scrub_profile_password() { touch "$scrubbed"; }
  run migrate_or_fetch_password SERVICE
  [ "$status" -eq 0 ]
  [ -e "$scrubbed" ]
}
