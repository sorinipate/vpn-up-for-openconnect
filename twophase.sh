# twophase.sh - two-phase OpenConnect: unprivileged authentication, then a
# privileged tunnel established by vpn-up-helper.
#
# See PRIVILEGED-HELPER-DESIGN.md §4 (two-phase), §5 (two binaries), §7 (Model B)
# and §16 step 8. The split exists so that the password, TOTP seed, client
# certificate, PKCS#11 PIN and SSO browser all stay OUTSIDE the privilege
# boundary: phase one runs as you, and only a session cookie crosses over.
#
# Prompt mode (core.sh's run_openconnect) is unchanged and remains the
# compatibility path for arbitrary extraArgs and split tunnelling.

# ---------------------------------------------------------------- locating it

# Installed location of the privileged binaries (§11.1). Both live on a
# root-owned path outside any user-writable prefix.
#
# VPN_UP_HELPER_DIR may override this, and that is safe: this is an
# UNPRIVILEGED process choosing which program to ask sudo about, and sudoers -
# not this variable - decides what may actually run as root. Pointing it
# somewhere else gets you a sudo refusal, not a privilege escalation.
helper_dir() {
  if [ -n "${VPN_UP_HELPER_DIR:-}" ]; then printf '%s' "${VPN_UP_HELPER_DIR}"; return; fi
  if [ "$(uname)" = Darwin ]; then printf '%s' "/opt/vpn-up/bin"
  else printf '%s' "/usr/local/libexec/vpn-up"; fi
}

helper_bin() { printf '%s/vpn-up-helper' "$(helper_dir)"; }
admin_bin()  { printf '%s/vpn-up-admin'  "$(helper_dir)"; }

# Two questions, deliberately separate, because the passwordless sudoers rule is
# opt-in (`install-helper --passwordless`). Without the tiers, an install that
# writes no rule would leave the helper installed and never used.

# Installed and runnable. `version` sits above the helper's root gate, so this
# proves presence and executability only - NOT that the install path is trusted.
# That is checked by the binaries themselves at every privileged invocation
# (§11.1), where a caller cannot skip it.
helper_mode_installed() {
  local h a; h="$(helper_bin)"; a="$(admin_bin)"
  [ -x "$h" ] && [ -x "$a" ] || return 1
  "$a" version >/dev/null 2>&1
}

# Genuinely passwordless - the gate a login service needs.
#
# `-k` is not decoration: `sudo -n` alone answers "can this run right now without
# prompting", which is also true whenever the user authenticated to sudo in the
# last few minutes. A service starting at boot has no such cache, so a plain
# `sudo -n` here would report "available" for a machine where the service is
# about to hang on a password prompt. With a command, `-k` makes sudo ignore the
# cached credentials without invalidating them, so this asks about policy.
helper_mode_available() {
  local h; h="$(helper_bin)"
  [ -x "$h" ] || return 1
  sudo -k -n "$h" version >/dev/null 2>&1
}

# Should THIS run use helper mode?
#
# Passwordless: always. Installed but not passwordless: only when there is a
# terminal, because the only cost is a sudo prompt and somebody has to be there
# to answer it. Unattended runs (the launchd agent / systemd unit, which invoke
# `vpn-up start <profile>` with no tty) fall through to prompt mode rather than
# blocking forever on a password nobody will type.
helper_mode_usable() {
  helper_mode_available && return 0
  helper_mode_installed || return 1
  [ -t 0 ] || [ -t 1 ]
}

# Authorize the privileged step BEFORE phase one spends anything.
#
# The interactive tier means sudo WILL ask for a password, and where it asks
# matters. Two reasons this is a separate, earlier step instead of letting the
# connect command prompt for itself:
#
#   1. Phase one consumes real credentials - a password, a TOTP code, a Duo
#      push, an SSO browser round trip. Finding out afterwards that sudo will
#      not authorize the helper wastes all of it, and a Duo push cannot be
#      recalled.
#   2. The cookie reaches the helper through a pipe. sudo reads its password
#      from the terminal rather than from stdin, so the two do not actually
#      collide - but a prompt surfacing in the middle of that pipeline is the
#      same collision run_openconnect already avoids by validating up front, and
#      helper mode has no reason to be the exception.
#
# `sudo -v` only when the helper is NOT already passwordless: -v validates the
# user in general rather than for one command, so a machine whose only rule is
# `NOPASSWD: /...:/vpn-up-helper` would be prompted by it for nothing.
#
# This is not a security control. sudoers decides what may run as root; this
# decides only when the person is asked.
helper_sudo_prepare() {
  helper_mode_available && return 0
  print_warning "Establishing the tunnel needs your password.\n"
  sudo -v
}

# ------------------------------------------------- phase-one output decoding

# Strict decoder for `openconnect --authenticate` output.
#
# Upstream emits KEY='VALUE' lines so they can be eval'd. We do NOT eval, and we
# do not parse shell either: we accept exactly the five known keys, single
# quoted, with no escape interpretation. A backslash or `$` inside a value is a
# literal byte, and anything unrecognised is a hard failure rather than a
# skipped line - a future OpenConnect emitting something we do not understand
# must be visible, not silently dropped.
#
# Reads stdin. On success sets AUTH_COOKIE / AUTH_HOST / AUTH_CONNECT_URL /
# AUTH_FINGERPRINT / AUTH_RESOLVE. The cookie is left in a shell variable only:
# never exported, never on a command line.
#
# SCOPE: this checks the FORMAT, not the meaning of the values. Whether
# CONNECT_URL is a usable https URL and whether FINGERPRINT is long enough to
# pin anything are decided by the C validators where those values are consumed -
# the connect URL by vpn-up-helper, the fingerprint by vpn-up-admin. Growing a
# hand-rolled URL parser here to duplicate them would be two implementations of
# one rule, which is the thing helper/t/fixtures/auth exists to prevent.
#
# There are two decoders for this format: this one, which runs in production,
# and vu_parse_auth() in helper/src/authparse.c, which is the reference with the
# harder corpus. Both are driven by the shared fixtures in
# helper/t/fixtures/auth (see its README), so a divergence in the format rules
# fails a test instead of going unnoticed.
parse_auth_output() {
  AUTH_COOKIE=""; AUTH_HOST=""; AUTH_CONNECT_URL=""; AUTH_FINGERPRINT=""; AUTH_RESOLVE=""
  local line key rest val
  local seen_cookie=0 seen_host=0 seen_url=0 seen_fpr=0 seen_resolve=0
  local lineno=0

  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    if [ -z "$line" ]; then
      print_danger "Authentication output: blank line %d.\n" "$lineno"
      return 1
    fi
    case "$line" in
      *=*) : ;;
      *) print_danger "Authentication output: line %d is not KEY='VALUE'.\n" "$lineno"; return 1 ;;
    esac

    key="${line%%=*}"
    rest="${line#*=}"

    # The value must be wrapped in single quotes and end the line exactly.
    case "$rest" in
      "'"*"'") : ;;
      *) print_danger "Authentication output: %s is not single-quoted.\n" "$key"; return 1 ;;
    esac
    val="${rest#\'}"; val="${val%\'}"

    # A single-quoted shell string cannot contain a quote, so one here means the
    # line is not what it claims to be.
    case "$val" in
      *"'"*) print_danger "Authentication output: %s contains a quote.\n" "$key"; return 1 ;;
    esac
    case "$val" in
      *[[:cntrl:]]*) print_danger "Authentication output: %s contains a control byte.\n" "$key"; return 1 ;;
    esac

    case "$key" in
      COOKIE)      [ "$seen_cookie"  -eq 1 ] && { print_danger "Authentication output: duplicate COOKIE.\n"; return 1; }; AUTH_COOKIE="$val";      seen_cookie=1 ;;
      HOST)        [ "$seen_host"    -eq 1 ] && { print_danger "Authentication output: duplicate HOST.\n"; return 1; };   AUTH_HOST="$val";        seen_host=1 ;;
      CONNECT_URL) [ "$seen_url"     -eq 1 ] && { print_danger "Authentication output: duplicate CONNECT_URL.\n"; return 1; }; AUTH_CONNECT_URL="$val"; seen_url=1 ;;
      FINGERPRINT) [ "$seen_fpr"     -eq 1 ] && { print_danger "Authentication output: duplicate FINGERPRINT.\n"; return 1; }; AUTH_FINGERPRINT="$val"; seen_fpr=1 ;;
      RESOLVE)     [ "$seen_resolve" -eq 1 ] && { print_danger "Authentication output: duplicate RESOLVE.\n"; return 1; }; AUTH_RESOLVE="$val";     seen_resolve=1 ;;
      *)
        print_danger "Authentication output: unrecognised key '%s' on line %d.\n" "$key" "$lineno"
        return 1 ;;
    esac
  done

  [ "$lineno" -gt 0 ] || { print_danger "Authentication produced no output.\n"; return 1; }
  return 0
}

# Helper mode requires the CONNECT_URL contract. Older OpenConnect emits only a
# numeric HOST, and Model B binds an origin - collapsing to an address would
# discard exactly what is being bound. Detect the output contract rather than
# guessing a version number.
require_helper_auth_contract() {
  if [ -z "$AUTH_COOKIE" ]; then
    print_danger "Authentication did not produce a cookie.\n"; return 1
  fi
  if [ -z "$AUTH_FINGERPRINT" ]; then
    print_danger "Authentication did not report a server fingerprint.\n"; return 1
  fi
  if [ -z "$AUTH_CONNECT_URL" ]; then
    print_danger "OpenConnect is too old for hardened helper mode (--authenticate produced no CONNECT_URL). Use prompt mode.\n"
    return 1
  fi
  return 0
}

# ------------------------------------------------------- extraArgs translation

# Translate a profile's extraArgs into the helper's closed tunable table (§10).
#
# This is why existing profiles keep working in helper mode: `--no-dtls --mtu
# 1400` becomes `--tunable no-dtls --tunable mtu=1400`, while anything that can
# name a program to run is refused with the flag named. --useragent and --os are
# not tunables - they belong to phase one (and --useragent to both) - so they are
# routed, not rejected.
#
# Sets HELPER_TUNABLES (array), PHASE1_EXTRA (array). Returns 1 on anything
# untranslatable.
translate_extra_args() {
  HELPER_TUNABLES=(); PHASE1_EXTRA=(); HELPER_USERAGENT=""
  local raw="$1" tok value
  [ -z "$raw" ] && return 0

  local toks=() split rc
  split="$(printf '%s\n' "$raw" | xargs -n1 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    print_danger "extraArgs for this profile has malformed quoting.\n"; return 1
  fi
  mapfile -t toks <<< "$split"
  [ "${#toks[@]}" -eq 1 ] && [ -z "${toks[0]}" ] && return 0

  local i=0 n="${#toks[@]}"
  while [ "$i" -lt "$n" ]; do
    tok="${toks[$i]}"
    i=$((i + 1))
    [ -z "$tok" ] && continue

    # Accept both --flag=value and --flag value.
    case "$tok" in
      *=*) value="${tok#*=}"; tok="${tok%%=*}" ;;
      *)   value="" ;;
    esac

    case "$tok" in
      --no-dtls|--no-http-keepalive|--disable-ipv6)
        HELPER_TUNABLES+=("--tunable" "${tok#--}") ;;
      --mtu|--base-mtu|--reconnect-timeout|--force-dpd)
        if [ -z "$value" ]; then value="${toks[$i]:-}"; i=$((i + 1)); fi
        if [ -z "$value" ]; then
          print_danger "extraArgs: %s needs a value.\n" "$tok"; return 1
        fi
        HELPER_TUNABLES+=("--tunable" "${tok#--}=${value}") ;;
      --useragent)
        if [ -z "$value" ]; then value="${toks[$i]:-}"; i=$((i + 1)); fi
        HELPER_USERAGENT="$value"
        PHASE1_EXTRA+=("--useragent=${value}") ;;
      --os)
        if [ -z "$value" ]; then value="${toks[$i]:-}"; i=$((i + 1)); fi
        PHASE1_EXTRA+=("--os=${value}") ;;
      *)
        print_danger "extraArgs contains '%s', which helper mode does not accept. Flags that can name a program to run are only available in prompt mode (type your sudo password), and the rest must be in the tunable table. See SECURITY.md.\n" "$tok"
        return 1 ;;
    esac
  done
  return 0
}

# ------------------------------------------------------------------ phase one

# Authenticate as the invoking user and capture the session descriptor.
#
# Everything sensitive happens here, unprivileged: the password and TOTP code go
# in on stdin, a client certificate or PKCS#11 token is read with the user's own
# access, and an SSO browser opens in the user's own session - which also fixes
# the long-standing Linux problem of a root-spawned browser never reaching the
# desktop.
#
# Sets AUTH_* on success. Stdout of openconnect is captured; its stderr is left
# attached to the terminal so prompts and progress remain visible.
phase_one_authenticate() {
  local args=() out rc

  args+=(--authenticate)
  args+=("--protocol=${PROTOCOL}")
  args+=("--user=${VPN_USER}")
  [ -n "${VPN_GROUP}" ] && args+=(--authgroup "${VPN_GROUP}")

  # Pin during authentication too, not only at connect: otherwise phase one
  # would trust the system store while phase two pins, and the fingerprint we
  # bind would be whatever answered.
  [ -n "${SERVER_CERTIFICATE}" ] && args+=("--servercert=${SERVER_CERTIFICATE}")
  [ -n "${VPN_PROXY:-}" ] && args+=("--proxy=${VPN_PROXY}")

  # Client certificate / PKCS#11: used HERE, with the user's own access to the
  # token. Neither the path nor the PIN ever crosses the privilege boundary.
  if [ -n "${VPN_CLIENT_CERT:-}" ]; then
    args+=("--certificate=${VPN_CLIENT_CERT}")
    [ -n "${VPN_CLIENT_KEY:-}" ] && args+=("--sslkey=${VPN_CLIENT_KEY}")
  fi

  [ "${VPN_TOKEN_MODE:-}" = totp ] && args+=(--token-mode=totp)
  [ "${#PHASE1_EXTRA[@]}" -gt 0 ] && args+=("${PHASE1_EXTRA[@]}")

  if [ "${VPN_AUTH_MODE:-password}" = sso ]; then
    args+=("--external-browser=$(resolve_external_browser)")
    args+=("${VPN_HOST}")
    out="$(openconnect "${args[@]}")"; rc=$?
  else
    args+=(--passwd-on-stdin)
    args+=("${VPN_HOST}")
    local stdin_lines="$VPN_PASSWD"
    local second="${VPN_SECOND_FACTOR:-$VPN_DUO2FAMETHOD}"
    [ -n "$second" ] && stdin_lines+=$'\n'"$second"
    out="$(printf '%s\n' "$stdin_lines" | openconnect "${args[@]}")"; rc=$?
    unset stdin_lines second
  fi

  if [ "$rc" -ne 0 ]; then
    # "Authentication failed" would overclaim: this non-zero code covers a
    # DNS failure, a TLS failure and a rejected credential identically (see
    # VPN_RC_PREAUTH, outcome.sh) -- there is no seam here to tell them apart.
    print_danger "Authentication or session setup failed (openconnect exited %d).\n" "$rc"
    return 1
  fi

  parse_auth_output <<< "$out" || return 1
  unset out
  require_helper_auth_contract || return 1
  return 0
}

# ------------------------------------------------------------------ phase two

# Hand the cookie to the privileged helper.
#
# The cookie goes on STDIN and nowhere else, so it never appears in the process
# table. Note what is absent from this command line: no fingerprint (the helper
# reads it from the approval registry, so a caller cannot substitute a gateway),
# no password, no certificate, no script, and nothing that did not come from the
# closed schema.
run_openconnect_helper() {
  local h; h="$(helper_bin)"
  local args=(connect
              "--profile-id" "${VPN_PROFILE_ID}"
              "--protocol"   "${PROTOCOL}"
              "--connect-url" "${AUTH_CONNECT_URL}")

  # RESOLVE pins the gateway's address for this session. The helper checks that
  # the host half names the approved endpoint, so a well-formed value pointing
  # somewhere else is refused there rather than trusted here.
  [ -n "${AUTH_RESOLVE}" ] && args+=("--resolve" "${AUTH_RESOLVE}")
  [ -n "${VPN_PROXY:-}" ]  && args+=("--proxy" "${VPN_PROXY}")
  [ -n "${HELPER_USERAGENT:-}" ] && args+=("--useragent" "${HELPER_USERAGENT}")
  [ "${QUIET:-FALSE}" = TRUE ] && args+=("--quiet")
  [ "${#HELPER_TUNABLES[@]}" -gt 0 ] && args+=("${HELPER_TUNABLES[@]}")

  # Where this run's output starts, so a refusal can be told from a session that
  # ended (see _helper_run_had_tunnel below). Taken before anything is written.
  local mark=0
  [ -f "${LOG_FILE_PATH:-}" ] && mark=$(( $(wc -c < "$LOG_FILE_PATH" 2>/dev/null || printf 0) ))

  write_connection_state

  # Plain `sudo`, NOT `sudo -n`.
  #
  # `-n` was correct while helper mode existed only behind a passwordless rule.
  # It is wrong now that `install-helper` writes that rule only with
  # `--passwordless`: on an interactive-tier machine `-n` fails right here,
  # AFTER phase one has already spent the user's password and second factor, and
  # with no fallback - and it fails only sometimes, because a warm sudo
  # credential cache makes `-n` succeed. helper_sudo_prepare() has already put
  # the prompt somewhere sensible; if that cache lapsed during a slow SSO round
  # trip, sudo asks again on the terminal rather than discarding the session.
  #
  # Unattended callers never reach this: helper_mode_usable() sends a run with
  # no terminal to prompt mode precisely so nothing blocks on a prompt.
  # shellcheck disable=SC2024  # the log is opened by this user; the root child inherits the fd
  printf '%s\n' "${AUTH_COOKIE}" | sudo "$h" "${args[@]}" 2>&1 | tee -a "$LOG_FILE_PATH"
  local rc="${PIPESTATUS[1]}"

  unset AUTH_COOKIE
  rm -f "$PID_FILE_PATH" "$STATE_FILE_PATH"

  # A refusal is not a disconnection. Announcing one fires the user's
  # `disconnected` hooks for a tunnel that never existed. The same check also
  # feeds the outcome code below (0/POLICY/ATTEMPT_FAILED, outcome.sh) — this
  # is diagnostics/supervisor-instruction only and never feeds admit_attempt.
  local had_tunnel=1
  if _helper_run_had_tunnel "$mark"; then
    notify "VPN Up" "Disconnected from ${VPN_NAME:-VPN}"
    run_hooks disconnected "${VPN_NAME:-}" "${VPN_HOST:-}"
  else
    had_tunnel=0
  fi
  local outcome; outcome="$(outcome_from_run "$rc" "$had_tunnel")"
  return "$outcome"
}

# Did this run actually get a tunnel, or was it turned away at the door?
#
# The evidence is what the run appended to the log from byte $1 onwards. Both
# refusal shapes announce themselves, each on a line of its own:
#
#   sudo: a password is required               <- sudo never ran the helper
#   vpn-up-helper: profile ... is not approved <- the helper refused before exec
#
# That second prefix is a dependable marker *because* the helper execs
# OpenConnect on success: once the tunnel is up there is no vpn-up-helper
# process left to print anything under that name. So a run whose every non-blank
# line carries one of those two prefixes never had a tunnel. Both prefixes are
# fixed strings our own code and sudo emit, not a parsed report format.
#
# Deliberately conservative the other way. Silence is ambiguous - `--quiet` is a
# supported option - so no output at all counts as a tunnel, leaving the
# previous behaviour in place wherever the evidence does not clearly say
# otherwise. An OpenConnect that started and then failed to reach the gateway
# DID run, and still reports a disconnection, exactly as prompt mode does.
_helper_run_had_tunnel() {
  local mark="$1" chunk line saw_refusal=0
  [ -f "${LOG_FILE_PATH:-}" ] || return 0
  chunk="$(tail -c "+$((mark + 1))" "$LOG_FILE_PATH" 2>/dev/null)" || return 0
  [ -n "$chunk" ] || return 0
  while IFS= read -r line; do
    case "$line" in
      "") continue ;;
      "sudo: "*|"vpn-up-helper: "*) saw_refusal=1 ;;
      *) return 0 ;;
    esac
  done <<< "$chunk"
  [ "$saw_refusal" -eq 1 ] && return 1
  return 0
}

# Authenticate, then hand off to the tunnel.
#
# Narrower than it used to be: `translate_extra_args` now runs in
# connection_preflight() and `helper_sudo_prepare`'s interactive `sudo -v`
# now runs in run_admitted_connection()'s epilogue (core.sh) — both before
# this is ever reached, per the design's four-phase split. By the time this
# runs, only phase_one_authenticate (-> VPN_RC_PREAUTH) and
# run_openconnect_helper (-> 0/VPN_RC_POLICY/VPN_RC_ATTEMPT_FAILED) remain
# its own concern.
connect_via_helper() {
  print_primary "Authenticating as %s (unprivileged) ...\n" "${USER:-$(id -un)}"
  phase_one_authenticate || return "$VPN_RC_PREAUTH"

  if [ -n "${AUTH_HOST}" ] && [ "${VPN_UP_VERBOSE:-FALSE}" = TRUE ]; then
    print_warning "Gateway reported host %s\n" "${AUTH_HOST}"
  fi

  print_primary "Establishing the tunnel via %s ...\n" "$(helper_bin)"
  run_openconnect_helper
}

# ------------------------------------------------------------------- stopping

stop_via_helper() {
  local h; h="$(helper_bin)"
  # No pid is passed: the helper reads it from root-owned state and verifies the
  # process identity before signalling, so a recycled pid is never touched.
  #
  # Plain `sudo` for the same reason as connect: with the passwordless rule
  # opt-in, `-n` would refuse to stop a tunnel this very session started, and
  # stop's caller would then fall through to the pid-file path - which cannot
  # find a helper-mode tunnel, because the helper keeps its pid in root-owned
  # state. The result was a tunnel that could not be stopped at all.
  sudo "$h" stop --profile-id "${VPN_PROFILE_ID}"
}

# ------------------------------------------------------------------ approval

# Approve this profile's endpoint, which is an interactive, password-gated
# operation by design (§5): vpn-up-admin is deliberately NOT in the passwordless
# sudoers rule, so an attacker holding that rule cannot approve anything.
approve_profile() {
  local name="${1:-}"
  [ -z "$name" ] && { print_danger "Usage: %s approve-profile <profile>\n" "${DISPLAY_NAME}"; return 1; }
  load_profile_fields "$name" || return 1
  profile_id_ensure "$name" || return 1

  translate_extra_args "${VPN_EXTRA_ARGS:-}" || return 1
  print_primary "Authenticating to record the endpoint and its certificate ...\n"
  phase_one_authenticate || return 1

  local a; a="$(admin_bin)"
  local args=(approve
              "--profile-id"  "${VPN_PROFILE_ID}"
              "--protocol"    "${PROTOCOL}"
              "--endpoint"    "${AUTH_CONNECT_URL}"
              "--fingerprint" "${AUTH_FINGERPRINT}")
  if [ -n "${VPN_PROXY:-}" ]; then args+=("--proxy" "${VPN_PROXY}")
  else args+=("--no-proxy"); fi

  unset AUTH_COOKIE
  print_warning "This step needs your password: approving an endpoint must never be possible without one.\n"
  sudo "$a" "${args[@]}"
}
