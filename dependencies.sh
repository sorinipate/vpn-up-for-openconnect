# dependencies.sh - dependency checks and doctor

# Returns 1 rather than exiting: reached from vpn-up.command's top-level
# `start)` dispatch, before start() itself runs, so under a service this must
# route through service_exit_code() (outcome.sh) like every other failure in
# that call tree, not terminate the process directly. See check_dependencies()
# below, whose own return value the dispatch now checks.
require_bin() {
  local bin="$1"; local hint="$2"
  if ! command -v "$bin" >/dev/null 2>&1; then
    print_danger "Missing dependency: %s\n" "$bin"
    [ -n "$hint" ] && print_warning "Hint: %s\n" "$hint"
    return 1
  fi
}

# Major version of the installed openconnect, or empty if unparseable.
# `openconnect --version` prints e.g. "OpenConnect version v9.12" (some distro
# builds drop the leading 'v').
openconnect_major() {
  openconnect --version 2>&1 | sed -n 's/.*[Vv]ersion v\{0,1\}\([0-9][0-9]*\)\..*/\1/p' | head -1
}

# Gate the SSO path on openconnect >= 9.0 (when --external-browser landed).
# Lenient when the version can't be determined so it never blocks on odd builds.
require_openconnect_sso() {
  local major; major="$(openconnect_major)"
  if [ -z "$major" ]; then
    print_warning "Could not determine openconnect version; SSO (external browser) needs >= 9.0.\n"
    return 0
  fi
  if [ "$major" -lt 9 ]; then
    print_danger "SSO (external browser) needs openconnect >= 9.0; found v%s. Upgrade openconnect.\n" "$major"
    return 1
  fi
  return 0
}

# TOTP profiles need `oathtool` (oath-toolkit) to generate the one-time code.
# Gate only the TOTP path so non-TOTP users aren't required to install it.
require_oathtool() {
  if ! command -v oathtool >/dev/null 2>&1; then
    print_danger "TOTP 2FA needs 'oathtool'. Install via: brew install oath-toolkit | apt-get install oathtool\n"
    return 1
  fi
  return 0
}

check_dependencies() {
  local rc=0
  require_bin xmlstarlet "Install via: brew install xmlstarlet | apt-get install xmlstarlet" || rc=1
  require_bin openconnect "Install via: brew install openconnect | apt-get install openconnect" || rc=1
  if [ "$(uname)" = "Darwin" ]; then
    require_bin security "macOS provides this by default" || rc=1
  else
    command -v secret-tool >/dev/null 2>&1 || print_warning "Optional: 'secret-tool' for keyring secrets. Falling back to OpenSSL vault.\n"
  fi
  command -v openssl >/dev/null 2>&1 || print_warning "Optional: 'openssl' for encrypted vault fallback.\n"
  return "$rc"
}

# ----------------------------------------------------- privilege boundary check
#
# PRIVILEGED-HELPER-DESIGN.md §5 rests on ONE invariant:
#
#     vpn-up-helper   connect | stop | version     <- the ONLY NOPASSWD binary
#     vpn-up-admin    approve | revoke | list      <- NEVER NOPASSWD
#
# If the passwordless binary can also grant approvals, Model B means nothing: an
# attacker holding the passwordless grant approves whatever endpoint it likes and
# then connects there "legitimately".
#
# The check is on EFFECTIVE PASSWORDLESS REACHABILITY, not on whether a name
# appears in a sudoers file: rules can come from LDAP, from includes, from
# Defaults targetpw, or from an alias, none of which grepping /etc/sudoers.d
# would find.
#
# Two corrections to how that used to be asked here, both of which produced a
# green line that meant nothing:
#
#   1. `sudo -n -l <cmd>` was read as "not permitted" whenever it failed, but it
#      also fails when LISTING itself needs a password (listpw). That printed
#      "[OK] vpn-up-admin is not reachable without a password" for a machine
#      where it might well be.
#   2. `sudo -n` honours the credential cache, so anything the user is merely
#      allowed to run looks passwordless for minutes after they authenticate.
#
# Both are fixed by executing OUR OWN binaries with `sudo -k -n`: -k makes sudo
# ignore the cached credentials, and `version` cannot fail on its own, so a
# non-zero exit means sudo refused. Safe to execute because both binaries are
# root-owned on a trusted path - which is emphatically not true of openconnect,
# and the legacy-grant check below therefore never executes it.
#
# vpn-up-admin in an ORDINARY authenticated rule is legitimate administrator
# policy and passes. Only passwordless reachability fails.
doctor_privilege_boundary() {
  local rc=0
  echo
  echo "Privilege boundary (helper mode):"

  if ! command -v sudo >/dev/null 2>&1; then
    echo "  [..] sudo not found; helper mode is unavailable on this machine"
    return 0
  fi

  local h a
  h="$(helper_bin)"; a="$(admin_bin)"

  if [ -x "$h" ]; then
    if sudo -k -n "$h" version >/dev/null 2>&1; then
      echo "  [OK] vpn-up-helper is reachable without a password (this is the intended rule)"
    else
      echo "  [..] vpn-up-helper is installed but not passwordless; helper mode works"
      echo "       interactively and will not run unattended. Authorize it with:"
      echo "       ${PROGRAM_NAME} install-helper --passwordless"
    fi
  else
    echo "  [..] vpn-up-helper not installed at $h (prompt mode is in use)"
    echo "       Install it with: ${PROGRAM_NAME} install-helper"
  fi

  # The invariant. When the binary is absent the question cannot be asked by
  # execution, so it is reported as unproven rather than as a pass: a rule naming
  # a path that does not exist yet is still a rule, and would take effect the
  # moment something is installed there.
  if [ ! -x "$a" ]; then
    # Nothing to execute, so fall back to asking sudo's policy about the path. A
    # rule naming a path that does not exist yet is still a rule and would take
    # effect the moment something is installed there, so an affirmative answer is
    # still reported. A negative one is NOT reported as an OK: `sudo -l` also
    # fails when listing needs a password, and when the command does not resolve.
    if sudo -k -n -l "$a" >/dev/null 2>&1; then
      echo "  [!!] a passwordless rule names $a, which is not even installed yet."
      echo "       Remove it: it would take effect the moment that path exists."
      rc=1
    else
      echo "  [..] vpn-up-admin is not installed; its passwordless reachability"
      echo "       cannot be proven either way yet"
    fi
  elif sudo -k -n "$a" version >/dev/null 2>&1; then
    echo "  [!!] vpn-up-admin IS REACHABLE WITHOUT A PASSWORD."
    echo "       This breaks the approval boundary: anything holding the passwordless"
    echo "       grant can approve an endpoint and then connect to it. Remove"
    echo "       vpn-up-admin from every NOPASSWD rule; it is meant to be run as"
    echo "       'sudo vpn-up-admin ...' with a real password prompt."
    rc=1
  else
    echo "  [OK] vpn-up-admin is not reachable without a password"
  fi
  return "$rc"
}

# ------------------------------------------------- trusted execution closure
#
# Design section 11.4: every executable, script, library, interpreter, sourced
# hook and search path reachable from the privileged OpenConnect execution must
# be outside the caller's write control. Section 11.6 turns that into a support
# matrix, and this reports which row this machine is in.
#
# Run through vpn-up-admin, which does the walk in C, so the answer shown here is
# produced by exactly the code the helper runs before every execve rather than by
# a shell approximation of it. No sudo: the check reads ownership and mode bits,
# which are world-readable, and it writes nothing.
#
# Deliberately does NOT affect doctor's exit status. A failing closure means
# "helper mode is not available on this machine", which for now is true almost
# everywhere — there is no installer, and macOS fails closed until the dyld work
# in step 13. Doctor failing should mean something is MISCONFIGURED, not that a
# roadmap item is outstanding.
doctor_execution_closure() {
  echo
  echo "Trusted execution closure (helper mode eligibility):"

  local a; a="$(admin_bin)"
  if [ ! -x "$a" ]; then
    echo "  [..] vpn-up-admin not installed at $a"
    echo "       Helper mode is not available yet; prompt mode is in use, and the"
    echo "       caveat in SECURITY.md about a user-writable openconnect applies."
    return 0
  fi

  # Indent its report so it reads as part of doctor's output.
  "$a" verify-closure 2>&1 | sed 's/^/  /'
  return 0
}

# ------------------------------------------------------------- legacy grants
#
# The rule this project used to document - NOPASSWD on the openconnect binary -
# is equivalent to passwordless root (SECURITY.md). doctor reports it whether or
# not the helper is installed, because that grant is the actual finding.
#
# Detection is by POLICY LISTING, never by execution. Running a possibly
# user-writable openconnect under sudo to discover whether it can be run under
# sudo would execute attacker-controlled code as root to answer the question.
doctor_legacy_grants() {
  echo
  echo "Legacy passwordless openconnect grant:"
  if ! command -v sudo >/dev/null 2>&1; then
    echo "  [..] sudo not found; nothing to check"
    return 0
  fi
  # helperinstall.sh owns the probe and the exact list of documented paths.
  command -v vu_report_legacy_grants >/dev/null 2>&1 || . "${PROGRAM_PATH}/helperinstall.sh"
  if ! vu_tools_resolve >/dev/null 2>&1; then
    echo "  [..] could not resolve a trusted sudo; skipping"
    return 0
  fi
  vu_report_legacy_grants || true
  return 0
}

# Installed state and manifest drift. A changed hash is not an attack signal -
# anyone who can write a root-owned path can rewrite the manifest too - it is
# how you notice an installation that no longer matches this checkout.
doctor_helper_install() {
  echo
  echo "Privileged helper installation:"
  local h a m
  h="$(helper_bin)"; a="$(admin_bin)"; m="$(_vu_manifest_file)"
  if [ ! -x "$h" ] || [ ! -x "$a" ]; then
    echo "  [..] not installed (prompt mode). Install with: ${PROGRAM_NAME} install-helper"
    return 0
  fi
  echo "  [OK] installed in $(helper_dir)"
  if [ -r "$m" ]; then
    echo "  -    policy ABI $(_vu_manifest_value policy-abi || echo unknown)"
    local recorded actual
    for pair in "helper-sha256:$h" "admin-sha256:$a"; do
      recorded="$(_vu_manifest_value "${pair%%:*}" || true)"
      actual="$(_vu_sha256 "${pair#*:}" 2>/dev/null || true)"
      if [ -n "${recorded:-}" ] && [ -n "${actual:-}" ] && [ "$recorded" != "$actual" ]; then
        echo "  [..] ${pair##*/} differs from the manifest (reinstalled outside install-helper?)"
      fi
    done
  else
    echo "  [..] no manifest at $m; this installation was not made by install-helper"
  fi
  return 0
}

# -------------------------------------------- rate-limiter state (outcome.sh)
#
# Two residual conditions the locking design in outcome.sh deliberately never
# auto-recovers, because doing so from the hot path would risk exactly the
# class of bug that design closes (see PRIVILEGED-HELPER-DESIGN.md's
# rate-limiter section): a `.lock` directory whose `owner` metadata never
# appeared (never reclaimed on age — there is no pid to test liveness
# against), and a `.lock.reclaiming` meta-lock left behind if a process died
# in the handful of operations between acquiring it and removing it. Both are
# vanishingly rare (the windows involved are microseconds) and both are
# reported here, not auto-cleared, so an operator has to make the call.
_VU_DOCTOR_LOCK_STALE_SECS=60

doctor_rate_limiter_state() {
  echo
  echo "Rate-limiter state:"
  local dir="${DATA_DIR}/state" d found=0 now
  now="$(date +%s)"
  [ -d "$dir" ] || { echo "  [OK] no state directory yet"; return 0; }

  # Main lock: the residual case is metadata that never appeared at all --
  # never auto-reclaimed (see outcome.sh), so ANY age with no readable owner
  # file is reported, not just an old one.
  for d in "$dir"/*.lock; do
    [ -d "$d" ] || continue
    case "$d" in *.lock.reclaiming) continue ;; esac
    if [ ! -r "$d/owner" ]; then
      found=1
      echo "  [!!] Incomplete VPN state lock detected: $d"
      echo "       VPN Up cannot determine whether this lock was fully acquired."
      echo "       No authentication attempt will proceed until it is cleared: rm -rf '$d'"
    fi
  done

  # The reclaim meta-lock: its normal lifetime is microseconds and it always
  # writes metadata immediately, so readability is not the signal here --
  # age past a generous diagnostic-only threshold is.
  for d in "$dir"/*.lock.reclaiming; do
    [ -d "$d" ] || continue
    local created age
    created="$(awk -F'=' '/^created=/{print substr($0,9); exit}' "$d/owner" 2>/dev/null)"
    age=$(( now - ${created:-$now} ))
    if [ -z "$created" ] || [ "$age" -ge "$_VU_DOCTOR_LOCK_STALE_SECS" ]; then
      found=1
      echo "  [!!] Stuck lock-reclaim marker detected: $d"
      echo "       A process likely died while reclaiming a stale lock; this is not auto-cleared."
      echo "       No authentication attempt will proceed until it is cleared: rm -rf '$d'"
    fi
  done

  [ "$found" = 0 ] && echo "  [OK] no stuck locks found"
  return 0
}

# ---------------------------------------------- orphaned PKCS#11 PIN files
#
# A staged PIN file (core.sh, _prepare_pkcs11_pin) is a plaintext credential
# that normally lives for as long as its tunnel session does -- possibly
# hours -- so age alone cannot tell a live session's PIN file apart from an
# orphaned one left behind by an abnormal termination (review round 8, HIGH
# #2: run_admitted_connection's TERM/INT trap, and connect_via_helper's
# early removal once a cookie is obtained, close the common cases, but not
# an unhandled SIGKILL or a signal delivered to this shell alone without
# reaching its tunnel child). So this uses the same liveness test as
# attempt-owner reclaim (§3.5, outcome.sh) rather than an age threshold: the
# owning process's pid is embedded in the filename itself
# (".${PROGRAM_NAME}.pin.<pid>.XXXXXX"), and only a file whose pid is
# demonstrably dead is reported. Like the lock checks above, this is
# diagnostic only -- it never removes anything itself.
#
# The same pid-reuse caveat §3.5 already documents applies here too, in the
# opposite direction: if this exact pid was reused by an unrelated process
# before doctor runs, a genuinely orphaned file reads as "still owned" and is
# silently skipped. That is a false negative in a diagnostic check, not a
# safety gap -- nothing privileged ever trusts this file's mere presence.
doctor_pin_files() {
  echo
  echo "PKCS#11 PIN files:"
  local dir="${DATA_DIR}/pids" f found=0 base rest pid
  [ -d "$dir" ] || { echo "  [OK] no PIN files found"; return 0; }
  for f in "$dir"/."${PROGRAM_NAME}".pin.*; do
    [ -e "$f" ] || continue
    base="${f##*/}"
    rest="${base#."${PROGRAM_NAME}".pin.}"
    pid="${rest%%.*}"
    case "$pid" in
      ''|*[!0-9]*) pid="" ;;
    esac
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      continue   # a live session still legitimately needs this file
    fi
    found=1
    echo "  [!!] Orphaned PKCS#11 PIN file detected: $f"
    echo "       Its owning process (pid ${pid:-unknown}) is no longer running."
    echo "       This file holds a plaintext PIN; remove it: rm -f '$f'"
  done
  [ "$found" = 0 ] && echo "  [OK] no orphaned PIN files found"
  return 0
}

doctor() {
  echo "=== vpn-up doctor ==="
  echo "- OS         : $(uname -a)"
  echo "- Shell      : $SHELL"
  echo "- Bash       : ${BASH_VERSION:-unknown}"
  echo "- Program    : ${PROGRAM_NAME}"
  echo "- Path       : ${PROGRAM_PATH}"
  echo "- Data dir   : ${DATA_DIR}"
  echo "- Config     : ${CONFIGURATION_FILE}"
  echo "- Profiles   : ${PROFILES_FILE}"
  echo "- PID/LOG    : ${PID_FILE_PATH} / ${LOG_FILE_PATH}"
  echo
  printf "Checking dependencies...\n"
  for b in xmlstarlet openconnect openssl; do
    if command -v "$b" >/dev/null 2>&1; then
      echo "  [OK] $b -> $(command -v "$b")"
    else
      echo "  [!!] $b MISSING"
    fi
  done
  if command -v openconnect >/dev/null 2>&1; then
    local _ocmaj; _ocmaj="$(openconnect_major)"
    echo "  -    openconnect version: $(openconnect --version 2>&1 | head -1)"
    if [ -n "$_ocmaj" ] && [ "$_ocmaj" -ge 9 ]; then
      echo "  [OK] SSO / external browser supported (openconnect >= 9.0)"
    else
      echo "  [..] SSO / external browser needs openconnect >= 9.0 (detected: ${_ocmaj:-unknown})"
    fi
  fi
  if command -v oathtool >/dev/null 2>&1; then
    echo "  [OK] oathtool -> $(command -v oathtool) (TOTP 2FA supported)"
  else
    echo "  [..] oathtool not found (needed only for TOTP 2FA: brew install oath-toolkit | apt-get install oathtool)"
  fi
  # PKCS#11 (p11-kit / GnuTLS) lets openconnect use a client certificate from a
  # smartcard / YubiKey PIV; file-based client certs need nothing extra.
  if command -v p11tool >/dev/null 2>&1 || command -v p11-kit >/dev/null 2>&1; then
    echo "  [OK] PKCS#11 tooling present (smartcard / YubiKey-PIV client certificates)"
  else
    echo "  [..] p11-kit/p11tool not found (needed only for PKCS#11 client certs: brew install p11-kit | apt-get install p11-kit; file-based client certs work without it)"
  fi
  if [ "$(uname)" = "Darwin" ]; then
    if command -v security >/dev/null 2>&1; then echo "  [OK] security (Keychain)"; else echo "  [!!] security missing"; fi
  else
    if command -v secret-tool >/dev/null 2>&1; then echo "  [OK] secret-tool (Secret Service)"; else echo "  [..] secret-tool not found (fallback to OpenSSL vault)"; fi
  fi
  echo
  echo "Secret backend in use:"
  . "${PROGRAM_PATH}/encryption.sh"
  echo "  -> $(secrets_backend)"
  # helper_bin/admin_bin come from twophase.sh, which vpn-up.command sources at
  # startup. Sourced here only if something called doctor without it.
  command -v helper_bin >/dev/null 2>&1 || . "${PROGRAM_PATH}/twophase.sh"
  command -v install_helper >/dev/null 2>&1 || . "${PROGRAM_PATH}/helperinstall.sh"
  local boundary_rc=0
  doctor_helper_install
  doctor_privilege_boundary || boundary_rc=$?
  doctor_legacy_grants
  doctor_execution_closure
  doctor_rate_limiter_state
  doctor_pin_files

  echo
  echo "Config preview:"
  if [ -f "$CONFIGURATION_FILE" ]; then
    grep -E '^(readonly (BACKGROUND|QUIET|SHOW_BANNER|NOTIFICATIONS|ENCRYPTION_ENABLED))' "$CONFIGURATION_FILE" || true
  else
    echo "  (no config yet; run ./vpn-up.command setup)"
  fi

  # A broken privilege boundary must make `doctor` FAIL, not merely mention it in
  # a wall of otherwise-green output. This is the one check here whose failure
  # means the security model is not holding.
  return "$boundary_rc"
}