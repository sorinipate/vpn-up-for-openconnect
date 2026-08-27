# dependencies.sh - dependency checks and doctor

require_bin() {
  local bin="$1"; local hint="$2"
  if ! command -v "$bin" >/dev/null 2>&1; then
    print_danger "Missing dependency: %s\n" "$bin"
    [ -n "$hint" ] && print_warning "Hint: %s\n" "$hint"
    exit 1
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
  require_bin xmlstarlet "Install via: brew install xmlstarlet | apt-get install xmlstarlet"
  require_bin openconnect "Install via: brew install openconnect | apt-get install openconnect"
  if [ "$(uname)" = "Darwin" ]; then
    require_bin security "macOS provides this by default"
  else
    command -v secret-tool >/dev/null 2>&1 || print_warning "Optional: 'secret-tool' for keyring secrets. Falling back to OpenSSL vault.\n"
  fi
  command -v openssl >/dev/null 2>&1 || print_warning "Optional: 'openssl' for encrypted vault fallback.\n"
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