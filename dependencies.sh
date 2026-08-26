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
# appears in a sudoers file. `sudo -n -l <command>` asks sudo's own policy
# whether that exact command can run without a password, which is the question
# that matters and is not answerable by grepping /etc/sudoers.d: rules can come
# from LDAP, from includes, from Defaults targetpw, or from an alias.
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
    if sudo -n -l "$h" >/dev/null 2>&1; then
      echo "  [OK] vpn-up-helper is reachable without a password (this is the intended rule)"
    else
      echo "  [..] vpn-up-helper is installed but not passwordless; helper mode will not"
      echo "       run unattended. See SECURITY.md for the sudoers rule."
    fi
  else
    echo "  [..] vpn-up-helper not installed at $h (prompt mode is in use)"
  fi

  # The invariant. Checked even when the binary is not installed at this path,
  # because a rule naming a path that does not exist yet is still a rule.
  if sudo -n -l "$a" >/dev/null 2>&1; then
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
  local boundary_rc=0
  doctor_privilege_boundary || boundary_rc=$?
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