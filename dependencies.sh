# dependencies.sh - dependency checks and doctor

require_bin() {
  local bin="$1"; local hint="$2"
  if ! command -v "$bin" >/dev/null 2>&1; then
    print_danger "Missing dependency: %s\n" "$bin"
    [ -n "$hint" ] && print_warning "Hint: %s\n" "$hint"
    exit 1
  fi
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

doctor() {
  echo "=== vpn-up doctor ==="
  echo "- OS         : $(uname -a)"
  echo "- Shell      : $SHELL"
  echo "- Bash       : ${BASH_VERSION:-unknown}"
  echo "- Program    : ${PROGRAM_NAME}"
  echo "- Path       : ${PROGRAM_PATH}"
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
  if [ "$(uname)" = "Darwin" ]; then
    if command -v security >/dev/null 2>&1; then echo "  [OK] security (Keychain)"; else echo "  [!!] security missing"; fi
  else
    if command -v secret-tool >/dev/null 2>&1; then echo "  [OK] secret-tool (Secret Service)"; else echo "  [..] secret-tool not found (fallback to OpenSSL vault)"; fi
  fi
  echo
  echo "Secret backend in use:"
  . "${PROGRAM_PATH}/encryption.sh"
  echo "  -> $(secrets_backend)"
  echo
  echo "Config preview:"
  if [ -f "$CONFIGURATION_FILE" ]; then
    grep -E '^(readonly (SUDO|BACKGROUND|QUIET|ENCRYPTION_ENABLED))' "$CONFIGURATION_FILE" || true
  else
    echo "  (no config yet; run ./vpn-up.command setup)"
  fi
}