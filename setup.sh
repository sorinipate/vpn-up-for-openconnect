# setup.sh - interactive configuration

_bool_default() {
  local input="$1"; local default="$2"
  input="$(printf '%s' "$input" | tr '[:lower:]' '[:upper:]')"
  case "$input" in
    TRUE|T|YES|Y|1)  echo TRUE ;;
    FALSE|F|NO|N|0)  echo FALSE ;;
    "")              echo "${default}" ;;
    *)               echo "${default}" ;;
  esac
}

save_configuration() {
  mkdir -p "$(dirname "$CONFIGURATION_FILE")"
  local tmp="${CONFIGURATION_FILE}.tmp"
  cat > "${tmp}" <<'CFG'
# VPN-UP SETTINGS

readonly PRIMARY="\x1b[36;1m"
readonly SUCCESS="\x1b[32;1m"
readonly WARNING="\x1b[35;1m"
readonly DANGER="\x1b[31;1m"
readonly RESET="\x1b[0m"

# CORE
readonly SUDO=__SUDO__
#        ├ TRUE
#        └ FALSE
# NOTE: The sudo password is never stored anywhere. For passwordless operation,
# add a scoped sudoers rule for openconnect (see README).

# OPENCONNECT OPTIONS
readonly BACKGROUND=__BACKGROUND__
#        ├ TRUE          Runs in background after startup
#        └ FALSE         Runs in foreground after startup

readonly QUIET=__QUIET__
#        ├ TRUE          Less output
#        └ FALSE         Detailed output

# ENCRYPTION
readonly ENCRYPTION_ENABLED=TRUE  # Toggle affects only file fallback; keychain/keyring are preferred.
CFG
  sed -i.bak "s/__SUDO__/${__WZ_SUDO}/" "${tmp}"
  sed -i.bak "s/__BACKGROUND__/${__WZ_BACKGROUND}/" "${tmp}"
  sed -i.bak "s/__QUIET__/${__WZ_QUIET}/" "${tmp}"
  rm -f "${tmp}.bak"
  mv "${tmp}" "${CONFIGURATION_FILE}"
  chmod 600 "${CONFIGURATION_FILE}"
  print_success "Saved configuration to %s\n" "${CONFIGURATION_FILE}"
}

setup_wizard() {
  printf "%b\n" "${PRIMARY}Running first-time setup...${RESET}"

  read -r -p "Use sudo for privileged operations? (TRUE/FALSE) [TRUE]: " _in_sudo
  __WZ_SUDO="$(_bool_default "${_in_sudo}" "TRUE")"

  read -r -p "Run in background after connect? (TRUE/FALSE) [TRUE]: " _in_bg
  __WZ_BACKGROUND="$(_bool_default "${_in_bg}" "TRUE")"

  read -r -p "Quiet output? (TRUE/FALSE) [TRUE]: " _in_quiet
  __WZ_QUIET="$(_bool_default "${_in_quiet}" "TRUE")"

  # Clean up any sudo password stored by older versions; storing it defeats
  # sudo's protection (any process running as this user could retrieve it).
  if [ -n "$(secrets_get "__GLOBAL__" "sudo_password" 2>/dev/null)" ]; then
    secrets_delete "__GLOBAL__" "sudo_password"
    print_warning "Removed stored sudo password (no longer supported). For passwordless use, see the sudoers rule in the README.\n"
  fi

  save_configuration
}