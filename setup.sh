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
# NOTE: SUDO password is NEVER stored in this file; it is saved securely via the secrets backend if you opt in.

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

  # Optional: store sudo password securely for non-interactive runs
  if [ "${__WZ_SUDO}" = TRUE ]; then
    read -r -p "Store sudo password securely for non-interactive use? (TRUE/FALSE) [FALSE]: " _in_store
    _STORE="$(_bool_default "${_in_store}" "FALSE")"
    if [ "$_STORE" = TRUE ]; then
      read -r -s -p "Enter sudo password (will be saved securely): " _p; echo
      if [ -n "$_p" ]; then
        secrets_set "__GLOBAL__" "sudo_password" "$_p"
        print_success "Saved sudo password securely.\n"
      else
        print_warning "Empty password; nothing saved.\n"
      fi
    fi
  fi

  save_configuration
}