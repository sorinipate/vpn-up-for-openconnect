#!/usr/bin/env bash
# VPN Up for OpenConnect - Main Entry Point (Bash >= 4 required)
# Author: Sorin-Doru Ipate (@sorinipate)

# --- Require Bash >= 4 ---
if [[ -z "${BASH_VERSINFO[*]}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "This script requires Bash >= 4. Install Homebrew bash and ensure it's first in PATH (e.g., /opt/homebrew/bin)." >&2
  exit 1
fi

# Treat unset variables as errors (typos in variable names fail fast).
set -u

PROGRAM_NAME=$(basename "$0")
PROGRAM_PATH=$(cd "$(dirname "$0")" && pwd)

# User state (config, profiles, secrets, logs, pids) lives OUTSIDE the
# program directory so reinstalling/cleaning the repo never touches it.
DATA_DIR="${VPN_UP_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/vpn-up}"

# Exports
export PROGRAM_NAME PROGRAM_PATH DATA_DIR
export CONFIGURATION_FILE="${DATA_DIR}/${PROGRAM_NAME}.config"
export PROFILES_FILE="${DATA_DIR}/${PROGRAM_NAME}.profiles"

( umask 077; mkdir -p "${DATA_DIR}/logs" "${DATA_DIR}/pids" )
chmod 700 "${DATA_DIR}" "${DATA_DIR}/logs" "${DATA_DIR}/pids" 2>/dev/null || true

# One-time migration of legacy state from the old in-repo config/ directory.
for _legacy_file in "${PROGRAM_NAME}.config" "${PROGRAM_NAME}.profiles" \
                    "${PROGRAM_NAME}.secrets.enc" "${PROGRAM_NAME}.secrets"; do
  if [ -f "${PROGRAM_PATH}/config/${_legacy_file}" ] && [ ! -e "${DATA_DIR}/${_legacy_file}" ]; then
    mv "${PROGRAM_PATH}/config/${_legacy_file}" "${DATA_DIR}/${_legacy_file}"
    chmod 600 "${DATA_DIR}/${_legacy_file}" 2>/dev/null || true
    echo "Migrated ${_legacy_file} to ${DATA_DIR}/" >&2
  fi
done
unset _legacy_file

# Source modules
. "${PROGRAM_PATH}/logging.sh"
. "${PROGRAM_PATH}/ui.sh"
. "${PROGRAM_PATH}/dependencies.sh"
. "${PROGRAM_PATH}/encryption.sh"
. "${PROGRAM_PATH}/network.sh"
. "${PROGRAM_PATH}/profiles.sh"
. "${PROGRAM_PATH}/core.sh"
. "${PROGRAM_PATH}/setup.sh"

# Default colors if config not yet present
PRIMARY="\x1b[36;1m"; SUCCESS="\x1b[32;1m"; WARNING="\x1b[35;1m"; DANGER="\x1b[31;1m"; RESET="\x1b[0m"

print_info() {
cat <<EOF
Usage: $PROGRAM_NAME <command>

Commands:
  start [profile]      Start VPN (interactive menu, or directly by profile name)
  stop                 Stop VPN
  status               Show VPN status (profile, gateway, uptime)
  restart [profile]    Restart VPN (stop+start)
  list                 List configured VPN profiles
  logs [-f]            Show the connection log (-f to follow)
  setup                Run setup wizard (regenerate config)
  set-secret           Save a secret field for a profile (e.g., password)
  delete-secret        Delete a stored secret for a profile
  pin <host[:port]>    Print the pin-sha256 value for a gateway's certificate
  pin --save <profile> Fetch the pin and write it into the profile
  doctor               Diagnose environment and secret backend

Examples:
  $PROGRAM_NAME start "Work VPN"
  $PROGRAM_NAME set-secret "Work VPN" password
  $PROGRAM_NAME pin vpn.example.com
  $PROGRAM_NAME pin --save "Work VPN"
  $PROGRAM_NAME logs -f
EOF
}

case "${1:-}" in
  start)      check_dependencies; start "${2:-}" ;;
  stop)       stop ;;
  status)     status ;;
  restart)    "$0" stop; "$0" start "${2:-}" ;;
  list)       list_profiles ;;
  logs)       show_logs "${2:-}" ;;
  setup)      setup_wizard ;;
  set-secret) shift; profile="${1:-}"; field="${2:-}"; { [ -z "$profile" ] || [ -z "$field" ]; } && { echo "Usage: $0 set-secret <profile> <field>"; exit 1; }
              [ "$field" = "sudo_password" ] && { echo "Storing the sudo password is not supported (it would defeat sudo's protection). See the sudoers rule in the README." >&2; exit 1; }
              read -r -s -p "Enter value for ${profile}.${field}: " value; echo
              secrets_set "${profile}" "${field}" "${value}"; echo "Saved secret for ${profile}.${field}." ;;
  delete-secret) shift; profile="${1:-}"; field="${2:-}"; { [ -z "$profile" ] || [ -z "$field" ]; } && { echo "Usage: $0 delete-secret <profile> <field>"; exit 1; }
                 secrets_delete "${profile}" "${field}"; echo "Deleted secret for ${profile}.${field} (if existed)." ;;
  pin)        shift
              if [ "${1:-}" = "--save" ]; then
                profile="${2:-}"; [ -z "$profile" ] && { echo "Usage: $0 pin --save <profile>"; exit 1; }
                pin_save "$profile"; exit $?
              fi
              host="${1:-}"; [ -z "$host" ] && { echo "Usage: $0 pin <host[:port]> | pin --save <profile>"; exit 1; }
              if pin_value="$(fetch_server_pin "$host")"; then
                echo "$pin_value"
                if verify_gateway_cert "$host"; then
                  echo "(certificate also validates against the system trust store)"
                else
                  echo "WARNING: certificate does NOT validate against the system trust store." >&2
                  echo "Only use this pin if you have verified it out-of-band (e.g., with your VPN administrator)." >&2
                fi
              else
                echo "Could not retrieve certificate from $host" >&2; exit 1
              fi ;;
  doctor)     doctor ;;
  *)          print_info ;;
esac
