#!/usr/bin/env bash
# VPN Up for OpenConnect - Main Entry Point (Bash >= 4 required)
# Author: Sorin-Doru Ipate (@sorinipate)

# --- Require Bash >= 4 ---
if [[ -z "${BASH_VERSINFO[*]}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "This script requires Bash >= 4. Install Homebrew bash and ensure it's first in PATH (e.g., /opt/homebrew/bin)." >&2
  exit 1
fi

PROGRAM_NAME=$(basename "$0")
PROGRAM_PATH=$(cd "$(dirname "$0")" && pwd)

# Exports
export PROGRAM_NAME PROGRAM_PATH
export CONFIGURATION_FILE="${PROGRAM_PATH}/config/${PROGRAM_NAME}.config"
export PROFILES_FILE="${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles"

mkdir -p "${PROGRAM_PATH}/config" "${PROGRAM_PATH}/logs" "${PROGRAM_PATH}/pids"

# Source modules
. "${PROGRAM_PATH}/logging.sh"
. "${PROGRAM_PATH}/ui.sh"
. "${PROGRAM_PATH}/dependencies.sh"
. "${PROGRAM_PATH}/encryption.sh"
. "${PROGRAM_PATH}/profiles.sh"
. "${PROGRAM_PATH}/core.sh"
. "${PROGRAM_PATH}/setup.sh"

# Default colors if config not yet present
PRIMARY="\x1b[36;1m"; SUCCESS="\x1b[32;1m"; WARNING="\x1b[35;1m"; DANGER="\x1b[31;1m"; RESET="\x1b[0m"

print_info() {
cat <<EOF
Usage: $PROGRAM_NAME <command>

Commands:
  start          Start VPN (interactive profile selection)
  stop           Stop VPN
  status         Show VPN status
  restart        Restart VPN (stop+start)
  setup          Run setup wizard (regenerate config)
  set-secret     Save a secret field for a profile (e.g., password)
  delete-secret  Delete a stored secret for a profile (e.g., sudo password)
  doctor         Diagnose environment and secret backend

Examples:
  $PROGRAM_NAME start
  $PROGRAM_NAME set-secret WorkVPN password
  $PROGRAM_NAME set-secret __GLOBAL__ sudo_password
  $PROGRAM_NAME doctor
EOF
}

case "$1" in
  start)      check_dependencies; start ;;
  stop)       stop ;;
  status)     status ;;
  restart)    "$0" stop; "$0" start ;;
  setup)      setup_wizard ;;
  set-secret) shift; profile="$1"; field="$2"; [ -z "$profile" -o -z "$field" ] && { echo "Usage: $0 set-secret <profile> <field>"; exit 1; }
              read -r -s -p "Enter value for ${profile}.${field}: " value; echo
              secrets_set "${profile}" "${field}" "${value}"; echo "Saved secret for ${profile}.${field}." ;;
  delete-secret) shift; profile="$1"; field="$2"; [ -z "$profile" -o -z "$field" ] && { echo "Usage: $0 delete-secret <profile> <field>"; exit 1; }
                 secrets_delete "${profile}" "${field}"; echo "Deleted secret for ${profile}.${field} (if existed)." ;;
  doctor)     doctor ;;
  *)          print_info ;;
esac
