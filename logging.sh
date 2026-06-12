# logging.sh - simple logging helpers

PID_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.pid"
LOG_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.log"

print_primary() { printf "${PRIMARY:-\x1b[36;1m}$1${RESET:-\x1b[0m}" "${@:2}"; }
print_success() { printf "${SUCCESS:-\x1b[32;1m}$1${RESET:-\x1b[0m}" "${@:2}"; }
print_warning() { printf "${WARNING:-\x1b[35;1m}$1${RESET:-\x1b[0m}" "${@:2}"; }
print_danger()  { printf "${DANGER:-\x1b[31;1m}$1${RESET:-\x1b[0m}"  "${@:2}"; }

check_file_existence() {
  local file_path="$1"; local file_name="$2"
  if [ ! -f "$file_path" ]; then
    printf "%b%s file missing! \n%b" "${DANGER:-\x1b[31;1m}" "$file_name" "${RESET:-\x1b[0m}"
    exit 1
  fi
}

is_network_available() { ping -c 1 1.1.1.1 >/dev/null 2>&1; }

# True only if the PID is numeric AND the process is actually openconnect —
# guards against PID reuse and corrupted PID files.
is_openconnect_pid() {
  local pid="$1"
  [ -n "$pid" ] || return 1
  case "$pid" in *[!0-9]*) return 1 ;; esac
  ps -p "$pid" -o comm= 2>/dev/null | grep -q 'openconnect'
}

is_vpn_running() {
  [ -f "$PID_FILE_PATH" ] && is_openconnect_pid "$(cat "$PID_FILE_PATH")"
}

print_current_ip_address() {
  current_ip=$(curl -s https://api.ipify.org)
  print_primary "Current IP address: %s\n" "$current_ip"
}