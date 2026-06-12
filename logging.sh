# logging.sh - simple logging helpers

PID_FILE_PATH="${PROGRAM_PATH}/pids/${PROGRAM_NAME}.pid"
LOG_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.log"

# Color codes are printed separately from the message so they never go
# through printf format processing; data must be passed as arguments to a
# literal format string (e.g. print_warning "Loaded %s\n" "$file").
_print_color() { local color="$1" fmt="$2"; shift 2; printf "%b" "$color"; printf -- "$fmt" "$@"; printf "%b" "${RESET:-\x1b[0m}"; }
print_primary() { _print_color "${PRIMARY:-\x1b[36;1m}" "$@"; }
print_success() { _print_color "${SUCCESS:-\x1b[32;1m}" "$@"; }
print_warning() { _print_color "${WARNING:-\x1b[35;1m}" "$@"; }
print_danger()  { _print_color "${DANGER:-\x1b[31;1m}"  "$@"; }

check_file_existence() {
  local file_path="$1"; local file_name="$2"
  if [ ! -f "$file_path" ]; then
    printf "%b%s file missing! \n%b" "${DANGER:-\x1b[31;1m}" "$file_name" "${RESET:-\x1b[0m}"
    exit 1
  fi
}

# ICMP is often blocked; fall back to a plain HTTP reachability probe.
is_network_available() {
  ping -c 1 1.1.1.1 >/dev/null 2>&1 && return 0
  command -v curl >/dev/null 2>&1 \
    && curl -s --connect-timeout 4 --max-time 6 -o /dev/null "http://captive.apple.com/hotspot-detect.html"
}

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
  local current_ip
  current_ip=$(curl -s --max-time 5 https://api.ipify.org) || current_ip="(unavailable)"
  print_primary "Current IP address: %s\n" "${current_ip:-"(unavailable)"}"
}