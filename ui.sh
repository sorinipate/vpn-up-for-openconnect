# ui.sh - UI helpers (banner, colors)

# Banner ASCII art provided by user
readonly ASCII_ART='
    ╔═════════════════════════════════════════════════════════════════╗
    ║                                                                 ║
    ║ ██╗   ██╗  ██████╗    ███╗   ██╗           ██╗   ██╗   ██████╗  ║
    ║ ██║   ██║  ██╔══██╗   ████╗  ██║           ██║   ██║   ██╔══██╗ ║
    ║ ██║   ██║  ██████╔╝   ██╔██╗ ██║  ███████  ██║   ██║   ██████╔╝ ║
    ║ ╚██╗ ██╔╝  ██╔═══╝    ██║╚██╗██║           ██║   ██║   ██╔═══╝  ║
    ║  ╚████╔╝   ██║        ██║ ╚████║           ╚██████╔╝   ██║      ║
    ║   ╚═══╝    ╚═╝        ╚═╝  ╚═══╝            ╚═════╝    ╚═╝      ║
    ║                                                                 ║
    ║                   F O R   O P E N C O N N E C T                 ║
    ╚═════════════════════════════════════════════════════════════════╝
'

PRIMARY="${PRIMARY:-\x1b[36;1m}"
RESET="${RESET:-\x1b[0m}"

# Desktop notification on connect/disconnect (best-effort, never fatal).
notify() {
  [ "${NOTIFICATIONS:-TRUE}" = TRUE ] || return 0
  local title="$1" message="$2"
  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"${message//\"/\\\"}\" with title \"${title//\"/\\\"}\"" >/dev/null 2>&1 || true
  elif command -v notify-send >/dev/null 2>&1; then
    notify-send "$title" "$message" 2>/dev/null || true
  fi
}

show_banner() {
  # Only show when interactive and enabled; independent of QUIET, which
  # controls openconnect's output verbosity.
  [ -t 1 ] || return 0
  [ "${SHOW_BANNER:-TRUE}" = TRUE ] || return 0
  printf "%b\n" "${PRIMARY}${ASCII_ART}${RESET}"
}