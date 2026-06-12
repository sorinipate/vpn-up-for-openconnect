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

show_banner() {
  # Only show when interactive and enabled; independent of QUIET, which
  # controls openconnect's output verbosity.
  [ -t 1 ] || return 0
  [ "${SHOW_BANNER:-TRUE}" = TRUE ] || return 0
  printf "%b\n" "${PRIMARY}${ASCII_ART}${RESET}"
}