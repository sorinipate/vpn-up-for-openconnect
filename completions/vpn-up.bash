# bash completion for vpn-up.command
# bash:  source /path/to/completions/vpn-up.bash   (e.g. from ~/.bashrc)
# zsh :  autoload -U +X bashcompinit && bashcompinit
#        source /path/to/completions/vpn-up.bash

_vpn_up_complete_profiles() {
  local cur="$1" line
  cur="${cur//\\ / }"   # un-escape spaces the shell already escaped
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      "$cur"*) COMPREPLY+=("${line// /\\ }") ;;
    esac
  done < <("${COMP_WORDS[0]}" list-names 2>/dev/null)
}

_vpn_up() {
  local cur prev cmd
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd="${COMP_WORDS[1]:-}"

  if [ "$COMP_CWORD" -eq 1 ]; then
    mapfile -t COMPREPLY < <(compgen -W "start stop status restart list logs setup add-profile remove-profile service set-secret delete-secret pin doctor" -- "$cur")
    return
  fi

  case "$cmd" in
    service)
      if [ "$COMP_CWORD" -eq 2 ]; then
        mapfile -t COMPREPLY < <(compgen -W "install uninstall status" -- "$cur")
      elif [ "$COMP_CWORD" -eq 3 ] && { [ "$prev" = "install" ] || [ "$prev" = "uninstall" ]; }; then
        _vpn_up_complete_profiles "$cur"
      fi
      ;;
    start|restart|stop|remove-profile)
      [ "$COMP_CWORD" -eq 2 ] && _vpn_up_complete_profiles "$cur"
      ;;
    set-secret|delete-secret)
      if [ "$COMP_CWORD" -eq 2 ]; then
        _vpn_up_complete_profiles "$cur"
      elif [ "$COMP_CWORD" -eq 3 ]; then
        mapfile -t COMPREPLY < <(compgen -W "password" -- "$cur")
      fi
      ;;
    logs)
      if [ "$cur" = "-" ] || [ "$cur" = "-f" ]; then
        COMPREPLY=("-f")
      else
        _vpn_up_complete_profiles "$cur"
      fi
      ;;
    pin)
      if [ "$COMP_CWORD" -eq 2 ]; then
        mapfile -t COMPREPLY < <(compgen -W "--save" -- "$cur")
      elif [ "$prev" = "--save" ]; then
        _vpn_up_complete_profiles "$cur"
      fi
      ;;
  esac
}

complete -F _vpn_up vpn-up.command ./vpn-up.command vpn-up
