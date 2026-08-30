#!/usr/bin/env bats
# install-helper / uninstall-helper: the decisions, not the plumbing.
#
# Nothing privileged runs here. vu_sudo() is the single privileged call site in
# helperinstall.sh, so the suite overrides it with a recorder that also SIMULATES
# each operation inside a sandbox - so state evolves the way a real install would
# and the assertions can be about outcomes as well as about argv.
#
# What these tests are for: every requirement in this file was a review finding
# that a working installer would still have gotten wrong. The dangerous ones are
# the assertions that something did NOT happen.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_DIRNAME/.."
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR/pids" "$DATA_DIR/logs"
  # Never the real home: _vu_any_service_installed looks in it.
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"

  print_warning() { printf -- "$1" "${@:2}"; }
  print_danger()  { printf -- "$1" "${@:2}" >&2; }
  print_success() { printf -- "$1" "${@:2}"; }
  print_primary() { printf -- "$1" "${@:2}"; }

  source "$BATS_TEST_DIRNAME/../logging.sh"
  source "$BATS_TEST_DIRNAME/../outcome.sh"
  source "$BATS_TEST_DIRNAME/../twophase.sh"
  source "$BATS_TEST_DIRNAME/../helperinstall.sh"

  SANDBOX="$BATS_TEST_TMPDIR/sandbox"
  SUDOERS="$SANDBOX/etc/sudoers.d"
  TARGET="$SANDBOX/opt/vpn-up/bin"
  BUILD="$SANDBOX/build"
  LOG="$SANDBOX/sudo.log"
  mkdir -p "$SUDOERS" "$BUILD" "$SANDBOX"
  : > "$LOG"

  export VPN_UP_HELPER_DIR="$TARGET"        # honoured by twophase.sh's helper_dir
  _vu_sudoers_dir() { printf '%s' "$SUDOERS"; }
  _vu_build_dir()   { printf '%s' "$BUILD"; }

  VISUDO_RC=0
  NOPASSWD_HELPER=1     # exit status the probe should see (0 = passwordless)
  NOPASSWD_ADMIN=1
  LEGACY_LIST=fail      # bare `sudo -l`: fail | ok
  LEGACY_RULE=none      # -ll output: none | nopasswd | authenticate | garbage

  # A stand-in for the compiled binaries: answers `version`, `verify-closure`
  # and `list` the way the real ones do.
  _vu_fake_binary() {
    cat > "$1" <<'EOS'
#!/bin/sh
case "$1" in
  version)        echo "$(basename "$0") (policy engine 1)"
                  echo "  registry root /etc/vpn-up"
                  echo "  state root    /run/vpn-up" ;;
  verify-closure) echo "closure: all objects trusted"; exit "${FAKE_CLOSURE_RC:-0}" ;;
  list)           echo "no approved profiles for uid $(id -u)"; exit "${FAKE_LIST_RC:-0}" ;;
  *)              exit 2 ;;
esac
EOS
    chmod +x "$1"
  }

  _vu_build_binaries() {
    _vu_fake_binary "$BUILD/vpn-up-helper"
    _vu_fake_binary "$BUILD/vpn-up-admin"
  }
  _vu_have_toolchain() { return 0; }
  # The sandbox lives under BATS_TEST_TMPDIR, which is user-owned, so the real
  # chain walk refuses it - correctly. The flow tests therefore report the
  # sandbox as root-owned and unwritable, and the WALK ITSELF is tested
  # separately below against real paths and against locally-stubbed trees.
  #
  # Deliberately stubbing the two stat helpers rather than _vu_path_trusted: the
  # real walk still runs here, so a walk that crashed or stopped early would
  # still show up in these tests. Any test that needs the truth calls
  # use_real_stat.
  # Preserved under other names BEFORE being shadowed, so a test that needs the
  # truth restores it by name. The previous version of use_real_stat re-sourced
  # helperinstall.sh instead, which also reset vu_sudo and the sandbox path
  # overrides above - a footgun waiting for its first victim.
  eval "_real_file_owner_uid() $(declare -f file_owner_uid | tail -n +2)"
  eval "_real_file_mode() $(declare -f file_mode | tail -n +2)"
  eval "_real_acl_extended() $(declare -f _vu_acl_extended | tail -n +2)"

  file_owner_uid() { echo 0; }
  file_mode() { echo 755; }
  _vu_acl_extended() { return 1; }

  # The trust walk has its own tests; the flow tests must not depend on the
  # permissions of the host's /usr/bin.
  vu_tools_resolve() {
    # Resolved, not hardcoded: /bin/mv and /usr/sbin/visudo are not in the same
    # place on every distribution, and a test that fails for that reason would be
    # a platform difference masquerading as a finding.
    VU_SUDO="$(command -v sudo || echo /usr/bin/sudo)"
    VU_INSTALL="$(command -v install)"
    VU_VISUDO="$(command -v visudo || echo /usr/sbin/visudo)"
    VU_MV="$(command -v mv)"; VU_CAT="$(command -v cat)"
    VU_RM="$(command -v rm)"; VU_RMDIR="$(command -v rmdir)"
    return 0
  }

  # Record, then simulate. Ordinary user permissions, sandbox paths.
  vu_sudo() {
    printf '%s\n' "$*" >> "$LOG"
    case "$1" in
      -k)
        # a probe: `-k -n <bin> version` or `-k -n [-l|-ll] [path]`
        shift 2
        case "$1" in
          -l)  [ "$LEGACY_LIST" = ok ] ;;
          -ll) [ "$LEGACY_LIST" = ok ] || return 1
               case "$LEGACY_RULE" in
                 nopasswd)     echo "    Commands: !authenticate"; return 0 ;;
                 authenticate) echo "    Commands: authenticate";  return 0 ;;
                 garbage)      echo "something else entirely";     return 0 ;;
                 *) return 1 ;;
               esac ;;
          *"vpn-up-helper") return "$NOPASSWD_HELPER" ;;
          *"vpn-up-admin")  return "$NOPASSWD_ADMIN" ;;
          *) return 1 ;;
        esac
        ;;
      */install)
        # The only operation that genuinely needs simulating: -o 0 -g 0 requires
        # root. Everything after `--` is the real argument list, which is how
        # production always calls it.
        shift
        local -a rest=(); local seen=0 a
        for a in "$@"; do
          if [ "$seen" = 1 ]; then rest+=("$a"); elif [ "$a" = "--" ]; then seen=1; fi
        done
        if [ "${1:-}" = "-d" ]; then
          mkdir -p "${rest[@]}"
        else
          mkdir -p "$(dirname "${rest[1]}")"; cp "${rest[0]}" "${rest[1]}"
        fi
        ;;
      */visudo)  return "$VISUDO_RC" ;;
      # mv, cat, rm and rmdir take exactly the flags production passes, so the
      # real utilities run them - no argument re-parsing to get wrong.
      */mv)      shift; mv "$@" ;;
      */cat)     shift; cat "$@" ;;
      */rm)      shift; rm "$@" ;;
      */rmdir)   shift; rmdir "$@" 2>/dev/null ;;
      *)         "$@" ;;                      # e.g. the staged binary's `version`
    esac
  }
}

# Put the genuine stat helpers back, for the tests whose whole point is what the
# filesystem actually says. Without this they would be asserting against setup's
# stubs, which is the shape of a test that cannot fail.
use_real_stat() {
  file_owner_uid()   { _real_file_owner_uid "$@"; }
  file_mode()        { _real_file_mode "$@"; }
  _vu_acl_extended() { _real_acl_extended "$@"; }
}

legacy_line() { printf '%s ALL=(root) NOPASSWD: /usr/sbin/openconnect' "$(id -un)"; }
plant_legacy() { legacy_line > "$SUDOERS/vpn-up"; }
sudo_log()     { cat "$LOG"; }

# --- refusals that must happen before anything is installed ----------------

@test "install-helper refuses to run as root" {
  id() { if [ "${1:-}" = -u ]; then echo 0; else command id "$@"; fi; }
  run install_helper
  [ "$status" -ne 0 ]
  [[ "$output" == *"as yourself"* ]]
  [ ! -e "$TARGET/vpn-up-helper" ]
}

@test "a failing closure check installs nothing" {
  export FAKE_CLOSURE_RC=1
  run install_helper --yes
  [ "$status" -ne 0 ]
  [ ! -e "$TARGET/vpn-up-helper" ]
  run sudo_log
  [[ "$output" != *install* ]]
}

@test "declining the legacy retirement aborts before any mutation" {
  plant_legacy
  # No --yes, and read gets EOF, which is not a yes.
  run install_helper </dev/null
  [ "$status" -ne 0 ]
  [ ! -e "$TARGET/vpn-up-helper" ]
  [ -f "$SUDOERS/vpn-up" ]                     # left exactly as it was
  run sudo_log
  [[ "$output" != *install* ]]
}

@test "an unrecognised legacy sudoers file refuses before mutation and is untouched" {
  {
    legacy_line
    printf '\n%s ALL=(root) NOPASSWD: /usr/bin/id\n' "$(id -un)"
  } > "$SUDOERS/vpn-up"
  local before; before="$(cat "$SUDOERS/vpn-up")"
  run install_helper --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a rule VPN Up wrote"* ]]
  [ "$(cat "$SUDOERS/vpn-up")" = "$before" ]
  [ ! -e "$TARGET/vpn-up-helper" ]
  run sudo_log
  [[ "$output" != *install* ]]
}

# --- the central invariant -------------------------------------------------

@test "without --passwordless: the legacy rule is STILL retired, and no rule replaces it" {
  plant_legacy
  run install_helper --yes
  [ "$status" -eq 0 ]
  [ -x "$TARGET/vpn-up-helper" ]
  [ ! -e "$SUDOERS/vpn-up" ]                   # retired
  [ ! -e "$SUDOERS/vpn-up-$(id -u)" ]          # and nothing took its place
  [[ "$output" == *"Retired the legacy"* ]]
}

@test "with --passwordless: legacy out, helper-only rule in" {
  plant_legacy
  NOPASSWD_HELPER=0
  run install_helper --yes --passwordless
  [ "$status" -eq 0 ]
  [ ! -e "$SUDOERS/vpn-up" ]
  local rule="$SUDOERS/vpn-up-$(id -u)"
  [ -f "$rule" ]
  [ "$(cat "$rule")" = "#$(id -u) ALL=(root) NOPASSWD: $TARGET/vpn-up-helper" ]
  grep -q "NOPASSWD" "$rule"
  if grep -q "openconnect" "$rule"; then false; fi
  if grep -q "vpn-up-admin" "$rule"; then false; fi
}

@test "the rule names the user numerically, not by name" {
  run _vu_helper_rule_line
  [[ "$output" == "#$(id -u) "* ]]
  [[ "$output" != *"$(id -un)"* ]] || skip "this account's name is its uid"
}

# --- the sudoers transaction ------------------------------------------------

@test "visudo validates the staged dot-file before the move, and a failure moves nothing" {
  VISUDO_RC=1
  run install_helper --yes --passwordless
  [ "$status" -ne 0 ]
  [ ! -e "$SUDOERS/vpn-up-$(id -u)" ]
  run sudo_log
  [[ "$output" == *"visudo -cf $SUDOERS/.vpn-up-$(id -u).new"* ]]
  [[ "$output" != *"mv -f $SUDOERS/.vpn-up-$(id -u).new"* ]]
}

@test "the staged sudoers name contains a dot, so sudo ignores it while it exists" {
  NOPASSWD_HELPER=0
  run install_helper --yes --passwordless
  [ "$status" -eq 0 ]
  run sudo_log
  [[ "$output" == *"/.vpn-up-$(id -u).new"* ]]
}

@test "post-check failure removes the rule this run created, and never restores the legacy one" {
  plant_legacy
  NOPASSWD_HELPER=0
  NOPASSWD_ADMIN=0            # the boundary violation the post-check must catch
  run install_helper --yes --passwordless
  [ "$status" -ne 0 ]
  [[ "$output" == *"approval boundary is broken"* ]]
  [ ! -e "$SUDOERS/vpn-up-$(id -u)" ]   # rolled back
  [ ! -e "$SUDOERS/vpn-up" ]            # NOT restored: never roll back into arbitrary root
  [ -x "$TARGET/vpn-up-helper" ]        # binaries stay; interactive mode still works
}

@test "rollback does not remove a passwordless rule this run only preserved" {
  printf '#%s ALL=(root) NOPASSWD: %s/vpn-up-helper\n' "$(id -u)" "$TARGET" > "$SUDOERS/vpn-up-$(id -u)"
  NOPASSWD_HELPER=0
  NOPASSWD_ADMIN=0
  run install_helper --yes --passwordless
  [ "$status" -ne 0 ]
  [ -f "$SUDOERS/vpn-up-$(id -u)" ]
}

# --- upgrade idempotency (Phase A') ----------------------------------------

@test "an upgrade WITHOUT --passwordless leaves an existing helper rule alone" {
  local rule="$SUDOERS/vpn-up-$(id -u)"
  printf '#%s ALL=(root) NOPASSWD: %s/vpn-up-helper\n' "$(id -u)" "$TARGET" > "$rule"
  NOPASSWD_HELPER=0
  run install_helper --yes
  [ "$status" -eq 0 ]
  [ -f "$rule" ]
  run sudo_log
  [[ "$output" != *"rm -f -- $rule"* ]]
}

@test "an upgrade WITH --passwordless preserves an already-correct rule rather than rewriting it" {
  local rule="$SUDOERS/vpn-up-$(id -u)"
  printf '#%s ALL=(root) NOPASSWD: %s/vpn-up-helper\n' "$(id -u)" "$TARGET" > "$rule"
  NOPASSWD_HELPER=0
  run install_helper --yes --passwordless
  [ "$status" -eq 0 ]
  [[ "$output" == *"already present"* ]]
  run sudo_log
  [[ "$output" != *".vpn-up-$(id -u).new"* ]]
}

@test "a modified per-uid rule is refused, not rewritten" {
  local rule="$SUDOERS/vpn-up-$(id -u)"
  printf '#%s ALL=(root) NOPASSWD: /usr/bin/id\n' "$(id -u)" > "$rule"
  run install_helper --yes --passwordless
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  [ "$(cat "$rule")" = "#$(id -u) ALL=(root) NOPASSWD: /usr/bin/id" ]
  [[ "$output" == *"Not touching"* ]] || [[ "$output" == *"not the rule this installer writes"* ]]
}

# --- binaries ---------------------------------------------------------------

@test "binaries are staged and renamed, never written onto the live path" {
  run install_helper --yes
  [ "$status" -eq 0 ]
  run sudo_log
  [[ "$output" == *"install -o 0 -g 0 -m 0755 -- $BUILD/vpn-up-helper $TARGET/.vpn-up-helper.new"* ]]
  [[ "$output" == *"mv -f -- $TARGET/.vpn-up-helper.new $TARGET/vpn-up-helper"* ]]
}

@test "install verification uses list, not version: version is exempt from the self-path check" {
  run install_helper --yes
  [ "$status" -eq 0 ]
  run sudo_log
  [[ "$output" == *"$TARGET/vpn-up-admin list"* ]]
}

@test "a self-check failure from the installed binary is a failed install" {
  export FAKE_LIST_RC=1
  run install_helper --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"§11.1 self-check"* ]] || [[ "$output" == *"self-check"* ]]
}

@test "the manifest records the installed files' hashes, and is not shell" {
  run install_helper --yes
  [ "$status" -eq 0 ]
  local m="$TARGET/manifest"
  [ -f "$m" ]
  grep -q '^manifest-version=1$' "$m"
  grep -q '^policy-abi=1$' "$m"
  local recorded actual
  recorded="$(sed -n 's/^helper-sha256=//p' "$m")"
  actual="$(_vu_sha256 "$TARGET/vpn-up-helper")"
  [ "$recorded" = "$actual" ]
  # No source-tree path, and nothing that would matter if it were ever sourced.
  if grep -q "$PROGRAM_PATH" "$m"; then false; fi
  if grep -qE '[`$();|&]' "$m"; then false; fi
}

# --- probes -----------------------------------------------------------------

@test "every passwordless probe carries -k, so a warm sudo cache cannot answer for policy" {
  NOPASSWD_HELPER=0
  run install_helper --yes --passwordless
  [ "$status" -eq 0 ]
  run sudo_log
  # Every probe of one of our binaries must be cache-independent.
  local probes
  probes="$(printf '%s\n' "$output" | grep -E 'vpn-up-(helper|admin) version' || true)"
  [ -n "$probes" ]
  while IFS= read -r line; do
    [[ "$line" == "-k -n "* ]]
  done <<< "$probes"
}

@test "helper_mode_available is cache-independent too" {
  # The login-service gate: at boot there is no credential cache, so a probe that
  # honours one would report "available" for a machine about to hang on a prompt.
  mkdir -p "$TARGET"
  printf '#!/bin/sh\nexit 0\n' > "$TARGET/vpn-up-helper"; chmod +x "$TARGET/vpn-up-helper"
  local seen="$BATS_TEST_TMPDIR/args"
  sudo() { printf '%s\n' "$*" > "$seen"; return 0; }
  run helper_mode_available
  [ "$status" -eq 0 ]
  [[ "$(cat "$seen")" == "-k -n "* ]]
}

@test "the openconnect probe never executes openconnect" {
  LEGACY_LIST=ok
  LEGACY_RULE=nopasswd
  vu_tools_resolve
  run vu_report_legacy_grants
  [ "$status" -ne 0 ]
  [[ "$output" == *"WITHOUT a password"* ]]
  run sudo_log
  # Listing only: no invocation that would run the binary.
  [[ "$output" != *"openconnect --version"* ]]
  while IFS= read -r line; do
    [[ "$line" == *" -l"* ]] || [[ "$line" == *" -ll "* ]]
  done <<< "$(grep openconnect "$LOG" || true)"
}

@test "an unlistable policy is inconclusive, not a clean bill of health" {
  LEGACY_LIST=fail
  vu_tools_resolve
  run vu_report_legacy_grants
  [ "$status" -eq 0 ]
  [[ "$output" == *"cannot prove absence"* ]]
  [[ "$output" != *"no passwordless openconnect grant found"* ]]
}

@test "an unrecognised -ll format is inconclusive too" {
  LEGACY_LIST=ok
  LEGACY_RULE=garbage
  vu_tools_resolve
  run vu_legacy_grant_state /usr/sbin/openconnect
  [ "$output" = "unknown" ]
}

@test "an authenticate-required rule is not reported as passwordless" {
  LEGACY_LIST=ok
  LEGACY_RULE=authenticate
  vu_tools_resolve
  run vu_legacy_grant_state /usr/sbin/openconnect
  [ "$output" = "no" ]
}

# --- trusted utility resolution --------------------------------------------

@test "utility trust is chain-wide: a root-owned tool under a writable directory is refused" {
  # The finding this exists for. A file can be root:root 0755 and still be
  # replaceable, because whoever can write the parent can rename the entry.
  local tree="$BATS_TEST_TMPDIR/tree/bin"
  mkdir -p "$tree"
  printf '#!/bin/sh\n' > "$tree/install"; chmod 755 "$tree/install"
  file_owner_uid() { echo 0; }                       # every component root-owned
  file_mode() { case "$1" in *"/tree/bin") echo 777 ;; *) echo 755 ;; esac; }
  _vu_acl_extended() { return 1; }
  run _vu_path_trusted "$tree/install" yes
  [ "$status" -ne 0 ]
  _vu_path_trusted "$tree/install" yes || true
  [[ "$VU_TRUST_REASON" == *"/tree/bin is group- or world-writable"* ]]
}

@test "a user-owned utility is refused, and the reason names the owner" {
  use_real_stat
  local t="$BATS_TEST_TMPDIR/mine"
  printf '#!/bin/sh\n' > "$t"; chmod 755 "$t"
  run _vu_path_trusted "$t" yes
  [ "$status" -ne 0 ]
  _vu_path_trusted "$t" yes || true
  [[ "$VU_TRUST_REASON" == *"owned by uid $(id -u)"* ]]
}

@test "a real system utility passes the walk" {
  use_real_stat
  local p; p="$(command -v install)" || skip "no install(1)"
  run _vu_path_trusted "$p" yes
  [ "$status" -eq 0 ]
}

@test "a root-owned but world-writable directory is refused (the mode branch, on a real path)" {
  use_real_stat
  run _vu_path_trusted /tmp
  [ "$status" -ne 0 ]
  _vu_path_trusted /tmp || true
  [[ "$VU_TRUST_REASON" == *"group- or world-writable"* ]]
}

@test "sudo must be setuid root" {
  # Verified on macOS and Linux: /usr/bin/sudo is -r-s--x--x root. Parsing a mode
  # string cannot see that bit on BSD (stat -f %Lp omits it; it lives in %Mp), so
  # this uses the shell's own -u test.
  local p; p="$(command -v sudo)" || skip "no sudo"
  run _vu_mode_setuid_root "$p"
  [ "$status" -eq 0 ]
  run _vu_mode_setuid_root "$(command -v cat)"
  [ "$status" -ne 0 ]
}

@test "resolution collapses a doubled slash from a root-level symlink" {
  # dirname "/var" is "/", so composing "$dir/$target" yields "//private/var",
  # and `cd //private; pwd -P` keeps the doubled slash on macOS. That would leak
  # into every path comparison downstream.
  run _vu_resolve_path /var
  [[ "$output" != //* ]]
}

@test "a symlink loop is refused rather than followed forever" {
  ln -s "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  ln -s "$BATS_TEST_TMPDIR/b" "$BATS_TEST_TMPDIR/a"
  run _vu_resolve_path "$BATS_TEST_TMPDIR/a"
  [ "$status" -ne 0 ]
}

@test "ACL handling is platform-correct, and detects a real ACL" {
  # Two failure modes, opposite directions, and both matter:
  #
  #   too strict - on Linux the ordinary mode bits ARE three base ACL entries, so
  #                plain getfacl prints something for every file. Treating that as
  #                "has an ACL" rejects every stock system utility and makes the
  #                installer unusable. `getfacl -s` is what distinguishes an
  #                extended entry.
  #   too loose  - an ACL that grants write past the mode bits is exactly what
  #                this check exists to catch, so it has to be caught.
  #
  # This asserts both, against the REAL implementation. It previously asserted
  # only the first, against setup's stub, which made it a test that could not
  # fail - proven by breaking the real function and watching it still pass.
  use_real_stat

  local d="$BATS_TEST_TMPDIR/acl"
  mkdir -p "$d"

  # No ACL yet: mode bits alone must not read as one.
  run _vu_acl_extended "$d"
  [ "$status" -ne 0 ]
  # And a real system utility, which is the case that would break the installer.
  run _vu_acl_extended /usr/bin/install
  [ "$status" -ne 0 ]

  if [ "$(uname)" = Darwin ]; then
    # The same idiom helper/t/test_closure.c uses for the §11.5 probe.
    chmod +a# 0 "everyone allow write" "$d" 2>/dev/null || skip "no ACL support on this filesystem"
  else
    command -v setfacl >/dev/null 2>&1 || skip "no setfacl"
    setfacl -m "u:$(id -u):rwx" "$d" 2>/dev/null || skip "no ACL support on this filesystem"
    # The premise, asserted rather than assumed: if `getfacl -s` prints nothing
    # for a directory that demonstrably carries an extended ACL, then the
    # implementation is built on a false premise and must not skip past it.
    [ -n "$(getfacl -s -- "$d" 2>/dev/null)" ]
  fi

  run _vu_acl_extended "$d"
  [ "$status" -eq 0 ]
}

# --- dry run ----------------------------------------------------------------

@test "--dry-run changes nothing and does not claim a verdict" {
  plant_legacy
  run install_helper --dry-run
  [ "$status" -eq 0 ]
  [ ! -e "$TARGET/vpn-up-helper" ]
  [ -f "$SUDOERS/vpn-up" ]
  [[ "$output" == *"not a"*"verdict"* ]]
  run sudo_log
  [[ "$output" != *install* ]]
  [[ "$output" != *" mv "* ]]
  [[ "$output" != *" rm "* ]]
}

# --- uninstall --------------------------------------------------------------

@test "uninstall removes the rule before the binaries" {
  NOPASSWD_HELPER=0
  install_helper --yes --passwordless >/dev/null
  : > "$LOG"
  NOPASSWD_HELPER=1                     # the rule is gone, so the probe fails
  run uninstall_helper
  [ "$status" -eq 0 ]
  [ ! -e "$TARGET/vpn-up-helper" ]
  local order
  order="$(grep -nE "rm -f -- $SUDOERS/vpn-up-$(id -u)|rm -f -- $TARGET/vpn-up-helper" "$LOG" | head -2)"
  [[ "$(printf '%s' "$order" | head -1)" == *"$SUDOERS/vpn-up-$(id -u)"* ]]
}

@test "uninstall keeps the binaries when passwordless reachability cannot be disproved" {
  NOPASSWD_HELPER=0
  install_helper --yes --passwordless >/dev/null
  NOPASSWD_HELPER=0                     # some OTHER rule still names the helper
  run uninstall_helper
  [ "$status" -ne 0 ]
  [ -x "$TARGET/vpn-up-helper" ]
  [[ "$output" == *"still reachable as root without a password"* ]]
}

@test "uninstall will not delete a sudoers file it did not write" {
  local rule="$SUDOERS/vpn-up-$(id -u)"
  printf '#%s ALL=(root) NOPASSWD: /usr/bin/id\n' "$(id -u)" > "$rule"
  install_helper --yes >/dev/null
  run uninstall_helper
  [ -f "$rule" ]
  [ "$(cat "$rule")" = "#$(id -u) ALL=(root) NOPASSWD: /usr/bin/id" ]
}

@test "--purge touches only the invoking uid's approvals" {
  install_helper --yes >/dev/null
  local reg="$SANDBOX/etc/vpn-up"
  mkdir -p "$reg/approvals/$(id -u)" "$reg/approvals/4242"
  : > "$reg/approvals/$(id -u)/profile-a"
  : > "$reg/approvals/4242/profile-b"
  # Point the recorded roots at the sandbox, the way the installed binary would.
  _vu_admin_root() { case "$2" in registry) printf '%s' "$reg" ;; state) printf '%s' "$SANDBOX/run/vpn-up" ;; esac; }
  run uninstall_helper --purge
  [ "$status" -eq 0 ]
  [ ! -e "$reg/approvals/$(id -u)" ]
  [ -f "$reg/approvals/4242/profile-b" ]
}


# --- the login-service warning ---------------------------------------------

@test "retiring the legacy rule warns when a login service would break" {
  # The first version of this check guessed the launchd label and guessed wrong,
  # so it could never have fired on macOS. These are service.sh's own names.
  plant_legacy
  if [ "$(uname)" = Darwin ]; then
    export VPN_UP_LAUNCH_AGENT_DIR="$BATS_TEST_TMPDIR/agents"
    mkdir -p "$VPN_UP_LAUNCH_AGENT_DIR"
    : > "$VPN_UP_LAUNCH_AGENT_DIR/com.sorinipate.vpn-up.work.plist"
  else
    export VPN_UP_SYSTEMD_DIR="$BATS_TEST_TMPDIR/units"
    mkdir -p "$VPN_UP_SYSTEMD_DIR"
    : > "$VPN_UP_SYSTEMD_DIR/vpn-up-work.service"
  fi
  run install_helper --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"login service is installed"* ]]
  [[ "$output" == *"unattended reconnects"* ]]
}

@test "no login service, no warning" {
  plant_legacy
  export VPN_UP_LAUNCH_AGENT_DIR="$BATS_TEST_TMPDIR/empty"
  export VPN_UP_SYSTEMD_DIR="$BATS_TEST_TMPDIR/empty"
  mkdir -p "$BATS_TEST_TMPDIR/empty"
  run install_helper --yes
  [ "$status" -eq 0 ]
  [[ "$output" != *"login service is installed"* ]]
}

# --- the target chain -------------------------------------------------------

@test "a user-writable ancestor refuses the install and is never install -d'd" {
  # The amendment that protects /usr/local and /opt: `install -d -o 0 -g 0 -m 0755`
  # applied to an existing directory REWRITES its owner and mode. An installer may
  # verify an ancestor; it may not normalise one to make its own install fit.
  mkdir -p "$SANDBOX/opt"
  # Matched on the suffix, not on "$SANDBOX/opt": the walk resolves symlinks
  # first, and on macOS BATS_TEST_TMPDIR lives under /var -> /private/var, so a
  # stub keyed on the unresolved path never fires. (Found by this test failing.)
  file_mode() { case "$1" in */sandbox/opt) echo 777 ;; *) echo 755 ;; esac; }
  run install_helper --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"/opt is group- or world-writable"* ]]
  [ ! -e "$TARGET/vpn-up-helper" ]
  run sudo_log
  [[ "$output" != *"install -d"* ]]
}

@test "a missing ancestor is created, not refused" {
  # Creating a directory that does not exist touches nothing pre-existing, so it
  # is allowed where modifying one is not.
  run install_helper --yes
  [ "$status" -eq 0 ]
  [ -d "$SANDBOX/opt/vpn-up/bin" ]
  run sudo_log
  [[ "$output" == *"install -d -o 0 -g 0 -m 0755 -- $SANDBOX/opt"* ]]
}

@test "an existing vpn-up directory with foreign binaries and no manifest is refused" {
  mkdir -p "$TARGET"
  printf '#!/bin/sh\n' > "$TARGET/vpn-up-helper"
  chmod +x "$TARGET/vpn-up-helper"
  run install_helper --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"no VPN Up manifest"* ]]
}

# --- legacy matching, exactly ------------------------------------------------

@test "each of the three documented legacy rules is recognised" {
  for p in /opt/homebrew/bin/openconnect /opt/homebrew/sbin/openconnect /usr/sbin/openconnect; do
    run _vu_is_legacy_rule_file "$(id -un) ALL=(root) NOPASSWD: $p"
    [ "$status" -eq 0 ]
    # …and with the trailing newline `echo | tee` actually leaves behind.
    run _vu_is_legacy_rule_file "$(printf '%s ALL=(root) NOPASSWD: %s\n' "$(id -un)" "$p")"
    [ "$status" -eq 0 ]
  done
}

@test "a legacy rule for a different user is not ours to remove" {
  run _vu_is_legacy_rule_file "somebodyelse ALL=(root) NOPASSWD: /usr/sbin/openconnect"
  [ "$status" -ne 0 ]
}

@test "anything beyond the exact line is refused: comments, extra rules, Defaults, other paths" {
  local u; u="$(id -un)"
  local bad_files=(
    "$u ALL=(root) NOPASSWD: /usr/sbin/openconnect
# added by hand"
    "# a comment
$u ALL=(root) NOPASSWD: /usr/sbin/openconnect"
    "$u ALL=(root) NOPASSWD: /usr/sbin/openconnect
$u ALL=(root) NOPASSWD: /usr/bin/id"
    "Defaults:$u !authenticate
$u ALL=(root) NOPASSWD: /usr/sbin/openconnect"
    "$u ALL=(root) NOPASSWD: /usr/local/bin/openconnect"
    "$u ALL=(root) NOPASSWD: /usr/sbin/openconnect --script /tmp/x"
    "$u ALL=(ALL) NOPASSWD: ALL"
  )
  local f
  for f in "${bad_files[@]}"; do
    run _vu_is_legacy_rule_file "$f"
    [ "$status" -ne 0 ] || {
      echo "wrongly matched: $f" >&2
      return 1
    }
  done
}
