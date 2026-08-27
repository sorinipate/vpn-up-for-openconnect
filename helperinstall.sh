# helperinstall.sh - install and uninstall the privileged helper (design §14).
#
# This is the step that turns the helper from code into a boundary. Everything
# else in helper/ is inert until both binaries sit on a root-owned path.
#
# TWO THINGS THIS FILE DOES NOT PRETEND (see SECURITY.md, "install-time trust"):
#
#   1. The runtime boundary defends against any process running as you AFTER
#      installation. Installation itself does not: the binaries are compiled in
#      a tree you can write, so a process running as you during the ceremony
#      could substitute what root then installs. Provenance that root could
#      verify independently needs a distribution channel this project does not
#      have yet (§17.6).
#   2. Because of (1), the passwordless sudoers rule is OPT-IN (--passwordless).
#      An install without it still gets the closed argv schema, Model B binding
#      and the closure check, at the cost of one password per connect.
#
# Retiring the legacy `NOPASSWD: openconnect` rule is NOT opt-in, though. Adding
# a hardened boundary while leaving the old arbitrary-root grant in place is
# worse than either alone, because it looks fixed:
#
#   before                    install-helper           + --passwordless
#   NOPASSWD openconnect  ->  no NOPASSWD rule     ->  NOPASSWD vpn-up-helper
#   (arbitrary root)          (interactive sudo)       (helper only, one uid)
#
# Structure: PHASE A decides and can refuse; PHASE B mutates. Nothing is
# installed before every question has an answer, so a "no" at the confirmation
# prompt cannot leave a half-hardened machine behind.
#
# No bash script and no compiler ever runs as root here. Each privileged step
# execs exactly one root-owned utility by absolute path.

# --------------------------------------------------------------------- paths
#
# Functions, not variables, so tests can override them and production has no
# environment-driven redirection of where root writes.
_vu_sudoers_dir()          { printf '%s' "/etc/sudoers.d"; }
_vu_legacy_sudoers_file()  { printf '%s/vpn-up' "$(_vu_sudoers_dir)"; }
_vu_uid_sudoers_file()     { printf '%s/vpn-up-%s' "$(_vu_sudoers_dir)" "$(id -u)"; }
_vu_manifest_file()        { printf '%s/manifest' "$(helper_dir)"; }
_vu_build_dir()            { printf '%s/helper/build' "${PROGRAM_PATH}"; }

_vu_have_toolchain() {
  command -v cc >/dev/null 2>&1 || return 1
  [ "$(uname)" = Darwin ] || return 0
  # A bare `cc` on macOS can be a stub that only prints "xcode-select: note:
  # install requested"; the tools have to actually be selected.
  xcode-select -p >/dev/null 2>&1
}

# Compiled AS YOU, never as root. See the header: a root compile would put CC,
# CPATH, LIBRARY_PATH and compiler spec files inside root's TCB for no gain,
# because the source tree is writable by you either way.
_vu_build_binaries() {
  ( cd "${PROGRAM_PATH}/helper" && make >/dev/null )
}

# The three rules VPN Up's own documentation has ever told people to write. Used
# for exact matching only: anything else in that file is somebody's policy and
# is not ours to rewrite.
_vu_legacy_openconnect_paths() {
  printf '%s\n' \
    /opt/homebrew/bin/openconnect \
    /opt/homebrew/sbin/openconnect \
    /usr/sbin/openconnect
}

# ------------------------------------------------- trusted path resolution
#
# The shell half of §11.1/§11.4. It answers one question: could the invoking
# user influence what gets executed here? Ownership of the file alone does not
# answer it - whoever can write the PARENT can replace the entry - so the walk
# goes all the way to /.
#
# This duplicates vu_path_trusted() in C. Exposing that as a subcommand would
# give one implementation for both, but it would widen a frozen privileged ABI,
# so the duplication is deliberate and the C side stays authoritative for
# anything the binaries themselves check.

# Resolve symlinks, in the leaf and in every parent, without realpath(1) -
# macOS does not ship it. `pwd -P` handles the parents; the loop handles a
# symlinked leaf.
_vu_resolve_path() {
  local p="$1" hops=0 target dir base
  while [ -L "$p" ]; do
    hops=$((hops + 1))
    [ "$hops" -gt 40 ] && return 1          # a symlink loop, not a path
    target="$(readlink "$p")" || return 1
    case "$target" in
      /*) p="$target" ;;
      *)
        # dirname "/var" is "/", so a naive "$dir/$target" yields "//private/var",
        # and `cd //private; pwd -P` keeps the doubled slash on macOS (POSIX
        # leaves a leading "//" implementation-defined). That leaks into every
        # path comparison downstream, so compose it explicitly instead.
        dir="$(dirname "$p")"
        case "$dir" in
          /) p="/$target" ;;
          *) p="$dir/$target" ;;
        esac
        ;;
    esac
  done
  dir="$(dirname "$p")"; base="$(basename "$p")"
  dir="$(cd "$dir" 2>/dev/null && pwd -P)" || return 1
  case "$dir" in //*) dir="${dir#/}" ;; esac
  if [ "$dir" = "/" ]; then printf '%s' "/$base"; else printf '%s' "$dir/$base"; fi
}

# Group or other write bit set? file_mode (logging.sh) prints octal on both
# platforms; 8# makes bash read it as octal rather than decimal.
_vu_mode_shared_write() {
  local mode; mode="$(file_mode "$1")" || return 0    # unreadable: assume the worst
  [ -n "$mode" ] || return 0
  [ "$(( 8#$mode & 8#22 ))" -ne 0 ]
}

# Uses the shell's own -u test rather than parsing a mode string, because BSD
# stat does NOT put the setuid bit where the mode check above reads it: in
# `stat -f`, %Lp is the permission bits and the setuid/setgid/sticky bits are a
# separate field (%Mp). Parsing %Lp therefore reports "not setuid" for
# /usr/bin/sudo on macOS - verified - which would have made this check pass
# nothing while looking like it worked.
_vu_mode_setuid_root() { [ -u "$1" ]; }

# An ACL can grant write where the mode bits say otherwise. What counts as "an
# ACL" differs by platform, and getting it wrong here would reject stock system
# utilities:
#
#   Linux  the ordinary owner/group/other bits ARE three base ACL entries, so
#          getfacl prints something for every file. `getfacl -s` skips files
#          that have only those, which is exactly the distinction needed: output
#          means an extended entry (named user/group, mask) or a default ACL.
#   macOS  `ls -lde` prints numbered ACE lines only when an ACL exists.
#
# Where no tool exists this reports "unchecked" rather than "clean" - the mode
# bit checks still apply, and doctor says what could not be verified.
_vu_acl_extended() {
  local p="$1"
  if [ "$(uname)" = Darwin ]; then
    command -v ls >/dev/null 2>&1 || return 1
    # shellcheck disable=SC2010  # parsing ls's ACE lines, not filenames: `ls -lde`
    # is the only interface macOS offers for reading an ACL, and the numbered
    # "0: user:... allow ..." lines it appends are exactly what is being matched.
    ls -lde "$p" 2>/dev/null | grep -qE '^[[:space:]]*[0-9]+: '
  else
    command -v getfacl >/dev/null 2>&1 || return 1
    getfacl -s -- "$p" 2>/dev/null | grep -q '[^[:space:]]'
  fi
}

VU_TRUST_REASON=""

# The full walk. want_exec=yes additionally requires a regular executable file.
_vu_path_trusted() {
  local p="$1" want_exec="${2:-no}" cur owner
  VU_TRUST_REASON=""

  p="$(_vu_resolve_path "$p")" || { VU_TRUST_REASON="cannot resolve $1"; return 1; }
  if [ ! -e "$p" ]; then VU_TRUST_REASON="$p does not exist"; return 1; fi
  if [ "$want_exec" = yes ] && { [ ! -f "$p" ] || [ ! -x "$p" ]; }; then
    VU_TRUST_REASON="$p is not an executable file"; return 1
  fi

  cur="$p"
  while : ; do
    owner="$(file_owner_uid "$cur")"
    if [ "${owner:-x}" != "0" ]; then
      VU_TRUST_REASON="$cur is owned by uid ${owner:-unknown}, not root"; return 1
    fi
    if _vu_mode_shared_write "$cur"; then
      VU_TRUST_REASON="$cur is group- or world-writable"; return 1
    fi
    if _vu_acl_extended "$cur"; then
      VU_TRUST_REASON="$cur carries an ACL, which can grant write past the mode bits"; return 1
    fi
    [ "$cur" = "/" ] && break
    cur="$(dirname "$cur")"
  done
  return 0
}

# ---------------------------------------------------------- privileged tools
#
# Resolved once, verified to /, then only ever executed by absolute path. A fake
# `sudo` earlier in PATH would otherwise capture the password - and that needs no
# access to this repository, just a line in a shell profile.
VU_SUDO=""; VU_INSTALL=""; VU_VISUDO=""; VU_MV=""; VU_CAT=""; VU_RM=""; VU_RMDIR=""

_vu_resolve_tool() {
  local name="$1" p
  p="$(command -v "$name" 2>/dev/null)" || { print_danger "Cannot find '%s'.\n" "$name"; return 1; }
  if ! _vu_path_trusted "$p" yes; then
    print_danger "Refusing to run '%s' through sudo: %s\n" "$name" "$VU_TRUST_REASON"
    return 1
  fi
  _vu_resolve_path "$p"
}

vu_tools_resolve() {
  VU_SUDO="$(_vu_resolve_tool sudo)"       || return 1
  if ! _vu_mode_setuid_root "$VU_SUDO"; then
    print_danger "%s is not setuid root; refusing to use it.\n" "$VU_SUDO"
    return 1
  fi
  VU_INSTALL="$(_vu_resolve_tool install)" || return 1
  VU_VISUDO="$(_vu_resolve_tool visudo)"   || return 1
  VU_MV="$(_vu_resolve_tool mv)"           || return 1
  VU_CAT="$(_vu_resolve_tool cat)"         || return 1
  VU_RM="$(_vu_resolve_tool rm)"           || return 1
  VU_RMDIR="$(_vu_resolve_tool rmdir)"     || return 1
  return 0
}

# The single privileged call site. Overridden by the test suite.
vu_sudo() { "$VU_SUDO" "$@"; }

# "Can this run with NO authentication?" - which is NOT what `sudo -n` answers.
#
# sudo caches a successful authentication, and this installer guarantees a warm
# cache: Phase A reads a root-only file and Phase B runs many privileged steps.
# A plain `sudo -n` afterwards would report "passwordless" for anything the user
# is merely allowed to run, so a post-install check could roll back a good rule,
# and uninstall could refuse to remove its own binaries after using sudo to
# delete its own rule.
#
# `-k` with a command makes sudo ignore the cached credentials (and not update
# them), which turns this into a question about policy. It does not invalidate
# the timestamp, so the installer's own later sudo calls do not re-prompt.
vu_sudo_nopasswd() { vu_sudo -k -n "$@"; }

# ------------------------------------------------------------------- probes

# Ours: root-owned, on a trusted path, so executing them to find out is safe.
# `version` sits above the root gate on purpose - sudo either authorizes the
# command or it does not, and version cannot fail on its own, so a non-zero exit
# means sudo refused.
vu_helper_passwordless() { vu_sudo_nopasswd "$(helper_bin)" version >/dev/null 2>&1; }
vu_admin_passwordless()  { vu_sudo_nopasswd "$(admin_bin)"  version >/dev/null 2>&1; }

# Theirs: openconnect may be user-writable, and executing it to discover whether
# it can be executed as root would run attacker-controlled code as root to
# answer the question. Policy listing only.
#
# Prints one of: yes | no | unknown. "unknown" is a real answer: `sudo -l` can
# itself require a password (listpw), which is indistinguishable from "not
# permitted" by exit status, and the verbose format is version-dependent.
vu_legacy_grant_state() {
  local path="$1" out
  if ! vu_sudo -k -n -l >/dev/null 2>&1; then
    printf 'unknown'; return 0
  fi
  if ! out="$(vu_sudo -k -n -ll "$path" 2>/dev/null)"; then
    printf 'no'; return 0
  fi
  # NOPASSWD compiles to !authenticate in the verbose listing. If the format is
  # not what we expect, say unknown rather than guessing.
  case "$out" in
    *'!authenticate'*) printf 'yes' ;;
    *authenticate*)    printf 'no' ;;
    *)                 printf 'unknown' ;;
  esac
}

# Every openconnect a documented rule could name, plus whatever is on PATH.
vu_report_legacy_grants() {
  local p state found=0 unknown=0 candidates
  candidates="$(_vu_legacy_openconnect_paths)"
  if p="$(command -v openconnect 2>/dev/null)"; then
    candidates="$candidates
$p"
  fi
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    state="$(vu_legacy_grant_state "$p")"
    case "$state" in
      yes)     print_danger "  [!!] %s is reachable as root WITHOUT a password\n" "$p"; found=1 ;;
      unknown) unknown=1 ;;
    esac
  done <<EOF
$(printf '%s\n' "$candidates" | sort -u)
EOF
  if [ "$found" = 1 ]; then
    print_warning "  Remove those rules by hand: they grant arbitrary root (see SECURITY.md).\n"
    return 1
  fi
  if [ "$unknown" = 1 ]; then
    print_warning "  [..] cannot prove absence of a legacy passwordless grant (sudo would not list without authenticating)\n"
    return 0
  fi
  printf "  [OK] no passwordless openconnect grant found\n"
  return 0
}

# ------------------------------------------------------------------ sudoers
#
# The rule names ONLY the helper, and names the user numerically. sudoers(5):
# "#user-ID" is a valid User, and the pound sign is not a comment when it occurs
# in a user-name context followed by digits. That removes username quoting from
# the problem entirely, and matches a registry already keyed by SUDO_UID.
_vu_helper_rule_line() { printf '#%s ALL=(root) NOPASSWD: %s\n' "$(id -u)" "$(helper_bin)"; }

# Read a root-only file exactly, trailing newlines included. Command
# substitution strips them, so a sentinel goes on the end and comes back off.
# Returns non-zero when the file does not exist or cannot be read, which doubles
# as the existence check: /etc/sudoers.d is 0750 root and its files are 0440, so
# an unprivileged [ -e ] cannot answer the question, and `sudo test` would mean
# putting another utility through the trust walk for nothing.
#
# The sentinel carries cat's exit status out of the command substitution, which
# otherwise reports printf's, and preserves trailing newlines that $() strips -
# both matter, because the legacy-rule match is byte-exact.
_vu_read_root_file() {
  local out st
  out="$(vu_sudo "$VU_CAT" -- "$1" 2>/dev/null; printf 'X%s' "$?")" || return 1
  st="${out##*X}"
  out="${out%X*}"
  [ "$st" = 0 ] || return 1
  printf '%s' "$out"
}

# Is this file byte-for-byte one of the rules VPN Up's docs produced?
_vu_is_legacy_rule_file() {
  local content="$1" user expected p
  user="$(id -un)"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    expected="$user ALL=(root) NOPASSWD: $p"
    [ "$content" = "$expected" ] && return 0
    [ "$content" = "$expected
" ] && return 0
  done <<EOF
$(_vu_legacy_openconnect_paths)
EOF
  return 1
}

_vu_is_our_helper_rule_file() {
  local content="$1" expected
  expected="$(_vu_helper_rule_line)"          # already ends in \n
  [ "$content" = "$expected" ] && return 0
  [ "$content" = "${expected%
}" ] && return 0
  return 1
}

# Stage inert, validate, then activate.
#
# The staged name begins with a dot: sudo skips any filename containing one when
# processing an @includedir, so the file has no effect while it exists. visudo
# runs BEFORE the move, never after, and the move is a rename within one
# directory, so activation is atomic.
_vu_activate_helper_rule() {
  local final staged tmp
  final="$(_vu_uid_sudoers_file)"
  staged="$(_vu_sudoers_dir)/.$(basename "$final").new"
  tmp="$(mktemp "${TMPDIR:-/tmp}/vpn-up-sudoers.XXXXXX")" || return 1

  _vu_helper_rule_line > "$tmp"
  if ! vu_sudo "$VU_INSTALL" -o 0 -g 0 -m 0440 -- "$tmp" "$staged"; then
    rm -f "$tmp"; print_danger "Could not stage %s\n" "$staged"; return 1
  fi
  rm -f "$tmp"

  if ! vu_sudo "$VU_VISUDO" -cf "$staged" >/dev/null; then
    print_danger "visudo rejected the generated rule; nothing was activated.\n"
    vu_sudo "$VU_RM" -f -- "$staged"
    return 1
  fi
  if ! vu_sudo "$VU_MV" -f -- "$staged" "$final"; then
    print_danger "Could not activate %s\n" "$final"
    vu_sudo "$VU_RM" -f -- "$staged"
    return 1
  fi
  print_success "Wrote %s (helper only).\n" "$final"
  return 0
}

# ------------------------------------------------------------------- pieces

_vu_sha256() {
  local f="$1"
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 -- "$f" | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$f" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -- "$f" | sed 's/.*= //'
  else return 1; fi
}

# Ask the binary where its roots are instead of restating compile-time pins in
# shell. `vpn-up-admin version` prints them, and a duplicated constant here would
# be a constant that can drift.
_vu_admin_root() {   # _vu_admin_root <bin> registry|state
  local bin="$1" which="$2"
  "$bin" version 2>/dev/null | sed -n "s/^  ${which} root *//p" | head -1
}

# Which directories in the install path are VPN Up's own? Only those may be
# created, and only those may be removed on uninstall. Everything above is
# somebody else's - verified, never modified.
_vu_owned_dirs() {
  local dir; dir="$(helper_dir)"
  case "$dir" in
    */vpn-up|*/vpn-up/*) : ;;
    *) printf '%s\n' "$dir"; return 0 ;;
  esac
  local cur="$dir" out=""
  while : ; do
    out="$cur
$out"
    case "$(basename "$cur")" in vpn-up) break ;; esac
    cur="$(dirname "$cur")"
    [ "$cur" = "/" ] && break
  done
  printf '%s' "$out" | grep -v '^$'
}

_vu_is_owned_dir() {
  local want="$1" d
  while IFS= read -r d; do [ "$d" = "$want" ] && return 0; done <<EOF
$(_vu_owned_dirs)
EOF
  return 1
}

# Ancestors: verify, never modify. Missing components are created (which changes
# nothing pre-existing); an existing one that fails the walk is a refusal, not
# something to chmod into shape.
#
# Measured rather than assumed, because the whole rule rests on it: `install -d
# -m 0755` on a directory that is ALREADY mode 700 leaves it 755. So running it
# over the target chain would rewrite an administrator's /usr/local or /opt to
# make our install fit - and can LOOSEN a deliberately tight mode, which is the
# opposite of what an installer for a privilege boundary should be capable of.
VU_DIRS_TO_CREATE=""
_vu_plan_target_chain() {
  local dir cur rest comp
  dir="$(helper_dir)"
  VU_DIRS_TO_CREATE=""
  cur=""
  rest="${dir#/}"
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"
    if [ "$comp" = "$rest" ]; then rest=""; else rest="${rest#*/}"; fi
    cur="$cur/$comp"
    if [ -e "$cur" ]; then
      if ! _vu_path_trusted "$cur"; then
        print_danger "Install path refused: %s\n" "$VU_TRUST_REASON"
        print_warning "Helper mode needs every directory above the binaries to be outside your write control.\n"
        return 1
      fi
      if _vu_is_owned_dir "$cur" && ! _vu_dir_is_reusable "$cur"; then
        return 1
      fi
    else
      if ! _vu_is_owned_dir "$cur"; then
        # A missing ancestor is fine to create - nothing existing is touched -
        # but say so, because creating /usr/local/libexec is a visible act.
        print_warning "Will create %s (root-owned, 0755).\n" "$cur"
      fi
      VU_DIRS_TO_CREATE="$VU_DIRS_TO_CREATE$cur
"
    fi
  done
  return 0
}

# An existing VPN Up directory is reused only if it is recognisably ours: our
# manifest, or nothing of ours in it yet. Foreign binaries sitting at that path
# mean something else owns it, and this installer does not overwrite that.
_vu_dir_is_reusable() {
  local d="$1"
  [ "$d" = "$(helper_dir)" ] || return 0
  [ -f "$(_vu_manifest_file)" ] && return 0
  if [ -e "$d/vpn-up-helper" ] || [ -e "$d/vpn-up-admin" ]; then
    print_danger "%s already holds vpn-up binaries but no VPN Up manifest.\n" "$d"
    print_warning "Refusing to overwrite an installation this program did not create.\n"
    return 1
  fi
  return 0
}

# Stage, prove it runs, then rename. An interrupted upgrade must not leave a
# truncated executable at a path a NOPASSWD rule may already name.
_vu_install_binary() {
  local src="$1" name="$2" dir final staged
  dir="$(helper_dir)"; final="$dir/$name"; staged="$dir/.$name.new"
  vu_sudo "$VU_INSTALL" -o 0 -g 0 -m 0755 -- "$src" "$staged" || return 1
  # Run it as YOURSELF: the staged file is 0755, so proving it is a working
  # executable needs no privilege, and a root exec that buys nothing is a root
  # exec that should not happen.
  if ! "$staged" version >/dev/null 2>&1; then
    print_danger "The staged %s does not run; nothing was replaced.\n" "$name"
    vu_sudo "$VU_RM" -f -- "$staged"
    return 1
  fi
  vu_sudo "$VU_MV" -f -- "$staged" "$final" || return 1
  return 0
}

# Hashes of the INSTALLED files, not of helper/build - the installed copies are
# root-owned and outside the same-UID window, so the manifest records what root
# actually installed rather than what a build directory held earlier.
#
# Fixed key=value data. Never sourced; no source-tree path in it (paths carry
# whitespace and control bytes for no benefit).
_vu_write_manifest() {
  local abi="$1" tmp hsum asum
  hsum="$(_vu_sha256 "$(helper_bin)")" || { print_warning "No sha256 tool; manifest will omit hashes.\n"; hsum="unknown"; }
  asum="$(_vu_sha256 "$(admin_bin)")"  || asum="unknown"
  tmp="$(mktemp "${TMPDIR:-/tmp}/vpn-up-manifest.XXXXXX")" || return 1
  {
    printf 'manifest-version=1\n'
    printf 'policy-abi=%s\n' "$abi"
    printf 'helper-sha256=%s\n' "$hsum"
    printf 'admin-sha256=%s\n' "$asum"
  } > "$tmp"
  vu_sudo "$VU_INSTALL" -o 0 -g 0 -m 0644 -- "$tmp" "$(_vu_manifest_file)" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  return 0
}

_vu_manifest_value() {
  local key="$1" f; f="$(_vu_manifest_file)"
  [ -r "$f" ] || return 1
  sed -n "s/^${key}=//p" "$f" | head -1
}

_vu_policy_abi() { "$1" version 2>/dev/null | sed -n 's/.*policy engine \([0-9]*\)).*/\1/p' | head -1; }

# ------------------------------------------------------------------ install

_vu_install_usage() {
  cat >&2 <<EOF
Usage: ${PROGRAM_NAME} install-helper [--passwordless] [--yes] [--dry-run]

  --passwordless   also authorize vpn-up-helper for passwordless sudo, so a
                   login service can reconnect unattended. Read SECURITY.md
                   first: it makes a locally built binary root-reachable with
                   no password.
  --yes            do not prompt (for scripted use)
  --dry-run        show what would change; make no changes
EOF
}

install_helper() {
  local want_passwordless=0 assume_yes=0 dry_run=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --passwordless) want_passwordless=1 ;;
      --yes|-y)       assume_yes=1 ;;
      --dry-run)      dry_run=1 ;;
      -h|--help)      _vu_install_usage; return 0 ;;
      *)              print_danger "Unknown option '%s'.\n" "$1"; _vu_install_usage; return 2 ;;
    esac
    shift
  done

  # ============================================================ PHASE A
  #
  # Decide everything here. Nothing below this line changes the system.

  if [ "$(id -u)" = 0 ]; then
    print_danger "Run this as yourself, not with sudo.\n"
    print_warning "It elevates one step at a time and will prompt for your password. Running the\n"
    print_warning "whole installer as root would put a user-writable bash script inside root's TCB.\n"
    return 1
  fi

  if ! _vu_have_toolchain; then
    print_danger "Helper mode needs a C toolchain to build vpn-up-helper.\n"
    if [ "$(uname)" = Darwin ]; then
      print_warning "Install the Xcode command line tools: xcode-select --install\n"
    else
      print_warning "Install a compiler, e.g. apt-get install build-essential\n"
    fi
    print_warning "See PRIVILEGED-HELPER-DESIGN.md §17.2 for why the binaries are compiled here.\n"
    return 1
  fi

  vu_tools_resolve || return 1

  # Built AS YOU. A root compile would drag CC, CPATH, LIBRARY_PATH and compiler
  # spec files into root's TCB for nothing: the source tree is writable by you
  # either way, which is the assumption stated at the top of this file.
  printf "Building the helper binaries (as %s)...\n" "$(id -un)"
  if ! _vu_build_binaries; then
    print_danger "Build failed; nothing was installed.\n"
    return 1
  fi
  local built_helper built_admin
  built_helper="$(_vu_build_dir)/vpn-up-helper"
  built_admin="$(_vu_build_dir)/vpn-up-admin"
  if [ ! -x "$built_helper" ] || [ ! -x "$built_admin" ]; then
    print_danger "Build produced no binaries; nothing was installed.\n"
    return 1
  fi

  # The closure gate. On macOS this is where the install stops today: the Mach-O
  # library closure is unimplemented, so verify-closure refuses (§11.7) rather
  # than installing a boundary nobody has verified.
  printf "\nChecking this machine's OpenConnect execution closure...\n"
  # Status captured BEFORE the indenting pipe: a pipeline reports the exit status
  # of its LAST command, so `verify-closure | sed` would have reported sed's - it
  # always succeeds - and this gate would have passed everything. That is the gate
  # that makes macOS fail closed, so it silently mattered a great deal.
  local closure_out closure_rc=0
  closure_out="$("$built_admin" verify-closure 2>&1)" || closure_rc=$?
  printf '%s\n' "$closure_out" | sed 's/^/  /'
  if [ "$closure_rc" -ne 0 ]; then
    print_danger "\nThis machine cannot run helper mode: the OpenConnect execution closure failed.\n"
    print_warning "Helper mode needs a root-owned OpenConnect whose whole closure is outside your\n"
    print_warning "write control. Install it from a package manager that owns its prefix as root\n"
    print_warning "(a distro package on Linux, MacPorts on macOS); Homebrew cannot be used for\n"
    print_warning "helper mode. Prompt mode keeps working either way. See §11.6.\n"
    return 1
  fi

  _vu_plan_target_chain || return 1

  # Legacy state, and consent for retiring it. Reading the file needs root; it is
  # the only privileged step in Phase A, and it is a read.
  local legacy_file legacy_content legacy_state="absent"
  legacy_file="$(_vu_legacy_sudoers_file)"
  if [ "$dry_run" = 1 ]; then
    legacy_state="unknown"          # a dry run makes no privileged reads
  elif legacy_content="$(_vu_read_root_file "$legacy_file")"; then
    if _vu_is_legacy_rule_file "$legacy_content"; then
      legacy_state="ours"
    else
      legacy_state="foreign"
    fi
  fi

  if [ "$legacy_state" = foreign ]; then
    print_danger "\n%s exists but is not a rule VPN Up wrote.\n" "$legacy_file"
    printf '%s\n' "$legacy_content" | sed 's/^/  | /'
    print_warning "Refusing to touch it, and refusing to install a boundary while an unknown\n"
    print_warning "passwordless rule may still grant arbitrary root. Review that file, remove the\n"
    print_warning "openconnect grant by hand, then run this again.\n"
    return 1
  fi

  if [ "$legacy_state" = ours ]; then
    printf "\n"
    print_warning "Found VPN Up's legacy passwordless rule:\n"
    printf '  | %s\n' "$legacy_content"
    print_warning "That rule grants arbitrary root, so it is removed as part of this install.\n"
    if _vu_any_service_installed; then
      print_warning "A login service is installed. Removing this rule stops unattended reconnects\n"
      print_warning "until you run 'install-helper --passwordless' and approve the profile.\n"
    fi
    if [ "$assume_yes" != 1 ] && [ "$dry_run" != 1 ]; then
      local reply=""
      read -r -p "Remove the legacy rule and continue? [y/N]: " reply
      case "$reply" in
        [yY]*) : ;;
        *) print_warning "Nothing was changed.\n"; return 1 ;;
      esac
    fi
  fi

  # Current passwordless state for this uid, so Phase B knows whether it is
  # creating a rule, preserving one, or leaving a foreign one alone.
  # --passwordless means "enable it if it is not already enabled" - never "this
  # run turns it off", which would break a login service on an ordinary upgrade.
  local uid_file uid_state="absent" uid_content
  uid_file="$(_vu_uid_sudoers_file)"
  if [ "$dry_run" = 1 ]; then
    uid_state="unknown"
  elif uid_content="$(_vu_read_root_file "$uid_file")"; then
    if _vu_is_our_helper_rule_file "$uid_content"; then uid_state="ours"; else uid_state="foreign"; fi
  fi
  if [ "$uid_state" = foreign ]; then
    print_danger "\n%s exists and is not the rule this installer writes.\n" "$uid_file"
    print_warning "Leaving it alone. Review it by hand; passwordless state is unchanged.\n"
  fi

  if [ "$dry_run" = 1 ]; then
    printf "\nDry run - the following would change:\n"
    printf '%s' "$VU_DIRS_TO_CREATE" | sed -n 's/^\(..*\)$/  create directory \1 (root, 0755)/p'
    printf "  install %s -> %s\n" "$built_helper" "$(helper_bin)"
    printf "  install %s -> %s\n" "$built_admin"  "$(admin_bin)"
    printf "  write   %s\n" "$(_vu_manifest_file)"
    printf "  retire  %s (if it holds VPN Up's legacy rule)\n" "$legacy_file"
    if [ "$want_passwordless" = 1 ]; then
      printf "  write   %s\n" "$uid_file"
      printf '          %s' "$(_vu_helper_rule_line)"
    else
      printf "  no passwordless rule (pass --passwordless to authorize one)\n"
    fi
    print_warning "\nRoot-only state was not read, so the sudoers rows above are marked unknown\n"
    print_warning "rather than checked. A dry run is a preview of intended changes, not a\n"
    print_warning "security-readiness verdict - run 'doctor' for that.\n"
    return 0
  fi

  # ============================================================ PHASE B
  #
  # From here on the system changes.

  printf "\n"
  local d
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    vu_sudo "$VU_INSTALL" -d -o 0 -g 0 -m 0755 -- "$d" || {
      print_danger "Could not create %s\n" "$d"; return 1; }
  done <<EOF
$VU_DIRS_TO_CREATE
EOF

  _vu_install_binary "$built_helper" vpn-up-helper || return 1
  _vu_install_binary "$built_admin"  vpn-up-admin  || return 1
  print_success "Installed vpn-up-helper and vpn-up-admin in %s.\n" "$(helper_dir)"

  # ABI drift: approval records carry a version, and a record from another ABI is
  # refused at connect time. Better to hear that now than on the next connect.
  local old_abi new_abi
  old_abi="$(_vu_manifest_value policy-abi || true)"
  new_abi="$(_vu_policy_abi "$(admin_bin)")"
  if [ -n "${old_abi:-}" ] && [ -n "$new_abi" ] && [ "$old_abi" != "$new_abi" ]; then
    print_warning "Policy ABI changed (%s -> %s): existing approvals will be refused.\n" "$old_abi" "$new_abi"
    print_warning "Re-approve each profile with '%s approve-profile'.\n" "${PROGRAM_NAME}"
  fi
  _vu_write_manifest "${new_abi:-unknown}" || print_warning "Could not write the manifest.\n"

  # Verified by RUNNING the installed binary, not by re-checking in shell. `list`
  # is below the root gate, so it performs the §11.1 self-path walk on the real
  # path as root; `version` is exempt from that check by design and would prove
  # nothing about the path.
  if ! vu_sudo "$(admin_bin)" list >/dev/null; then
    print_danger "The installed vpn-up-admin refused to run from %s.\n" "$(helper_dir)"
    print_warning "That is the §11.1 self-check: the install path is not outside your write control.\n"
    return 1
  fi
  print_success "The installed binaries accept their own install path.\n"

  if [ "$legacy_state" = ours ]; then
    if vu_sudo "$VU_RM" -f -- "$legacy_file"; then
      print_success "Retired the legacy passwordless openconnect rule (%s).\n" "$legacy_file"
    else
      print_danger "Could not remove %s; it still grants arbitrary root.\n" "$legacy_file"
      return 1
    fi
  fi

  local created_rule=0
  if [ "$want_passwordless" = 1 ]; then
    case "$uid_state" in
      ours)
        print_success "Passwordless rule already present at %s; keeping it.\n" "$uid_file"
        vu_sudo "$VU_VISUDO" -cf "$uid_file" >/dev/null || {
          print_danger "The existing rule no longer validates.\n"; return 1; }
        ;;
      foreign)
        print_warning "Not touching %s; passwordless mode was not enabled.\n" "$uid_file"
        ;;
      *)
        _vu_activate_helper_rule || return 1
        created_rule=1
        ;;
    esac
  else
    printf "\nNo passwordless rule was written. Connecting will ask for your password.\n"
    printf "Run '%s install-helper --passwordless' if you need unattended reconnects.\n" "${PROGRAM_NAME}"
  fi

  # Post-checks against the EFFECTIVE policy: our file validating says nothing
  # about what sudo will do, since another sudoers file can broaden or override
  # it. Cache-independent, or this would just read back the password typed above.
  printf "\n"
  local failed=0
  if [ "$want_passwordless" = 1 ] && [ "$uid_state" != foreign ]; then
    if vu_helper_passwordless; then
      print_success "vpn-up-helper runs without a password (the intended rule).\n"
    else
      print_danger "vpn-up-helper is still not passwordless.\n"
      failed=1
    fi
  fi
  if vu_admin_passwordless; then
    print_danger "vpn-up-admin IS reachable without a password. The approval boundary is broken:\n"
    print_danger "anything holding that grant can approve an endpoint and then connect to it.\n"
    failed=1
  else
    print_success "vpn-up-admin is not reachable without a password.\n"
  fi

  if [ "$failed" = 1 ]; then
    # Asymmetric on purpose: roll back to NO VPN Up passwordless rule, never to
    # the legacy openconnect rule. A later check failing must not undo the one
    # unambiguous improvement this run made.
    if [ "$created_rule" = 1 ]; then
      vu_sudo "$VU_RM" -f -- "$uid_file" && \
        print_warning "Removed the rule this run created (%s).\n" "$uid_file"
    fi
    print_warning "The binaries are installed and interactive helper mode still works.\n"
    print_warning "The legacy rule, if there was one, stays retired.\n"
    return 1
  fi

  printf "\nLegacy grants elsewhere:\n"
  vu_report_legacy_grants || true

  printf "\n"
  print_success "Helper mode is installed. Approve a profile before connecting:\n"
  printf "  %s approve-profile\n" "${PROGRAM_NAME}"
  return 0
}

# Is any login service installed? Retiring the legacy rule breaks unattended
# reconnects, and the person running this deserves to hear that before it
# happens rather than at next login.
# service.sh owns these names and locations; the values below are its variables
# when it has been sourced (production always has) and its defaults otherwise.
# The first version of this guessed the launchd label and guessed wrong, so the
# warning could never have fired on macOS.
_vu_any_service_installed() {
  local dir pattern f
  if [ "$(uname)" = Darwin ]; then
    dir="${LAUNCH_AGENT_DIR:-${VPN_UP_LAUNCH_AGENT_DIR:-$HOME/Library/LaunchAgents}}"
    pattern="${SERVICE_LABEL_PREFIX:-com.sorinipate.vpn-up}.*.plist"
  else
    dir="${SYSTEMD_USER_DIR:-${VPN_UP_SYSTEMD_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}}"
    pattern="vpn-up-*.service"
  fi
  for f in "$dir"/$pattern; do
    [ -e "$f" ] && return 0
  done
  return 1
}

# ---------------------------------------------------------------- uninstall

uninstall_helper() {
  local purge=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --purge)   purge=1 ;;
      -h|--help) printf 'Usage: %s uninstall-helper [--purge]\n' "${PROGRAM_NAME}"; return 0 ;;
      *)         print_danger "Unknown option '%s'.\n" "$1"; return 2 ;;
    esac
    shift
  done

  if [ "$(id -u)" = 0 ]; then
    print_danger "Run this as yourself, not with sudo.\n"
    return 1
  fi
  vu_tools_resolve || return 1

  # Ask the installed binary where its roots are BEFORE removing it. A duplicated
  # constant in shell would be one that can drift from the compile-time pin, and
  # reading it afterwards would read it from a binary that no longer exists.
  local reg_root state_root
  reg_root="$(_vu_admin_root "$(admin_bin)" registry 2>/dev/null || true)"
  state_root="$(_vu_admin_root "$(admin_bin)" state 2>/dev/null || true)"

  # Privilege comes down BEFORE the binaries do. Removing the executable while a
  # grant still names its path would leave a passwordless rule pointing at a path
  # whose lifecycle nobody controls any more.
  local uid_file content
  uid_file="$(_vu_uid_sudoers_file)"
  if content="$(_vu_read_root_file "$uid_file")"; then
    if _vu_is_our_helper_rule_file "$content"; then
      vu_sudo "$VU_RM" -f -- "$uid_file" || { print_danger "Could not remove %s\n" "$uid_file"; return 1; }
      print_success "Removed %s.\n" "$uid_file"
    else
      print_warning "%s is not the rule this installer wrote; leaving it alone.\n" "$uid_file"
    fi
  fi

  # Cache-independent, and this is the clearest case for it: the step above used
  # sudo, so a plain `sudo -n` would succeed on the warm timestamp and an
  # ordinary uninstall would refuse to finish itself.
  if vu_helper_passwordless; then
    print_danger "vpn-up-helper is still reachable as root without a password.\n"
    print_warning "Some other sudoers rule names it. Keeping the binaries: a stale grant pointing\n"
    print_warning "at this constrained helper is safer than one pointing at a path that no longer\n"
    print_warning "exists (anything could later occupy it). Remove that rule, then run this again.\n"
    return 1
  fi

  local f
  for f in "$(helper_bin)" "$(admin_bin)" "$(_vu_manifest_file)"; do
    if [ -e "$f" ]; then
      vu_sudo "$VU_RM" -f -- "$f" && print_success "Removed %s.\n" "$f"
    fi
  done

  # Only VPN Up's own directories, deepest first, and only when empty.
  local dirs d
  dirs="$(_vu_owned_dirs | sed '1!G;h;$!d')"
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    [ -d "$d" ] || continue
    vu_sudo "$VU_RMDIR" -- "$d" 2>/dev/null && print_success "Removed %s.\n" "$d"
  done <<EOF
$dirs
EOF

  if [ "$purge" = 1 ]; then
    # Current uid only. The registry is deliberately multi-user
    # (<root>/approvals/<uid>/<profile>), so removing the whole tree would
    # discard another user's approvals. A machine-wide purge is an
    # administrative act, not this command.
    local uid
    uid="$(id -u)"
    if [ -z "${reg_root:-}" ] || [ -z "${state_root:-}" ]; then
      print_warning "Could not read the registry/state roots from vpn-up-admin; skipping --purge.\n"
      print_warning "Nothing was removed from %s.\n" "${reg_root:-the registry}"
    else
      # Those directories are 0700 root, so there is no unprivileged way to ask
      # whether they exist; rm -rf is silent on a missing path, hence "if it
      # existed" rather than a claim about what was there.
      for d in "$reg_root/approvals/$uid" "$state_root/$uid"; do
        vu_sudo "$VU_RM" -rf -- "$d" && print_success "Purged %s (if it existed).\n" "$d"
      done
      print_warning "Approvals belonging to other users were left alone.\n"
    fi
  fi

  print_success "Helper mode removed. Prompt mode still works.\n"
  return 0
}
