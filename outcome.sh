# outcome.sh - unattended-authentication-attempt rate limiter, and the
# outcome-code plumbing that lets a service supervisor be told "stop" for a
# permanent condition and "restart" for a transient one.
#
# THE CENTRAL DESIGN DECISION: this module gates ADMISSION of an unattended
# attempt. It never classifies what OpenConnect returned, never waits for it,
# and OpenConnect's eventual outcome never changes how much rate-limit budget
# was spent. The outcome codes below exist for diagnostics and supervisor
# instructions ONLY -- outcome_from_run() is never consulted by
# admit_attempt(), and nothing here should ever grow a dependency in that
# direction ("we know this was PREAUTH, so let's back off harder" is exactly
# the mistake this file exists to prevent).
#
# See PRIVILEGED-HELPER-DESIGN.md's rate-limiter security invariants for the
# nine properties admit_attempt() and the locking below exist to hold. The
# ninth (record_attempt_verification, below) is additive, not an amendment to
# the central design decision above: it reads a genuine post-attempt signal
# (helper-mode tunnel-up telemetry, unrelated to OpenConnect's exit code) but
# only ever from OUTSIDE admit_attempt(), strictly after an attempt already
# admitted has finished -- so it still cannot change whether or how long
# admission itself waited, only whether a LATER breaker-expiry quietly
# resumes retrying or escalates to a pause. Never held to touch ST_ATTEMPTS
# or ST_OPEN_UNTIL, which stay exactly as outcome-blind as the original eight
# invariants require.

# ------------------------------------------------------------- outcome codes
readonly VPN_RC_RUN_ENDED=0         # ran; no claim about why it ended
# shellcheck disable=SC2034  # consumed by twophase.sh (connect_via_helper)
readonly VPN_RC_PREAUTH=10          # helper mode: died before a session cookie
# 11 is reserved for a future MFA-specific code. Nothing emits it today:
# password and second-factor rejection share one `openconnect --authenticate`
# invocation with a single rc=1, so there is no seam to tell them apart.
readonly VPN_RC_CONFIG=12           # profile/config cannot run unattended (terminal)
readonly VPN_RC_POLICY=13           # sudo/helper refused before any tunnel (terminal)
readonly VPN_RC_ATTEMPT_FAILED=20   # an attempt returned non-zero; cause unknown
# shellcheck disable=SC2034  # consumed by core.sh (connection_preflight)
readonly VPN_RC_NO_NETWORK=21       # the network/reachability gate said no
# shellcheck disable=SC2034  # consumed by core.sh (start())
readonly VPN_RC_ALREADY_ACTIVE=22   # this profile is already running (transient)
# shellcheck disable=SC2034  # consumed by core.sh (connection_preflight)
readonly VPN_RC_SECRETS_UNAVAILABLE=23 # secrets backend errored, not "not stored" (transient)
readonly VPN_RC_SUPERVISOR_RETRY=75 # "restart me" (EX_TEMPFAIL)

# Maps an outcome code to the one instruction a service supervisor
# understands: 0 means "stop supervising" (launchd's KeepAlive dictionary /
# systemd's Restart=on-failure both honour this), any other value means
# "restart me". Only CONFIG and POLICY are terminal; everything else is a
# condition that can resolve on its own and must keep being retried.
service_exit_code() {
  case "$1" in
    "$VPN_RC_CONFIG"|"$VPN_RC_POLICY") printf '0' ;;
    *) printf '%d' "$VPN_RC_SUPERVISOR_RETRY" ;;
  esac
}

# outcome_from_run <rc> <had_tunnel: 1=ran 0=refused-before-exec>
#
# Diagnostics/supervisor classification only -- see the file header. rc==0 is
# checked first and unconditionally: a clean exit is not evidence of failure,
# and this is what keeps every existing bare-call test (a stub `sudo`
# returning 0) passing unchanged. had_tunnel distinguishes a helper-mode
# refusal (_helper_run_had_tunnel in twophase.sh) from an attempt that ran;
# prompt mode has no such signal and always passes 1.
outcome_from_run() {
  local rc="$1" had_tunnel="${2:-1}"
  if [ "$rc" -eq 0 ]; then printf '%d' "$VPN_RC_RUN_ENDED"; return 0; fi
  if [ "$had_tunnel" = 0 ]; then printf '%d' "$VPN_RC_POLICY"; return 0; fi
  printf '%d' "$VPN_RC_ATTEMPT_FAILED"
}

# ------------------------------------------------------- small field reader
#
# Reads one key=value line from a fixed-format state file. Index-based prefix
# match (not a regex), matching the _kv_lookup idiom already used for the
# secrets vault (encryption.sh) -- the key here is always one of our own
# literal field names, never attacker-influenced, so this is just a plain
# reader, not a parser that needs to defend against the key itself.
#
# ALWAYS returns 0, even when the file doesn't exist or the key is absent --
# a missing file is the routine, expected case for a profile's first-ever
# admission (or lock/state read), not an error, and every call site already
# treats empty output as "not found" via a validating `case`. Making the
# failure exit-status-only (rather than also non-zero) means
# `v="$(_state_field ...)"` can never itself become a failing statement that
# would abort execution under a stricter shell mode somewhere up the call
# chain -- this file must behave the same whether or not `set -e` is active.
_state_field() {
  local key="$1" file="$2"
  [ -r "$file" ] || return 0
  awk -F'=' -v k="$key" 'index($0,k"=")==1{print substr($0,length(k)+2); exit}' "$file"
}

# ------------------------------------------------------------------- locking
#
# mkdir gives atomic, portable mutual exclusion with no flock(1) dependency
# (deliberately: macOS ships no flock(1), and a kernel-backed primitive would
# need two separate implementations for one lock that is not a security
# boundary anyway).
#
# THE LOCK IS MANDATORY, NOT BEST-EFFORT. State corruption may fail open (see
# _state_read below); failure to serialize must never fail open into an
# authentication attempt -- an unlocked TOTP reservation or attempt-ownership
# check would let a second process reach the same conclusion and act on it
# too. So _state_lock never gives up: a service just keeps polling (it was
# already about to wait), and nothing in this file ever proceeds unlocked.
#
# Reclaim triggers ONLY on a demonstrably dead pid, never on age. A lock whose
# owner metadata never appeared is deliberately left stuck rather than
# reclaimed by elapsed time: a merely-stalled (not dead) holder could resume
# and write its own metadata into a *different* lock generation a reclaimer
# had since recreated at the same path, letting two processes believe they
# hold the same lock. There is no pid to test liveness against for that case,
# and guessing "probably dead" from age is exactly the mistake this design
# corrects for attempt ownership (see _attempt_owner_stale below) -- applying
# it here would just relocate the bug. `vpn-up doctor` reports a stuck
# metadata-less lock for manual clearing instead (dependencies.sh).
_VU_LOCK_POLL="${VPN_UP_LOCK_POLL:-0.2}"

# KNOWN, DELIBERATE LIMITATION: lock/owner identity below is `$$`, which in
# bash is the ORIGINAL shell's pid even inside a `( ... ) &` subshell --
# `BASHPID` is what identifies the actual subprocess there. Real `vpn-up`
# invocations are always separate top-level processes (never nested
# subshells of one another calling admit_attempt against the same profile),
# so this is not a correctness gap in production. It does mean a test or any
# other caller that backgrounds admit_attempt/totp_wait_for_fresh_step within
# the SAME shell (rather than a genuinely separate process) can observe
# misleading liveness: the recorded owner remains the live parent pid even
# after the backgrounded subshell has "died". Switching to `BASHPID` would
# need `_state_lock` to stop returning a token via command substitution (a
# subshell of ITS OWN, with the identical problem one level down) and instead
# run inline in the caller's shell -- a real change, not a one-line swap, and
# not made here because the scenario it fixes does not occur in production.

# Reclaim is serialized through a second, much shorter-lived mkdir lock, so at
# most one process is ever mid-reclaim for a given profile at a time -- this
# is what closes the gap between "decide this lock looks stale" and "act on
# that decision", which is not atomic on its own. If .lock.reclaiming is ever
# found stuck (a process dying in the handful of operations between mkdir and
# rmdir), that too is a `doctor`-reported, manually-cleared condition, not
# something the hot path tries to auto-recover -- recovering it automatically
# would need the same reclaim-of-a-reclaimer machinery one level up, which
# relocates the problem rather than closing it.
_state_lock() {
  local f="$1" lockdir="${1}.lock" reclaimdir="${1}.lock.reclaiming"
  local pid dir_warned=0 dir_fail_streak=0
  while :; do
    # The parent directory (${DATA_DIR}/state/) must exist before `mkdir
    # "$lockdir"` can ever succeed. vpn-up.command creates it at startup, but
    # relying on that alone here would make lock acquisition silently depend
    # on a step this function has no way to verify happened. Retried every
    # iteration (not just once before the loop) so a transient condition --
    # a momentarily read-only filesystem, a race with something else
    # removing it -- can self-heal without ever needing this function to
    # give up, which stays true to "never fails open": a service just keeps
    # polling, same as ordinary lock contention.
    #
    # But an infrastructure failure here (permission denied, no space, the
    # path is blocked by a plain file) is NOT the same condition as another
    # process holding the lock, and reproduced directly: left unchecked, the
    # two are indistinguishable from the outside -- both just poll silently
    # forever, with nothing in the log or on an interactive terminal to tell
    # an operator which one they're looking at. This does not change the
    # retry contract (still never gives up, still never proceeds unlocked);
    # it only makes the infrastructure case diagnosable once it's persisted
    # long enough to rule out an ordinary race with directory creation.
    if ! ( umask 077; mkdir -p "$(dirname "$f")" ) 2>/dev/null && [ ! -d "$(dirname "$f")" ]; then
      dir_fail_streak=$((dir_fail_streak + 1))
      if [ "$dir_warned" = 0 ] && [ "$dir_fail_streak" -ge 10 ]; then
        # >&2 is not optional here: _state_lock's entire stdout IS its return
        # value, read by every caller through command substitution
        # (`token="$(_state_lock "$f")"`). print_danger's own _print_color
        # writes to stdout (fd 1) like every other print_* helper in this
        # codebase -- correct for them, since nothing else here treats a
        # function's stdout as a value channel. Left unredirected, this line
        # prepended its own text to the token itself: reproduced directly,
        # the caller received "<warning>\n<real token>" as "the token",
        # which _state_unlock could never match against the lock's actual
        # metadata -- so the one call meant to make this condition
        # diagnosable also silently wedged the lock it was warning about.
        print_danger "Could not create or write the VPN state directory (%s); authentication attempts cannot be tracked until this is fixed (check permissions/disk space). Still retrying.\n" "$(dirname "$f")" >&2
        dir_warned=1
      fi
      sleep "$_VU_LOCK_POLL" 2>/dev/null || sleep 1
      continue
    fi
    dir_fail_streak=0
    if mkdir "$lockdir" 2>/dev/null; then
      local token; token="$$-${RANDOM}-$(date +%s%N 2>/dev/null || date +%s)"
      if {
           printf 'pid=%s\n' "$$"
           printf 'token=%s\n' "$token"
           printf 'created=%s\n' "$(date +%s)"
         } > "${lockdir}/.owner.tmp" 2>/dev/null \
         && mv -f "${lockdir}/.owner.tmp" "${lockdir}/owner" 2>/dev/null; then
        printf '%s' "$token"
        return 0
      fi
      # Could not publish this lock's own ownership metadata (a full disk, a
      # permission surprise) -- reporting success here without checking would
      # leave _state_unlock unable to ever prove ownership (no owner file, or
      # a stale one, to match pid/token against), wedging the lock
      # permanently: no one could unlock it, and it has no metadata for the
      # dead-pid reclaim path below to act on either. Reproduced directly
      # (faulting the write) against the previous unchecked version: it
      # returned 0 with a token, while the lock directory was left with no
      # readable owner file -- exactly the "wedged, no owner metadata"
      # condition this design's own §3.3 says must never auto-clear.
      # We just created this directory ourselves via an uncontested mkdir, so
      # nothing else can be treating it as its lock yet -- safe to remove it
      # and retry from the top rather than leave it stranded.
      rm -rf "$lockdir" 2>/dev/null
      sleep "$_VU_LOCK_POLL" 2>/dev/null || sleep 1
      continue
    fi

    pid="$(_state_field pid "${lockdir}/owner" 2>/dev/null)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      if mkdir "$reclaimdir" 2>/dev/null; then
        { printf 'pid=%s\n' "$$"; printf 'created=%s\n' "$(date +%s)"; } \
          > "${reclaimdir}/owner" 2>/dev/null
        # Re-read: the world may have moved while we were acquiring the
        # meta-lock. Only act if the SAME condition still holds.
        pid="$(_state_field pid "${lockdir}/owner" 2>/dev/null)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
          local uniq; uniq="${f}.lock.reclaimed.$$.${RANDOM}.$(date +%s%N 2>/dev/null || date +%s)"
          mv -f "$lockdir" "$uniq" 2>/dev/null && rm -rf "$uniq" 2>/dev/null
        fi
        rm -rf "$reclaimdir" 2>/dev/null   # not rmdir: it holds an owner file
      fi
      # else: someone else is already reclaiming this round; fall through to
      # the poll below and re-evaluate everything fresh next time around.
    fi
    sleep "$_VU_LOCK_POLL" 2>/dev/null || sleep 1
  done
}

# _state_unlock <file> <token>
#
# Only acts if the metadata still names THIS process's own pid and token.
# This is provably always true when reached: reclaim above fires only for a
# demonstrably dead pid, and while a holder is alive with its metadata
# written -- true for the whole span between _state_lock returning and this
# call -- no other process can be a legitimate reclaimer of it. So the check
# is a correctness assertion, not the load-bearing mechanism; if it ever
# fails, that is a bug in this locking code, and the safe response is to do
# nothing rather than delete a lock we can no longer prove is ours.
_state_unlock() {
  local f="$1" token="$2" lockdir="${1}.lock" pid seen_token
  pid="$(_state_field pid "${lockdir}/owner" 2>/dev/null)"
  seen_token="$(_state_field token "${lockdir}/owner" 2>/dev/null)"
  if [ "$pid" = "$$" ] && [ "$seen_token" = "$token" ]; then
    rm -rf "$lockdir" 2>/dev/null
  fi
}

# ------------------------------------------------------------- state fields
#
# One file per profile: ${DATA_DIR}/state/<slug>.<sha256>.state
# (attempt_state_file(), logging.sh). Three genuinely separate concerns live
# in it -- the attempt-rate history, the TOTP step reservation, and the
# in-progress owner marker -- and each has its own named operation below;
# there is deliberately no generic "clear everything" function.
#
# Never sourced. Read into ST_* shell variables by _state_read, which treats
# a non-numeric or missing field as its safe default (fail OPEN on field
# corruption) -- a corrupt state file must never block a connection. This is
# distinct from lock *acquisition* failure above, which never fails open.
#
# Every existing call site already holds _state_lock's lock when it calls
# this, so when a value needs correcting (the far-future clamp below), this
# persists the corrected value back to disk once, in the same transaction,
# rather than only adjusting the in-memory copy. An in-memory-only clamp is a
# bug, not a simplification: `now + 3600` is recomputed relative to a NEW
# `now` on every subsequent read, so the on-disk poison value would make the
# breaker look freshly-opened forever, silently turning "at most one hour"
# into "indefinitely" -- confirmed by reproduction, not merely reasoned about.
_state_read() {
  # $2 (expected_profile) is the caller's OWN already-known profile name --
  # deliberately not read back from the file's own profile= field, which is
  # same-UID-writable and not identity (see _state_persist and logging.sh's
  # attempt_state_file: the FILENAME's digest is what actually prevents
  # collision). Using the on-disk field to decide whether the clamp below may
  # be persisted meant a missing/corrupt profile= field silently disabled the
  # write-back entirely -- reproduced directly: two reads a second apart of a
  # file with a poisoned open_until_epoch and no profile= field each computed
  # a fresh `now + 3600`, i.e. the exact moving-horizon bug the persisted
  # clamp exists to close, just reopened via a different missing field.
  local f="$1" expected_profile="$2" v dirty=0

  ST_ATTEMPTS=""
  v="$(_state_field attempts "$f" 2>/dev/null)"
  local tok
  for tok in $v; do
    case "$tok" in ''|*[!0-9]*) continue ;; esac
    ST_ATTEMPTS="${ST_ATTEMPTS:+$ST_ATTEMPTS }$tok"
  done

  v="$(_state_field open_until_epoch "$f" 2>/dev/null)"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  ST_OPEN_UNTIL="$v"
  # Clamp a poisoned/far-future value: bounds a same-UID attacker's
  # availability cost to at most an hour, per the design's threat model.
  local now; now="$(date +%s)"
  if [ "$ST_OPEN_UNTIL" -gt $((now + 3600)) ]; then
    ST_OPEN_UNTIL=$((now + 3600))
    dirty=1
  fi

  v="$(_state_field last_totp_step "$f" 2>/dev/null)"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  ST_TOTP_STEP="$v"

  v="$(_state_field attempt_owner_pid "$f" 2>/dev/null)"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  ST_OWNER_PID="$v"

  v="$(_state_field attempt_owner_epoch "$f" 2>/dev/null)"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  ST_OWNER_EPOCH="$v"

  v="$(_state_field paused "$f" 2>/dev/null)"
  case "$v" in 1) v=1 ;; *) v=0 ;; esac
  ST_PAUSED="$v"

  # How many consecutive SERVICE attempts, in a row, never reached a
  # genuine (helper-mode, script-confirmed) tunnel-up -- see
  # record_attempt_verification below. Absent on an old state file, which
  # fails open to 0 exactly like every other field here: an upgrade must
  # never retroactively treat a profile as already mid-escalation.
  v="$(_state_field unverified_streak "$f" 2>/dev/null)"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  ST_UNVERIFIED_STREAK="$v"

  if [ "$dirty" = 1 ] && [ -n "$expected_profile" ]; then
    _state_persist_current "$f" "$expected_profile" 2>/dev/null || true
  fi
}

# Atomic replace (temp file + mv), matching the vault/secrets-file convention
# elsewhere in this project. Always writes the full field set; callers pass
# the profile's exact name (never the ST_* read of it) so identity is never
# derived from a field this same-UID-writable file could have corrupted --
# see logging.sh's attempt_state_file(): the FILENAME is what actually
# prevents collision, this field is only a sanity check.
_state_persist() {
  local f="$1" profile="$2" attempts="$3" open_until="$4" totp_step="$5" \
        owner_pid="$6" owner_epoch="$7" paused="$8" unverified_streak="${9:-0}"
  local dir; dir="$(dirname "$f")"
  ( umask 077; mkdir -p "$dir" ) 2>/dev/null
  chmod 700 "$dir" 2>/dev/null || true
  local tmp="${f}.tmp.$$"
  # The write itself must be checked, not just the final `mv`: a partial
  # write (disk full mid-printf, the temp file's directory vanishing, ...)
  # still leaves a file at $tmp for `mv` to happily rename into place, which
  # would report success while installing a TRUNCATED state file -- silently
  # dropping fields like attempt_owner_pid or last_totp_step to their
  # fail-open defaults on the next read. Reproduced directly by faulting the
  # write after a few fields: the old code returned 0 with a truncated file
  # on disk. One checked printf, not several independently-unchecked ones.
  if ! (
    umask 077
    printf 'version=1\nprofile=%s\nattempts=%s\nopen_until_epoch=%s\nlast_totp_step=%s\nattempt_owner_pid=%s\nattempt_owner_epoch=%s\npaused=%s\nunverified_streak=%s\n' \
      "$profile" "$attempts" "$open_until" "$totp_step" \
      "$owner_pid" "$owner_epoch" "$paused" "$unverified_streak" > "$tmp"
  ) 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    return 1
  fi
  chmod 600 "$tmp" 2>/dev/null || true
  if ! mv -f "$tmp" "$f" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    return 1
  fi
}

# Persist using the currently-loaded ST_* variables -- the common case inside
# a lock/read/mutate-one-field/unlock transaction.
_state_persist_current() {
  local f="$1" profile="$2"
  _state_persist "$f" "$profile" "$ST_ATTEMPTS" "$ST_OPEN_UNTIL" "$ST_TOTP_STEP" \
    "$ST_OWNER_PID" "$ST_OWNER_EPOCH" "$ST_PAUSED" "$ST_UNVERIFIED_STREAK"
}

# ------------------------------------------------------------ admit_attempt
#
# admit_attempt <profile> <SERVICE|INTERACTIVE>
#
# Gates admission of an unattended authentication attempt. See the file
# header: this never looks at what OpenConnect returns, and every wait is the
# SAME short poll (never a computed "sleep for the remaining N minutes") --
# each iteration re-derives its decision from a fresh locked read, so nothing
# decided before a wait survives it. SERVICE and INTERACTIVE genuinely
# disagree about what admission means: only SERVICE is throttled by the
# curve/breaker and only SERVICE appends to the attempt ring; INTERACTIVE is
# only ever blocked by a live owner (or a tunnel that is already up), so a
# person at a terminal is never made to wait on the curve.
#
# Return contract: 0 = admitted. 2 = the profile already has a tunnel running
# right now (INTERACTIVE only -- SERVICE just waits for it to end, same as a
# live owner). 1 = gave up for any other reason (could not even resolve the
# state path, or the state file could not be durably written after repeated
# tries).
_ATTEMPT_WINDOW=7200        # 2h sliding window
_ATTEMPT_THRESHOLD=6        # attempts within the window before the breaker opens
_ATTEMPT_CURVE=(0 60 120 240 480 900)   # seconds, indexed by attempts-in-window
_ATTEMPT_BREAKER_SECS=3600  # 1h temporary breaker
_ATTEMPT_POLL="${VPN_UP_ATTEMPT_POLL:-5}"

# Ninth invariant (§15.1 amendment, "unverified-attempt escalation"): past
# this many CONSECUTIVE admitted SERVICE attempts that never reached a
# genuine, helper-mode-verified tunnel-up (record_attempt_verification,
# below -- never OpenConnect's exit code, and never read or written from
# inside admit_attempt itself), the breaker escalates to a hard pause instead
# of quietly retiring its window and letting the retry loop resume. Expressed
# as a multiple of _ATTEMPT_THRESHOLD (attempts per breaker cycle) so it
# reads as "this many full breaker cycles with zero verified connects in
# between" -- three, by default: enough that a single bad cycle (a genuine
# transient outage with no verification signal at all, since prompt mode and
# a pre-52cbe8c helper/client pair produce none) is never mistaken for a
# stuck credential, while still bounding a real Duo-push storm to a few hours
# rather than forever.
_UNVERIFIED_STREAK_CYCLES=3
_UNVERIFIED_STREAK_LIMIT=$((_ATTEMPT_THRESHOLD * _UNVERIFIED_STREAK_CYCLES))

admit_attempt() {
  local profile="$1" mode="$2" f
  f="$(attempt_state_file "$profile")" || return 1

  local token now n delay max_attempt a persist_failures=0
  while :; do
    token="$(_state_lock "$f")"
    _state_read "$f" "$profile"

    # A tunnel already running for this profile is a stronger signal than
    # the owner marker and must be checked independently of it: the owner is
    # released as soon as OpenConnect finishes DAEMONIZING (run_openconnect's
    # background branch), not when the tunnel itself ends, so an established
    # background connection can be live with no owner recorded at all. This
    # closes the exact gap start()'s one-time ensure_profile_not_running()
    # check leaves open once admission is allowed to wait an arbitrary
    # amount of time afterward.
    # Called directly rather than via profile_vpn_running(): that wrapper's
    # boolean return can't distinguish "ambiguous" from "not running" (it
    # returns false for both), which here would let admission continue as
    # if nothing were running -- the exact gap this check exists to close.
    # Unlike a live owner/tunnel below, ambiguity doesn't resolve itself on
    # a timer (a legacy pid file whose ownership can't be proven, or a
    # confirmed-dead legacy pair whose cleanup failed, both need a human),
    # so this fails the admission outright rather than looping -- the
    # resolver has already printed its own diagnostic.
    if ! resolve_profile_runtime_files "$profile"; then
      _state_unlock "$f" "$token"
      return 1
    fi
    if [ -n "$RESOLVED_PID_FILE" ]; then
      _state_unlock "$f" "$token"
      if [ "$mode" = SERVICE ]; then
        sleep "$_ATTEMPT_POLL"
        continue
      fi
      return 2
    fi

    if [ "$ST_OWNER_PID" != 0 ]; then
      if kill -0 "$ST_OWNER_PID" 2>/dev/null; then
        _state_unlock "$f" "$token"
        sleep "$_ATTEMPT_POLL"
        continue
      fi
      # Stale: liveness only, never age (see logging.sh / design doc §3.5 --
      # both prompt and helper mode block for the entire tunnel session, so a
      # live owner can legitimately be hours old).
      ST_OWNER_PID=0
      ST_OWNER_EPOCH=0
    fi

    if [ "$ST_PAUSED" = 1 ]; then
      _state_unlock "$f" "$token"
      sleep "$_ATTEMPT_POLL"
      continue
    fi

    if [ "$mode" = SERVICE ]; then
      now="$(date +%s)"

      # Drop entries outside the window in EITHER direction: a poisoned or
      # clock-skewed FUTURE timestamp has a negative "age" from now, which a
      # naive "age <= WINDOW" test never prunes -- it would otherwise keep
      # inflating the attempt count and keep pushing the curve delay's
      # reference point into the future indefinitely.
      local pruned="" age
      for a in $ST_ATTEMPTS; do
        age=$((now - a))
        if [ "$age" -ge 0 ] && [ "$age" -le "$_ATTEMPT_WINDOW" ]; then
          pruned="${pruned:+$pruned }$a"
        fi
      done
      ST_ATTEMPTS="$pruned"

      if [ "$ST_OPEN_UNTIL" -gt "$now" ]; then
        _state_unlock "$f" "$token"
        sleep "$_ATTEMPT_POLL"
        continue
      fi
      if [ "$ST_OPEN_UNTIL" != 0 ]; then
        # The breaker just expired: retire ONLY the window that triggered it.
        # last_totp_step, paused and any owner are untouched -- there is no
        # generic "clear state", only this named transition. If the write
        # itself fails, the stale open_until is simply seen again next
        # iteration and retried -- no outcome is claimed either way here. But
        # a persistently-failing write must still go through the same POLL
        # sleep as every other wait in this loop: without one, a permanently
        # failing persist spins on lock/read/write as fast as the disk lets
        # it, burning CPU instead of backing off (reproduced directly: ~200
        # cycles in 250ms with no sleep on this path).
        #
        # Ninth invariant: past _UNVERIFIED_STREAK_LIMIT, quietly retiring the
        # window and letting the curve resume is exactly the unbounded
        # Duo-push loop this design otherwise leaves open (see the file
        # header and PRIVILEGED-HELPER-DESIGN.md §15.1's amendment) -- escalate
        # to a hard pause instead, which needs a human (pause_clear, or fixing
        # the credential via secrets_set -> attempt_history_clear) to lift.
        # The streak resets here too: a paused profile starts its next three
        # cycles fresh rather than carrying a permanent grudge, the same way
        # ST_ATTEMPTS/ST_OPEN_UNTIL are retired, not merely frozen.
        if [ "$ST_UNVERIFIED_STREAK" -ge "$_UNVERIFIED_STREAK_LIMIT" ]; then
          ST_ATTEMPTS=""
          ST_OPEN_UNTIL=0
          ST_PAUSED=1
          ST_UNVERIFIED_STREAK=0
          if _state_persist_current "$f" "$profile"; then
            _state_unlock "$f" "$token"
            print_danger "%d consecutive attempts for '%s' never established a tunnel -- this looks like a stuck credential or rejected MFA, not a network blip. Paused until you fix it and run: %s start '%s'\n" \
              "$_UNVERIFIED_STREAK_LIMIT" "$profile" "${DISPLAY_NAME:-vpn-up}" "$profile"
            notify "VPN Up" "Repeated unverified attempts for ${profile}; paused until you intervene"
          else
            _state_unlock "$f" "$token"
          fi
          sleep "$_ATTEMPT_POLL"
          continue
        fi
        ST_ATTEMPTS=""
        ST_OPEN_UNTIL=0
        if _state_persist_current "$f" "$profile"; then
          _state_unlock "$f" "$token"
          continue
        fi
        _state_unlock "$f" "$token"
        sleep "$_ATTEMPT_POLL"
        continue
      fi

      n=0
      for a in $ST_ATTEMPTS; do n=$((n + 1)); done

      if [ "$n" -ge "$_ATTEMPT_THRESHOLD" ]; then
        ST_OPEN_UNTIL=$((now + _ATTEMPT_BREAKER_SECS))
        if _state_persist_current "$f" "$profile"; then
          _state_unlock "$f" "$token"
          print_warning "Authentication attempts keep being admitted for '%s' (%d in the last window); pausing for an hour. If the stored credential is wrong, fix it, then run: %s start '%s'\n" \
            "$profile" "$n" "${DISPLAY_NAME:-vpn-up}" "$profile"
          notify "VPN Up" "Repeated attempts for ${profile}; backing off for an hour"
        else
          # The breaker did not actually get recorded -- do not claim it did.
          _state_unlock "$f" "$token"
        fi
        sleep "$_ATTEMPT_POLL"
        continue
      fi

      max_attempt=0
      for a in $ST_ATTEMPTS; do
        [ "$a" -gt "$max_attempt" ] && max_attempt="$a"
      done
      delay="${_ATTEMPT_CURVE[$n]}"
      if [ "$now" -lt $((max_attempt + delay)) ]; then
        _state_unlock "$f" "$token"
        sleep "$_ATTEMPT_POLL"
        continue
      fi
    fi

    # Admitted: take ownership now, inside the same transaction that checked
    # it -- and only a SERVICE attempt ever consumes rate-limit budget.
    ST_OWNER_PID=$$
    ST_OWNER_EPOCH="$(date +%s)"
    if [ "$mode" = SERVICE ]; then
      ST_ATTEMPTS="${ST_ATTEMPTS:+$ST_ATTEMPTS }$(date +%s)"
      local -a _ring
      read -r -a _ring <<< "$ST_ATTEMPTS"
      if [ "${#_ring[@]}" -gt "$_ATTEMPT_THRESHOLD" ]; then
        _ring=("${_ring[@]: -${_ATTEMPT_THRESHOLD}}")
      fi
      ST_ATTEMPTS="${_ring[*]}"
    fi
    if _state_persist_current "$f" "$profile"; then
      _state_unlock "$f" "$token"
      return 0
    fi
    # The commit itself failed to land on disk. Returning "admitted" here
    # would be the exact failure this whole design exists to prevent: VPN Up
    # would believe it holds exclusive ownership while nothing durable backs
    # that belief, and a second process reading the (unchanged) old state
    # could reach the identical conclusion. Never claim success; retry a
    # bounded number of times for an interactive caller (a hung terminal
    # command is worse than a clear failure), and indefinitely for a service,
    # which is already built to tolerate exactly this kind of wait.
    _state_unlock "$f" "$token"
    persist_failures=$((persist_failures + 1))
    if [ "$mode" != SERVICE ] && [ "$persist_failures" -ge 3 ]; then
      return 1
    fi
    sleep "$_ATTEMPT_POLL"
  done
}

# Releases attempt ownership if (and only if) this process still holds it.
# Called from run_admitted_connection's explicit epilogue (core.sh) -- see
# the design doc for why that is a plain function call and not a signal
# handler or a `trap ... RETURN`.
release_attempt_owner() {
  local profile="$1" f token
  f="$(attempt_state_file "$profile")" || return 0
  token="$(_state_lock "$f")"
  _state_read "$f" "$profile"
  if [ "$ST_OWNER_PID" = "$$" ]; then
    ST_OWNER_PID=0
    ST_OWNER_EPOCH=0
    _state_persist_current "$f" "$profile"
  fi
  _state_unlock "$f" "$token"
}

# Records whether ONE admitted SERVICE attempt reached a genuine, verified
# tunnel-up -- ninth invariant (§15.1 amendment): this is called from
# run_admitted_connection's epilogue (core.sh), AFTER connect_via_helper/
# run_openconnect has already returned, and NEVER from inside admit_attempt
# itself. That ordering is what keeps this from becoming the mistake §15.1's
# header warns about ("we know this was PREAUTH, so let's back off harder"):
# it cannot retroactively change whether THIS attempt was admitted or how
# long it was made to wait, only whether the NEXT breaker-expiry transition
# (admit_attempt, above) treats a quiet retire-and-resume as safe.
#
# `verified` is a tri-state, not a bool: "1" (a genuine helper-mode connect
# was confirmed for this exact attempt) resets the streak, "0" (helper mode
# ran but never confirmed one) increments it, and anything else -- most
# commonly the empty string, meaning no signal was available at all (prompt
# mode, or a helper/client pair predating the event-status telemetry) --
# leaves the streak untouched rather than guessing. A profile that only ever
# runs in prompt mode therefore never escalates via this path at all, which
# is correct: prompt mode has no way to tell "stuck at a Duo prompt" from
# "about to succeed" (core.sh's own _record_foreground_openconnect_pid
# comment), so it must not pretend otherwise here either.
record_attempt_verification() {
  local profile="$1" verified="$2" f token
  case "$verified" in
    0|1) : ;;
    *) return 0 ;;
  esac
  f="$(attempt_state_file "$profile")" || return 0
  token="$(_state_lock "$f")"
  _state_read "$f" "$profile"
  if [ "$verified" = 1 ]; then
    ST_UNVERIFIED_STREAK=0
  else
    ST_UNVERIFIED_STREAK=$((ST_UNVERIFIED_STREAK + 1))
  fi
  _state_persist_current "$f" "$profile"
  _state_unlock "$f" "$token"
}

# Clears only the attempt-rate history -- never called on a manual start (see
# §3.6 of the design: "clear history" and "start now" are different signals
# and must not be conflated, or a sleeping service and a manual start could
# both admit an attempt at once). Called from secrets_set() on `password`.
# The unverified streak is cleared alongside it: a corrected credential is
# exactly the kind of fix that should earn a fresh run at the escalation
# threshold too, the same reasoning §3.6 already applies to the curve itself.
attempt_history_clear() {
  local profile="$1" f token
  f="$(attempt_state_file "$profile")" || return 0
  token="$(_state_lock "$f")"
  _state_read "$f" "$profile"
  ST_ATTEMPTS=""
  ST_OPEN_UNTIL=0
  ST_UNVERIFIED_STREAK=0
  _state_persist_current "$f" "$profile"
  _state_unlock "$f" "$token"
}

# Clears the TOTP step reservation. Deliberately separate from
# attempt_history_clear: a corrected password does not make the previously
# reserved TOTP step meaningful again, and a changed TOTP secret is the one
# case where clearing the reservation is actually correct (the generated code
# now comes from a different seed).
totp_step_reservation_clear() {
  local profile="$1" f token
  f="$(attempt_state_file "$profile")" || return 0
  token="$(_state_lock "$f")"
  _state_read "$f" "$profile"
  ST_TOTP_STEP=0
  _state_persist_current "$f" "$profile"
  _state_unlock "$f" "$token"
}

# Called directly by admit_attempt()'s unverified-streak escalation (ninth
# invariant, above) -- its first real production caller. Still also the
# mechanism a future fix for the `vpn-up stop`-under-service gap (design doc,
# "flagged, not decided") would reuse; not wired into `stop` by this change.
pause_set() {
  local profile="$1" f token
  f="$(attempt_state_file "$profile")" || return 0
  token="$(_state_lock "$f")"
  _state_read "$f" "$profile"
  ST_PAUSED=1
  _state_persist_current "$f" "$profile"
  _state_unlock "$f" "$token"
}
pause_clear() {
  local profile="$1" f token
  f="$(attempt_state_file "$profile")" || return 0
  token="$(_state_lock "$f")"
  _state_read "$f" "$profile"
  ST_PAUSED=0
  _state_persist_current "$f" "$profile"
  _state_unlock "$f" "$token"
}

# ------------------------------------------------------------------- TOTP
#
# Reserve the current 30s step BEFORE generating a code from it -- see the
# design doc for why this is launchd-specific (ThrottleInterval has no floor
# after a session that ran longer than 30s, so a drop-and-respawn can land
# inside the same step as the code the server just consumed) and why
# reserve-then-generate, not generate-then-record, is the safe failure
# direction: a mid-transaction crash wastes at most one step, rather than
# risking a replay.
# Default step length; a profile may override it (totpStepSeconds) and pass
# its own value as totp_wait_for_fresh_step's second argument -- this constant
# is only the fallback when a profile doesn't, and must match oathtool
# --totp's implicit default (core.sh's generate_totp).
TOTP_STEP_SECS=30

totp_wait_for_fresh_step() {
  local profile="$1" step_secs="${2:-$TOTP_STEP_SECS}" f token now step persist_failures=0
  [ "${VPN_UP_NO_TOTP_WAIT:-}" = 1 ] && return 0
  # A missing state file path (e.g. no sha256 tool) must not be read as "no
  # reservation needed" -- that would silently drop the whole exclusivity
  # guarantee this function exists to provide. Refuse instead.
  f="$(attempt_state_file "$profile")" || return 1
  while :; do
    token="$(_state_lock "$f")"
    _state_read "$f" "$profile"
    now="$(date +%s)"
    step=$(( now / step_secs ))
    # <=, not ==: if the clock has moved BACKWARDS far enough that step is
    # now LOWER than the last reserved step, treating it as "fresh" would
    # both regenerate an already-used code and overwrite the stored
    # reservation with a lower value, making old steps eligible again after
    # the clock is corrected. Only a step strictly ahead of the last
    # reservation is ever fresh.
    if [ "$step" -le "$ST_TOTP_STEP" ]; then
      _state_unlock "$f" "$token"
      sleep "$_ATTEMPT_POLL"
      continue
    fi
    ST_TOTP_STEP="$step"
    if _state_persist_current "$f" "$profile"; then
      _state_unlock "$f" "$token"
      return 0
    fi
    # The write itself failed (disk full, state dir vanished, ...). Returning
    # success here would let the caller generate a code with no reservation
    # actually recorded -- exactly the failure-open-into-authentication this
    # exists to prevent. Retry a bounded number of times, then give up.
    _state_unlock "$f" "$token"
    persist_failures=$((persist_failures + 1))
    if [ "$persist_failures" -ge 3 ]; then
      return 1
    fi
    sleep "$_ATTEMPT_POLL"
  done
}
