# encryption.sh - secure secret storage (keychain/keyring preferred; OpenSSL fallback)
# ENCRYPTION_KEY is ignored by design; we use OS keychain/keyring or an encrypted vault with a passphrase prompt.
# ENCRYPTION_ENABLED governs only the file fallback: TRUE=encrypted vault, FALSE=plaintext file (0600).

SECRETS_NAMESPACE="${PROGRAM_NAME}"
SECRETS_DIR="${DATA_DIR}"
SECRETS_VAULT="${SECRETS_DIR}/${PROGRAM_NAME}.secrets.enc"
SECRETS_PLAIN="${SECRETS_DIR}/${PROGRAM_NAME}.secrets"
SECRETS_TMP="${SECRETS_DIR}/${PROGRAM_NAME}.secrets.tmp"

ensure_secret_paths() {
  mkdir -p "${SECRETS_DIR}"
  chmod 700 "${SECRETS_DIR}" 2>/dev/null || true
}

secrets_backend() {
  if command -v security >/dev/null 2>&1 && [ "$(uname)" = "Darwin" ]; then
    echo "keychain"; return
  fi
  if command -v secret-tool >/dev/null 2>&1; then
    echo "secret-tool"; return
  fi
  if [ "${ENCRYPTION_ENABLED:-TRUE}" = "FALSE" ]; then
    echo "file"; return
  fi
  echo "openssl"
}

secrets_key() {
  local profile="$1"; local field="$2"
  echo "${SECRETS_NAMESPACE}:profile=${profile}:field=${field}"
}

# ----- macOS Keychain -----
# The secret is passed via `security -i` (commands on stdin) rather than -w on
# the command line, so it never appears in the process table.
_security_quote() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }
# `-U` already means "update in place if the item exists" (confirmed directly
# against `security add-generic-password -h`: "-U  Update item if it already
# exists"), so a pre-delete gains nothing and is actively dangerous: if the
# subsequent add then fails for any reason, the item is gone with nothing
# written in its place, destroying the only surviving copy of a credential
# that was valid a moment earlier. Reproduced directly on a disposable test
# keychain that `-U` alone updates an existing item without a prior delete.
secrets_set_keychain() {
  local k="$1"; local v="$2"
  printf 'add-generic-password -a %s -s %s -w %s -U\n' \
    "$(_security_quote "$k")" "$(_security_quote "${SECRETS_NAMESPACE}")" "$(_security_quote "$v")" \
    | security -i >/dev/null
}
secrets_get_keychain() { local k="$1"; security find-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" -w 2>/dev/null; }
secrets_delete_keychain() { local k="$1"; security delete-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" >/dev/null 2>&1 || true; }

# security's own exit status DOES distinguish these on macOS: 44 is
# errSecItemNotFound specifically (confirmed directly: a lookup against a
# nonexistent account/service reproducibly exits 44, distinct from any other
# failure), so a genuinely absent secret must map to ABSENT here, not to a
# backend error -- a generic "any non-zero exit means the backend errored"
# reading would make a password that was simply never stored retry forever
# instead of ever reaching the terminal "store it first" message.
#
# On success, prints the fetched value to stdout -- this is a single backend
# round-trip that both checks AND fetches, not merely a check. A previous
# version discarded the value here and made callers call secrets_get_keychain
# again afterward; that left a real gap between "confirmed present" and
# "actually read" where the backend could fail in between (review round 5,
# BLOCKER #2), and for the openssl vault backend the equivalent pattern is
# worse than just a race -- it decrypts the vault twice, prompting for the
# passphrase twice in an interactive session. One fetch, reused by the caller.
_secret_check_keychain() {
  local k="$1" out
  out="$(security find-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" -w 2>/dev/null)"
  case $? in
    0)  printf '%s' "$out"; return 0 ;;
    44) return 1 ;;
    *)  return 2 ;;
  esac
}

# ----- Linux Secret Service -----
secrets_set_secrettool() { local k="$1"; local v="$2"; secret-tool store --label="${SECRETS_NAMESPACE}" app "${SECRETS_NAMESPACE}" account "$k" <<<"$v"; }
secrets_get_secrettool() { local k="$1"; secret-tool lookup app "${SECRETS_NAMESPACE}" account "$k"; }
secrets_delete_secrettool() { local k="$1"; secret-tool clear app "${SECRETS_NAMESPACE}" account "$k" 2>/dev/null || true; }

# Unlike Keychain, secret-tool's own EXIT STATUS does not distinguish "not
# found" from a backend/D-Bus error -- both return 1. An earlier version of
# this function tried to disambiguate by probing whether the Secret Service
# was reachable on the session bus (NameHasOwner), reasoning that a reachable
# service's own failed lookup must mean "not found". Review round 5 (BLOCKER
# #1) correctly identified that as unsound: a reachable, live Secret Service
# can still fail a specific lookup for a reason that has nothing to do with
# "not found" -- a locked collection, a malformed request, any other D-Bus
# error -- and NameHasOwner proves none of that.
#
# The actual, structural signal is on STDERR, not the exit code -- verified
# directly against libsecret's own tool/secret-tool.c
# (secret_tool_action_lookup): the GError branch prints
# "<prgname>: <error->message>\n" to stderr before returning 1; the
# value==NULL ("no matching secret") branch returns 1 with nothing printed at
# all. So whether this invocation produced ANY stderr output is exactly the
# distinction needed, and it comes from the one lookup already being made --
# no second probe, no D-Bus dependency, no environment-specific heuristic.
# Captured through a scratch file (not a second invocation) so this stays a
# single backend round-trip, matching _secret_check_keychain above; the value
# itself is printed to stdout on success, for the same reason.
_secret_check_secrettool() {
  local k="$1" out err rc errfile
  ensure_secret_paths
  errfile="${SECRETS_DIR}/.secrettool-err.$$"
  # Prove the capture file is actually writable BEFORE trusting anything
  # downstream of it. If SECRETS_DIR is missing/unwritable (or blocked by a
  # plain file), the `2>"$errfile"` redirection below fails on its own,
  # before secret-tool ever runs -- reproduced directly: the command
  # substitution then captures nothing, $errfile is never created, and
  # reading it back as empty looked identical to "no error message", which
  # this function reads as ABSENT. That is exactly backwards: a local I/O
  # failure is a backend/environment error, and must never be classified as
  # "the secret does not exist" -- a genuinely unrelated, transient local
  # condition would otherwise permanently stop a service the same way a
  # truly missing secret does.
  if ! : > "$errfile" 2>/dev/null; then
    return 2
  fi
  out="$(secret-tool lookup app "${SECRETS_NAMESPACE}" account "$k" 2>"$errfile")"
  rc=$?
  err="$(cat "$errfile" 2>/dev/null)"
  rm -f "$errfile" 2>/dev/null
  if [ "$rc" -eq 0 ]; then
    printf '%s' "$out"
    return 0
  fi
  [ -n "$err" ] && return 2
  return 1
}

# ----- OpenSSL encrypted vault -----
# Vault contents only ever exist decrypted in shell variables and pipes —
# never on disk. The passphrase reaches openssl via the environment
# (-pass env:), not argv, so it is not visible in the process table.
#
# Cipher parameters live in one array so encryption, decryption and the
# write-verify round-trip below cannot drift apart.
_VAULT_CIPHER=(-aes-256-cbc -pbkdf2 -iter 200000 -salt -base64)

_vault_pass_prompt() { if [ -z "${_VAULT_PASSPHRASE+x}" ]; then read -r -s -p "Enter vault passphrase for ${PROGRAM_NAME}: " _VAULT_PASSPHRASE; echo; fi; }
_vault_decrypt() {
  ensure_secret_paths
  [ -s "${SECRETS_VAULT}" ] || { echo ""; return 0; }
  _vault_pass_prompt
  if ! _VP="${_VAULT_PASSPHRASE}" openssl enc -d "${_VAULT_CIPHER[@]}" \
        -in "${SECRETS_VAULT}" -pass env:_VP; then
    print_danger "Vault decryption failed (wrong passphrase?). Aborting to avoid data loss.\n" >&2
    unset _VAULT_PASSPHRASE
    return 1
  fi
}

# Write the vault atomically, and never report success unless the new contents
# are on disk AND readable back.
#
# The previous implementation wrote openssl's output straight over the only copy
# of the vault with `-out "${SECRETS_VAULT}"`, ignored openssl's exit status, and
# ended in `chmod ... || true` — so the function always returned 0. A failed or
# partial encryption therefore truncated the vault while `set-secret` reported
# "Saved". That matters most for unattended operation, where a service can be
# left with no usable credential and no indication anything went wrong.
_vault_encrypt() {
  _vault_pass_prompt
  local _plain _tmp _back
  _plain="$(cat)"
  _tmp="${SECRETS_VAULT}.tmp.$$"

  if ! ( umask 077; printf '%s\n' "$_plain" \
           | _VP="${_VAULT_PASSPHRASE}" openssl enc "${_VAULT_CIPHER[@]}" \
               -out "$_tmp" -pass env:_VP ); then
    rm -f "$_tmp"
    print_danger "Vault encryption failed; the existing vault is unchanged.\n" >&2
    return 1
  fi
  if [ ! -s "$_tmp" ]; then
    rm -f "$_tmp"
    print_danger "Vault encryption produced no output; the existing vault is unchanged.\n" >&2
    return 1
  fi
  # Read it back before it becomes the only copy: openssl exiting 0 is not proof
  # that what landed on disk decrypts to what we handed it.
  if ! _back="$(_VP="${_VAULT_PASSPHRASE}" openssl enc -d "${_VAULT_CIPHER[@]}" \
                  -in "$_tmp" -pass env:_VP 2>/dev/null)" || [ "$_back" != "$_plain" ]; then
    rm -f "$_tmp"
    print_danger "Vault write-verify failed (re-read did not match); the existing vault is unchanged.\n" >&2
    return 1
  fi
  chmod 600 "$_tmp" 2>/dev/null || true
  # Same directory, so this is an atomic replace: readers see either the old
  # vault or the new one, never a half-written file.
  if ! mv -f "$_tmp" "${SECRETS_VAULT}"; then
    rm -f "$_tmp"
    print_danger "Could not install the new vault; the existing vault is unchanged.\n" >&2
    return 1
  fi
}
# Exact-string key matching via awk index() — keys and values may both
# contain '=' (keys do: "...:profile=X:field=y"), so field splitting on '='
# is wrong, and keys must never be interpolated into a regex.
_kv_lookup() { _K="$1" awk 'index($0, ENVIRON["_K"] "=")==1 { print substr($0, length(ENVIRON["_K"])+2); exit }'; }
_kv_filter_out() { _K="$1" awk 'index($0, ENVIRON["_K"] "=")!=1 && $0!="" {print}'; }

secrets_set_openssl() {
  local k="$1"; local v="$2"
  ensure_secret_paths
  local data; data="$(_vault_decrypt)" || return 1
  data="$(printf "%s\n" "$data" | _kv_filter_out "$k")"
  { printf "%s=%s\n" "$k" "$v"; [ -n "$data" ] && printf "%s\n" "$data"; } | _vault_encrypt
}
secrets_get_openssl() { local k="$1"; local data; data="$(_vault_decrypt)" || return 1; printf "%s\n" "$data" | _kv_lookup "$k"; }
secrets_delete_openssl() {
  local k="$1"
  local data; data="$(_vault_decrypt)" || return 1
  data="$(printf "%s\n" "$data" | _kv_filter_out "$k")"
  printf "%s\n" "$data" | _vault_encrypt
}

# ----- Plain file (when ENCRYPTION_ENABLED=FALSE) -----
# Keys are matched as exact strings (awk), never interpolated into a regex.
# Staged through a temp file and renamed, like the vault, so a failure part-way
# leaves the previous contents intact instead of a truncated secrets file.
secrets_set_file() {
  local k="$1"; local v="$2"
  ensure_secret_paths
  ( umask 077; touch "${SECRETS_PLAIN}" "${SECRETS_TMP}" )
  chmod 600 "${SECRETS_PLAIN}" "${SECRETS_TMP}"
  if ! { _kv_filter_out "$k" < "${SECRETS_PLAIN}" > "${SECRETS_TMP}" \
         && printf "%s=%s\n" "$k" "$v" >> "${SECRETS_TMP}"; }; then
    rm -f "${SECRETS_TMP}"
    print_danger "Could not stage the secrets file; nothing was changed.\n" >&2
    return 1
  fi
  if ! mv "${SECRETS_TMP}" "${SECRETS_PLAIN}"; then
    rm -f "${SECRETS_TMP}"
    print_danger "Could not update the secrets file; nothing was changed.\n" >&2
    return 1
  fi
}
secrets_get_file() { local k="$1"; [ -f "${SECRETS_PLAIN}" ] || { echo ""; return 0; }; _kv_lookup "$k" < "${SECRETS_PLAIN}"; }
secrets_delete_file() {
  local k="$1"
  [ -f "${SECRETS_PLAIN}" ] || return 0
  ( umask 077; : > "${SECRETS_TMP}" )
  if ! _kv_filter_out "$k" < "${SECRETS_PLAIN}" > "${SECRETS_TMP}"; then
    rm -f "${SECRETS_TMP}"
    print_danger "Could not stage the secrets file; nothing was deleted.\n" >&2
    return 1
  fi
  if ! mv "${SECRETS_TMP}" "${SECRETS_PLAIN}"; then
    rm -f "${SECRETS_TMP}"
    print_danger "Could not update the secrets file; nothing was deleted.\n" >&2
    return 1
  fi
  chmod 600 "${SECRETS_PLAIN}"
}

# ----- Unified API -----
#
# secrets_set clears the rate limiter's attempt history on a successful
# password change (outcome.sh: attempt_history_clear) — the natural repair
# workflow once a stored credential was wrong — and additionally clears the
# TOTP step reservation on a token_secret change, since a new seed makes any
# previously reserved step meaningless. Neither clear applies to any other
# field, and neither ever runs on a failed write.
secrets_set() {
  local profile="$1"; local field="$2"; local value="$3"; local b rc=0; b="$(secrets_backend)"
  local k; k="$(secrets_key "$profile" "$field")"
  case "$b" in
    keychain)    secrets_set_keychain "$k" "$value" ;;
    secret-tool) secrets_set_secrettool "$k" "$value" ;;
    openssl)     secrets_set_openssl "$k" "$value" ;;
    file)        secrets_set_file "$k" "$value" ;;
  esac
  rc=$?
  if [ "$rc" -eq 0 ]; then
    command -v attempt_history_clear >/dev/null 2>&1 || . "${PROGRAM_PATH}/outcome.sh"
    case "$field" in
      password)     attempt_history_clear "$profile" ;;
      token_secret) attempt_history_clear "$profile"; totp_step_reservation_clear "$profile" ;;
    esac
  fi
  return "$rc"
}
secrets_get() { local profile="$1"; local field="$2"; local b; b="$(secrets_backend)"; local k; k="$(secrets_key "$profile" "$field")"; case "$b" in keychain) secrets_get_keychain "$k" ;; secret-tool) secrets_get_secrettool "$k" ;; openssl) secrets_get_openssl "$k" ;; file) secrets_get_file "$k" ;; esac; }
# _secret_check() (core.sh) is the tri-state entry point callers use; it
# dispatches to _secret_check_keychain/_secret_check_secrettool above for
# those two backends and falls back to a generic secrets_get()-based check
# (correct for the openssl/file backends) for everything else -- including
# whenever this file hasn't been sourced at all, which several existing unit
# tests rely on when they stub secrets_get() directly without a real backend.
secrets_delete() { local profile="$1"; local field="$2"; local b; b="$(secrets_backend)"; local k; k="$(secrets_key "$profile" "$field")"; case "$b" in keychain) secrets_delete_keychain "$k" ;; secret-tool) secrets_delete_secrettool "$k" ;; openssl) secrets_delete_openssl "$k" ;; file) secrets_delete_file "$k" ;; esac; }

# Every secret field a profile can own. Deleting a profile must clear all of
# them, or the orphans linger in the keychain/vault after the profile is gone.
# Keep this list in step with every secrets_set call site (setup.sh add-profile,
# `set-secret`); a new field added there and forgotten here reintroduces the leak.
SECRET_FIELDS="password token_secret key_password"

# Remove all of a profile's secrets. Field-by-field through secrets_delete so
# each backend's own delete path (and its "absent is not an error" behaviour) is
# reused unchanged.
secrets_delete_profile() {
  local profile="$1" field
  for field in $SECRET_FIELDS; do
    secrets_delete "$profile" "$field"
  done
}