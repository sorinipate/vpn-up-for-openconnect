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
secrets_set_keychain() {
  local k="$1"; local v="$2"
  security delete-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" >/dev/null 2>&1 || true
  printf 'add-generic-password -a %s -s %s -w %s -U\n' \
    "$(_security_quote "$k")" "$(_security_quote "${SECRETS_NAMESPACE}")" "$(_security_quote "$v")" \
    | security -i >/dev/null
}
secrets_get_keychain() { local k="$1"; security find-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" -w 2>/dev/null; }
secrets_delete_keychain() { local k="$1"; security delete-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" >/dev/null 2>&1 || true; }

# ----- Linux Secret Service -----
secrets_set_secrettool() { local k="$1"; local v="$2"; secret-tool store --label="${SECRETS_NAMESPACE}" app "${SECRETS_NAMESPACE}" account "$k" <<<"$v"; }
secrets_get_secrettool() { local k="$1"; secret-tool lookup app "${SECRETS_NAMESPACE}" account "$k"; }
secrets_delete_secrettool() { local k="$1"; secret-tool clear app "${SECRETS_NAMESPACE}" account "$k" 2>/dev/null || true; }

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