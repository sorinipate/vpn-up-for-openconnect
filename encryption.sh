# encryption.sh - secure secret storage (keychain/keyring preferred; OpenSSL fallback)
# ENCRYPTION_KEY is ignored by design; we use OS keychain/keyring or an encrypted vault with a passphrase prompt.
# ENCRYPTION_ENABLED governs only the file fallback: TRUE=encrypted vault, FALSE=plaintext file (0600).

SECRETS_NAMESPACE="${PROGRAM_NAME}"
SECRETS_DIR="${PROGRAM_PATH}/config"
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
secrets_set_keychain() { local k="$1"; local v="$2"; security delete-generic-password -a "$k" >/dev/null 2>&1 || true; security add-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" -w "$v" -U >/dev/null; }
secrets_get_keychain() { local k="$1"; security find-generic-password -a "$k" -s "${SECRETS_NAMESPACE}" -w 2>/dev/null; }
secrets_delete_keychain() { local k="$1"; security delete-generic-password -a "$k" >/dev/null 2>&1 || true; }

# ----- Linux Secret Service -----
secrets_set_secrettool() { local k="$1"; local v="$2"; secret-tool store --label="${SECRETS_NAMESPACE}" app "${SECRETS_NAMESPACE}" account "$k" <<<"$v"; }
secrets_get_secrettool() { local k="$1"; secret-tool lookup app "${SECRETS_NAMESPACE}" account "$k"; }
secrets_delete_secrettool() { :; }  # no-op

# ----- OpenSSL encrypted vault -----
_vault_pass_prompt() { if [ -z "${_VAULT_PASSPHRASE+x}" ]; then read -r -s -p "Enter vault passphrase for ${PROGRAM_NAME}: " _VAULT_PASSPHRASE; echo; fi; }
_vault_decrypt() {
  ensure_secret_paths
  [ -f "${SECRETS_VAULT}" ] || { : > "${SECRETS_VAULT}"; chmod 600 "${SECRETS_VAULT}"; }
  [ -s "${SECRETS_VAULT}" ] || { echo ""; return 0; }
  _vault_pass_prompt
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in "${SECRETS_VAULT}" -pass pass:"${_VAULT_PASSPHRASE}"
}
_vault_encrypt() { _vault_pass_prompt; openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -out "${SECRETS_VAULT}" -pass pass:"${_VAULT_PASSPHRASE}"; chmod 600 "${SECRETS_VAULT}"; }
secrets_set_openssl() {
  local k="$1"; local v="$2"
  ensure_secret_paths
  local data="$(_vault_decrypt)"
  data="$(printf "%s\n" "$data" | awk -F= -v kk="$k" 'BEGIN{OFS="="} $1!=kk {print}')" || true
  { printf "%s=%s\n" "$k" "$v"; printf "%s\n" "$data"; } > "${SECRETS_TMP}"
  sort -u "${SECRETS_TMP}" > "${SECRETS_TMP}.sorted"
  rm -f "${SECRETS_TMP}"
  _vault_encrypt < "${SECRETS_TMP}.sorted"
  rm -f "${SECRETS_TMP}.sorted"
}
secrets_get_openssl() { local k="$1"; local data="$(_vault_decrypt)"; printf "%s\n" "$data" | awk -F= -v kk="$k" '$1==kk { $1=""; sub(/^=/,""); print; exit }'; }
secrets_delete_openssl() { local k="$1"; local data="$(_vault_decrypt)"; data="$(printf "%s\n" "$data" | awk -F= -v kk="$k" 'BEGIN{OFS="="} $1!=kk {print}')" || true; printf "%s\n" "$data" | _vault_encrypt; }

# ----- Plain file (when ENCRYPTION_ENABLED=FALSE) -----
secrets_set_file() { local k="$1"; local v="$2"; ensure_secret_paths; touch "${SECRETS_PLAIN}"; chmod 600 "${SECRETS_PLAIN}"; grep -v -E "^${k}=" "${SECRETS_PLAIN}" > "${SECRETS_TMP}" 2>/dev/null || true; printf "%s=%s\n" "$k" "$v" >> "${SECRETS_TMP}"; sort -u "${SECRETS_TMP}" > "${SECRETS_PLAIN}"; rm -f "${SECRETS_TMP}"; }
secrets_get_file() { local k="$1"; [ -f "${SECRETS_PLAIN}" ] || { echo ""; return 0; }; awk -F= -v kk="$k" '$1==kk{ $1=""; sub(/^=/,""); print; exit }' "${SECRETS_PLAIN}"; }
secrets_delete_file() { local k="$1"; [ -f "${SECRETS_PLAIN}" ] || return 0; grep -v -E "^${k}=" "${SECRETS_PLAIN}" > "${SECRETS_TMP}" 2>/dev/null || true; mv "${SECRETS_TMP}" "${SECRETS_PLAIN}"; chmod 600 "${SECRETS_PLAIN}"; }

# ----- Unified API -----
secrets_set() { local profile="$1"; local field="$2"; local value="$3"; local b; b="$(secrets_backend)"; local k; k="$(secrets_key "$profile" "$field")"; case "$b" in keychain) secrets_set_keychain "$k" "$value" ;; secret-tool) secrets_set_secrettool "$k" "$value" ;; openssl) secrets_set_openssl "$k" "$value" ;; file) secrets_set_file "$k" "$value" ;; esac; }
secrets_get() { local profile="$1"; local field="$2"; local b; b="$(secrets_backend)"; local k; k="$(secrets_key "$profile" "$field")"; case "$b" in keychain) secrets_get_keychain "$k" ;; secret-tool) secrets_get_secrettool "$k" ;; openssl) secrets_get_openssl "$k" ;; file) secrets_get_file "$k" ;; esac; }
secrets_delete() { local profile="$1"; local field="$2"; local b; b="$(secrets_backend)"; local k; k="$(secrets_key "$profile" "$field")"; case "$b" in keychain) secrets_delete_keychain "$k" ;; secret-tool) secrets_delete_secrettool "$k" ;; openssl) secrets_delete_openssl "$k" ;; file) secrets_delete_file "$k" ;; esac; }