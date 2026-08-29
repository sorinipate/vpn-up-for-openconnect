#!/usr/bin/env bats
# Round-trip tests for the secret storage backends (file + openssl vault).
# The keychain/secret-tool backends need a live keyring and are not exercised
# in CI; the shared key-matching helpers are covered through these two.

setup() {
  export PROGRAM_NAME="vpnup-test"
  export PROGRAM_PATH="$BATS_TEST_TMPDIR"
  export DATA_DIR="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_DIR"
  print_danger() { printf -- "$1" "${@:2}" >&2; }
  export -f print_danger
  source "$BATS_TEST_DIRNAME/../outcome.sh"
  source "$BATS_TEST_DIRNAME/../encryption.sh"
  export _VAULT_PASSPHRASE="test-pass-123"
}

@test "file backend: set/get round-trip with =, quotes, spaces" {
  k="$(secrets_key "My VPN" password)"
  v='p@ss=w/eird"chars'\''!'
  secrets_set_file "$k" "$v"
  [ "$(secrets_get_file "$k")" = "$v" ]
}

@test "file backend: delete with regex metacharacters in key is exact" {
  k1="$(secrets_key 'A.B[1]+' password)"
  k2="$(secrets_key 'AXB11'   password)"
  secrets_set_file "$k1" "v1"
  secrets_set_file "$k2" "v2"
  secrets_delete_file "$k1"
  [ -z "$(secrets_get_file "$k1")" ]
  [ "$(secrets_get_file "$k2")" = "v2" ]
}

@test "openssl vault: set/get/update/delete round-trip" {
  k="$(secrets_key "Work VPN" password)"
  secrets_set_openssl "$k" "first"
  [ "$(secrets_get_openssl "$k")" = "first" ]
  secrets_set_openssl "$k" "second"
  [ "$(secrets_get_openssl "$k")" = "second" ]
  secrets_delete_openssl "$k"
  [ -z "$(secrets_get_openssl "$k")" ]
}

@test "openssl vault: other entries survive set and delete" {
  ka="$(secrets_key A password)"; kb="$(secrets_key B password)"
  secrets_set_openssl "$ka" "va"
  secrets_set_openssl "$kb" "vb"
  secrets_delete_openssl "$ka"
  [ "$(secrets_get_openssl "$kb")" = "vb" ]
}

@test "openssl vault: wrong passphrase fails instead of wiping" {
  k="$(secrets_key C password)"
  secrets_set_openssl "$k" "keepme"
  _VAULT_PASSPHRASE="WRONG"
  run secrets_set_openssl "$k" "clobber"
  [ "$status" -ne 0 ]
  _VAULT_PASSPHRASE="test-pass-123"
  [ "$(secrets_get_openssl "$k")" = "keepme" ]
}

@test "vault and plain files are created with 600 permissions" {
  source "$BATS_TEST_DIRNAME/../logging.sh"
  secrets_set_openssl "$(secrets_key D password)" "v"
  secrets_set_file "$(secrets_key D password)" "v"
  [ "$(file_mode "$SECRETS_VAULT")" = "600" ]
  [ "$(file_mode "$SECRETS_PLAIN")" = "600" ]
}

@test "no plaintext temp files left behind" {
  secrets_set_openssl "$(secrets_key E password)" "v"
  secrets_delete_openssl "$(secrets_key E password)"
  [ ! -e "$SECRETS_TMP" ]
  [ ! -e "${SECRETS_TMP}.sorted" ]
}

@test "secrets_key namespaces profile and field" {
  [ "$(secrets_key "Work VPN" password)" = "${PROGRAM_NAME}:profile=Work VPN:field=password" ]
}

@test "_security_quote escapes quotes and backslashes for security -i" {
  [ "$(_security_quote 'plain')" = '"plain"' ]
  [ "$(_security_quote 'a"b')" = '"a\"b"' ]
  [ "$(_security_quote 'a\b')" = '"a\\b"' ]
}

# --- tri-state existence checks (review round 4) ---
#
# A generic "secrets_get's own exit status means present/absent/error" read
# is correct for the openssl/file backends, but Keychain and Secret Service
# each fold "absent" and "backend error" into overlapping exit statuses of
# their own -- these test each backend's OWN probe against exit codes/output
# verified against real behavior (Keychain: reproduced directly on this
# machine -- `security find-generic-password` against a nonexistent
# account/service reliably exits 44; Secret Service: no live D-Bus/secret-tool
# environment is available here, so this is verified against libsecret's
# published secret-tool.c source instead -- see PRIVILEGED-HELPER-DESIGN.md).

@test "_secret_check_keychain: found is present, errSecItemNotFound (44) is absent, anything else is backend error" {
  security() { return 0; }
  if _secret_check_keychain "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ]

  security() { return 44; }
  if _secret_check_keychain "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 1 ]

  security() { return 51; }   # e.g. a locked/unavailable keychain
  if _secret_check_keychain "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 2 ]
}

@test "_secret_check_secrettool: a successful lookup is present" {
  secret-tool() { return 0; }
  if _secret_check_secrettool "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 0 ]
}

@test "_secret_check_secrettool: a failed lookup with the Secret Service reachable is absent" {
  # secret-tool's own exit status can't distinguish "not found" from a
  # backend error (both return 1) -- so a failed lookup is only read as
  # ABSENT once the Secret Service is confirmed reachable on the session bus.
  secret-tool() { return 1; }
  command() { [ "$1" = -v ] && [ "$2" = dbus-send ] && return 0 || builtin command "$@"; }
  dbus-send() { echo "boolean true"; return 0; }
  if _secret_check_secrettool "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 1 ]
}

@test "_secret_check_secrettool: a failed lookup with the Secret Service NOT reachable is backend error" {
  secret-tool() { return 1; }
  command() { [ "$1" = -v ] && [ "$2" = dbus-send ] && return 0 || builtin command "$@"; }
  dbus-send() { echo "boolean false"; return 0; }
  if _secret_check_secrettool "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 2 ]
}

@test "_secret_check_secrettool: a failed lookup with no dbus-send available is backend error (safe default)" {
  # Never guess ABSENT when the health probe itself can't run.
  secret-tool() { return 1; }
  command() { [ "$1" = -v ] && [ "$2" = dbus-send ] && return 1 || builtin command "$@"; }
  if _secret_check_secrettool "k"; then rc=0; else rc=$?; fi
  [ "$rc" -eq 2 ]
}

@test "secrets_backend honors platform tools and ENCRYPTION_ENABLED" {
  # no keyring tools, encryption on -> openssl vault
  uname() { echo Linux; }
  command() { return 1; }
  ENCRYPTION_ENABLED=TRUE
  [ "$(secrets_backend)" = "openssl" ]
  # explicit plaintext opt-out -> file
  ENCRYPTION_ENABLED=FALSE
  [ "$(secrets_backend)" = "file" ]
  # Darwin with security available -> keychain regardless
  uname() { echo Darwin; }
  command() { [ "$2" = "security" ]; }
  [ "$(secrets_backend)" = "keychain" ]
  # Linux with secret-tool -> secret-tool
  uname() { echo Linux; }
  command() { [ "$2" = "secret-tool" ]; }
  [ "$(secrets_backend)" = "secret-tool" ]
}

# --- profile-wide deletion (every secret field, not just the password) ---
#
# These pin the backend to the plaintext file explicitly. Note that
# ENCRYPTION_ENABLED=FALSE is NOT sufficient: secrets_backend() checks for the
# macOS keychain before it looks at that variable, so on Darwin these tests
# would otherwise read and write the developer's real login keychain.

_use_file_backend() { secrets_backend() { echo file; }; }

@test "secrets_delete_profile clears password, token_secret and key_password" {
  _use_file_backend
  secrets_set "Work VPN" password      "pw"
  secrets_set "Work VPN" token_secret  "JBSWY3DPEHPK3PXP"
  secrets_set "Work VPN" key_password  "1234"
  [ "$(secrets_get "Work VPN" password)"     = "pw" ]
  [ "$(secrets_get "Work VPN" token_secret)" = "JBSWY3DPEHPK3PXP" ]
  [ "$(secrets_get "Work VPN" key_password)" = "1234" ]

  secrets_delete_profile "Work VPN"

  [ -z "$(secrets_get "Work VPN" password)" ]
  [ -z "$(secrets_get "Work VPN" token_secret)" ]
  [ -z "$(secrets_get "Work VPN" key_password)" ]
}

@test "secrets_delete_profile leaves other profiles' secrets alone" {
  _use_file_backend
  secrets_set "Work VPN" token_secret "seed-work"
  secrets_set "Home VPN" token_secret "seed-home"

  secrets_delete_profile "Work VPN"

  [ -z "$(secrets_get "Work VPN" token_secret)" ]
  [ "$(secrets_get "Home VPN" token_secret)" = "seed-home" ]
}

@test "secrets_delete_profile is a no-op (not an error) when nothing is stored" {
  _use_file_backend
  run secrets_delete_profile "Never Used"
  [ "$status" -eq 0 ]
}

@test "SECRET_FIELDS covers every field the codebase stores" {
  # Guards the list in encryption.sh against a new secrets_set field being
  # added elsewhere without being added to SECRET_FIELDS.
  local found f
  found="$(grep -rhoE 'secrets_set +"[^"]+" +"?[a-z_]+"?' \
             "$BATS_TEST_DIRNAME/../setup.sh" "$BATS_TEST_DIRNAME/../vpn-up.command" 2>/dev/null \
           | grep -oE '(password|token_secret|key_password|sudo_password)' | sort -u)"
  [ -n "$found" ]   # the grep itself must still match something
  for f in $found; do
    # sudo_password is legacy cleanup only; it is never stored any more.
    [ "$f" = "sudo_password" ] && continue
    case " $SECRET_FIELDS " in
      *" $f "*) : ;;
      *) echo "field '$f' is stored somewhere but missing from SECRET_FIELDS"; return 1 ;;
    esac
  done
}

# --- vault durability: a failed write must never destroy the existing vault ---
#
# The bug these cover: _vault_encrypt used to write openssl's output straight
# over the only copy of the vault, ignore openssl's exit status, and return 0
# regardless — so a failed encryption truncated the vault while the caller
# reported success.

_seed_vault() {   # one good entry, so there is something to lose
  secrets_set_openssl "$(secrets_key 'Work VPN' password)" "original-pw"
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}

@test "vault: successful set reports success and is readable back" {
  _seed_vault
  run secrets_set_openssl "$(secrets_key 'Work VPN' token_secret)" "seed-1"
  [ "$status" -eq 0 ]
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' token_secret)")" = "seed-1" ]
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' password)")"     = "original-pw" ]
}

@test "vault: encryption failure reports failure and leaves the vault intact" {
  _seed_vault
  local _before; _before="$(cat "$SECRETS_VAULT")"

  # openssl fails only when encrypting; decryption still works so we can verify.
  openssl() {
    local a; for a in "$@"; do [ "$a" = "-d" ] && { command openssl "$@"; return $?; }; done
    return 1
  }

  run secrets_set_openssl "$(secrets_key 'Work VPN' password)" "should-not-land"
  [ "$status" -ne 0 ]

  unset -f openssl
  [ "$(cat "$SECRETS_VAULT")" = "$_before" ]
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}

@test "vault: silently empty encrypt output is refused, vault intact" {
  _seed_vault
  local _before; _before="$(cat "$SECRETS_VAULT")"

  # Exits 0 but writes nothing — the case a bare status check would miss.
  openssl() {
    local a; for a in "$@"; do [ "$a" = "-d" ] && { command openssl "$@"; return $?; }; done
    return 0
  }

  run secrets_set_openssl "$(secrets_key 'Work VPN' password)" "should-not-land"
  [ "$status" -ne 0 ]

  unset -f openssl
  [ "$(cat "$SECRETS_VAULT")" = "$_before" ]
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}

@test "vault: write-verify catches ciphertext that does not read back" {
  _seed_vault
  local _before; _before="$(cat "$SECRETS_VAULT")"

  # Encrypt "succeeds" but produces garbage: only the read-back check sees this.
  openssl() {
    local a out=""
    for a in "$@"; do [ "$a" = "-d" ] && { command openssl "$@"; return $?; }; done
    # find the -out target and write plausible-looking but undecryptable bytes
    while [ "$#" -gt 0 ]; do [ "$1" = "-out" ] && { out="$2"; break; }; shift; done
    cat > /dev/null
    printf 'U2FsdGVkX1_not_real_ciphertext\n' > "$out"
    return 0
  }

  run secrets_set_openssl "$(secrets_key 'Work VPN' password)" "should-not-land"
  [ "$status" -ne 0 ]

  unset -f openssl
  [ "$(cat "$SECRETS_VAULT")" = "$_before" ]
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}

@test "vault: no temp file is left behind after a failed write" {
  _seed_vault
  openssl() {
    local a; for a in "$@"; do [ "$a" = "-d" ] && { command openssl "$@"; return $?; }; done
    return 1
  }
  run secrets_set_openssl "$(secrets_key 'Work VPN' password)" "nope"
  unset -f openssl
  [ "$status" -ne 0 ]
  run bash -c 'ls "'"$SECRETS_VAULT"'".tmp.* 2>/dev/null'
  [ -z "$output" ]
}

@test "vault: delete propagates an encryption failure" {
  _seed_vault
  openssl() {
    local a; for a in "$@"; do [ "$a" = "-d" ] && { command openssl "$@"; return $?; }; done
    return 1
  }
  run secrets_delete_openssl "$(secrets_key 'Work VPN' password)"
  unset -f openssl
  [ "$status" -ne 0 ]
  [ "$(secrets_get_openssl "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}

# --- plain file backend: same durability contract ---

@test "file backend: rename failure reports failure and keeps the old contents" {
  secrets_set_file "$(secrets_key 'Work VPN' password)" "original-pw"
  local _before; _before="$(cat "$SECRETS_PLAIN")"
  mv() { return 1; }
  run secrets_set_file "$(secrets_key 'Work VPN' password)" "should-not-land"
  unset -f mv
  [ "$status" -ne 0 ]
  [ "$(cat "$SECRETS_PLAIN")" = "$_before" ]
  [ "$(secrets_get_file "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}

@test "file backend: delete rename failure propagates (old code ended in chmod and swallowed it)" {
  secrets_set_file "$(secrets_key 'Work VPN' password)" "original-pw"
  local _before; _before="$(cat "$SECRETS_PLAIN")"
  mv() { return 1; }
  run secrets_delete_file "$(secrets_key 'Work VPN' password)"
  unset -f mv
  [ "$status" -ne 0 ]
  [ "$(cat "$SECRETS_PLAIN")" = "$_before" ]
  [ "$(secrets_get_file "$(secrets_key 'Work VPN' password)")" = "original-pw" ]
}
