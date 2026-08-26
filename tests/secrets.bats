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
