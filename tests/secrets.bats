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
  secrets_set_openssl "$(secrets_key D password)" "v"
  secrets_set_file "$(secrets_key D password)" "v"
  perms_enc="$(stat -f '%Lp' "$SECRETS_VAULT" 2>/dev/null || stat -c '%a' "$SECRETS_VAULT")"
  perms_plain="$(stat -f '%Lp' "$SECRETS_PLAIN" 2>/dev/null || stat -c '%a' "$SECRETS_PLAIN")"
  [ "$perms_enc" = "600" ]
  [ "$perms_plain" = "600" ]
}

@test "no plaintext temp files left behind" {
  secrets_set_openssl "$(secrets_key E password)" "v"
  secrets_delete_openssl "$(secrets_key E password)"
  [ ! -e "$SECRETS_TMP" ]
  [ ! -e "${SECRETS_TMP}.sorted" ]
}
