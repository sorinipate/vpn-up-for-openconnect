# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/sorinipate/vpn-up-for-openconnect/security/advisories/new)
rather than opening a public issue. You should receive a response within a week.

## Security model

- **Passwords** are stored in the OS keychain (macOS), Secret Service
  (Linux), or an AES-256-CBC + PBKDF2 OpenSSL vault as a fallback — never in
  plaintext files unless `ENCRYPTION_ENABLED=FALSE` is set explicitly.
  Plaintext `<password>` values found in profile XML are migrated to the
  secrets backend and blanked in the XML on first use.
- **The sudo password is never stored.** For non-interactive use, create a
  sudoers rule scoped to the `openconnect` binary only (see README).
- **Server identity fails closed**: a `pin-sha256` pin in
  `<serverCertificate>`, or the gateway certificate must validate against the
  system trust store.
- **User state** (config, profiles, secrets, logs) lives in
  `~/.config/vpn-up` with `700`/`600` permissions. The config file is only
  sourced if owned by the current user and not group/world-writable.
- Secrets are never passed on command lines (process table) and are not
  exported to child-process environments.

## Scope notes

- This tool shells out to `openconnect`, `openssl`, `xmlstarlet`, and the
  platform keychain tools; vulnerabilities in those belong upstream.
- The plaintext file backend (`ENCRYPTION_ENABLED=FALSE`) is an explicit
  opt-out and is out of scope for confidentiality reports.
