# Changelog
All notable changes to **VPN Up for OpenConnect** will be documented in this file.

The format is inspired by *Keep a Changelog* and this project adheres to **Semantic Versioning**.

---

## [v3.1.0] — 2026-06-12
### UI Update

### Added
- `SHOW_BANNER` configuration setting (default `TRUE`) to control the
  start-up ASCII banner (PR #22).
- Setup wizard prompt for the banner preference; `doctor` includes
  `SHOW_BANNER` in its config preview (PR #22).
- ASCII banner displayed at the top of the README (PR #23).

### Changed
- `QUIET` now governs only openconnect's output verbosity; it no longer
  hides the banner. Existing configs without `SHOW_BANNER` default to
  showing it (PR #22).

---

## [v3.0.0] — 2026-06-12
### Security Hardening Release

### Breaking
- **Stored sudo password support removed.** Storing it defeated sudo's
  protection; use the scoped `sudoers.d` rule documented in the README for
  passwordless operation. Any previously stored sudo password is deleted on
  the next `setup`, and `set-secret` refuses `sudo_password`.
- **User state moved to `~/.config/vpn-up`** (config, profiles, secrets
  vault, logs, PID files) — override with `VPN_UP_HOME`/`XDG_CONFIG_HOME`.
  Legacy files in the in-repo `config/` directory migrate automatically on
  first run.
- **Server identity now fails closed**: without a `pin-sha256` pin in
  `<serverCertificate>`, the gateway certificate must validate against the
  system trust store. Legacy SHA1 pins still work but warn.

### Added
- `pin <host[:port]>` command — prints the gateway's RFC 7469 `pin-sha256`
  value and reports whether the certificate also chain-validates.
- CI: shellcheck, bats test suite (secret backends + profile parsing), and
  gitleaks secret scanning on every push/PR.
- `SECURITY.md` with reporting instructions and the security model.

### Fixed
- `stop` could never actually stop the VPN: it killed the root-owned
  openconnect process without sudo, then deleted the PID file anyway. Now
  `sudo kill` with PID-identity verification and a SIGKILL fallback.
- Stored secrets were unretrievable on the OpenSSL-vault and plain-file
  backends (keys contain `=`, which broke the field-based lookup).
- `delete-secret` on Linux was a silent no-op; now uses `secret-tool clear`.
- Empty profile fields (e.g. a blanked `<password>`) shifted every following
  field during XML parsing.
- The shell hung forever after a successful background-mode connect (the
  daemonized child kept the log pipe open).
- openconnect's stderr was not captured in the log, and the log was created
  root-owned.
- A wrong vault passphrase silently re-encrypted an empty vault (data loss);
  it now aborts.

### Security
- Plaintext `<password>` values are blanked in the profile XML after
  migration to the secrets backend; the field is deprecated.
- Secrets no longer enter child-process environments or appear on command
  lines (process table); vault contents never touch disk decrypted.
- The config file is only sourced if owned by the current user and not
  group/world-writable; data files are created `600`, directories `700`.
- Leaked credentials were purged from the published git history; GitHub
  secret scanning and push protection are enabled on the repository.

---

## [v2.0.0] — 2025-12-16
### Secure & Modern Bash Release

### Added
- Secure secrets management using:
  - macOS **Keychain**
  - Linux **Secret Service**
  - OpenSSL-encrypted vault fallback (AES-256-CBC + PBKDF2)
- Interactive setup wizard (`setup`)
- Secrets management commands:
  - `set-secret`
  - `delete-secret`
- Environment diagnostics command (`doctor`)
- Bash version guard (requires **Bash ≥ 4**)
- Modular architecture (`core`, `profiles`, `encryption`, `ui`, etc.)
- Duo 2FA support:
  - `push`, `phone`, `sms`, or 6-digit passcode
  - Empty 2FA field allows gateway auto-push
- Optional secure storage of sudo password (`__GLOBAL__.sudo_password`)

### Changed
- OpenConnect execution now uses **argv arrays** (no `eval`)
- AuthGroup (`--authgroup`) is passed before stdin authentication
- Profile XML parsing now supports both legacy and modern tags:
  - `username | user`
  - `group | authGroup`
  - `duo2FAMethod | duoMethod`
- Plaintext passwords in profiles are automatically migrated to secure storage
- UI banner rendering isolated in `ui.sh` and shown only when interactive

### Fixed
- Authentication failures caused by AuthGroup prompts consuming password input
- Duo 2FA input being misinterpreted as AuthGroup selection
- Quoting and injection issues from `eval`
- Inconsistent behavior across macOS and Linux
- Bash 3.2 incompatibilities on macOS

### Security
- Passwords are **never stored in plaintext**
- `ENCRYPTION_KEY` configuration is intentionally ignored to avoid insecure key storage
- Secrets are always retrieved from OS-level secure storage when available

### Known Issues
- Some AnyConnect gateways emit an initial “Unexpected 404” banner; this is benign if the connection proceeds successfully

---

## [v1.6-alpha] — 2023-12-06
### Cross-Platform Compatibility Update

### Added
- macOS and Linux compatibility improvements
- Automatic dependency checks and installation prompts
- Homebrew integration for macOS
- Improved user prompts and feedback
- Enhanced error handling and logging

### Changed
- Simplified setup process for new users
- Improved script robustness across environments

---

## [v1.5]
### Configuration & Authentication Enhancements

### Added
- XML-based configuration for VPN profiles
- Duo 2FA support
- Support for multiple VPN protocols:
  - AnyConnect
  - Juniper Network Connect
  - Palo Alto GlobalProtect
  - Pulse Secure

---

## [v1.0]
### Initial Release

### Added
- Basic OpenConnect wrapper
- Interactive VPN selection
- Background execution support
- Status and stop commands

---