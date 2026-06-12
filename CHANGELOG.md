# Changelog
All notable changes to **VPN Up for OpenConnect** will be documented in this file.

The format is inspired by *Keep a Changelog* and this project adheres to **Semantic Versioning**.

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