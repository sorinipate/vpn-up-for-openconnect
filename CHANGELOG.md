# Changelog
All notable changes to **VPN Up for OpenConnect** will be documented in this file.

The format is inspired by *Keep a Changelog* and this project adheres to **Semantic Versioning**.

---

## [v3.9.1] — 2026-06-18
### Fixed

- The default profiles template (`config/vpn-up.command.profiles.default`) could not
  be parsed by `xmlstarlet`: its `<extraArgs>` comments contained `--` (e.g.
  `--no-dtls`, `--protocol`), which the XML spec forbids inside comments and modern
  libxml2 rejects as a fatal error. Users who **edit the seeded template by hand**
  (rather than using `add-profile`, which generates comment-free XML) hit
  `Double hyphen within comment` errors and an empty list from `vpn-up list` and the
  interactive `start` menu, and silent "no profiles" detection. Reworded the comments
  to be `--`-free; added a regression test that parses the shipped template.

---

## [v3.9.0] — 2026-06-18
### Client-certificate authentication

### Added
- **Client-certificate authentication** (`<clientCertificate>` / `<clientKey>`,
  also prompted by `add-profile`). Authenticate with an X.509 cert/key **file** or
  a **PKCS#11 URI** (smartcard / **YubiKey PIV**), on its own (cert-only) or
  alongside a password, Duo, TOTP, or SSO — it's additive and doesn't change the
  auth precedence. The cert/key **path or URI is not a secret** (it stays in the
  profile); a key passphrase or PKCS#11 PIN **never reaches openconnect's argv**.
  An encrypted key/token prompts interactively; for unattended/login-service use,
  store a PKCS#11 PIN (`vpn-up set-secret '<profile>' key_password`) and `vpn-up`
  feeds it through a transient `0600` `pin-source` file, shredded after the session.
- `doctor` now reports **PKCS#11** (`p11-kit`/`p11tool`) availability; `service`
  preflight understands cert-only and PKCS#11 profiles.

### Documented
- **FIDO2 / passkeys / YubiKey-WebAuthn already work with SSO** — because the
  browser-based SAML/SSO login runs in your real browser, no extra configuration is
  needed. New [client-certificate](https://sorinipate.github.io/vpn-up-for-openconnect/client-certificate-auth/)
  docs page; SSO page notes the WebAuthn support.

---

## [v3.8.0] — 2026-06-18
### TOTP 2FA & Argument Passthrough Update

### Added
- **TOTP authenticator-app 2FA** (`<tokenMode>totp</tokenMode>`). For gateways
  that prompt for a time-based code (Google Authenticator / Authy / hardware
  TOTP), store the base32 seed once (`vpn-up set-secret '<profile>' token_secret`,
  or via the `add-profile` wizard) and `vpn-up` generates the current code with
  `oathtool` at connect time and feeds it as the 2FA answer. The **seed never
  reaches openconnect's argv or disk** — only the short-lived code transits on
  stdin (we deliberately avoid `--token-secret`, which would expose it). Because
  it needs no interaction, a TOTP profile **can run as a login service with
  auto-reconnect** (unlike Duo-passcode and SSO). New `oathtool` dependency
  (TOTP only); surfaced by `doctor`; shown in `vpn-up list`.
- **Extra openconnect arguments** per profile (`<extraArgs>`, also an optional
  prompt in `add-profile`). Power-user passthrough for flags vpn-up doesn't model
  (`--no-dtls`, `--os=win`, `--csd-wrapper`, proxies, MTU, …). Tokenized with
  `xargs` so quotes are respected without `eval`; appended verbatim before the
  gateway host. Duplicating a flag vpn-up already manages prints a warning but is
  still passed.

---

## [v3.7.0] — 2026-06-16
### Browser-based SSO Login Update

### Added
- **SSO / external-browser authentication** for gateways that force a
  browser-based SAML/SSO login (Okta, Azure AD, Ping Identity — typically with
  an embedded Duo iframe). Set `<authMode>sso</authMode>` on a profile (or answer
  the new prompt in `add-profile`) and `vpn-up` connects via OpenConnect's
  `--external-browser`: no password is piped, the login happens in the browser,
  and the tunnel comes up afterward. Requires openconnect ≥ 9.0 (surfaced by
  `doctor`); supported for `anyconnect`/`gp`. SSO profiles run in the foreground
  and cannot run as a login service (interactive session required). The browser
  opener defaults to `open`/`xdg-open` and is overridable with
  `VPN_UP_EXTERNAL_BROWSER` (useful on Linux, where the root/sudo process may not
  reach the desktop session). New `AUTH` column in `vpn-up list`.

---

## [v3.6.0] — 2026-06-13
### First-Run Usability & Docs Update

### Added
- `LICENSE` file (MIT — previously only claimed in the README) and
  `CONTRIBUTING.md` with the PR/CI workflow and development setup.

### Changed
- First run of `start` with no profiles now offers the `add-profile` wizard
  interactively instead of dead-ending into "edit the XML template by hand"
  (scripts and service mode still get the template-seeding behavior).
- Setup wizard: removed the "Use sudo?" question — the `SUDO` config value
  has been dead since v3.0.0 (nothing reads it); all wizard prompts now use
  the `[Y/n]` style (y/n/true/false all accepted, as before).
- User-facing messages and usage text now say `vpn-up` (matching the
  Homebrew command) instead of the internal `vpn-up.command` name; data file
  names and the Keychain namespace are unchanged.
- README restructured: badges, table of contents, scannable feature list,
  quick start, usage examples, and a roadmap section.

---

## [v3.5.1] — 2026-06-13
### Review & Coverage Update

### Fixed
- Homebrew installs: the `vpn-up` wrapper now resolves through the stable
  `opt` path, so login services installed from a brew copy survive
  `brew upgrade` (previously the LaunchAgent pointed at a versioned Cellar
  path). Tap formula change; reinstall or upgrade picks it up.
- `service status` matched launchd labels as a regex; now an exact match.
- Config validation fails closed if file permissions cannot be determined.
- After a `Login failed` connection attempt, the error now points at
  `delete-secret` so a mistyped stored password isn't silently reused.

### Added
- Test coverage across the whole application: CLI dispatch, status/stop scan
  logic, config safety checks, log selection, notifications/banner gating,
  setup templating, secrets backend selection, service install/uninstall,
  and helper parsing — 71 bats tests total (up from 29), run on macOS and
  Ubuntu in CI.

---

## [v3.5.0] — 2026-06-12
### Lifecycle & Maintenance Update

### Added
- `remove-profile <name>` — removes the XML block, the stored secret, the
  per-profile PID/state/log files, and any installed login service in one
  confirmed step; refuses while the profile is connected.
- Lifecycle hooks: executable scripts in `~/.config/vpn-up/hooks/connected.d/`
  and `disconnected.d/` run on tunnel up/down with `VPN_EVENT`, `VPN_NAME`,
  and `VPN_HOST` in the environment. Hooks must be user-owned and not
  group/world-writable or they are skipped; failures never block the VPN.
- Release automation: publishing a GitHub release now updates the Homebrew
  tap formula (url + sha256) automatically.

### Changed
- CI runs the test suite on macOS as well as Ubuntu (added post-v3.4.0
  along with portable stat helpers that fixed config validation on Linux).

---

## [v3.4.0] — 2026-06-12
### Service & Notifications Update

### Added
- `service install|uninstall|status` — run a profile as a login service with
  auto-reconnect: launchd user agent on macOS, systemd user unit on Linux.
  The service manager supervises openconnect in the foreground and restarts
  it if the tunnel drops (30s throttle). Preflight checks catch missing
  passwordless sudo, missing stored password, and passcode-2FA profiles.
- Desktop notifications on connect/disconnect/failure (macOS Notification
  Center via osascript, Linux via notify-send); new `NOTIFICATIONS` setting
  (default `TRUE`), prompted in setup and shown by `doctor`.
- Foreground sessions now record their own PID/state (openconnect only
  writes `--pid-file` when daemonizing), so `status` and `stop` work during
  foreground and service sessions too.

### Changed
- Service mode (`VPN_UP_SERVICE=1`) fails fast with clear errors instead of
  prompting: non-interactive `sudo -n`, stored-secret requirement, and a
  passcode-2FA guard.

---

## [v3.3.0] — 2026-06-12
### Profiles & Completion Update

### Added
- `add-profile` — guided profile creation: validates inputs, appends a
  well-formed `<VPN>` block, and optionally stores the password in the
  secrets backend and saves the gateway's certificate pin in one flow.
- Bash/zsh tab completion (`completions/vpn-up.bash`) for commands and
  profile names, including names with spaces.
- Per-profile PID, state, and log files — `status` reports every running
  connection, `stop [profile]` and `logs [-f] [profile]` target a specific
  one, and `logs` with no argument shows the most recent log.

### Changed
- Stale PID/state files are cleaned up automatically during `status`.
- One-connection-at-a-time policy is kept: `start` refuses while any VPN is
  running (the per-profile files make the bookkeeping accurate, not the
  tunnels concurrent).

---

## [v3.2.0] — 2026-06-12
### Scriptability & CLI Update

### Added
- `start [profile]` / `restart [profile]` — connect directly by profile name,
  no interactive menu; with a stored secret the only interaction left is 2FA.
- `list` — tabular overview of configured profiles (name, protocol, host,
  2FA method; no secrets shown).
- `logs [-f]` — show the connection log, or follow it live.
- `pin --save <profile>` — fetch the gateway's `pin-sha256` and write it into
  the profile's `<serverCertificate>` directly.
- Richer `status`: connected profile, gateway, connect time, and uptime
  (recorded in a state file at connect, removed on stop).

### Changed
- A `duo2FAMethod` of `passcode` now prompts for the one-time code at connect
  time instead of reading a stale value from the XML.

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