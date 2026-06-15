# Product Requirements Document — VPN Up for OpenConnect

**Status:** Living document · **Owner:** Sorin-Doru Ipate · **Last updated:** 2026-06-16 (v3.7.0)

> This PRD describes *what* VPN Up is and *why*. For *how* it's built, see
> [ARCHITECTURE.md](ARCHITECTURE.md). For the change history, see
> [CHANGELOG.md](CHANGELOG.md).

---

## 1. Overview

**VPN Up for OpenConnect** is a secure, scriptable command-line VPN manager built
on top of [OpenConnect](https://www.infradead.org/openconnect/). It lets macOS and
Linux users connect to Cisco AnyConnect, Palo Alto GlobalProtect, Pulse Secure,
Juniper Network Connect, and ocserv gateways from the terminal — with named
profiles, Duo 2FA, browser-based SSO, certificate pinning, secure secret storage,
auto-reconnect, and shell completion.

It is a *wrapper*, not a fork: OpenConnect does the tunnelling; VPN Up provides the
profile management, credential hygiene, and lifecycle ergonomics that raw
`openconnect` command lines lack.

## 2. Problem statement

Connecting to a corporate SSL VPN from the command line with raw OpenConnect means
reassembling a long, error-prone invocation every time:

```bash
echo "$PASSWORD" | sudo openconnect --protocol=anyconnect --authgroup=Employees \
  --user=me --servercert pin-sha256:… --passwd-on-stdin vpn.example.com
```

This has real problems:

- **No profiles** — every gateway is a fresh command to remember.
- **Credential leakage** — passwords end up in shell history, the process table, or
  plaintext config files.
- **2FA friction** — Duo prompts collide with AuthGroup selection and password input.
- **No lifecycle** — no clean "is it up?", "stop it", "show me the log", or
  "reconnect at login".
- **The SSO trap** — modern gateways force a browser-based SAML/SSO login that the
  password-on-stdin pattern simply cannot satisfy.

The vendor GUI clients (Cisco AnyConnect Secure Mobility Client, GlobalProtect,
etc.) solve some of this but are heavyweight, GUI-only, and fragile across OS
upgrades. There is a gap for a **terminal-first, secure, scriptable** front end.

## 3. Goals & non-goals

### Goals
- Make connecting to an OpenConnect-compatible VPN a **single command** (`vpn-up start "Work"`).
- **Never** store or expose credentials in plaintext, argv, or child-process environments.
- Support the **authentication methods real gateways use**: password, Duo 2FA
  (push/phone/sms/passcode), and browser-based SAML/SSO.
- Provide **lifecycle ergonomics**: status, stop, logs, restart, auto-reconnect at login.
- Be **safe by default** (fail-closed server identity) and **auditable** (small, modular Bash).
- Run identically on **macOS and Linux**.

### Non-goals
- **Windows support** — explicitly out of scope.
- **A GUI** — terminal-first by design.
- **Replacing OpenConnect** — VPN Up orchestrates it; it does not reimplement tunnelling.
- **Multiple simultaneous tunnels** — one active connection at a time (per-profile
  state files make bookkeeping accurate, not the tunnels concurrent). Under consideration.

## 4. Target users & personas

| Persona | Need |
|---|---|
| **Developer / DevOps engineer** | Script VPN startup before running tools or remote-support tasks; connect by name in one line. |
| **Consultant** | Juggle many client VPN profiles on one machine without re-typing gateway details. |
| **Remote worker** | Reliable connect-at-login with auto-reconnect; not dependent on a vendor GUI. |
| **Security-conscious user** | Credentials in the OS keychain, certificate pinning, no plaintext, small auditable codebase. |

## 5. User stories

- *As a developer*, I run `vpn-up start "Work"` and I'm connected after a single Duo
  push — no password typed, no command to remember.
- *As a consultant*, I keep five client profiles and pick one from a menu (`vpn-up start`).
- *As an SSO user*, I mark a profile `authMode=sso`, and `vpn-up start` opens my
  browser for the Okta/Azure/Ping + Duo login, then the tunnel comes up.
- *As a remote worker*, I run `vpn-up service install "Work"` so the VPN connects at
  login and reconnects if it drops.
- *As an operator*, I run `vpn-up status` / `vpn-up logs -f` / `vpn-up stop "Work"`
  to see and control a specific connection.
- *As a security reviewer*, I run `vpn-up doctor` to see the environment, dependency
  versions, secret backend, and SSO availability at a glance.

## 6. Functional requirements

### 6.1 Connection
- **FR-1** Connect by profile name (`start <profile>`) or via an interactive menu (`start`).
- **FR-2** Support protocols `anyconnect`, `gp`, `pulse`, `nc`, with full AuthGroup/realm support.
- **FR-3** Support Duo 2FA methods `push`, `phone`, `sms`, and one-time `passcode`
  (prompted at connect time, never read from XML).
- **FR-4** Support **browser-based SAML/SSO** (`authMode=sso`) via OpenConnect's
  `--external-browser` (openconnect ≥ 9.0; `anyconnect`/`gp` only). No password is
  piped; the flow runs foreground with the controlling TTY.
- **FR-5** Background or foreground operation, configurable; SSO and service mode force foreground.

### 6.2 Credentials & identity
- **FR-6** Store secrets in the macOS Keychain, Linux Secret Service, or an
  AES-256-CBC + PBKDF2 OpenSSL vault — never in plaintext files, argv, or child env.
- **FR-7** Migrate any legacy plaintext `<password>` to the secrets backend and blank it in the XML.
- **FR-8** Never store the sudo password; offer a documented scoped sudoers rule for passwordless use.
- **FR-9** Fail closed on server identity: require a `pin-sha256` pin **or** system
  trust-store validation; provide `pin` / `pin --save` helpers.

### 6.3 Lifecycle & operations
- **FR-10** `status` reports each running connection (profile, gateway, uptime) from per-profile state.
- **FR-11** `stop [profile]` stops all or one connection (sudo kill + verify + SIGKILL fallback).
- **FR-12** `logs [-f] [profile]` shows/follows the per-profile connection log.
- **FR-13** `restart [profile]`, `list` / `list-names`.
- **FR-14** Login service with auto-reconnect: `service install|uninstall|status`
  (launchd on macOS, systemd user unit on Linux). SSO and passcode profiles are refused (interactive).
- **FR-15** Lifecycle hooks: user scripts in `hooks/connected.d` / `hooks/disconnected.d`,
  run with `VPN_EVENT`/`VPN_NAME`/`VPN_HOST` (never the password), skipped unless safely owned.

### 6.4 Management & diagnostics
- **FR-16** Guided `setup` wizard and `add-profile` / `remove-profile` (handle XML, secrets, pins, services).
- **FR-17** `set-secret` / `delete-secret` for the secrets backend.
- **FR-18** `doctor` reports OS, dependencies + openconnect version, secret backend, SSO availability, config.
- **FR-19** Bash/zsh tab completion for commands and profile names.

## 7. Non-functional requirements

- **NFR-1 Security** — no plaintext secrets at rest or in transit to child processes;
  config sourced only if user-owned and not group/world-writable; data files `600`,
  dirs `700`; no `eval`. See [SECURITY.md](SECURITY.md).
- **NFR-2 Portability** — macOS + Linux; Bash ≥ 4; GNU/BSD differences handled
  (`stat`, `ps`, `sed`). No hard dependency beyond `openconnect`, `xmlstarlet`, and a secret backend.
- **NFR-3 Isolation** — all user state under `~/.config/vpn-up` (override via
  `VPN_UP_HOME`/`XDG_CONFIG_HOME`); reinstalling/cleaning the program directory never touches it.
- **NFR-4 Quality** — shellcheck-clean; bats test suite on macOS + Ubuntu in CI; secret scanning (gitleaks) + CodeQL.
- **NFR-5 Auditability** — small modular Bash, one concern per module; no opaque binaries.
- **NFR-6 Reliability** — fail-closed identity; accurate per-profile PID/state bookkeeping; graceful stop with fallback.

## 8. Success metrics

- Time-to-connect for a configured profile: a single command + one 2FA approval.
- Zero plaintext credentials discoverable on disk, in argv, or in `~/.bash_history`.
- CI green (shellcheck + bats on both OSes + gitleaks + CodeQL) on every change.
- Installable in one step via Homebrew tap; survives `brew upgrade`.

## 9. Out of scope / explicit limitations

- Windows; GUI; concurrent multi-tunnel.
- SSO under a non-interactive login service (requires a desktop session).
- SSO on the `nc` protocol (unsupported by OpenConnect).
- On Linux, a root-spawned SSO browser may not reach the desktop session (mitigated by
  the `VPN_UP_EXTERNAL_BROWSER` override).

## 10. Roadmap (under consideration)

- TOTP / RSA token support via OpenConnect's native `--token-mode`.
- HTTP/SOCKS proxy passthrough as a profile field.
- Multiple simultaneous tunnels (per-profile state already lays the groundwork).

## 11. Release & distribution

- Semantic Versioning; PR-only `main` with required CI. See [RELEASING.md](RELEASING.md).
- Distributed via the `sorinipate/vpn-up` Homebrew tap; publishing a GitHub release
  auto-updates the tap formula (`url` + `sha256`).
