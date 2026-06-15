# Architecture — VPN Up for OpenConnect

**Last updated:** 2026-06-16 (v3.7.0)

> *What* and *why* live in [PRD.md](PRD.md); this document covers *how*. Function and
> file references are accurate as of the version above — verify against the source
> before relying on a specific line.

---

## 1. Design principles

1. **Wrap, don't reimplement.** OpenConnect owns tunnelling, protocols, and TLS.
   VPN Up owns profiles, credentials, lifecycle, and ergonomics.
2. **Secrets never leak.** No plaintext at rest, no credentials in `argv` (visible in
   the process table) or in child-process environments, no `eval`.
3. **Fail closed.** Unknown server identity, unsafe file permissions, or missing
   prerequisites stop the flow rather than proceeding insecurely.
4. **Small, modular, auditable Bash.** One concern per file; pure functions where
   possible; everything readable in an afternoon.
5. **Portable.** macOS + Linux, Bash ≥ 4; GNU/BSD tool differences are abstracted in helpers.
6. **User state is sacred and isolated.** It lives outside the program directory so
   reinstalling/cleaning the repo never touches it.

## 2. High-level shape

```
              ┌─────────────────────────────────────────────┐
   user  ───▶ │  vpn-up.command  (entry point / dispatcher)  │
              │  • Bash≥4 guard, set -u                       │
              │  • resolve paths, migrate legacy state        │
              │  • source modules, dispatch subcommand        │
              └───────────────┬─────────────────────────────-┘
                              │ sources (in order)
   logging.sh ─ ui.sh ─ dependencies.sh ─ encryption.sh ─ network.sh ─
   profiles.sh ─ core.sh ─ setup.sh ─ service.sh
                              │
                              ▼
        ┌───────────────┐         ┌──────────────────────────┐
        │  profiles XML │         │  secrets backend          │
        │ ~/.config/... │         │  Keychain / Secret Service │
        └───────────────┘         │  / OpenSSL vault          │
                              │    └──────────────────────────┘
                              ▼
                    sudo openconnect …  ──▶  tun interface + routes
                              │
            per-profile pid / state / log under ~/.config/vpn-up
```

## 3. Module responsibilities

All modules are sourced by [vpn-up.command](vpn-up.command) in dependency order.

| Module | Responsibility |
|---|---|
| **[vpn-up.command](vpn-up.command)** | Entry point. Bash≥4 guard, `set -u`, resolves `PROGRAM_NAME`/`PROGRAM_PATH`/`DATA_DIR`, one-time migration of legacy in-repo state, sources modules, and dispatches the subcommand `case`. Defines `DISPLAY_NAME` indirectly (via logging). |
| **[logging.sh](logging.sh)** | Paths, print helpers (`print_primary/success/warning/danger`), portable `stat` wrappers (`file_owner_uid`, `file_mode` — GNU `-c` first, BSD `-f` fallback), `profile_slug`, per-profile path setup (`set_profile_paths`), PID helpers (`is_openconnect_pid`, `any_vpn_running`), `show_logs`. Defines `DISPLAY_NAME`. |
| **[ui.sh](ui.sh)** | ASCII banner (`show_banner`, gated by `SHOW_BANNER` + TTY) and desktop notifications (`notify` → `osascript`/`notify-send`, gated by `NOTIFICATIONS`). |
| **[dependencies.sh](dependencies.sh)** | `require_bin`, `check_dependencies`, `doctor`. Also `openconnect_major` / `require_openconnect_sso` (the openconnect ≥ 9.0 gate for SSO). |
| **[encryption.sh](encryption.sh)** | Secret backend abstraction: `secrets_set/get/delete`, `secrets_backend` selection (macOS Keychain via `security -i` stdin; Linux Secret Service via `secret-tool`; OpenSSL AES-256-CBC + PBKDF2 vault fallback). Namespacing via `secrets_key`. |
| **[network.sh](network.sh)** | Connectivity check, certificate fetch/verify (`fetch_server_pin`, `verify_gateway_cert`), pin save (`pin_save`), `print_pin_instructions`, `print_current_ip_address`. |
| **[profiles.sh](profiles.sh)** | Profile XML read/validate: `load_profile_fields` (xmlstarlet → shell vars), `xpath_literal` (injection-safe XPath), `list_profiles`, `profile_names_raw`, `profile_exists`, password migration/scrub, protocol/2FA descriptions. |
| **[core.sh](core.sh)** | Main flow: `start`, `connect`, `run_openconnect`, `status`, `stop`, `write_connection_state`, `run_hooks`, `assert_safe_to_source`, `load_config`, `resolve_external_browser`. |
| **[setup.sh](setup.sh)** | Interactive wizards: `setup_wizard`, `add_profile_wizard`, `remove_profile`, `append_profile`, `save_configuration`, `_bool_default`. |
| **[service.sh](service.sh)** | Login-service mode: launchd plist / systemd unit generation, `service_install/uninstall/status`, `_service_preflight` (rejects passcode + SSO profiles). |
| **[completions/vpn-up.bash](completions/vpn-up.bash)** | Bash/zsh completion for commands and profile names. |

## 4. Data & state layout

All user state lives under **`DATA_DIR`** = `${VPN_UP_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/vpn-up}`,
created `700`, files `600`. Legacy in-repo `config/<name>.*` files migrate here on first run.

```
~/.config/vpn-up/
├── vpn-up.command.config        # sourced shell config (BACKGROUND, QUIET, SHOW_BANNER, NOTIFICATIONS, …)
├── vpn-up.command.profiles      # <VPNs> XML; one <VPN> per profile
├── vpn-up.command.secrets[.enc] # OpenSSL vault (only if that backend is in use)
├── logs/<name>.<slug>.log       # per-profile connection log (+ service.<slug>.log)
├── pids/<name>.<slug>.pid       # per-profile PID
├── pids/<name>.<slug>.state     # profile/host/connected_at for `status`
└── hooks/{connected,disconnected}.d/*   # user lifecycle scripts (must be safely owned)
```

`PROGRAM_NAME` (e.g. `vpn-up.command`) namespaces data files, slugs, and the Keychain
namespace; `DISPLAY_NAME` (`vpn-up`) is used only in user-facing text.

### Profile schema (`<VPN>`)
`name`, `protocol`, `host`, `authGroup` (alias `group`), `user` (alias `username`),
`password` (deprecated; migrated + blanked), `duo2FAMethod` (alias `duoMethod`),
`serverCertificate`, `authMode` (`password` default | `sso`). `load_profile_fields`
reads them positionally via `mapfile`, so **new fields are appended last** to avoid
shifting indices.

## 5. Key flows

### 5.1 `start` → `connect` → `run_openconnect`
1. **`start`** ensures config exists (else `setup_wizard`), loads it (`load_config`
   after `assert_safe_to_source`), handles the no-profiles first-run, runs network +
   already-running checks, then selects a profile (named or interactive menu).
2. `load_profile_fields` populates shell vars. For non-SSO profiles,
   `migrate_or_fetch_password` retrieves the secret (migrating legacy plaintext).
3. **`connect`** validates host/protocol, branches on auth:
   - **SSO** → service-mode + `nc` guards + `require_openconnect_sso` (≥ 9.0).
   - **Duo passcode** → prompt at connect time (refused in service mode).
   - Fail-closed server identity: `pin-sha256` pin, else `verify_gateway_cert`.
4. **`run_openconnect`** builds the `openconnect` argv array (no `eval`) and invokes
   `sudo openconnect …`:
   - **Password mode:** `--passwd-on-stdin`; password (+ optional Duo answer) piped on stdin.
   - **SSO mode:** `--external-browser=<resolved>`, **no** `--passwd-on-stdin`, **nothing**
     piped to stdin (openconnect keeps the TTY), forced foreground.
   - Background daemonizes (`--background`); foreground/service/SSO stay attached and
     the PID is captured via `pgrep` after a short delay (openconnect only writes
     `--pid-file` when daemonizing). `notify` + `run_hooks` fire on connect/disconnect.

### 5.2 Browser-command resolution (SSO)
`resolve_external_browser`: `VPN_UP_EXTERNAL_BROWSER` override → bundled
`openconnect-external-browser` → platform default (`open` / `xdg-open`). OpenConnect
opens the SSO URL and catches the returned token on its own localhost listener.

### 5.3 `stop` / `status`
Both scan `~/.config/vpn-up/pids/*.pid`. `status` reports details from the matching
`.state` and prunes stale entries. `stop` does `sudo kill` (openconnect runs as root),
waits, SIGKILL fallback, then cleans pid/state and fires the disconnected hook.

### 5.4 Service mode
`service install` writes a launchd plist (macOS) or systemd user unit (Linux) that runs
`vpn-up start <profile>` with `VPN_UP_SERVICE=1` and supervises openconnect in the
foreground (KeepAlive/Restart for auto-reconnect). `_service_preflight` refuses
passcode and SSO profiles (interactive) and warns on missing passwordless sudo / stored
password.

## 6. Security model (summary)

- **Config is executable shell** → sourced only after `assert_safe_to_source`
  (owner == current user, not group/world-writable). Same check gates hooks.
- **Secrets** live in OS keychain/keyring or an encrypted vault; the macOS path uses
  `security -i` (stdin) to keep secrets out of `argv`; the vault uses `-pass env:` with
  no decrypted temp files and fails closed on a wrong passphrase. Secrets are never `export`ed.
- **Server identity** fails closed (pin or trust store). XPath built via `xpath_literal`
  to prevent injection from profile names.
- **Privilege** — only `openconnect`/`kill` run under `sudo`; the sudo password is never
  stored. Optional scoped `sudoers.d` rule documented for non-interactive use.
- Full model and reporting: [SECURITY.md](SECURITY.md).

## 7. Quality & CI

- **Tests:** `bats` suite under [tests/](tests/) (`cli`, `core`, `lifecycle`, `logging`,
  `network`, `profiles`, `secrets`, `service`, `sso`, `ui_setup`), with stubs for
  network, sudo, keychain, and service managers.
- **CI** ([.github/workflows/ci.yml](.github/workflows/ci.yml)): shellcheck +
  `bats tests/` on **macOS and Ubuntu** + gitleaks + CodeQL on every push/PR. `main` is
  protected and PR-only.
- **Release** ([.github/workflows/release-tap.yml](.github/workflows/release-tap.yml)):
  publishing a GitHub release patches the Homebrew tap formula's `url` + `sha256`.

## 8. Notable design decisions & trade-offs

- **XML profiles via `xmlstarlet`** — human-editable and tag-alias tolerant; the cost is
  a dependency and positional field loading (mitigated by append-only schema growth).
- **Positional `mapfile` field loading** — fast and empty-field-safe (vs. `read -d`
  which collapses blank fields); requires new fields to be appended last.
- **One connection at a time** — per-profile state files make `status`/`stop`/`logs`
  accurate without the complexity of concurrent tunnels.
- **Wrapper, foreground PID capture via `pgrep`** — openconnect writes `--pid-file` only
  when daemonizing, so foreground/service/SSO sessions self-record after a short delay.
- **SSO forced foreground, no stdin pipe** — the single most important correctness
  detail for browser auth; the TTY must stay attached.
- **`PROGRAM_NAME` vs `DISPLAY_NAME`** — data-file/slug/Keychain namespace is decoupled
  from user-facing naming, so the public command reads `vpn-up` without disturbing state paths.
