# VPN Up for OpenConnect

> Secure, scriptable command-line VPN client for Cisco AnyConnect and other SSL VPNs, built on OpenConnect — for macOS & Linux.

[![CI](https://github.com/sorinipate/vpn-up-for-openconnect/actions/workflows/ci.yml/badge.svg)](https://github.com/sorinipate/vpn-up-for-openconnect/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sorinipate/vpn-up-for-openconnect)](https://github.com/sorinipate/vpn-up-for-openconnect/releases/latest)
[![License](https://img.shields.io/github/license/sorinipate/vpn-up-for-openconnect)](LICENSE)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue)

```text
    ╔═════════════════════════════════════════════════════════════════╗
    ║                                                                 ║
    ║ ██╗   ██╗  ██████╗    ███╗   ██╗           ██╗   ██╗   ██████╗  ║
    ║ ██║   ██║  ██╔══██╗   ████╗  ██║           ██║   ██║   ██╔══██╗ ║
    ║ ██║   ██║  ██████╔╝   ██╔██╗ ██║  ███████  ██║   ██║   ██████╔╝ ║
    ║ ╚██╗ ██╔╝  ██╔═══╝    ██║╚██╗██║           ██║   ██║   ██╔═══╝  ║
    ║  ╚████╔╝   ██║        ██║ ╚████║           ╚██████╔╝   ██║      ║
    ║   ╚═══╝    ╚═╝        ╚═╝  ╚═══╝            ╚═════╝    ╚═╝      ║
    ║                                                                 ║
    ║                   F O R   O P E N C O N N E C T                 ║
    ╚═════════════════════════════════════════════════════════════════╝
```

```console
$ vpn-up start "Frankfurt VPN"
Starting the Frankfurt VPN on frankfurt.simplica.com using Cisco AnyConnect ...
Connecting with Two-Factor Authentication (2FA) from Duo (PUSH) ...
Connected to Frankfurt VPN

$ vpn-up status
VPN is running (PID: 88933)
  Profile : Frankfurt VPN
  Gateway : frankfurt.simplica.com
  Since   : 2026-06-12 22:49:14
  Uptime  : 08:47
```

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Commands](#commands)
  - [Run as a login service](#run-as-a-login-service-auto-reconnect)
  - [Hooks](#hooks)
  - [Shell completion](#shell-completion)
  - [Secrets management](#secrets-management)
  - [Passwordless sudo](#passwordless-sudo-optional)
  - [Certificate pinning](#certificate-pinning)
  - [Diagnostics](#diagnostics)
- [Configuration](#-configuration)
- [Roadmap](#-roadmap)
- [Contributing & License](#-contributing--license)

---

## 🌟 Key Features

### Connect
- **Four SSL VPN protocols** via [OpenConnect](https://www.infradead.org/openconnect/): Cisco **AnyConnect** (and ocserv), Juniper **Network Connect**, Palo Alto **GlobalProtect**, and **Pulse Secure**
- **Multiple VPN profiles** — pick from an interactive menu or connect by name with zero prompts (`vpn-up start "Work VPN"`), with full **AuthGroup/realm** support
- **Duo 2FA** — `push`, `phone`, `sms`, or one-time passcodes prompted at connect time; empty method lets the gateway auto-push
- **Background or foreground** execution, per your config

### Secure
- **No plaintext passwords** — secrets live in the macOS **Keychain**, Linux **Secret Service**, or an AES-256-CBC + PBKDF2 OpenSSL vault; legacy plaintext is migrated and scrubbed automatically, and secrets never appear on command lines or in child-process environments
- **Fail-closed server identity** — `pin-sha256` certificate pinning with a one-command pin fetch, or strict system trust-store validation
- **The sudo password is never stored** — interactive prompt by default, or a sudoers rule scoped to the one `openconnect` binary
- **Isolated user data** — config, profiles, secrets, and logs live in `~/.config/vpn-up` with `600`/`700` permissions, untouched by updates or reinstalls

### Operate
- **Profile-aware lifecycle** — `status` shows profile, gateway, and uptime; `stop` and `logs -f` target a specific connection
- **Login service with auto-reconnect** — launchd (macOS) / systemd (Linux) supervision; reconnects when the tunnel drops
- **Lifecycle hooks** — run your own scripts on connect/disconnect (mount shares, switch proxies)
- **Desktop notifications** on connect/disconnect (Notification Center / `notify-send`)

### Manage
- **Guided setup** — a first-run wizard plus `add-profile` / `remove-profile`, which handle XML, secrets, pins, and services in one step
- **`doctor`** diagnostics — environment, dependencies, secret backend, and config at a glance
- **Bash/zsh tab completion** for commands and profile names
- **Hardened & tested** — 71 tests on macOS + Ubuntu in CI, shellcheck-clean, secret scanning, modern Bash (≥ 4), no `eval`

---

## 📋 Prerequisites & Installation

### Homebrew (macOS / Linux — recommended)

```bash
brew tap sorinipate/vpn-up
brew install vpn-up
```

Installs the `vpn-up` command with all dependencies (modern Bash, openconnect, xmlstarlet) and bash completion. Your data stays in `~/.config/vpn-up` either way.

### Manual — macOS (Apple Silicon / Intel)

macOS ships with Bash 3.2. Install modern Bash and the dependencies:

```bash
brew install bash openconnect xmlstarlet
```

Ensure Homebrew Bash is first in your PATH:

```bash
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zprofile
exec $SHELL -l
```

Then clone and run:

```bash
git clone https://github.com/sorinipate/vpn-up-for-openconnect.git
cd vpn-up-for-openconnect
chmod +x vpn-up.command
```

### Manual — Linux

```bash
# Debian / Ubuntu
sudo apt install bash openconnect xmlstarlet openssl

# RHEL / CentOS
sudo yum install bash openconnect xmlstarlet openssl

# Fedora
sudo dnf install bash openconnect xmlstarlet openssl
```

Optional (recommended): `secret-tool` for Secret Service keyring storage.

---

## 🚀 Quick Start

```bash
vpn-up setup          # one-time configuration wizard
vpn-up add-profile    # guided profile creation (+ password, + certificate pin)
vpn-up start          # connect (interactive menu)
```

> Manual installs: use `./vpn-up.command` instead of `vpn-up` throughout.

---

## ▶️ Usage

### Commands

```bash
vpn-up start                       # interactive profile menu
vpn-up start "Frankfurt VPN"       # connect directly (scriptable)
vpn-up list                        # list configured profiles
vpn-up add-profile                 # guided profile creation (+ secret, + pin)
vpn-up remove-profile "Old VPN"    # remove profile + secret + logs + service
vpn-up status                      # profile, gateway, uptime
vpn-up logs -f                     # follow the connection log
vpn-up stop                        # stop the VPN (or: stop "Frankfurt VPN")
```

Each profile keeps its own log and PID/state files under `~/.config/vpn-up`, so `status`, `stop`, and `logs` are profile-aware.

### Run as a login service (auto-reconnect)

```bash
vpn-up service install "Frankfurt VPN"    # connect at login, reconnect on drop
vpn-up service status
vpn-up service uninstall "Frankfurt VPN"
```

Uses a launchd user agent on macOS and a systemd user unit on Linux; the service manager supervises openconnect in the foreground and relaunches it if the tunnel drops (30s throttle). Requirements:

- the [passwordless sudoers rule](#passwordless-sudo-optional) — there is no TTY to type a sudo password into
- the profile's password stored in the secrets backend
- a non-interactive 2FA method (`push`, `phone`, `sms` — not `passcode`)

### Hooks

Drop executable scripts into `~/.config/vpn-up/hooks/connected.d/` or `~/.config/vpn-up/hooks/disconnected.d/` and they run (in name order) when a tunnel comes up or goes down. Hooks receive `VPN_EVENT`, `VPN_NAME`, and `VPN_HOST` in their environment (never the password). Because hooks are executable code, a hook is **skipped unless it is owned by you and not group/world-writable** — same rule as the config file. Hook failures are reported but never block the VPN.

```bash
mkdir -p ~/.config/vpn-up/hooks/connected.d
cat > ~/.config/vpn-up/hooks/connected.d/10-hello <<'EOF'
#!/bin/sh
echo "$(date): $VPN_NAME up ($VPN_HOST)" >> "$HOME/vpn-history.log"
EOF
chmod 700 ~/.config/vpn-up/hooks/connected.d/10-hello
```

### Shell completion

Homebrew installs completion automatically. For manual installs:

```bash
# bash (~/.bashrc)
source /path/to/vpn-up-for-openconnect/completions/vpn-up.bash

# zsh (~/.zshrc)
autoload -U +X bashcompinit && bashcompinit
source /path/to/vpn-up-for-openconnect/completions/vpn-up.bash
```

Completes commands and profile names (spaces handled).

### Secrets management

```bash
vpn-up set-secret "Frankfurt VPN" password
vpn-up delete-secret "Frankfurt VPN" password
```

Passwords are stored in the OS keychain/keyring (or an encrypted vault as fallback) — never in files, never in the process table, never exported to child processes.

### Passwordless sudo (optional)

`openconnect` needs root. By default you'll get the normal `sudo` prompt. Never store your sudo password anywhere; if you want non-interactive runs, grant passwordless sudo for `openconnect` **only**:

```bash
# macOS (Homebrew):
echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
# Linux:
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
sudo chmod 440 /etc/sudoers.d/vpn-up
sudo visudo -cf /etc/sudoers.d/vpn-up   # validate
```

> Verify the `openconnect` path with `command -v openconnect`. Keep the rule scoped to the one binary — do not add broad commands like `kill` here. Stopping the VPN will still ask for your sudo password; that's intentional.

### Certificate pinning

```bash
vpn-up pin vpn.example.com          # print the pin
vpn-up pin --save "Frankfurt VPN"   # write it into the profile
```

Prints the gateway's `pin-sha256:...` value for `<serverCertificate>`, or saves it into the profile directly with `--save`. If no pin is configured, the gateway's certificate **must** validate against the system trust store or the connection is refused (fail closed). Legacy SHA1 pins still work but print a deprecation warning. Verify any pin out-of-band with your VPN administrator before trusting it.

### Diagnostics

```bash
vpn-up doctor
```

---

## ⚙️ Configuration

All user state (config, profiles, secrets vault, logs, PID files) lives in **`~/.config/vpn-up`** (override with `VPN_UP_HOME` or `XDG_CONFIG_HOME`), so updating or deleting the program directory never touches your data. Legacy files from the old in-repo `config/` directory are migrated automatically on first run.

### Main config — `~/.config/vpn-up/vpn-up.command.config`

```bash
readonly QUIET=TRUE          # openconnect output verbosity
readonly BACKGROUND=TRUE
readonly SHOW_BANNER=TRUE    # ASCII banner on start (independent of QUIET)
readonly NOTIFICATIONS=TRUE  # desktop notification on connect/disconnect
readonly ENCRYPTION_ENABLED=TRUE
```

> ⚠️ `ENCRYPTION_KEY` is intentionally ignored. OS keychain/keyring is always preferred. The OpenSSL vault prompts for a passphrase when needed.

### VPN profiles — `~/.config/vpn-up/vpn-up.command.profiles`

Seeded from [config/vpn-up.command.profiles.default](config/vpn-up.command.profiles.default) on first run, or created via `vpn-up add-profile`:

```xml
<VPNs>
  <VPN>
    <name>Frankfurt VPN</name>
    <protocol>anyconnect</protocol>
    <host>frankfurt.example.com</host>
    <authGroup>SimplicaEmployees</authGroup>
    <user>your.username</user>
    <password></password>
    <duo2FAMethod>push</duo2FAMethod>
    <serverCertificate>pin-sha256:BASE64_HASH</serverCertificate>
  </VPN>
</VPNs>
```

Supported tag aliases: `username`/`user`, `group`/`authGroup`, `duoMethod`/`duo2FAMethod`. The `<password>` field is deprecated: plaintext values are migrated to the secrets backend and blanked in the XML automatically on first use — prefer `vpn-up set-secret`. A `duo2FAMethod` of `passcode` prompts for the one-time code at connect time.

---

## 🗺 Roadmap

**Under consideration** (open an issue if you need one of these):

- TOTP / RSA token support via openconnect's native `--token-mode`
- HTTP/SOCKS proxy passthrough as a profile field
- Multiple simultaneous tunnels (per-profile state files already lay the groundwork)

**Explicitly out of scope:** Windows support, GUI.

**Known behavior:** some AnyConnect gateways emit an initial `Unexpected 404 result from server` — this is benign if the connection proceeds successfully.

---

## 🤝 Contributing & License

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow (PRs only, shellcheck + test suite must pass on macOS and Ubuntu).

- 🔐 Security issues: please report privately via [SECURITY.md](SECURITY.md), not public issues
- 📄 Full release history: [CHANGELOG.md](CHANGELOG.md)
- ⚖️ Licensed under the [MIT License](LICENSE) — © Sorin-Doru Ipate

Thanks to all contributors and users who helped test and refine this project.
