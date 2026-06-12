# VPN Up for OpenConnect

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

## Secure Command-Line Client for Cisco AnyConnect (macOS & Linux)

**VPN Up for OpenConnect** is a modern, secure, and user-friendly Bash-based wrapper around `openconnect`, designed to simplify VPN connections while following best practices for security and maintainability.

This project is intended for **legitimate and authorized VPN access only**.

---

## 🚀 Features

### 🔐 Security First
- **No plaintext passwords**
- Secure storage via:
  - macOS **Keychain**
  - Linux **Secret Service**
  - OpenSSL-encrypted vault fallback (AES-256-CBC + PBKDF2)
- Automatic migration of legacy plaintext passwords
- The sudo password is never stored; passwordless operation via a scoped sudoers rule (see below)

### 🧠 Modern Architecture
- Requires **Bash ≥ 4**
- Fully modular codebase
- Safe command execution (no `eval`)
- Robust error handling and diagnostics

### 🔑 VPN & Authentication
- Multiple VPN profiles via XML
- Supported protocols:
  - Cisco AnyConnect (default)
  - Juniper Network Connect
  - Palo Alto GlobalProtect
  - Pulse Secure
- Duo 2FA support:
  - `push`, `phone`, `sms`, or 6-digit passcode
  - `passcode` in the profile prompts for the one-time code at connect time
  - Empty 2FA field allows gateway auto-push
- Correct handling of **AuthGroup** (realm) selection

### 🌍 Cross-Platform
- macOS (Apple Silicon & Intel)
- Linux (Debian/Ubuntu/RHEL/Fedora)
- Background or foreground execution
- Split routing handled by OpenConnect

### 🎨 User Experience
- Interactive profile selection
- Setup wizard
- ASCII banner (shown when interactive)
- Clear, color-coded output
- Diagnostic command (`doctor`)

---

## 📋 Requirements

### Mandatory
- **Bash ≥ 4**
- `openconnect`
- `xmlstarlet`

### Optional (recommended)
- `openssl` (for encrypted vault fallback)
- `secret-tool` (Linux keyring)

---

## 🛠 Installation

### Homebrew (macOS / Linux — recommended)

```bash
brew tap sorinipate/vpn-up
brew install vpn-up
```

Installs the `vpn-up` command with all dependencies (modern Bash,
openconnect, xmlstarlet) and bash completion. Your data stays in
`~/.config/vpn-up` either way.

### Manual — macOS (Apple Silicon / Intel)

macOS ships with Bash 3.2. Install modern Bash:

```bash
brew install bash openconnect xmlstarlet
```

Ensure Homebrew Bash is first in your PATH:
```bash
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zprofile
exec $SHELL -l
```

Or hard-wire the shebang in `vpn-up.command`:
```bash
#!/opt/homebrew/bin/bash
```

---

### Manual — Linux

```bash
# Debian / Ubuntu
sudo apt install bash openconnect xmlstarlet openssl

# RHEL / CentOS
sudo yum install bash openconnect xmlstarlet openssl

# Fedora
sudo dnf install bash openconnect xmlstarlet openssl
```

---

## ⚙️ Setup

```bash
chmod +x vpn-up.command
./vpn-up.command setup
```

The setup wizard will:
- Create configuration files
- Validate dependencies
- Prepare secure storage backends

---

## 📁 Configuration

All user state (config, profiles, secrets vault, logs, PID files) lives in
**`~/.config/vpn-up`** (override with `VPN_UP_HOME` or `XDG_CONFIG_HOME`),
so updating or deleting the program directory never touches your data.
Legacy files from the old in-repo `config/` directory are migrated
automatically on first run.

### Main Config
`~/.config/vpn-up/vpn-up.command.config`

```bash
readonly QUIET=TRUE          # openconnect output verbosity
readonly BACKGROUND=TRUE
readonly SHOW_BANNER=TRUE    # ASCII banner on start (independent of QUIET)
readonly NOTIFICATIONS=TRUE  # desktop notification on connect/disconnect
readonly ENCRYPTION_ENABLED=TRUE
```

> ⚠️ `ENCRYPTION_KEY` is intentionally ignored.  
> OS keychain/keyring is always preferred.  
> The OpenSSL vault prompts for a passphrase when needed.

---

### VPN Profiles
`~/.config/vpn-up/vpn-up.command.profiles`
(template seeded from `config/vpn-up.command.profiles.default` on first run)

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

#### Supported tag aliases
- `username` or `user`
- `group` or `authGroup`
- `duoMethod` or `duo2FAMethod`

---

## ▶️ Usage

### Basic Commands
```bash
./vpn-up.command start                  # interactive profile menu
./vpn-up.command start "Frankfurt VPN"  # connect directly (scriptable)
./vpn-up.command list                   # list configured profiles
./vpn-up.command add-profile            # guided profile creation (+ secret, + pin)
./vpn-up.command remove-profile "Old VPN"  # remove profile + secret + logs + service
./vpn-up.command status                 # profile, gateway, uptime
./vpn-up.command logs -f                # follow the connection log
./vpn-up.command stop                   # stop the VPN (or: stop "Frankfurt VPN")
```

Each profile keeps its own log and PID/state files under `~/.config/vpn-up`,
so `status`, `stop`, and `logs` are profile-aware.

### Run as a login service (auto-reconnect)
```bash
./vpn-up.command service install "Frankfurt VPN"    # connect at login, reconnect on drop
./vpn-up.command service status
./vpn-up.command service uninstall "Frankfurt VPN"
```
Uses a launchd user agent on macOS and a systemd user unit on Linux; the
service manager supervises openconnect in the foreground and relaunches it
if the tunnel drops (30s throttle). Requirements:
- the passwordless sudoers rule for openconnect (see above) — there is no TTY
  to type a sudo password into
- the profile's password stored in the secrets backend
- a non-interactive 2FA method (`push`, `phone`, `sms` — not `passcode`)

Desktop notifications fire on connect/disconnect (macOS Notification Center /
`notify-send`); disable with `NOTIFICATIONS=FALSE` in the config.

### Hooks

Drop executable scripts into `~/.config/vpn-up/hooks/connected.d/` or
`~/.config/vpn-up/hooks/disconnected.d/` and they run (in name order) when a
tunnel comes up or goes down — mount shares, switch proxies, ping monitoring.
Hooks receive `VPN_EVENT`, `VPN_NAME`, and `VPN_HOST` in their environment
(never the password). Because hooks are executable code, a hook is **skipped
unless it is owned by you and not group/world-writable** — same rule as the
config file. Hook failures are reported but never block the VPN.

```bash
mkdir -p ~/.config/vpn-up/hooks/connected.d
cat > ~/.config/vpn-up/hooks/connected.d/10-hello <<'EOF'
#!/bin/sh
echo "$(date): $VPN_NAME up ($VPN_HOST)" >> "$HOME/vpn-history.log"
EOF
chmod 700 ~/.config/vpn-up/hooks/connected.d/10-hello
```

### Shell completion
```bash
# bash (~/.bashrc)
source /path/to/vpn-up-for-openconnect/completions/vpn-up.bash

# zsh (~/.zshrc)
autoload -U +X bashcompinit && bashcompinit
source /path/to/vpn-up-for-openconnect/completions/vpn-up.bash
```
Completes commands and profile names (spaces handled).

### Secrets Management
```bash
./vpn-up.command set-secret "Frankfurt VPN" password
./vpn-up.command delete-secret "Frankfurt VPN" password
```

### Passwordless sudo (optional)

`openconnect` needs root. By default you'll get the normal `sudo` prompt.
Never store your sudo password anywhere; if you want non-interactive runs,
grant passwordless sudo for `openconnect` **only**:

```bash
# macOS (Homebrew):
echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
# Linux:
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
sudo chmod 440 /etc/sudoers.d/vpn-up
sudo visudo -cf /etc/sudoers.d/vpn-up   # validate
```

> Verify the `openconnect` path with `command -v openconnect`. Keep the rule
> scoped to the one binary — do not add broad commands like `kill` here.
> Stopping the VPN will still ask for your sudo password; that's intentional.

### Certificate pinning
```bash
./vpn-up.command pin vpn.example.com          # print the pin
./vpn-up.command pin --save "Frankfurt VPN"   # write it into the profile
```
Prints the gateway's `pin-sha256:...` value for `<serverCertificate>`,
or saves it into the profile directly with `--save`.
If no pin is configured, the gateway's certificate **must** validate against
the system trust store or the connection is refused (fail closed). Legacy
SHA1 pins still work but print a deprecation warning — re-pin with the
command above. Verify any pin out-of-band with your VPN administrator
before trusting it.

### Diagnostics
```bash
./vpn-up.command doctor
```

---

## 🔄 Migration Notes

- Plaintext `<password>` values in profiles are **automatically migrated** on first use
- After migration the `<password>` tag is **blanked in the XML automatically** — plaintext never lingers on disk
- The `<password>` field is deprecated; prefer `./vpn-up.command set-secret "<profile>" password`
- Ensure correct `authGroup` is set to avoid login prompts

---

## ⚠️ Known Behavior

- Some AnyConnect gateways emit:
  ```
  Unexpected 404 result from server
  ```
  This is **benign** if the connection proceeds successfully.

---

## 📄 License

MIT License  
© Sorin-Doru Ipate

---

## 🙏 Acknowledgments

Thanks to all contributors and users who helped test and refine this release.

---

## 🔖 Version History

See [CHANGELOG.md](CHANGELOG.md) for full release history.

---

**This project is production-ready, secure, and actively maintained.**