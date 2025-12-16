# VPN Up for OpenConnect

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
- Optional secure storage of sudo password (never stored in config)

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

### macOS (Apple Silicon / Intel)

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

### Linux

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

### Main Config
`config/vpn-up.command.config`

```bash
readonly QUIET=TRUE
readonly BACKGROUND=TRUE
readonly ENCRYPTION_ENABLED=TRUE
```

> ⚠️ `ENCRYPTION_KEY` is intentionally ignored.  
> OS keychain/keyring is always preferred.  
> The OpenSSL vault prompts for a passphrase when needed.

---

### VPN Profiles
`config/vpn-up.command.profiles`

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
./vpn-up.command start
./vpn-up.command status
./vpn-up.command stop
```

### Secrets Management
```bash
./vpn-up.command set-secret "Frankfurt VPN" password
./vpn-up.command delete-secret "Frankfurt VPN" password

# Optional sudo password (secure storage only)
./vpn-up.command set-secret __GLOBAL__ sudo_password
./vpn-up.command delete-secret __GLOBAL__ sudo_password
```

### Diagnostics
```bash
./vpn-up.command doctor
```

---

## 🔄 Migration Notes

- Plaintext `<password>` values in profiles are **automatically migrated** on first use
- You may safely remove passwords from profile XML afterward
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