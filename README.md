# VPN Up for OpenConnect

## A Command-Line Client for Cisco AnyConnect on macOS

VPN Up is a shell script designed to enhance your experience with OpenConnect on macOS. It simplifies the process of establishing a VPN connection and offers a range of features to make VPN usage more efficient and user-friendly.

---

## Features

- **Multiple VPN Connections**: Define and manage multiple VPN connections using different protocols.
- **Password-Free Login**: Run OpenConnect without the need to enter a username and password every time.
- **Background Mode**: Option to run the script in the background or quietly.
- **Certificate Authentication**: Support for authenticating with a certificate.
- **Two-Factor Authentication**: Integrated support for Duo's 2FA.
- **VPN Connection Status**: Check the status of your VPN connection easily.

---

## What's New

- **Configuration Profiles**: Application configuration and profiles have been externalized for easier management.
- **Duo 2FA Support**: Added 🆒 support for Duo Two-Factor Authentication.
- **Protocol Flexibility**: Now supports different VPN protocols.
- **Enhanced Options**: New options for start, stop, status, restart, and status checks.
- **Connection Status Check**: Ability to verify the status of the VPN connection.

---

## Sample Configuration

```bash
readonly SUDO=FALSE  # Options: TRUE or FALSE
readonly SUDO_PASSWORD=""

readonly BACKGROUND=TRUE  # Options: TRUE (Runs in background), FALSE (Runs in foreground)
readonly QUIET=TRUE       # Options: TRUE (Less output), FALSE (Detailed output)
```

---

## Sample VPN Profile

```bash
# VPN PROFILE 1
export VPN1_NAME="My Company VPN"
export VPN1_PROTOCOL=anyconnect
export VPN1_HOST=vpn.mycompany.com
export VPN1_AUTHGROUP=developers
export VPN1_USER=sorinipate
export VPN1_PASSWD="MyPassword"
export VPN1_DUO2FAMETHOD="push"  # Duo 2FA Method options: passcode, push, phone, sms
export VPN1_SERVER_CERTIFICATE="SHA1-OtherCharachters"
```

---

## How to Run VPN Up

1. **Install OpenConnect**: Ensure `openconnect` is installed. Instructions [here](https://formulae.brew.sh/formula/openconnect).
2. **Download the Script**: Get the latest release from [this link](https://github.com/sorinipate/vpn-up-for-openconnect/releases/tag/v1.3-alpha).
3. **Move the Folder**: Relocate the `vpn-up-for-openconnect` folder to the `bin` directory.
4. **Update Configuration**: Modify `vpn-up.command.config` with appropriate settings.
5. **Set Up VPN Profiles**: Update `vpn-up.command.profiles` with your VPN information. Ensure consistency in the number of profiles across the configuration files.
6. **Create an Alias**: Set up an alias in your `bash` or `zsh` shell. Instructions [here](https://wpbeaches.com/make-an-alias-in-bash-or-zsh-shell-in-macos-with-terminal/).
7. **Launch VPN Up**: Run `vpn-up` in your terminal to start.

---
