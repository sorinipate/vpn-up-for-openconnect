# VPN Up for OpenConnect

## A Command-Line Client for Cisco AnyConnect on macOS and Linux

VPN Up is a shell script designed to enhance your experience with OpenConnect, now on both macOS and Linux distributions. It simplifies the process of establishing a VPN connection and offers a range of features to make VPN usage more efficient and user-friendly.

---

## Features

- **Cross-Platform Support**: Works seamlessly on macOS and various Linux distributions.
- **Dynamic VPN Connection Options**: Generates VPN connection options dynamically from a centralized XML configuration.
- **Multiple VPN Connections**: Define and manage multiple VPN connections using different protocols.
- **Password-Free Login**: Run OpenConnect without entering a username and password every time.
- **Background Mode**: Option to run the script in the background or quietly.
- **Certificate Authentication**: Supports authenticating with a certificate.
- **Two-Factor Authentication**: Integrated support for Duo's 2FA.
- **VPN Connection Status**: Easily check the status of your VPN connection.
- **Automatic Dependency Management**: Checks for and installs required dependencies automatically.

---

## What's New in v1.6-alpha

- **Enhanced Cross-Platform Compatibility**: The script has been updated for compatibility with both macOS and Linux distributions.
- **Automatic Dependency Checks and Installation**: The script now checks for required dependencies at startup and offers an automatic installation option for missing dependencies.
- **Homebrew Integration for macOS**: Automated checks and installation option for Homebrew on macOS, used for installing other dependencies.
- **Improved User Interaction and Feedback**: Enhanced user prompts and feedback for better clarity and user guidance.
- **Robust Error Handling**: Improved error handling mechanisms for a smoother user experience.

---

## Sample Configuration

```bash
readonly SUDO=FALSE  # Options: TRUE or FALSE
readonly SUDO_PASSWORD=""

readonly BACKGROUND=TRUE  # Options: TRUE (Runs in background), FALSE (Runs in foreground)
readonly QUIET=TRUE       # Options: TRUE (Less output), FALSE (Detailed output)
```

---

## Sample VPN Profile (XML Format)

```xml
<VPN>
    <name>VPN PROFILE 1</name>
    <protocol options="anyconnect, nc, gp, pulse">anyconnect</protocol>
    <host>vpn.example.com</host>
    <authGroup>developers</authGroup>
    <user>username</user>
    <password>&lt;password&gt;</password>
    <duo2FAMethod options="passcode, push, phone, sms">&lt;2famethod&gt;</duo2FAMethod>
    <serverCertificate>SHA1-OtherCharacters</serverCertificate>
</VPN>
```

---

## Installation and Setup

1. **Download the Script**: Get the latest release from [this link](https://github.com/sorinipate/vpn-up-for-openconnect/releases/latest).
2. **Set Up the Script**:
   - Move the `vpn-up-for-openconnect` folder to a suitable directory (e.g., `bin`).
   - Update `vpn-up.command.config` with your settings.
   - Set up your VPN profiles in `vpn-up.command.profiles.xml`.
3. **Create an Alias**: Set up an alias in your shell (`bash` or `zsh`). Instructions [here](https://wpbeaches.com/make-an-alias-in-bash-or-zsh-shell-in-macos-with-terminal/).
4. **Run VPN Up**: Execute `vpn-up` in your terminal to start. The script will handle any missing dependencies automatically.

---
