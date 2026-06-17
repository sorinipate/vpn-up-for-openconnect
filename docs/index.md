---
layout: home
title: VPN Up for OpenConnect — Secure CLI VPN Manager for macOS & Linux
description: >-
  VPN Up is a secure, scriptable command-line VPN manager built on OpenConnect.
  Connect to Cisco AnyConnect, GlobalProtect, Pulse Secure and Juniper gateways
  from the terminal on macOS and Linux, with Duo 2FA and browser-based SSO.
permalink: /
---

# VPN Up for OpenConnect

**VPN Up** is a secure, scriptable command-line VPN manager built on
[OpenConnect](https://www.infradead.org/openconnect/). It connects macOS and
Linux machines to **Cisco AnyConnect**, Palo Alto **GlobalProtect**, **Pulse
Secure**, **Juniper Network Connect**, and **ocserv** gateways straight from the
terminal — with named profiles, **Duo 2FA**, **browser-based SSO**, certificate
pinning, secure secret storage, auto-reconnect, and shell completion.

It's built for developers, consultants, DevOps engineers, and remote workers who
would rather drive their VPN from the command line than a vendor GUI.

```console
$ vpn-up start "Frankfurt VPN"
Starting the Frankfurt VPN on frankfurt.example.com using Cisco AnyConnect ...
Connecting with Two-Factor Authentication (2FA) from Duo (PUSH) ...
Connected to Frankfurt VPN
```

## Install in one step

```bash
brew tap sorinipate/vpn-up
brew install vpn-up
```

See the [installation guide]({{ '/installation/' | relative_url }}) for manual setup on macOS and Linux.

## Why VPN Up?

- Connect to Cisco AnyConnect-compatible VPNs **without the vendor GUI client**
- Manage **multiple VPN profiles** and connect by name (`vpn-up start "Work"`)
- **Duo 2FA** from the command line — push, phone, SMS, or one-time passcode
- **Browser-based SSO** (Okta, Azure AD, Ping Identity) for gateways that force an external browser login
- Secrets in the macOS **Keychain**, Linux **Secret Service**, or an encrypted vault — never plaintext
- **Auto-reconnect at login** via launchd (macOS) or systemd (Linux)
- Scriptable: drop VPN startup into your dev, automation, and remote-support workflows

## Documentation

- [Installation]({{ '/installation/' | relative_url }}) — Homebrew and manual setup on macOS & Linux
- [Usage]({{ '/usage/' | relative_url }}) — commands, profiles, status/stop/logs, login service, hooks
- [SSO & Duo 2FA]({{ '/sso-duo/' | relative_url }}) — browser-based SAML/SSO login with Okta, Azure AD, Ping
- [Protocols]({{ '/protocols/' | relative_url }}) — AnyConnect, GlobalProtect, Pulse Secure, Juniper
- [Troubleshooting]({{ '/troubleshooting/' | relative_url }}) — common connection problems and fixes

## Guides

- [Cisco AnyConnect command-line alternative]({{ '/anyconnect-cli-alternative/' | relative_url }}) — connect to AnyConnect VPNs without the GUI client
- [Connect to GlobalProtect from the command line]({{ '/globalprotect-cli/' | relative_url }}) — Palo Alto GlobalProtect via OpenConnect
- [Auto-connect a VPN at login]({{ '/vpn-at-login/' | relative_url }}) — launchd (macOS) & systemd (Linux) with auto-reconnect
- [VPN Up vs. raw OpenConnect]({{ '/vs-openconnect/' | relative_url }}) — what the wrapper adds, and when to use each
- [VPN Up vs. openconnect-sso]({{ '/vs-openconnect-sso/' | relative_url }}) — two AnyConnect SSO clients compared, fairly
- [VPN Up vs. GlobalProtect-openconnect]({{ '/vs-globalprotect-openconnect/' | relative_url }}) — two GlobalProtect CLI clients compared

## Related articles

Background and design notes:

- [A Safer OpenConnect Workflow for Cisco AnyConnect VPNs on macOS and Linux](https://architegrity.com/blog/safer-openconnect-workflow-cisco-anyconnect-macos-linux) — Architegrity
- [A Safer OpenConnect Workflow for Cisco AnyConnect VPNs on macOS and Linux](https://dev.to/sorinipate/a-safer-openconnect-workflow-for-cisco-anyconnect-vpns-on-macos-and-linux-5g7o) — Dev.to
- [A Safer OpenConnect Workflow for Cisco AnyConnect VPNs on macOS and Linux](https://medium.com/@sorin.ipate/a-safer-openconnect-workflow-for-cisco-anyconnect-vpns-on-macos-and-linux-50062d66b082) — Medium

## Open source

VPN Up is MIT-licensed and developed on
[GitHub](https://github.com/sorinipate/vpn-up-for-openconnect). Issues and pull
requests are welcome — and if it saves you time, you can
[buy me a coffee ☕](https://buymeacoffee.com/sorinipate).
