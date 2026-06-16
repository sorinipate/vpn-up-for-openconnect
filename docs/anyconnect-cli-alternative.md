---
layout: page
title: A Cisco AnyConnect command-line alternative for macOS & Linux
description: >-
  Use VPN Up and OpenConnect as a terminal alternative to the Cisco AnyConnect
  Secure Mobility Client on macOS and Linux — profiles, Duo 2FA, and SSO included.
permalink: /anyconnect-cli-alternative/
---

# A Cisco AnyConnect command-line alternative

If you connect to a Cisco AnyConnect VPN but would rather not run the official
**AnyConnect Secure Mobility Client** GUI, VPN Up gives you a terminal-first
alternative built on [OpenConnect](https://www.infradead.org/openconnect/), which
speaks the AnyConnect protocol (and works with ocserv too).

> VPN Up is **not** the official Cisco client and is not affiliated with Cisco. It
> is a wrapper around OpenConnect for gateways that support an AnyConnect-compatible
> protocol.

## What you get instead of the GUI

| AnyConnect GUI feature | With VPN Up |
|---|---|
| Pick a connection profile | Named profiles — `vpn-up start "Work"` or an interactive menu |
| Group / realm selection | `<authGroup>` per profile (passed as `--authgroup`) |
| Duo / MFA prompt | `push` / `phone` / `sms` / `passcode`, or [browser SSO]({{ '/sso-duo/' | relative_url }}) |
| Saved password | Stored in the macOS Keychain / Linux keyring — never plaintext |
| Server certificate trust | `pin-sha256` pinning or system trust-store validation (fail closed) |
| Connect / disconnect / status | `start` / `stop` / `status` / `logs -f`, all profile-aware |

## Set it up

```bash
brew tap sorinipate/vpn-up
brew install vpn-up
vpn-up add-profile        # protocol: anyconnect; enter host, group, user
vpn-up start "Work VPN"   # connect; approve Duo when prompted
```

See the [installation guide]({{ '/installation/' | relative_url }}) for manual
setup, and [SSO & Duo 2FA]({{ '/sso-duo/' | relative_url }}) if your gateway forces
a browser-based Okta/Azure AD/Ping login.

## When it works (and when it doesn't)

VPN Up works wherever OpenConnect can connect to your gateway — the vast majority
of AnyConnect SSL-VPN deployments and ocserv. It does **not** implement
proprietary posture/HostScan agents some enterprises require; if your gateway
mandates the Cisco endpoint-posture client, you may still need the official app.
Otherwise, the command line is all you need.

Related: [supported protocols]({{ '/protocols/' | relative_url }}) ·
[VPN Up vs. raw OpenConnect]({{ '/vs-openconnect/' | relative_url }}).
