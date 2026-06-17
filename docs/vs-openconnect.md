---
layout: page
title: VPN Up vs. raw OpenConnect
description: >-
  How VPN Up compares to running openconnect directly — profiles, secure secrets,
  Duo 2FA, SSO, certificate pinning, and auto-reconnect, versus long ad-hoc commands.
permalink: /vs-openconnect/
---

# VPN Up vs. raw OpenConnect

VPN Up is **not** a replacement for [OpenConnect](https://www.infradead.org/openconnect/)
— it's a thin, secure wrapper around it. OpenConnect does the tunnelling; VPN Up
adds the profile management and credential hygiene that raw command lines lack.

## The raw way

```bash
echo "$PASSWORD" | sudo openconnect --protocol=anyconnect --authgroup=Employees \
  --user=me --servercert pin-sha256:… --passwd-on-stdin vpn.example.com
```

Every gateway is a long command to remember, the password lands in your shell
history and the process table, and there's no "is it up?", "stop it", or
"reconnect at login."

## The VPN Up way

```bash
vpn-up start "Work VPN"
```

## Side by side

| Capability | Raw `openconnect` | VPN Up |
|---|:---:|:---:|
| Multiple named profiles | manual | ✅ |
| Secrets in Keychain / keyring / encrypted vault | — | ✅ |
| Password kept out of argv & shell history | manual | ✅ |
| Duo 2FA prompt ordering (push/phone/sms/passcode) | manual | ✅ |
| Browser-based SSO (`--external-browser`) wiring | manual | ✅ |
| Certificate-pinning helper (`pin` / `pin --save`) | manual | ✅ |
| Profile-aware `status` / `logs -f` / `stop` | — | ✅ |
| Auto-reconnect login service (launchd/systemd) | manual | ✅ |
| Connect/disconnect hooks & desktop notifications | — | ✅ |
| Shell completion | — | ✅ |

## When to use which

- **Use raw `openconnect`** for a one-off connection, scripting around a single
  fixed gateway, or debugging the tunnel itself.
- **Use VPN Up** when you connect regularly, juggle multiple gateways, want
  credentials stored safely, need Duo/SSO handled cleanly, or want connect-at-login.

Under the hood it's still OpenConnect — so anything your gateway needs that
OpenConnect supports keeps working.

Get started: [installation]({{ '/installation/' | relative_url }}) ·
[usage]({{ '/usage/' | relative_url }}).

> Comparing specific clients? See
> [VPN Up vs. openconnect-sso]({{ '/vs-openconnect-sso/' | relative_url }}) (Cisco
> AnyConnect SSO) and
> [VPN Up vs. GlobalProtect-openconnect]({{ '/vs-globalprotect-openconnect/' | relative_url }}).
