---
layout: page
title: Auto-connect a VPN at login (launchd & systemd)
description: >-
  Run an OpenConnect VPN as a login service with auto-reconnect on macOS (launchd)
  and Linux (systemd) using VPN Up — setup, requirements, and the sudoers rule.
permalink: /vpn-at-login/
---

# Auto-connect a VPN at login, with auto-reconnect

VPN Up can run a profile as a **login service** that connects when you log in and
**reconnects automatically** if the tunnel drops — a launchd user agent on macOS
and a systemd user unit on Linux.

```bash
vpn-up service install "Work VPN"     # connect at login + auto-reconnect
vpn-up service status                 # list installed services
vpn-up service uninstall "Work VPN"   # remove it
```

The service manager supervises `openconnect` in the foreground and relaunches it
on drop (30-second throttle).

## Requirements

Because there's no terminal to type into at login, a service profile needs:

1. **A passwordless sudoers rule** scoped to the `openconnect` binary:

   ```bash
   # macOS (Homebrew):
   echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
   # Linux:
   echo "$USER ALL=(root) NOPASSWD: /usr/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
   sudo chmod 440 /etc/sudoers.d/vpn-up
   ```

2. **A stored password** — `vpn-up set-secret "Work VPN" password`.
3. **A non-interactive 2FA method** — `push`, `phone`, `sms`, or a
   [TOTP authenticator]({{ '/sso-duo/' | relative_url }}#totp-authenticator-app-codes-google-authenticator-authy-hardware-tokens)
   (the code is generated from the stored seed, so it's the ideal fit). Duo
   `passcode` and [browser SSO]({{ '/sso-duo/' | relative_url }}) profiles are
   **refused**, since both need a human.

`vpn-up service install` runs these preflight checks and warns you if anything is missing.

## Linux: start before you log in (optional)

By default a systemd *user* unit starts at your graphical/login session. To have it
start at boot (before interactive login), enable lingering for your user:

```bash
loginctl enable-linger "$USER"
```

## Inspecting the service

```bash
# macOS — service log:
tail -f ~/.config/vpn-up/logs/service.*.log
# Linux — unit status & logs:
systemctl --user status 'vpn-up-*'
journalctl --user -u 'vpn-up-*' -f
```

See [usage]({{ '/usage/' | relative_url }}) for the full command set and
[troubleshooting]({{ '/troubleshooting/' | relative_url }}) for sudo/connection issues.
