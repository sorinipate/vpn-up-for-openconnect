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

> ⚠️ **Not recommended for now.** The login service cannot work without a
> passwordless sudoers rule for `openconnect`, and that rule currently grants
> effective root to your account (see
> [Known limitations](https://github.com/sorinipate/vpn-up-for-openconnect/blob/main/SECURITY.md#known-limitations).
> Until VPN Up ships a root-owned privileged helper, prefer connecting manually
> and typing your sudo password. If you do install the service, do it only on a
> single-user machine you trust — not a shared or centrally managed one.

## Requirements

Because there's no terminal to type into at login, a service profile needs:

1. **Passwordless root for the connect step.** Two ways, and the first is
   strictly better:

   **The helper (preferred).** `vpn-up install-helper --passwordless` installs a
   root-owned `vpn-up-helper` and authorizes only *that* binary — one that builds
   the `openconnect` command line itself from a closed set of validated options,
   so the grant is not equivalent to arbitrary root the way the rule below is.
   Each profile also needs `vpn-up approve-profile` once. Needs a C toolchain;
   currently Linux with a distro-packaged `openconnect` (macOS and Homebrew are
   refused — see [SECURITY.md](https://github.com/sorinipate/vpn-up-for-openconnect/blob/main/SECURITY.md#known-limitations)).
   Note that `install-helper` **removes the legacy rule below**, so if you are
   migrating, run it and re-check the service.

   **The legacy sudoers rule** for the `openconnect` binary, where the helper is
   not available yet:

   ```bash
   command -v openconnect     # verify the real path first

   # macOS (Homebrew, Apple Silicon — usually /opt/homebrew/bin/openconnect):
   echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/bin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
   # Linux:
   echo "$USER ALL=(root) NOPASSWD: /usr/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
   sudo chmod 440 /etc/sudoers.d/vpn-up
   ```

   ⚠️ This rule grants **effective root** to your account, not a privilege
   scoped to one binary: sudoers does not constrain arguments, and
   `openconnect`'s `--script` / `--csd-wrapper` / `--config` flags execute
   programs as root. On macOS it is weaker still — Homebrew's prefix is owned by
   the installing user, so the permitted binary can simply be replaced. See
   [Known limitations](https://github.com/sorinipate/vpn-up-for-openconnect/blob/main/SECURITY.md#known-limitations).

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
