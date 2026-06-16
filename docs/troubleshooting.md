---
layout: page
title: Troubleshooting
description: >-
  Fixes for common OpenConnect VPN problems with VPN Up: Login failed, Unexpected
  404, sudo prompts, SSO browser not opening on Linux, and openconnect version.
permalink: /troubleshooting/
---

# Troubleshooting

Start with `vpn-up doctor` — it reports your OS, dependency and OpenConnect
versions, the active secret backend, and SSO availability.

## "Login failed"

Usually a stale stored password. Reset it and reconnect:

```bash
vpn-up delete-secret "Work VPN" password
vpn-up start "Work VPN"
```

For Duo, make sure the profile's method matches what your account expects
(`push`/`phone`/`sms`/`passcode`). See [SSO & Duo 2FA]({{ '/sso-duo/' | relative_url }}).

## "Unexpected 404 result from server"

Some Cisco AnyConnect gateways emit this banner on connect. It is **benign** if
the connection then proceeds and the tunnel comes up.

## It keeps asking for my sudo password

`openconnect` needs root, so VPN Up runs it under `sudo`. For non-interactive use
(and for the login service), add a sudoers rule scoped to the one binary:

```bash
# macOS (Homebrew):
echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
# Linux:
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
sudo chmod 440 /etc/sudoers.d/vpn-up
```

The sudo password is **never** stored. Verify the binary path with
`command -v openconnect`.

## SSO browser doesn't open (Linux)

Because `openconnect` runs as root, a root-spawned browser may not reach your
desktop session. Point VPN Up at a session-aware opener via
`VPN_UP_EXTERNAL_BROWSER` — see the
[SSO guide]({{ '/sso-duo/' | relative_url }}#linux--sudo-getting-the-browser-to-open).

## "SSO needs openconnect >= 9.0"

Browser-based SSO uses OpenConnect's `--external-browser`, added in 9.0. Upgrade:

```bash
brew upgrade openconnect          # macOS / Linuxbrew
sudo apt install --only-upgrade openconnect   # Debian/Ubuntu
```

Check with `openconnect --version` or `vpn-up doctor`.

## Can't run an SSO profile as a login service

Correct — SSO needs an interactive browser, so `service install` refuses SSO (and
Duo `passcode`) profiles. Use a non-interactive method (`push`/`phone`/`sms`) for
the [login service]({{ '/usage/' | relative_url }}#login-service-with-auto-reconnect).

## Still stuck?

Open an issue on
[GitHub](https://github.com/sorinipate/vpn-up-for-openconnect/issues) with the
output of `vpn-up doctor` and the last lines of `vpn-up logs` (redact anything
sensitive).
