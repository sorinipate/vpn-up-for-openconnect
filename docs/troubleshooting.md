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

`openconnect` needs root, so VPN Up runs it under `sudo`. That prompt is the
**safe** configuration — the sudo password is never stored anywhere.

> ⚠️ **A passwordless rule is not "just scoped to one binary."** sudoers matches
> the command, not its arguments, and several `openconnect` flags (`--script`,
> `--script-tun`, `--csd-wrapper`, `--config`) execute a program as root. A
> `NOPASSWD` rule for `openconnect` is therefore effectively passwordless root
> for your account. On macOS it is weaker still: Homebrew's prefix is owned by
> the installing user, so a rule pointing into it can be bypassed by replacing
> the binary. Read
> [Known limitations](https://github.com/sorinipate/vpn-up-for-openconnect/blob/main/SECURITY.md#known-limitations)
> before installing one.

If you accept that trade-off (it is required for the login service):

```bash
command -v openconnect     # verify the real path first

# macOS (Homebrew, Apple Silicon — usually /opt/homebrew/bin/openconnect):
echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/bin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
# Linux:
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/openconnect" | sudo tee /etc/sudoers.d/vpn-up
sudo chmod 440 /etc/sudoers.d/vpn-up
```

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
