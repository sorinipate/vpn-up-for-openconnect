---
layout: page
title: Usage
description: >-
  Connect to a VPN from the command line with VPN Up: named profiles, status,
  stop, logs, simultaneous tunnels, certificate pinning, login service with
  auto-reconnect, and hooks.
permalink: /usage/
---

# Using VPN Up from the command line

After [installing]({{ '/installation/' | relative_url }}), run the one-time setup
and create your first profile:

```bash
vpn-up setup          # one-time configuration wizard
vpn-up add-profile    # guided profile creation (+ password, + certificate pin)
vpn-up start          # connect (interactive menu)
```

> Manual installs use `./vpn-up.command` instead of `vpn-up`.

## Core commands

```bash
vpn-up start                       # interactive profile menu
vpn-up start "Frankfurt VPN"       # connect directly (scriptable)
vpn-up list                        # list configured profiles (name, protocol, host, 2FA, auth)
vpn-up add-profile                 # guided profile creation
vpn-up remove-profile "Old VPN"    # remove profile + secret + logs + service
vpn-up status                      # all running profiles, gateways, uptime
vpn-up logs -f                     # follow the connection log
vpn-up stop                        # stop all VPNs (or: stop "Frankfurt VPN")
vpn-up doctor                      # diagnose environment & secret backend
```

Each profile keeps its own log and PID/state files under `~/.config/vpn-up`, so
`status`, `stop`, and `logs` are profile-aware. Multiple different profiles can
be connected at the same time; starting the same profile twice is refused. Route
and DNS compatibility still depends on what each gateway pushes, so split-tunnel
or non-overlapping routes are the safest simultaneous setup.

## Secure secret storage

Passwords are stored in the macOS **Keychain**, the Linux **Secret Service**, or
an AES-256-CBC + PBKDF2 OpenSSL vault — never in plaintext files, never on the
command line, never exported to child processes.

```bash
vpn-up set-secret "Frankfurt VPN" password
vpn-up delete-secret "Frankfurt VPN" password
```

## Login service with auto-reconnect

Connect at login and reconnect automatically if the tunnel drops — launchd on
macOS, a systemd user unit on Linux:

```bash
vpn-up service install "Frankfurt VPN"
vpn-up service status
vpn-up service uninstall "Frankfurt VPN"
```

Requirements: a passwordless sudoers rule for `openconnect`, a stored password,
and a non-interactive 2FA method (push/phone/sms — not passcode, and not SSO).

## Certificate pinning

```bash
vpn-up pin vpn.example.com          # print the pin-sha256 value
vpn-up pin --save "Frankfurt VPN"   # write it into the profile
```

If no pin is configured, the gateway certificate must validate against the system
trust store, or VPN Up refuses to connect (fail closed).

## Lifecycle hooks

Drop executable scripts in `~/.config/vpn-up/hooks/connected.d/` or
`disconnected.d/` to run your own actions on tunnel up/down (mount shares, switch
proxies). Hooks receive `VPN_EVENT`, `VPN_NAME`, and `VPN_HOST` — never the
password — and are skipped unless owned by you and not group/world-writable.

## Advanced: extra openconnect arguments

For a flag VPN Up doesn't model (`--no-dtls`, `--os=win`, `--csd-wrapper`, an
HTTP/SOCKS proxy, MTU, `--reconnect-timeout`, …), set `<extraArgs>` on the profile
(or use the optional prompt in `add-profile`). The value is appended verbatim to
the openconnect command, just before the gateway host:

```xml
<extraArgs>--no-dtls --reconnect-timeout 30</extraArgs>
```

- Tokenized with `xargs`, so quotes are respected (`"--csd-wrapper=/path with space"`
  stays one argument) and the value is **never** `eval`'d.
- Avoid flags VPN Up already manages (`--protocol`, `--user`, `--passwd-on-stdin`,
  `--background`, `--servercert`, `--authgroup`, `--pid-file`, `--external-browser`,
  `--token-mode`/`--token-secret`). Duplicating one warns but is still passed.
- **openconnect runs as root**, so some flags execute programs as root (e.g.
  `--csd-wrapper`, `--script`) — only add flags you'd run under `sudo` yourself.

See also: [SSO & Duo 2FA]({{ '/sso-duo/' | relative_url }}) and
[supported protocols]({{ '/protocols/' | relative_url }}).
