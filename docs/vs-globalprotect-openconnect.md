---
layout: page
title: VPN Up vs. GlobalProtect-openconnect
description: >-
  How VPN Up compares to yuezk/GlobalProtect-openconnect for connecting to Palo
  Alto GlobalProtect VPNs from the command line — platform support, protocols,
  free vs. paid GUI, authentication (SSO, Duo, TOTP, client certificates), and
  auto-reconnect.
permalink: /vs-globalprotect-openconnect/
---

# VPN Up vs. GlobalProtect-openconnect

[GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect) is a
popular, well-packaged **GlobalProtect** VPN client for Linux, written in Rust and
built on OpenConnect, with both a CLI and a system-tray GUI. VPN Up overlaps with it
on [GlobalProtect from the command line]({{ '/globalprotect-cli/' | relative_url }}),
so this page lays out the real differences. (Both are good tools built on the same
OpenConnect foundation; this aims to be fair, not a pitch.)

## Side by side

| | GlobalProtect-openconnect | VPN Up |
|---|---|---|
| Protocols | GlobalProtect **only** | anyconnect, **gp**, pulse, nc |
| Platforms | **Linux only** (broad distro packaging) | **macOS + Linux** |
| Language / runtime | Rust + Tauri + `webkit2gtk` | Bash (+ `openconnect`, `xmlstarlet`) |
| Interface | CLI **and** GUI + system tray | CLI only (terminal-first by design) |
| License / cost | CLI free (GPL-3.0); **GUI proprietary, paid** (7-day trial) | **Fully free, MIT** — no paid tier |
| Browser SSO / SAML | Yes (default or specified browser) | Yes (`--external-browser`, needs OpenConnect ≥ 9) |
| FIDO2 / YubiKey | **Yes** (browser SSO) | Yes — via browser SSO (passkeys / WebAuthn); YubiKey **PIV** as a client certificate |
| Client-certificate auth | Yes | **Yes** — file or PKCS#11 / YubiKey PIV (first-class) |
| Duo push / phone / sms / passcode | Not the focus | First-class |
| TOTP authenticator codes | — (uses FIDO2 / SSO instead) | Yes — seed in keychain, code on stdin; works non-interactively |
| Named profiles + keyring secrets | Portal/gateway config + keyring | Yes (Keychain, Secret Service, or encrypted vault) |
| Profile-aware `status` / `stop` / `logs` | Tray-driven | Yes, scriptable |
| Auto-connect / reconnect | Auto-connect on startup (tray) | **Login service (launchd / systemd)** with auto-reconnect |
| Hooks / notifications / completion / `doctor` | Partial (tray) | Yes |
| Dependencies | webkit2gtk, libsecret, appindicator, pkexec, keyring | openconnect, xmlstarlet, secret backend (+ `oathtool` for TOTP) |
| Maintenance | Active (broad packaging) | Active (CI, docs, regular releases) |

## The real differences

**Scope.** GlobalProtect-openconnect is a *GlobalProtect specialist* — deep on one
protocol, with a native desktop app, a system tray, and packages for nearly every
Linux distribution. VPN Up is a *multi-protocol generalist* — the same workflow
whether the gateway speaks Cisco AnyConnect, GlobalProtect, Pulse Secure, or
Juniper Network Connect.

**Platform.** This is the decisive one for many people: GlobalProtect-openconnect
is **Linux-only — there is no macOS build**. If you're on a Mac, VPN Up (or
openconnect-sso for AnyConnect) is the option. If you live on Linux and only use
GlobalProtect, GlobalProtect-openconnect is purpose-built for you.

**Free vs. paid, and the trust model.** GlobalProtect-openconnect's *CLI* is GPL-3.0
and free, but its *GUI* is proprietary and requires payment after a 7-day trial. VPN
Up is entirely MIT and auditable Bash — nothing closed, nothing to pay for, and the
whole codebase is small enough to read end to end.

**Authentication.** The two now overlap more than they used to. Both do browser
SSO, and both get **FIDO2 / passkeys / YubiKey-WebAuthn** for free because the SSO
login happens in a browser. VPN Up also has first-class **Duo**, **TOTP**, and
**client-certificate** auth — a cert/key file *or* a **PKCS#11 / YubiKey PIV** token
(the [client-certificate guide]({{ '/client-certificate-auth/' | relative_url }})).
Its real differentiator is **non-interactive auth that runs as a login service**:
TOTP (code generated from a keychain seed) and a PKCS#11 cert (PIN fed via a
transient `pin-source` file) let a headless box or laptop auto-reconnect without a
human approving each prompt — at the trade-off that the seed/PIN lives in the
keychain ("1.5-factor"), which a hardware-only token avoids.

## When to choose which

**Choose GlobalProtect-openconnect if** you're on **Linux**, use **GlobalProtect**,
and want a **GUI / system-tray** experience with broad distro packaging — and you're
fine paying for the GUI (or staying on its free CLI).

**Choose VPN Up if** you need **macOS** support, connect to **more than just
GlobalProtect**, want a **fully-free, auditable, scriptable** tool, rely on **Duo,
TOTP, or a client certificate** (file or PKCS#11 / YubiKey PIV), or want
**auto-reconnect at login on a server or laptop** without a GUI. See
[installation]({{ '/installation/' | relative_url }}),
[GlobalProtect from the CLI]({{ '/globalprotect-cli/' | relative_url }}), and
[client-certificate auth]({{ '/client-certificate-auth/' | relative_url }}).

> Comparing other clients? See
> [VPN Up vs. openconnect-sso]({{ '/vs-openconnect-sso/' | relative_url }}) (Cisco
> AnyConnect SSO) and
> [VPN Up vs. raw OpenConnect]({{ '/vs-openconnect/' | relative_url }}).
