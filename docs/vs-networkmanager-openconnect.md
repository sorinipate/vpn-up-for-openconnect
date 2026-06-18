---
layout: page
title: VPN Up vs. NetworkManager-openconnect
description: >-
  How VPN Up compares to NetworkManager-openconnect (1.2.10+) for OpenConnect VPNs
  — the GNOME desktop NetworkManager plugin vs. a standalone, scriptable CLI on
  macOS and Linux, with SSO, Duo/TOTP, and client-certificate auth.
permalink: /vs-networkmanager-openconnect/
---

# VPN Up vs. NetworkManager-openconnect

[NetworkManager-openconnect](https://gitlab.gnome.org/GNOME/NetworkManager-openconnect)
is the **NetworkManager VPN plugin** for OpenConnect: it plugs OpenConnect into the
Linux desktop network stack so you manage the VPN from the GNOME **network applet /
Settings** (or `nmcli`), and NetworkManager itself handles auto-connect, reconnect,
DNS, and routing. Recent releases (1.2.10+) added SAML/SSO for some protocols and
PKCS#11 smartcard certificate selection.

Both tools build on the same OpenConnect engine, so this page focuses on the real
difference — the *model* — not a feature checklist. (Both are good; this aims to be
fair, not a pitch.)

## Side by side

| | NetworkManager-openconnect 1.2.10+ | VPN Up |
|---|---|---|
| Platform | **Linux only** — needs the NetworkManager daemon (and a desktop for SSO) | **macOS + Linux**, no daemon or desktop required |
| Model | Integrated into the **desktop network stack** | Standalone **CLI wrapper** with its own profiles/state |
| Interface | **GUI-first** (nm-applet / GNOME Settings) + `nmcli` / keyfiles | CLI only (terminal-first by design) |
| Protocols | anyconnect, gp, pulse, nc (whatever OpenConnect supports) | anyconnect, gp, pulse, nc |
| Browser SSO / SAML | Yes — **embedded `webkit2gtk`** auth dialog | Yes — your **real** browser (`--external-browser`, OpenConnect ≥ 9) |
| FIDO2 / passkeys in SSO | In the embedded webkit dialog | Native — in your real browser (passkeys / WebAuthn just work) |
| Client cert / PKCS#11 smartcard | **Yes** (incl. smartcard, since 1.2.10) | Yes — file or PKCS#11 / YubiKey PIV (first-class) |
| Duo push / phone / sms / passcode | Entered in the auth dialog | **First-class** method selection |
| TOTP authenticator codes | Typed into the auth dialog | First-class — seed in keychain, generated at connect; **works headless** |
| Auto-connect / reconnect | **Native to NetworkManager** (excellent) | Login service (launchd / systemd) with auto-reconnect |
| Profile-aware `status` / `stop` / `logs` | Via NetworkManager / `nmcli` | Yes, scriptable |
| Certificate pinning helper | — | Yes (`pin` / `pin --save`) |
| License / cost | Free, GPL-2.0+ | Free, MIT |
| Maintenance | Active (GNOME) | Active (CI, docs, regular releases) |

## The real differences

**Desktop network stack vs. standalone CLI.** This is the whole story.
NetworkManager-openconnect *is part of* the Linux desktop's network manager — the VPN
shows up in the system tray and GNOME Settings, NetworkManager brings it up/down with
your other connections, and reconnect/DNS/routing are handled by the same daemon that
runs your Wi-Fi. VPN Up is the opposite: a self-contained CLI that **assumes no
NetworkManager and no desktop**, keeps its own profiles and state, and runs `openconnect`
under `sudo` on demand.

**Platform.** NetworkManager-openconnect is **Linux-only** and presumes the
NetworkManager daemon is in charge — so there's no macOS build, and it's an awkward fit
on a **headless server** that doesn't run NetworkManager. VPN Up runs on **macOS and
Linux**, desktop or headless, with no daemon to adopt.

**SSO mechanism.** NetworkManager-openconnect authenticates SSO in an **embedded
`webkit2gtk`** dialog; VPN Up delegates to your **real browser**, where your password
manager, **passkeys, and FIDO2 / YubiKey-WebAuthn** already live (hardware WebAuthn is
often unreliable in an embedded browser).

**Auth ergonomics.** Both now do browser SSO and client certificates (including PKCS#11
smartcards). VPN Up adds **first-class Duo method selection** and **TOTP generated from
a keychain seed** — and because that's non-interactive, a TOTP profile can run as an
**auto-reconnecting login service** on a headless box, which the GUI-driven dialog flow
isn't built for.

## When to choose which

**Choose NetworkManager-openconnect if** you're on a **Linux desktop already using
NetworkManager / GNOME**, and you want the VPN integrated into the network applet and
Settings, brought up automatically alongside your other connections, with NetworkManager
handling reconnect and DNS.

**Choose VPN Up if** you're on **macOS**, on a **headless / server Linux** box, or you
simply want a **scriptable CLI that doesn't depend on NetworkManager or a desktop** —
with named profiles, first-class **Duo / TOTP**, real-browser **SSO**,
**client-certificate** auth (file or PKCS#11 / YubiKey PIV), and an auto-reconnecting
login service. See [installation]({{ '/installation/' | relative_url }}),
[SSO & 2FA]({{ '/sso-duo/' | relative_url }}), and
[client-certificate auth]({{ '/client-certificate-auth/' | relative_url }}).

> Comparing other clients? See
> [VPN Up vs. openconnect-sso]({{ '/vs-openconnect-sso/' | relative_url }}) (Cisco
> AnyConnect SSO),
> [VPN Up vs. GlobalProtect-openconnect]({{ '/vs-globalprotect-openconnect/' | relative_url }}),
> and [VPN Up vs. raw OpenConnect]({{ '/vs-openconnect/' | relative_url }}).
