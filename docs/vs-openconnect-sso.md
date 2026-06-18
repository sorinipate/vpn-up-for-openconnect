---
layout: page
title: VPN Up vs. openconnect-sso
description: >-
  How VPN Up compares to openconnect-sso for Cisco AnyConnect SAML/SSO on macOS
  and Linux — both do browser SSO and TOTP now; the differences are the SSO
  mechanism, lifecycle/auto-reconnect, runtime, and maintenance.
permalink: /vs-openconnect-sso/
---

# VPN Up vs. openconnect-sso

[openconnect-sso](https://github.com/vlaci/openconnect-sso) is a well-known
Python tool that automates **SAML/SSO** login to Cisco AnyConnect VPNs using an
embedded browser. VPN Up overlaps with it now that it also supports
[browser SSO]({{ '/sso-duo/' | relative_url }}) and
[TOTP]({{ '/sso-duo/' | relative_url }}#totp-authenticator-app-codes-google-authenticator-authy-hardware-tokens),
so this page lays out the real differences. (Both are good tools; this aims to be
fair, not a pitch.)

## Side by side

| | openconnect-sso | VPN Up |
|---|---|---|
| Language / runtime | Python + Qt WebEngine | Bash (+ `openconnect`, `xmlstarlet`) |
| Browser SSO | Embedded Qt browser, **auto-fills** the IdP form | Native `--external-browser` → your **real** browser (needs OpenConnect ≥ 9) |
| Works on OpenConnect < 9 | Yes (brings its own browser) | No (SSO needs ≥ 9) |
| Auto-fill SSO username / password / TOTP | Yes (config rules) | No — you log in in the browser |
| TOTP 2FA | Auto-filled into the SSO form | Generated from a keychain seed for the gateway prompt; seed never on argv/disk |
| Extra openconnect args | Yes (`-- …`) | Yes (`<extraArgs>`, quote-safe, with collision warnings) |
| Duo push / phone / sms / passcode | Not the focus | First-class |
| Client-certificate auth | Not a focus | **Yes** — file or PKCS#11 / YubiKey PIV (first-class) |
| Named profiles + keyring secrets | Yes / Yes | Yes / Yes (Keychain, Secret Service, or encrypted vault) |
| Protocols | Cisco AnyConnect (SAML) | anyconnect, gp, pulse, nc |
| `status` / `stop` / `logs`, cert pinning | — | Yes |
| Auto-reconnect login service (launchd/systemd) | — | Yes (and TOTP works there, non-interactively) |
| Hooks / notifications / completion / `doctor` | — | Yes |
| Platforms | Linux, macOS, Windows (experimental) | macOS, Linux |
| Maintenance | Latest release v0.8.0 (Dec 2021) | Active (CI, docs, regular releases) |

## The two real differences

**SSO philosophy.** openconnect-sso *automates the login form* inside an embedded
browser — it can fully script username, password, and TOTP entry, and it works
even on older OpenConnect because it brings its own browser. VPN Up instead
*delegates to your real browser* via OpenConnect ≥ 9's `--external-browser`: you
complete the login where your password manager, passkeys, and Duo already live.
Because it's your real browser, **FIDO2 / passkeys / YubiKey-WebAuthn just work** —
hardware WebAuthn is often unreliable inside an embedded Qt browser. Simpler and
arguably safer, at the cost of needing OpenConnect ≥ 9 and a desktop session.

**Scope.** openconnect-sso is focused on the SSO *login*. VPN Up is a full
lifecycle manager — profiles, secure secrets, Duo, certificate pinning,
`status`/`stop`/`logs`, [connect-at-login with auto-reconnect]({{ '/vpn-at-login/' | relative_url }}),
hooks, and multiple protocols — and it's actively maintained.

## When to choose which

**Choose openconnect-sso if** you specifically need the SSO login **fully
auto-filled in an embedded browser**, you're stuck on **OpenConnect < 9**, or you
need **Windows** (experimental) — accepting that it hasn't shipped a release since
2021.

**Choose VPN Up if** you want a maintained, lightweight tool for everyday use:
multiple profiles, keychain secrets, Duo + TOTP + browser SSO, multiple protocols,
and especially **auto-reconnect on a server or laptop**. See
[installation]({{ '/installation/' | relative_url }}) and
[SSO & 2FA]({{ '/sso-duo/' | relative_url }}).

> Not a Cisco AnyConnect / SAML setup? See also
> [VPN Up vs. raw OpenConnect]({{ '/vs-openconnect/' | relative_url }}),
> [VPN Up vs. GlobalProtect-openconnect]({{ '/vs-globalprotect-openconnect/' | relative_url }}),
> and [VPN Up vs. NetworkManager-openconnect]({{ '/vs-networkmanager-openconnect/' | relative_url }}).
