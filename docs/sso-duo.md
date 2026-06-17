---
layout: page
title: SSO & Duo 2FA
description: >-
  Browser-based SAML/SSO login (Okta, Azure AD, Ping Identity) with an embedded
  Duo iframe, plus Duo push/phone/sms/passcode — from the OpenConnect command line.
permalink: /sso-duo/
---

# Browser-based SSO and Duo 2FA with OpenConnect

Modern corporate gateways increasingly force a **browser-based SAML/SSO login** —
an Okta, Azure AD, or Ping Identity page, often wrapping an embedded **Duo**
iframe — instead of accepting a username and password on the command line. VPN Up
handles both classic Duo 2FA and the browser-based "SSO trap."

## Duo 2FA (push, phone, SMS, passcode)

Set the Duo method on a profile and VPN Up handles the prompt order so Duo and
AuthGroup selection don't collide:

- `push` — approve on your phone (Duo Mobile)
- `phone` — callback to your registered phone
- `sms` — texted passcodes
- `passcode` — one-time code, prompted at connect time (never read from config)
- *empty* — let the gateway auto-push

```bash
vpn-up start "Work VPN"   # connect; approve the Duo push when prompted
```

## TOTP authenticator-app codes (Google Authenticator, Authy, hardware tokens)

If your gateway prompts for a time-based one-time code, store the base32 seed
once and VPN Up generates the current code at connect time:

```bash
vpn-up set-secret "Work VPN" token_secret   # paste the base32 seed
```

Set `<tokenMode>totp</tokenMode>` on the profile (the `add-profile` wizard offers
it as a 2FA choice). Requires **`oathtool`** (`brew install oath-toolkit` /
`apt install oathtool`; reported by `vpn-up doctor`).

- The **seed stays in your keychain** — it's never passed to OpenConnect's command
  line or written to disk. Only the short-lived 6-digit code is sent, on stdin.
- TOTP needs no interaction, so it's the **one 2FA method that can run as a
  [login service]({{ '/vpn-at-login/' | relative_url }})** with auto-reconnect —
  ideal for headless servers. (Duo passcode and SSO can't, since they need a human.)
- Security note: keeping the seed beside the password in one keychain is
  effectively "1.5-factor" — it's opt-in.

## Browser-based SSO (Okta, Azure AD, Ping Identity)

For gateways that require an external browser login, mark the profile with
`authMode=sso` — either answer **yes** to the SSO prompt in `vpn-up add-profile`,
or set it in the profile XML:

```xml
<VPN>
  <name>Work SSO</name>
  <protocol>anyconnect</protocol>   <!-- anyconnect or gp; not nc -->
  <host>vpn.example.com</host>
  <authMode>sso</authMode>
</VPN>
```

Then connect normally:

```bash
vpn-up start "Work SSO"
```

VPN Up runs OpenConnect with `--external-browser`: it opens your browser to the
identity provider, you complete the login (including Duo) there, and the tunnel
comes up afterward. **No password is stored or piped** for SSO profiles.

### Requirements and behavior

- **OpenConnect ≥ 9.0** (when `--external-browser` landed). `vpn-up doctor` reports
  your version and whether SSO is available.
- Supported for the **`anyconnect`** and **`gp`** protocols (not `nc`).
- Runs in the **foreground**; an SSO profile **cannot run as a login service**
  because it needs an interactive desktop session.

### Linux + sudo: getting the browser to open

OpenConnect runs as root via `sudo`, so a root-spawned browser may not reach your
desktop session on Linux. If the browser doesn't appear, point VPN Up at a
session-aware opener:

```bash
# ~/bin/vpn-up-browser  (chmod +x)
#!/bin/sh
exec sudo -u "$SUDO_USER" xdg-open "$@"
```

```bash
export VPN_UP_EXTERNAL_BROWSER="$HOME/bin/vpn-up-browser"
```

`VPN_UP_EXTERNAL_BROWSER` overrides the opener (default: `open` on macOS,
`xdg-open` on Linux, or the bundled `openconnect-external-browser` helper).

See also: [usage]({{ '/usage/' | relative_url }}) and
[supported protocols]({{ '/protocols/' | relative_url }}).
