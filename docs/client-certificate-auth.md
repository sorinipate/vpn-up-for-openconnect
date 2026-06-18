---
layout: page
title: Client-certificate VPN authentication (file or PKCS#11 / YubiKey PIV)
description: >-
  Authenticate to an OpenConnect VPN with an X.509 client certificate using VPN
  Up — a PEM/key file or a PKCS#11 smartcard / YubiKey PIV — on macOS and Linux,
  with the key passphrase / PIN kept out of the process table.
permalink: /client-certificate-auth/
---

# Client-certificate authentication

VPN Up can authenticate to a gateway with an **X.509 client certificate** —
either a file on disk or a **PKCS#11** token such as a smartcard or **YubiKey
PIV**. A client certificate is *additive*: it works on its own (cert-only) or
alongside a password, Duo, TOTP, or browser SSO — it does not replace them.

## Configure a profile

Add `clientCertificate` (and, if the private key is separate, `clientKey`) to the
profile. Each may be a **file path** or a **PKCS#11 URI**.

```xml
<VPN>
  <name>Work (cert)</name>
  <protocol>anyconnect</protocol>
  <host>vpn.example.com</host>
  <user>you</user>
  <!-- A PEM file holding cert + key, or split across two files: -->
  <clientCertificate>/etc/vpn/me.pem</clientCertificate>
  <clientKey></clientKey>
</VPN>
```

Or run the wizard: `vpn-up add-profile` prompts for the certificate (and, for a
`pkcs11:` URI, offers to store the PIN). Then connect:

```bash
vpn-up start "Work (cert)"
```

## Smartcards & YubiKey PIV (PKCS#11)

OpenConnect addresses smartcard certificates with a [PKCS#11
URI](https://www.infradead.org/openconnect/pkcs11.html). List your token's
objects with `p11tool --list-all` and use the URI as the certificate:

```xml
<clientCertificate>pkcs11:manufacturer=piv_II;id=%01;type=cert</clientCertificate>
```

`vpn-up doctor` reports whether PKCS#11 tooling (`p11-kit`/`p11tool`) is present.

## Where the passphrase / PIN goes

The certificate **path or URI is not a secret**, so it lives in the profile XML.
A **key passphrase or PKCS#11 PIN is** a secret and never goes on the command
line (it would otherwise be visible in the process table):

- **Interactive (default, most secure):** if the key/token needs a passphrase or
  PIN, OpenConnect prompts for it on the terminal. Nothing is stored.
- **Stored, for a login service:** store the PKCS#11 PIN in the secrets backend so
  the connection can run unattended —

  ```bash
  vpn-up set-secret "Work (cert)" key_password
  ```

  VPN Up feeds it to OpenConnect through a transient `0600` file
  (`pin-source`), never on the command line, and removes the file after the
  session.

## Running as a login service

A cert profile can [auto-connect at login]({{ '/vpn-at-login/' | relative_url }})
only when it needs no interactive prompt:

- **PKCS#11 token:** store the PIN (`key_password`) first.
- **File-based key:** use an **unencrypted key** with `0600` permissions (the file
  permissions protect it). A passphrase-protected file key cannot run as a service
  because there is no terminal to prompt on.

`vpn-up service install "Work (cert)"` warns if the profile would need a prompt.

## Related

- [SSO & 2FA]({{ '/sso-duo/' | relative_url }}) — browser SSO (passkeys / YubiKey
  WebAuthn work here too), Duo, and TOTP.
- [Supported protocols]({{ '/protocols/' | relative_url }}) ·
  [Auto-connect at login]({{ '/vpn-at-login/' | relative_url }}).
