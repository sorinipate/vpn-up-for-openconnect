---
layout: page
title: Connect to GlobalProtect from the command line (OpenConnect)
description: >-
  Connect to a Palo Alto GlobalProtect VPN from the terminal on macOS and Linux
  using OpenConnect and VPN Up — portal/gateway host, SSO, and Duo supported.
permalink: /globalprotect-cli/
---

# Connect to GlobalProtect from the command line

VPN Up connects to **Palo Alto GlobalProtect** gateways through OpenConnect's `gp`
protocol — a terminal alternative to the GlobalProtect app on macOS and Linux.

## Create a GlobalProtect profile

Use the wizard (`vpn-up add-profile`, choose protocol `gp`) or write the profile
XML directly:

```xml
<VPN>
  <name>GP VPN</name>
  <protocol>gp</protocol>
  <host>gateway.example.com</host>   <!-- portal or gateway host -->
  <user>you</user>
  <authMode>password</authMode>      <!-- or: sso -->
</VPN>
```

Then connect:

```bash
vpn-up start "GP VPN"
```

## Portal vs. gateway host

GlobalProtect deployments expose a **portal** and one or more **gateways**.
OpenConnect can usually connect using either hostname; if a portal returns a
gateway list, point the profile at the specific gateway you want. If your
organization publishes a dedicated gateway hostname, prefer that.

## SSO and Duo

GlobalProtect frequently uses a **browser-based SAML/SSO login** (Okta, Azure AD,
Ping) with Duo. Set `authMode=sso` on the profile and VPN Up opens your browser
for the login — see [SSO & Duo 2FA]({{ '/sso-duo/' | relative_url }}) (requires
OpenConnect ≥ 9.0). For non-SSO gateways, use a Duo method (`push`/`phone`/`sms`).

## Troubleshooting

If the connection is rejected, double-check the host (portal vs. gateway) and your
group/realm, and run `vpn-up doctor` to confirm your OpenConnect version. More
fixes on the [troubleshooting page]({{ '/troubleshooting/' | relative_url }}).

Related: [supported protocols]({{ '/protocols/' | relative_url }}) ·
[Cisco AnyConnect CLI alternative]({{ '/anyconnect-cli-alternative/' | relative_url }}) ·
[VPN Up vs. GlobalProtect-openconnect]({{ '/vs-globalprotect-openconnect/' | relative_url }}).
