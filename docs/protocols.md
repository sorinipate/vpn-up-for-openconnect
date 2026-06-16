---
layout: page
title: Supported protocols
description: >-
  Connect to Cisco AnyConnect, Palo Alto GlobalProtect, Pulse Secure and Juniper
  Network Connect VPNs from the command line via OpenConnect with VPN Up.
permalink: /protocols/
---

# Supported VPN protocols

VPN Up speaks every SSL-VPN protocol that [OpenConnect](https://www.infradead.org/openconnect/)
supports. Set `<protocol>` on a profile (or pick it in `vpn-up add-profile`).

| Protocol value | Gateway | Notes |
|---|---|---|
| `anyconnect` | **Cisco AnyConnect** (and ocserv) | Default. Full AuthGroup/realm and [browser SSO]({{ '/sso-duo/' | relative_url }}) support. |
| `gp` | **Palo Alto GlobalProtect** | Portal/gateway login; browser SSO supported. |
| `pulse` | **Pulse Connect Secure** | Pulse/Ivanti SSL VPN. |
| `nc` | **Juniper Network Connect** | Legacy Juniper; no SSO support. |

## Cisco AnyConnect from the command line

A command-line alternative to the Cisco AnyConnect Secure Mobility Client for any
AnyConnect-compatible gateway:

```bash
vpn-up start "Work VPN"   # protocol: anyconnect
```

Supports AuthGroup/realm selection, Duo 2FA, certificate pinning, and
[browser-based SSO]({{ '/sso-duo/' | relative_url }}) for Okta/Azure AD/Ping gateways.

## GlobalProtect, Pulse Secure, and Juniper

Set the matching protocol value in the profile:

```xml
<VPN>
  <name>GP VPN</name>
  <protocol>gp</protocol>          <!-- or: pulse, nc -->
  <host>gw.example.com</host>
  <user>you</user>
</VPN>
```

GlobalProtect supports browser SSO; Pulse and Juniper use password / Duo 2FA flows.

## Not sure what your gateway speaks?

If the vendor client is "Cisco AnyConnect," use `anyconnect`. For Palo Alto
GlobalProtect use `gp`. When in doubt, try `anyconnect` first — many gateways are
AnyConnect-compatible. See [troubleshooting]({{ '/troubleshooting/' | relative_url }})
if a connection fails.
