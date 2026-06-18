---
layout: page
title: Split-tunnel routing — send only some traffic through the VPN
description: >-
  Route only chosen subnets and hosts through an OpenConnect VPN (Cisco
  AnyConnect, GlobalProtect) on macOS and Linux using VPN Up and vpn-slice —
  keep the rest of your traffic on your normal connection.
permalink: /split-tunnel/
---

# Split-tunnel routing with VPN Up

By default OpenConnect honors whatever routes the gateway pushes — often
"send **all** traffic through the VPN." **Split tunneling** sends only the subnets
and hosts you choose through the tunnel and leaves everything else on your normal
connection (faster, more private, less load on the gateway).

VPN Up doesn't manage routes itself — OpenConnect does. The clean way to split
traffic is therefore the standard OpenConnect mechanism: replace the routing
helper (`vpnc-script`) with [**vpn-slice**](https://github.com/dlenski/vpn-slice),
which routes only what you name. VPN Up wires it in through a profile's
[`<extraArgs>`]({{ '/usage/' | relative_url }}) — no special feature required.

## 1. Install vpn-slice

```bash
# macOS / Linux (Homebrew)
brew install vpn-slice

# or, with pipx (any platform; needs Python 3.6+)
pipx install vpn-slice
```

It works on macOS, Linux, and BSD, and uses the VPN's DNS to resolve any hostnames
you list (writing them to `/etc/hosts` and cleaning up on disconnect).

## 2. Add it to a profile via `<extraArgs>`

Pass `vpn-slice` to OpenConnect with `--script`, listing what should go **through**
the VPN. Put it in the profile's `<extraArgs>` (quotes are required so the whole
`vpn-slice …` string stays one argument):

```xml
<extraArgs>--script "vpn-slice 10.0.0.0/8 vpn.corp.example.com"</extraArgs>
```

Then connect as usual:

```bash
vpn-up start "Work VPN"
```

Now only `10.0.0.0/8` and the resolved address of `vpn.corp.example.com` route
through the tunnel; the rest of your traffic stays on your normal connection.

You can also set this from the `add-profile` wizard — answer the optional
**"Extra openconnect arguments"** prompt with the same `--script "vpn-slice …"`
string.

### Include, exclude, and hostnames

vpn-slice's argument is a space-separated list:

- **Include** a subnet or host: `10.0.0.0/8`, `192.168.1.0/24`, `server1`
- **Exclude** a subnet (route everything *except* it through the VPN): prefix with
  `%`, e.g. `%10.123.0.0/24`
- **Host alias**: `alias=alias.corp.example.com=192.168.1.43`

```xml
<extraArgs>--script "vpn-slice 192.168.0.0/16 %192.168.99.0/24 wiki=wiki.corp=192.168.1.5"</extraArgs>
```

See the [vpn-slice README](https://github.com/dlenski/vpn-slice#readme) for the full
syntax. For reference, the equivalent raw OpenConnect command is:

```bash
sudo openconnect --protocol=anyconnect -s 'vpn-slice 10.0.0.0/8 vpn.corp.example.com' vpn.corp.example.com
```

## Alternative: a post-connect hook

If you'd rather keep the gateway's `vpnc-script` and just adjust routes afterward
(the approach in some macOS GlobalProtect how-tos), drop an executable script in
`~/.config/vpn-up/hooks/connected.d/`. VPN Up runs it after connecting with
`VPN_NAME` and `VPN_HOST` in the environment.

Note that hooks **don't** receive the tunnel interface (`utunN` / `tunN`) or the
assigned IP, so your script has to discover those itself (e.g. parse `ifconfig` /
`ip addr`) before calling `route`/`ip route`. That fragility — and the fact that it
would be macOS/Linux-specific — is exactly why **vpn-slice is the recommended
route**: it auto-detects the interface and works the same everywhere.

## Caveats

- **vpn-slice replaces `vpnc-script`.** Enabling it changes the whole routing/DNS
  model on purpose — only what you list is routed, and DNS for listed hosts goes to
  `/etc/hosts` rather than your resolver. That's the point, but it's a bigger change
  than a single flag.
- **Policy.** Some organizations require full-tunnel VPN; split tunneling may violate
  an acceptable-use policy. Check before you rely on it.
- **Runs as root.** `--script` runs the helper as root (OpenConnect runs under
  `sudo`). Only point it at a tool you trust — the same caution as any
  [`extraArgs`]({{ '/usage/' | relative_url }}) entry.

## Related

- [Usage]({{ '/usage/' | relative_url }}) — `extraArgs` and the rest of the CLI ·
  [Supported protocols]({{ '/protocols/' | relative_url }}) ·
  [Troubleshooting]({{ '/troubleshooting/' | relative_url }}).
