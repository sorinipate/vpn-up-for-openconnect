---
layout: page
title: Installation
description: >-
  Install VPN Up, an OpenConnect VPN command-line client, on macOS and Linux via
  Homebrew or manually. Dependencies: openconnect, xmlstarlet, modern Bash.
permalink: /installation/
---

# Installing VPN Up on macOS and Linux

VPN Up is a wrapper around [OpenConnect](https://www.infradead.org/openconnect/),
so it needs `openconnect`, `xmlstarlet`, and Bash ≥ 4. Your data always lives in
`~/.config/vpn-up`, untouched by upgrades or reinstalls.

## Homebrew (macOS / Linux — recommended)

```bash
brew tap sorinipate/vpn-up
brew install vpn-up
```

This installs the `vpn-up` command with all dependencies and bash completion, and
upgrades cleanly with `brew upgrade vpn-up`.

## Manual — macOS (Apple Silicon / Intel)

macOS ships with Bash 3.2, so install modern Bash and the dependencies:

```bash
brew install bash openconnect xmlstarlet
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zprofile
exec $SHELL -l
```

Then clone and run:

```bash
git clone https://github.com/sorinipate/vpn-up-for-openconnect.git
cd vpn-up-for-openconnect
chmod +x vpn-up.command
./vpn-up.command setup
```

## Manual — Linux

```bash
# Debian / Ubuntu
sudo apt install bash openconnect xmlstarlet openssl

# RHEL / CentOS
sudo yum install bash openconnect xmlstarlet openssl

# Fedora
sudo dnf install bash openconnect xmlstarlet openssl
```

Optional (recommended): `secret-tool` for Secret Service keyring storage. For
[browser-based SSO]({{ '/sso-duo/' | relative_url }}), you need **OpenConnect ≥ 9.0**.

## Verify your environment

```bash
vpn-up doctor
```

`doctor` reports your OS, dependencies and OpenConnect version, the active secret
backend, and whether SSO (external browser) is supported.

Next: [usage and commands]({{ '/usage/' | relative_url }}).
