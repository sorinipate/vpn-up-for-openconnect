# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/sorinipate/vpn-up-for-openconnect/security/advisories/new)
rather than opening a public issue. You should receive a response within a week.

## Security model

- **Passwords** are stored in the OS keychain (macOS), Secret Service
  (Linux), or an AES-256-CBC + PBKDF2 OpenSSL vault as a fallback — never in
  plaintext files unless `ENCRYPTION_ENABLED=FALSE` is set explicitly.
  Plaintext `<password>` values found in profile XML are migrated to the
  secrets backend and blanked in the XML on first use.
- **The sudo password is never stored.** `openconnect` runs under `sudo` and by
  default prompts for your password. A passwordless sudoers rule is optional and
  carries a real trade-off — see *Known limitations* below.
- **Server identity fails closed**: a `pin-sha256` pin in
  `<serverCertificate>`, or the gateway certificate must validate against the
  system trust store.
- **User state** (config, profiles, secrets, logs) lives in
  `~/.config/vpn-up` with `700`/`600` permissions. The config file is only
  sourced if owned by the current user and not group/world-writable.
- Secrets are never passed on command lines (process table) and are not
  exported to child-process environments.

## Known limitations

### A `NOPASSWD` sudoers rule for `openconnect` grants effective root

`vpn-up` invokes `sudo openconnect`. If you install the optional passwordless
sudoers rule that names the `openconnect` binary, that rule **is equivalent to
passwordless root for your account** — it is not a privilege "scoped to one
binary," and earlier documentation that described it that way was wrong.

Two independent reasons:

1. **sudoers does not constrain arguments.** A rule that names a command with no
   arguments lets the user run it with any arguments. `openconnect` has flags
   that execute another program as root — `--script`, `--script-tun`,
   `--csd-wrapper` — and `--config`/`--xmlconfig`, which can name those from a
   file. `sudo openconnect --script /tmp/anything <host>` therefore runs
   `/tmp/anything` as root.
2. **On macOS the permitted path is user-writable.** Homebrew's prefix
   (`/opt/homebrew`, or `/usr/local` on Intel) is owned by the installing user,
   so a rule pointing into it can be defeated by replacing the binary — no
   arguments involved. A sudoers rule is only meaningful if neither the
   permitted executable nor its parent directories are writable by the
   unprivileged user.
3. **A Homebrew `openconnect` runs a user-writable script as root by default.**
   `openconnect` has a compiled-in default `vpnc-script`, and on Homebrew that is
   `/opt/homebrew/etc/vpnc/vpnc-script` — owned by the installing user, in a
   group-writable parent. It is executed as root on every connect. So on a
   Homebrew install, `sudo openconnect` reaches root-controlled-by-the-user
   territory with **no unusual arguments at all**; `--script` is merely the
   explicit route. Check yours with `openconnect --version` (it prints the
   default) and `ls -l` the result.

Consequences worth being explicit about: any process running as your user can
use the rule without going through `vpn-up`, and anyone who can write your
profile store (`~/.config/vpn-up`) can get root at the next connect by adding an
`<extraArgs>` entry.

`vpn-up` prints a loud warning when `extraArgs` contains one of those flags, but
**that warning is a footgun guardrail, not a security control** — the rule
permits `openconnect` directly, so no amount of client-side filtering can
enforce anything. Point 3 makes that sharper still: with a user-writable default
`vpnc-script`, filtering arguments would not be sufficient even if it were
enforceable.

Planned fix: a root-owned privileged helper (`vpn-up-helper`) that accepts a
narrow, validated request and constructs the `openconnect` invocation itself,
with sudoers permitting only the helper and no longer `openconnect`. Until then:

- Prefer the interactive `sudo` prompt (the default) and no sudoers rule.
- The login service requires the rule, so it inherits this limitation and is
  not recommended on shared or managed machines.
- If you install the rule, point it at a root-owned `openconnect` outside any
  user-writable prefix, and confirm its default `vpnc-script`
  (`openconnect --version`) is root-owned too.

## Scope notes

- This tool shells out to `openconnect`, `openssl`, `xmlstarlet`, and the
  platform keychain tools; vulnerabilities in those belong upstream.
- The plaintext file backend (`ENCRYPTION_ENABLED=FALSE`) is an explicit
  opt-out and is out of scope for confidentiality reports.
