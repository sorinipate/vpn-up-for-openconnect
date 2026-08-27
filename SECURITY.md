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

Three independent reasons:

1. **sudoers does not constrain arguments.** A rule that names a command with no
   arguments lets the user run it with any arguments. `openconnect` has flags
   that execute another program as root — `--script`/`-s`, `--script-tun`/`-S`,
   `--csd-wrapper`, `--external-browser` (the SSO opener), and `--csd-user`
   (which enables execution of the *gateway-supplied* CSD binary; `=root` runs it
   as root) — plus `--config` and `--xmlconfig`/`-x`, which can name those from a
   file. `sudo openconnect --script /tmp/anything <host>` therefore runs
   `/tmp/anything` as root.
2. **On macOS the permitted path is user-writable.** Homebrew's prefix
   (`/opt/homebrew`, or `/usr/local` on Intel) is owned by the installing user,
   so a rule pointing into it can be defeated by replacing the binary — no
   arguments involved. A sudoers rule is only meaningful if neither the
   permitted executable nor its parent directories are writable by the
   unprivileged user.
3. **A Homebrew `openconnect` runs a user-writable script as root by default.**
   `openconnect` has a compiled-in default `vpnc-script`, and the Homebrew
   formula points it at `$HOMEBREW_PREFIX/etc/vpnc/vpnc-script` — inside the
   prefix, and so owned by the installing user, who can therefore modify it. It
   is executed as root on every connect. So on a Homebrew install,
   `sudo openconnect` reaches user-modifiable-code-as-root with **no unusual
   arguments at all**; `--script` is merely the explicit route. Check yours with
   `openconnect --help` (it prints the default under "VPN configuration script")
   and `ls -l` the result.

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

**The fix is available**: a root-owned privileged helper (`vpn-up-helper`) that
accepts a narrow, validated request and constructs the `openconnect` invocation
itself, with sudoers permitting only the helper and never `openconnect`.

```sh
vpn-up install-helper                  # retires the legacy rule; connects prompt for a password
vpn-up install-helper --passwordless   # also authorizes unattended connects (read below first)
vpn-up doctor                          # reports the boundary and this machine's eligibility
```

`install-helper` **retires the legacy `openconnect` rule whether or not you ask
for a passwordless one** — a hardened boundary next to the old arbitrary-root
grant is worse than either alone, because it looks fixed. It needs a C toolchain
(Xcode command line tools on macOS, `cc` on Linux), and it refuses to install on
a machine whose OpenConnect execution closure it cannot verify, which today means
**macOS is refused**: verifying the dynamic-library closure there needs Mach-O
and dyld support that is not written yet. Homebrew installations are refused on
every platform, for reason 2 above.

Until you have run it:

- Prefer the interactive `sudo` prompt (the default) and no sudoers rule.
- The login service requires a passwordless rule, so it inherits this limitation
  and is not recommended on shared or managed machines.
- If you install the legacy rule anyway, point it at a root-owned `openconnect`
  outside any user-writable prefix, and confirm its default `vpnc-script`
  (`openconnect --help`, under "VPN configuration script") is root-owned too.

### What installation itself assumes

The helper's boundary defends against an arbitrary process running as your user
**after** installation. Installation does not:

> The interactive installation ceremony assumes the source tree and the build
> artefacts are not being maliciously modified by another process running as your
> user while it runs.

`install-helper` compiles the helper from this checkout as *you* and then installs
the result as root. A process running as your user could substitute what root
installs, and no check inside the installed binary can detect that — it would be
the substituted code doing the checking. Verifying provenance independently needs
an input root can authenticate without trusting your account: a distribution
package, or a release signed with a key obtained out of band. VPN Up has neither
yet, so nothing shipped inside a user-writable checkout can close this.

That is why the passwordless rule is **opt-in**. Without `--passwordless` you get
the closed argument schema, the approved-endpoint binding and the closure check at
the cost of one password per connect, and a locally built binary never becomes
root-reachable-without-a-password as a side effect of installing.

## Scope notes

- This tool shells out to `openconnect`, `openssl`, `xmlstarlet`, and the
  platform keychain tools; vulnerabilities in those belong upstream.
- The plaintext file backend (`ENCRYPTION_ENABLED=FALSE`) is an explicit
  opt-out and is out of scope for confidentiality reports.
