# Privileged Helper — Security Design

**Status:** draft for review. No implementation yet.
**Supersedes:** the current `sudo openconnect` invocation model.
**Context:** [SECURITY.md → Known limitations](SECURITY.md#known-limitations).

This document has to be reviewed and agreed before `vpn-up-helper` is written,
because the helper *is* the application's root trust boundary. Everything below
is a proposal; open questions are collected in §12 and at least two of them
(§12.1, §12.2) can invalidate the whole approach on macOS if answered badly.

---

## 1. The problem being solved

`vpn-up` runs `sudo openconnect`. To run non-interactively (the login service,
or simply not typing a password each connect) users are told to install:

```
user ALL=(root) NOPASSWD: /path/to/openconnect
```

That rule is equivalent to passwordless root for the account, for three
independent reasons:

1. **sudoers does not constrain arguments.** A rule naming a command with no
   arguments permits any arguments. `openconnect --script`, `--script-tun`,
   `--csd-wrapper` execute a program as root; `--config`/`--xmlconfig` can name
   those from a file.
2. **The permitted binary may be user-writable.** Homebrew's prefix is owned by
   the installing user, so the binary can simply be replaced.
3. **The default `vpnc-script` may be user-writable.** `openconnect` has a
   compiled-in default script, executed as root on every connect. On Homebrew
   that is `/opt/homebrew/etc/vpnc/vpnc-script`, owned by the installing user.
   No unusual arguments are needed at all.

Point 3 is the reason this design cannot be only an argument filter.

### Non-goal: protecting against the calling user

The helper is invoked via `sudo` by an unprivileged user who *is* the person the
tunnel is for. Nothing here tries to stop that user from having root by other
means (they may be an admin; they may know their own password). What it stops is
the **rule itself** becoming a general-purpose root primitive, usable by:

- any process running as that user — a compromised shell, a malicious npm
  postinstall, a stolen SSH session — without the user's participation;
- anything that can write the profile store (`~/.config/vpn-up`), which today
  reaches root at the next connect via `<extraArgs>`;
- the login service's unattended, no-human-present execution path.

"Passwordless VPN" should cost the user passwordless-VPN privilege, not
passwordless-root privilege.

---

## 2. The invariant

> **For every possible input the helper accepts, from any caller, the privileged
> actions it performs are confined to bringing up or tearing down a VPN tunnel.**

Corollaries that constrain the rest of the design:

- **Caller authentication buys nothing and will not be attempted.** Any process
  running as the user can invoke the helper directly, so there is no
  distinguishable "real `vpn-up`" to authenticate. Request signing, shared
  secrets, and parent-process checks are all defeated by the attacker simply
  calling the helper the same way `vpn-up` does. Strictness of the accepted
  input is the entire security property; authentication is theatre. *(Noting
  this explicitly because "authenticated/strict request" was the phrasing in the
  review that prompted this document — the strict half is load-bearing, the
  authenticated half is not.)*
- **Therefore the profile store needs no integrity protection.** Editing
  `profiles.xml` can only produce inputs the helper already had to be safe
  against.
- **The helper must not depend on `vpn-up` having validated anything.**
  Every field is re-validated inside the boundary, or it is not accepted.

---

## 3. Trust boundary

```
        ┌───────────────────────────── unprivileged (uid = user) ──────────────┐
        │  vpn-up            reads ~/.config/vpn-up/profiles.xml (xmlstarlet)  │
        │                    reads secrets from keychain / vault               │
        │                    opens the log file as itself                      │
        └──────────────────────────────────┬───────────────────────────────────┘
                                           │ argv: typed request, closed schema
                                           │ stdin: secrets only
                                           │ fd 1/2: caller-opened log
                                           ▼
                                    sudo (env_reset)
        ┌───────────────────────────── privileged (uid 0) ──────────────────────┐
        │  vpn-up-helper     validates EVERY argv field against a grammar       │
        │                    reads NO user-writable file                        │
        │                    verifies openconnect + vpnc-script ownership       │
        │                    owns its own pid/state dir                         │
        │                    builds the openconnect argv itself                 │
        └──────────────────────────────────┬───────────────────────────────────┘
                                           ▼
                                      openconnect
```

Inputs that cross the boundary — all untrusted, all validated: **argv**,
**stdin**, **environment** (neutralised by `env_reset`, see §7.3), **inherited
fds** (harmless: opened by the caller, so they name only what the caller could
already write). Inputs that deliberately **do not** cross it: the profile XML,
the secrets backend, `~/.config/vpn-up/config`, hooks, and `$PATH`.

### Why the helper does not read the profile XML

Rejected outright. It would mean parsing an attacker-controlled XML document as
root, with `xmlstarlet` (a third-party dependency, and a whole XML parser with
entity handling) inside the boundary. Parsing stays unprivileged; the helper
receives already-extracted scalars and validates them as simple strings.

This costs nothing, precisely because of §2: since the helper must be safe for
arbitrary argv anyway, having `vpn-up` do the parsing gives up no security and
removes an entire parser from the trust boundary.

---

## 4. Operations

Three verbs, nothing else.

| Verb | Privileged action |
|---|---|
| `connect` | `execve` a validated `openconnect` argv, foreground, in the caller's process group |
| `stop` | `SIGTERM`/`SIGKILL` **one** pid, read from the helper's own root-owned state, verified to be an `openconnect` the helper started |
| `version` | print the helper's version and its pinned paths; no privileged effect (used by `doctor`) |

Explicitly **not** offered: reading logs (they are user-owned already), editing
profiles, installing services, running hooks, arbitrary `kill`.

`stop` fixes an existing hole in passing: `core.sh` currently does
`sudo kill "$pid"` with a pid from a user-writable file, which under a broad
sudoers rule is arbitrary-signal-to-any-pid-as-root. The helper never accepts a
pid on argv.

---

## 5. Request schema

`connect` accepts exactly these options. Anything unrecognised is a hard error —
no pass-through, ever. Empty values are rejected rather than silently dropped,
and **no value may begin with `-`** (so a validated value can never be
mistaken for a flag).

| Option | Type / grammar | Becomes |
|---|---|---|
| `--profile` | `^[A-Za-z0-9._-]{1,64}$`, and not `.`/`..` | state/pid filename only |
| `--host` | `^[A-Za-z0-9][A-Za-z0-9.-]{0,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,256})?$` | positional arg |
| `--protocol` | closed enum: `anyconnect nc gp pulse f5 fortinet array` | `--protocol=` |
| `--user` | `^[A-Za-z0-9._@+-]{1,256}$` (not leading `-`) | `--user=` |
| `--authgroup` | `^[A-Za-z0-9 ._@-]{1,128}$` | `--authgroup` |
| `--servercert` | `^(pin-sha256:[A-Za-z0-9+/=]{20,100}\|sha1:[0-9a-fA-F:]{20,100})$` | `--servercert=` |
| `--proxy` | `^(http\|https\|socks5)://[A-Za-z0-9._:@-]{1,256}$` | `--proxy=` |
| `--certificate` | absolute path **or** `pkcs11:` URI — see §5.1 | `--certificate=` |
| `--sslkey` | same as above | `--sslkey=` |
| `--pin-source` | absolute path under the caller's own state dir — see §5.1 | appended to the PKCS#11 URI |
| `--token-mode` | closed enum: `totp hotp` | `--token-mode=` |
| `--sso` | boolean | `--external-browser=<pinned>` (§9) |
| `--background` | boolean | `--background` |
| `--quiet` | boolean | `-q` |
| `--route` | repeatable; vpn-slice token grammar — see §8 | folded into one `--script` |
| `--tunable K=V` | closed table of safe flags — see §6 | the corresponding flag |

Secrets (password, second factor, PKCS#11 PIN) arrive on **stdin**, newline
separated, exactly as today — never on argv, so never in the process table.

Note the absences: no `--script`, no `--csd-wrapper`, no `--script-tun`, no
`--config`, no `--xmlconfig`, no `--external-browser` value, no `--pid-file`, no
`extraArgs`.

### 5.1 Path arguments

A path on argv is read *as root*, which is a confused-deputy risk (`--certificate
/etc/shadow` — root reads a file the caller cannot, and parse failures could
surface content into the log). Every accepted path is therefore:

1. absolute, no `..` component, and **not** a symlink at any component
   (resolved with `realpath`, compared, and `lstat`-checked);
2. a regular file;
3. **readable by the calling uid** — checked by the helper with the caller's
   real uid (from `SUDO_UID`) via `access(2)` semantics, i.e. dropping to that
   uid in a forked child to test. If the caller could not read it unaided, the
   helper will not read it for them;
4. for `--pin-source`, additionally confined to the caller's own state directory
   and required to be mode `0600` and owned by the caller.

This makes path arguments a no-op privilege-wise: root reads only what the
caller could already read.

---

## 6. `extraArgs`, and the policy that resolves the tension

Today `extraArgs` is a documented feature (`--no-dtls`, `--os=win`, MTU,
`--reconnect-timeout`, CSD wrappers, vpn-slice). Under this design it cannot be
passed through — that would recreate the vulnerability with extra steps.

**Proposed policy, and the core idea of this document:**

> **Arbitrary `openconnect` arguments require interactive `sudo`. Passwordless
> operation requires the helper, and the helper's closed schema.**

This is coherent rather than a compromise: typing your sudo password *is* the
authorisation for doing something arbitrary as root. What must never happen is
arbitrary root becoming *ambient* and available to any process running as you.

So `vpn-up` keeps two modes:

- **prompt mode** (default, unchanged) — `sudo openconnect`, `extraArgs` honoured
  verbatim, sudo prompts. Users who need an exotic flag keep working exactly as
  today, at the cost of typing a password.
- **helper mode** — `sudo -n vpn-up-helper`, closed schema, no `extraArgs`.
  Required for the login service.

A profile using `extraArgs` in helper mode gets a clear error naming the
offending flag and the two ways forward (drop it, or use prompt mode).

To keep helper mode useful, a **tunable table** covers the genuinely harmless
flags, each typed inside the helper:

| Tunable | Type | Flag emitted |
|---|---|---|
| `no-dtls` | boolean | `--no-dtls` |
| `no-http-keepalive` | boolean | `--no-http-keepalive` |
| `disable-ipv6` | boolean | `--disable-ipv6` |
| `mtu` | integer 576–9000 | `--mtu=N` |
| `base-mtu` | integer 576–9000 | `--base-mtu=N` |
| `reconnect-timeout` | integer 1–3600 | `--reconnect-timeout=N` |
| `dpd` | integer 0–3600 | `--dpd=N` |
| `os` | enum `linux linux-64 win mac-intel android apple-ios` | `--os=` |
| `useragent` | `^[A-Za-z0-9 ._/()-]{1,128}$` | `--useragent=` |

Booleans and bounded integers cannot express a program to run. The table lives
in the helper (root-owned) — never in the profile — and grows only by review.

---

## 7. Filesystem ownership, install location, and language

### 7.1 The install path is a security requirement, not a convention

The helper is worthless if it, or any directory above it, is writable by the
unprivileged user. That **rules out the Homebrew prefix**, which is where a
brew-tap tool would naturally install — including `/usr/local` on Intel macOS,
where Homebrew's prefix *is* the conventional `/usr/local`.

Proposed:

| Platform | Path |
|---|---|
| macOS | `/opt/vpn-up/bin/vpn-up-helper` (`/opt` is root-owned; `/opt/homebrew` being a sibling is irrelevant) |
| Linux | `/usr/local/libexec/vpn-up/vpn-up-helper` |

Modes: helper `0755 root:wheel` (macOS) / `root:root` (Linux); every parent
directory `0755` root-owned, no group/other write bit.

The load-bearing part is not the path but the **check**: the installer walks
from `/` to the target and refuses to install if any component is not root-owned
or is group/world-writable. The helper repeats the same walk on its own path at
startup and refuses to run if it fails. Path choice is then merely a default
that passes the check.

### 7.2 Shell script, and the bash 3.2 constraint

A root-owned shell script is acceptable if it is unwritable and the environment
is sanitised — but it must be interpreted by a **root-owned interpreter**. On
macOS the only one guaranteed root-owned and SIP-protected is `/bin/bash`, which
is **3.2.57**. A Homebrew `bash` is inside a user-writable prefix and is
therefore disqualified as the helper's shebang.

Consequence: **the helper must be bash 3.2 compatible.** No `mapfile`, no
associative arrays, no `${var^^}`, no `&>>`. The rest of the codebase targets
bash 4+ and can continue to; the helper is a separate, small, deliberately
boring program with its own compatibility floor and its own tests. (`/bin/sh`
POSIX is the fallback if 3.2 proves awkward.)

### 7.3 Environment

The sudoers rule must not use `setenv`, and `Defaults env_reset` (the default)
must hold. The helper additionally, as its first act: `unset` `BASH_ENV`, `ENV`,
`SHELLOPTS`, `BASHOPTS`, `CDPATH`, `IFS`, `LD_*`, `DYLD_*`, `PS4`; sets
`PATH=/usr/bin:/bin:/usr/sbin:/sbin`; and invokes every external command by
absolute path. It reads only `SUDO_UID`/`SUDO_USER` from the environment, and
treats them as untrusted integers/strings used solely for the §5.1 read check
and for locating the caller's state directory (both of which only ever *reduce*
what the helper will do).

### 7.4 Pinned executables — and the check that must not be skipped

The helper invokes `openconnect` by an absolute path baked in at install time,
and **before every `execve`** verifies that the binary and every parent
directory are root-owned and not group/world-writable, refusing otherwise. Same
check for the default `vpnc-script`, which the helper always passes explicitly
rather than relying on the compiled-in default (see §1.3 and §8).

The uncomfortable consequence is §12.1: on macOS, a Homebrew `openconnect` fails
this check.

---

## 8. Split tunnelling without reopening the hole

`--script` must never take a caller-supplied path. But split tunnelling is a
real, documented feature, so it needs a narrow mechanism rather than removal.

**Two dangers, both easy to miss:**

1. **`--script` is shell-evaluated.** `openconnect` passes the value to
   `/bin/sh -c`, so a validated *path* is not enough — the whole assembled
   string must be incapable of expressing anything else. Every route token
   therefore comes from a grammar containing no shell metacharacter at all: no
   space, quote, `$`, backtick, `;`, `|`, `&`, `(`, `)`, `<`, `>`, `\`, newline.
2. **`vpn-slice` must itself be root-owned.** It is a program the helper runs as
   root. A `pip install --user` vpn-slice is user-writable and disqualified, by
   the §7.4 check.

Proposed interface — the caller passes routes, never a script:

```
--route 10.0.0.0/8  --route %192.168.99.0/24  --route wiki=wiki.corp=192.168.1.5
```

Token grammar (each token validated independently, then joined with single
spaces):

- `^[0-9.]{7,15}(/[0-9]{1,2})?$` — IPv4 / CIDR
- `^[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?$` — IPv6 / CIDR
- `^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$` — hostname
- `^%` + any of the above — exclusion
- `^[A-Za-z0-9_-]{1,64}=[A-Za-z0-9.-]{1,253}(=[0-9.]{7,15})?$` — alias

The helper then emits `--script "<pinned vpn-slice> <tokens>"`, with the pinned
path from §7.4. Nothing else can appear in that string.

For the "keep the gateway's `vpnc-script` and adjust routes afterwards" recipe
in `docs/split-tunnel.md`, the answer in helper mode is the existing **hooks**
mechanism, which runs unprivileged and is already ownership-checked — not
`--script`. The docs will need to say which recipe belongs to which mode.

A future `--route-script NAME` (resolving `NAME` inside a root-owned
`scripts.d`, `^[A-Za-z0-9._-]+$`, ownership-checked, symlinks refused) is a
possible extension. It is deliberately **not** in v1: it hands root to a file the
user cannot write, which is safe, but it is also the feature most likely to be
mis-installed by a user with `sudo`, and it is not needed for vpn-slice.

---

## 9. SSO interaction — a vector the argument list misses

`resolve_external_browser()` (`core.sh:388`) picks an opener from `PATH`, or from
`$VPN_UP_EXTERNAL_BROWSER`, and `openconnect` **runs it as root** via
`--external-browser`. Under a passwordless rule that is a root-execution path
just as direct as `--script`, and it exists today with no unusual configuration.

In helper mode: `--sso` is a boolean. The helper resolves the opener itself, from
a closed set of absolute, ownership-checked paths (`/usr/bin/open` on macOS,
`/usr/bin/xdg-open` on Linux, or a root-owned `openconnect-external-browser`),
and `VPN_UP_EXTERNAL_BROWSER` is **ignored** inside the boundary. Overriding the
opener remains available in prompt mode.

(The existing Linux caveat — a root-spawned browser may not reach the user's
session — is unchanged and orthogonal. Longer term the right fix is for the
helper to drop to `SUDO_UID` for the browser step; out of scope for v1, but the
reason `--sso` is a boolean rather than a path is to keep that door open.)

---

## 10. Installation, migration, uninstall

`vpn-up install-helper` — interactive `sudo`, once:

1. Walk and verify the target directory chain (§7.1); create it root-owned if
   absent; refuse on any user-writable component.
2. Install the helper `0755` root-owned.
3. Verify the `openconnect` and `vpnc-script` paths to be pinned (§7.4) and
   **refuse to install** if they are user-writable, printing exactly what is
   wrong and how to get a root-owned `openconnect`.
4. Write `/etc/sudoers.d/vpn-up` containing only the helper rule, mode `0440`,
   validated with `visudo -cf` **before** being moved into place.
5. **Remove the legacy `openconnect` NOPASSWD line** — leaving it makes the
   helper pointless, since the old primitive still exists. Report any *other*
   rule that grants `openconnect` (or `ALL`) and explain that it must go too.

`vpn-up doctor` gains: legacy-rule detection, ownership check on the pinned
paths, and the default-`vpnc-script` check from §1.3 — as findings, whether or
not the helper is installed.

`vpn-up uninstall-helper` removes the sudoers file and the helper, and reports
what it removed. `setup.sh --uninstall` calls it.

Note that the sudoers rule for the helper still cannot constrain arguments — and
that is fine, by §2. The helper is the argument filter; sudoers only has to name
a program that is safe for all inputs.

---

## 11. Service behaviour

Unchanged in shape: the launchd agent / systemd user unit supervises a foreground
`openconnect` and restarts it on drop. Only the invocation changes, to
`sudo -n /opt/vpn-up/bin/vpn-up-helper connect --profile … --host …`.

`service install` preflight gains: helper installed, helper rule present,
`sudo -n` works against the helper, and the profile is expressible in the closed
schema (no `extraArgs`). Failing that last check is a clear error at install
time rather than a silent failure at login. Once the helper is the service's
path, the "not recommended" warning added to the docs can be lifted for
helper-mode services.

---

## 12. Open questions — decide these before implementing

### 12.1 macOS `openconnect` is user-writable. This is the blocker.

Homebrew's `openconnect` fails §7.4, so on the most common macOS setup the helper
would refuse to run — and if it did not refuse, it would hand root to a binary
the user can replace, achieving nothing. Options:

- **(a) Require a root-owned `openconnect` for helper mode.** Honest and simple;
  but there is no obvious root-owned source on macOS, so it means building or
  hand-installing, and most users will not.
- **(b) Have `install-helper` copy `openconnect` (and `vpnc-script`, and its
  dylib closure) to a root-owned location.** Works, but forks the install:
  security updates via `brew upgrade` would no longer reach the copy — trading a
  privilege bug for a patching bug, arguably worse.
- **(c) Accept the Homebrew binary and document the residual risk.** Then helper
  mode's honest claim shrinks to "narrows the argument surface", not "closes the
  root path" — a real but much smaller win, and it must be described that way.
- **(d) Ship helper mode as Linux-first**, where distro `openconnect` is
  root-owned, and treat macOS as (c) with a loud caveat until a better answer
  exists.

I lean **(d) with (c)'s honesty**, and would not claim more than the design
delivers on macOS. This needs an explicit decision, because it determines what
the README is allowed to promise.

### 12.2 Is a root-owned bash 3.2 script an acceptable boundary?

The alternative is a small compiled helper (C or Go), which removes shell
quoting/`IFS`/glob hazards and the 3.2 constraint, but adds a build toolchain and
per-arch artefacts to a project that is currently pure shell and installs by
`git clone`. My inclination is shell for v1 — the logic is validation and one
`execve`, which shell can do safely if written defensively — with the option
open.

### 12.3 Does prompt mode keep `extraArgs`?

§6 says yes. It means the vulnerability described in SECURITY.md still exists for
anyone who keeps the legacy sudoers rule. Since `install-helper` removes that
rule, and prompt mode without it requires a password per connect, this seems
right — but it is a deliberate decision to leave a sharp edge available.

### 12.4 Migration for existing service users

Installing the helper and deleting the legacy rule breaks any currently
installed service that was configured against `openconnect`. Does
`install-helper` offer to reinstall affected services, or refuse until the user
does? Refusing is safer and noisier; reinstalling is friendlier and touches
launchd/systemd during a security operation.

### 12.5 Scope of v1

Proposed cut: `connect` + `stop` + `version`, password and SSO auth, client
certificates, the §6 tunable table, and `--route` for vpn-slice. Deferred:
`--route-script`, dropping to `SUDO_UID` for the browser, and any CSD/trojan
wrapper support (`--csd-wrapper` has no safe narrow form yet — prompt mode only).

---

## 13. Test plan sketch

- **Grammar tests, per field**: accept the valid forms; reject empty, leading
  `-`, embedded whitespace/newline, shell metacharacters, `..`, unicode
  lookalikes, over-length, and every rejected flag from §5.
- **`--route` injection corpus**: `; rm -rf /`, `$(id)`, backticks, `|`, `&&`,
  newline, `--script=`, quotes — each must be refused, and the assembled
  `--script` string asserted character-exact.
- **Path handling**: symlink to `/etc/shadow` refused; file unreadable by the
  caller refused; `..` refused; directory refused; `pin-source` outside the
  caller's dir refused.
- **Ownership checks**: a temporary tree with a group-writable parent must make
  both `install-helper` and the helper's own startup check refuse.
- **`stop`**: a pid from a user-writable file is never honoured; a pid that is
  not an `openconnect` the helper started is never signalled.
- **Environment**: `BASH_ENV`/`IFS`/`PATH` set hostile at the call site must not
  change behaviour.
- **Argv assertion**: the emitted `openconnect` argv is compared element-by-
  element against a fixture for each profile shape (password, SSO, client cert,
  PKCS#11, background, routes) — the same technique `tests/extraargs.bats`
  already uses.
- **bash 3.2**: the helper's tests run under `/bin/bash` on macOS CI, not the
  Homebrew bash used for the rest of the suite.
