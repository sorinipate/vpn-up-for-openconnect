# Privileged Helper — Security Design

**Status:** draft, revision 2. No implementation yet.
**Supersedes:** the current `sudo openconnect` invocation model.
**Context:** [SECURITY.md → Known limitations](SECURITY.md#known-limitations).

Revision 2 changes three things from revision 1, all narrowing the privileged
surface rather than hardening it in place:

- **Two-phase OpenConnect.** Authentication happens unprivileged; the helper
  receives a session cookie and establishes only the tunnel. Password, TOTP,
  client certificates, PKCS#11 PINs, and the SSO browser leave the boundary
  entirely (§4, §6).
- **Compiled helper (C), not shell.** The remaining work is POSIX primitives,
  and a shell interpreter is itself attack surface — including `BASH_ENV`, which
  is evaluated *before* the script body runs, so no in-script mitigation is
  early enough (§8.2).
- **A root-owned OpenConnect is required on every platform.** Homebrew is
  unsupported for helper mode rather than being accommodated with a weakened
  claim (§8.4).

Open questions are in §14. Two of them (§14.1, §14.2) can still change the
shape of the implementation and should be settled first.

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
   arguments permits any arguments. `openconnect` executes a program as root via
   `--script`/`-s`, `--script-tun`/`-S`, `--csd-wrapper`, `--external-browser`
   (the SSO opener), and `--csd-user` (which enables the gateway-supplied CSD
   binary; `=root` runs it as root); `--config` and `--xmlconfig`/`-x` can name
   those from a file.
2. **The permitted binary may be user-writable.** Homebrew installs with the
   installing user as owner, so the binary can be replaced.
3. **The default `vpnc-script` may be user-writable.** `openconnect` has a
   compiled-in default script, executed as root on every connect, and the
   Homebrew formula points it inside the Homebrew prefix. No unusual arguments
   are needed at all.

Point 3 is why this design cannot be only an argument filter, and why §8.4 is
a hard requirement rather than a recommendation.

---

## 2. Threat model

### Caller identity is not trusted or authenticated; arbitrary-caller safety is required

The helper is invoked via `sudo` by an unprivileged user, and **any** process
running as that user can invoke it exactly as `vpn-up` does. There is no
distinguishable "real `vpn-up`" to authenticate: request signing, shared
secrets, and parent-process inspection are all defeated by an attacker calling
the helper the same way. Caller authentication is therefore not attempted.

The requirement that replaces it is stronger, not weaker:

> **The helper must remain safe when invoked maliciously, with arbitrary
> arguments and arbitrary stdin, by any process running as the calling user.**

### The invariant

> **For every input the helper accepts, from any caller, the privileged actions
> it performs are confined to establishing or tearing down a VPN tunnel.**

What that protects: the *rule* must not become a general-purpose root primitive
usable by a compromised shell, a malicious package postinstall, a stolen SSH
session, or anything that can write `~/.config/vpn-up` — none of which involve
the user's participation. It does not attempt to stop the user themselves from
obtaining root by other legitimate means (they may be an admin; they know their
own password). Passwordless VPN should cost passwordless-VPN privilege, not
passwordless-root privilege.

### What the profile store's integrity does and does not affect

> **The profile store does not need to be trusted by the privileged helper for
> privilege-boundary safety.**

Editing `profiles.xml` can only produce inputs the helper already has to be safe
against, so it cannot yield root. That is a narrow claim, and deliberately so —
profile integrity still matters for **credential theft** (a rewritten `<host>`
harvests the password at phase-one authentication), **server redirection**, and
**VPN configuration integrity**. Those remain real concerns, addressed by the
existing ownership/permission checks on `~/.config/vpn-up` and, if adopted, by
§14.6's endpoint authorization. They are simply not root-escalation concerns.

### Corollary

The helper must not depend on `vpn-up` having validated anything. Every field is
re-validated inside the boundary, or it is not accepted.

---

## 3. Trust boundary

```
   ┌──────────────────────── unprivileged (uid = user) ─────────────────────┐
   │ vpn-up                                                                 │
   │   reads ~/.config/vpn-up/profiles.xml (xmlstarlet)                     │
   │   reads secrets from keychain / vault                                   │
   │   PHASE ONE: openconnect --authenticate                                │
   │     · password / TOTP entered here                                      │
   │     · client certificate + PKCS#11 PIN used here                        │
   │     · SSO browser opened here, as the user, in the user's session        │
   │   parses the authentication output as untrusted data (never eval)        │
   │   opens the log file as itself                                          │
   └────────────────────────────────┬───────────────────────────────────────┘
                                    │ argv: COOKIE-less session descriptor
                                    │ stdin: cookie only
                                    │ fd 1/2: caller-opened log
                                    ▼
                             sudo (env_reset)
   ┌──────────────────────────── privileged (uid 0) ────────────────────────┐
   │ vpn-up-helper (compiled)                                               │
   │   validates every argv field against a grammar                          │
   │   reads NO user-writable file                                           │
   │   ownership-walks the pinned openconnect + vpnc-script                   │
   │   writes its own pid to root-owned state, then execve                    │
   │                                                                         │
   │ PHASE TWO: openconnect --cookie-on-stdin  (foreground, no daemonize)     │
   └────────────────────────────────┬───────────────────────────────────────┘
                                    ▼
                                 tunnel
```

Inputs crossing the boundary — all untrusted, all validated: **argv**,
**stdin** (a cookie, treated as an opaque byte string), **environment**
(neutralised by `env_reset`, §8.3), **inherited fds** (harmless: opened by the
caller, so they name only what the caller could already write). Inputs that
deliberately do **not** cross it: the profile XML, the secrets backend,
`~/.config/vpn-up/config`, hooks, `$PATH`, and every credential.

### Why the helper does not read the profile XML

Rejected outright: it would mean parsing an attacker-controlled XML document as
root, with `xmlstarlet` and a full XML parser inside the boundary. Parsing stays
unprivileged and the helper receives already-extracted scalars.

This costs nothing. Because the helper must be safe for arbitrary argv anyway
(§2), moving the parse outside gives up no security and removes an entire parser
from the boundary.

---

## 4. Two-phase OpenConnect — the central design decision

OpenConnect separates authentication from tunnel establishment, and upstream
[documents this as the way to keep authentication unprivileged][oc-nonroot] —
specifically citing PKCS#11 token access and SAML/browser flows as reasons.
`--authenticate` performs the whole login and prints a session descriptor;
`--cookie-on-stdin` then establishes the tunnel from it. Both are present in
OpenConnect 9.21 (verified: `--authenticate`, `--cookie-on-stdin`, `--resolve`,
`-C/--cookie`).

[oc-nonroot]: https://www.infradead.org/openconnect/nonroot.html

**Phase one, unprivileged**, as the user, in the user's session:

```
openconnect --authenticate --protocol=… --user=… [--authgroup=…]
            [--certificate=… --sslkey=…] [--token-mode=…] [--external-browser=…] host
```

emitting `COOKIE`, `HOST`, `CONNECT_URL`, `FINGERPRINT`, and `RESOLVE`.

**Phase two, privileged**, the helper's entire job:

```
openconnect --cookie-on-stdin --protocol=… --servercert=<FINGERPRINT>
            [--resolve=<HOST:IP>] [--script "<pinned vpn-slice> …"] <CONNECT_URL>
```

### What this deletes from the privileged surface

Gone from the root schema: `--user`, `--authgroup`, `--certificate`, `--sslkey`,
`--pin-source`, `--token-mode`, `--sso`, `--external-browser`.

Consequently:

- **Revision 1's §5.1 path logic largely disappears.** No certificate or key
  path is read as root, so there is no confused-deputy risk to mitigate with
  `SUDO_UID` read-tests, symlink resolution, and mode checks. The only remaining
  root-side path handling is the ownership walk on two *pinned* paths (§8.4),
  which is a fixed check rather than caller-driven validation.
- **The PKCS#11 PIN never crosses the boundary.** No transient `pin-source`
  file, no shredding, no `0600` dance inside root.
- **Revision 1's §9 dissolves.** There is no external-browser executable inside
  the privileged boundary at all. The Linux "root-spawned browser cannot reach
  the user's session" caveat also disappears — the browser now runs as the user
  by construction, which is a functional improvement, not just a security one.

### Parsing phase one's output

Upstream's example uses `eval $( … )`. **Do not.** The output is a network-facing
program's stdout; treat it as untrusted data. Read it line by line, accept only
the five expected `KEY=value` names, reject duplicates and anything else, and
validate each value against §6's grammar before it is used or forwarded. The
cookie is a bearer credential: it goes to the helper on **stdin**, never argv,
and must never be logged (phase two runs with `-q` where the profile requests
quiet, and the helper never echoes stdin).

### What two-phase does *not* fix, and makes more important

The helper no longer validates any server identity of its own. It pins whatever
`FINGERPRINT` the caller hands it, to whatever `CONNECT_URL` the caller hands
it. Under the §2 threat model the caller is untrusted, so **a compromised
user-level process can bring up a root-configured tunnel to a gateway of its
choosing.** That is not code execution, but it is privileged control of routing,
DNS, and interface configuration.

This is exactly §14.6, and two-phase raises its priority: with authentication
outside the boundary, endpoint approval is the only remaining place where "which
VPN may this account establish without a password" could be constrained. It also
means **`--profile-id` is a label for state, not an authorization** — nothing
should be built on the assumption that it proves a configured profile was used.

One genuine strengthening: `FINGERPRINT` is the certificate phase one actually
authenticated against, so phase two is bound to the same endpoint rather than to
a value copied out of a profile. Where the profile has no pin, phase one still
validates against the system trust store and phase two inherits that decision.

---

## 5. Operations

Three verbs.

| Verb | Privileged action |
|---|---|
| `connect` | write own pid to root-owned state, then `execve` a validated foreground `openconnect` |
| `stop` | signal **one** pid, read from root-owned state, verified still to be that `openconnect` |
| `version` | print version and pinned paths; no privileged effect (for `doctor`) |

Not offered: reading logs (user-owned already), editing profiles, installing
services, running hooks, arbitrary `kill`.

### No `--background`

Backgrounding is removed from the helper. `openconnect`'s daemonization is tied
to `--pid-file` and brings pid-transfer complexity the design does not need.
The helper always `execve`s a **foreground** `openconnect`, so:

- **the helper's pid becomes the `openconnect` pid** — `execve` replaces the
  image, it does not fork — which means the helper can write `getpid()` into
  root-owned state *before* exec'ing and the recorded pid is exactly right, with
  no race, no `--pid-file`, and no scanning the process table (which `core.sh`
  does today via `_openconnect_pid_for_pid_file`);
- interactive `vpn-up` backgrounds and supervises the helper process itself if
  the user asked for background;
- launchd/systemd supervises the helper directly, which is what they want.

### `stop`, and why it still needs root

An unprivileged parent cannot signal its own root child, so `stop` cannot be
"the caller kills what it forked" — it stays a helper verb. The helper never
accepts a pid on argv. It reads the pid from its own root-owned state and, before
signalling, verifies the process is still the same one: the pinned `openconnect`
path (`/proc/<pid>/exe` on Linux, `proc_pidpath` on macOS) **and** a recorded
start time, so a recycled pid is never signalled. Then `SIGTERM`, wait, `SIGKILL`.

This closes an existing hole in passing: `core.sh:325`/`336` currently run
`sudo kill "$pid"` with a pid from a user-writable file, which under a broad
sudoers rule is arbitrary-signal-as-root.

### Root-owned state

```
/run/vpn-up/<SUDO_UID>/<profile-id>/{pid,started,endpoint}      # Linux
/var/run/vpn-up/<SUDO_UID>/<profile-id>/{pid,started,endpoint}  # macOS
```

Root-owned, `0700` per-uid directory. The `SUDO_UID` component matters: without
it, if more than one user is granted the helper rule, user A could address user
B's identically-named profile. `SUDO_UID` is trustworthy here precisely because
`env_reset` holds — sudo strips the caller's copy and sets its own from the real
invoking uid — and the helper refuses to run if it is absent or unparseable
rather than defaulting to anything.

---

## 6. Request schema

`connect` accepts exactly this. Anything unrecognised is a hard error; no
pass-through, ever. Empty values are rejected rather than silently dropped, and
**no value may begin with `-`**.

```
vpn-up-helper connect
    --profile-id <UUID>
    --protocol <enum>
    --connect-url <URL>
    --fingerprint <pin>
    [--resolve <HOST:IP>]
    [--route <token> ...]
    [--tunable <K=V> ...]
    [--quiet]
stdin: the session cookie
```

| Option | Validation |
|---|---|
| `--profile-id` | RFC 4122 UUID, or 32 hex chars. Used only as a state directory name; canonicalised and length-checked, never path-joined from raw input |
| `--protocol` | closed enum: `anyconnect nc gp pulse f5 fortinet array` |
| `--connect-url` | `https://` only; host per §7 hostname rules; optional `:port` 1–65535; path restricted to `[A-Za-z0-9._~/%+-]{0,512}`; no userinfo, no fragment, no control bytes |
| `--fingerprint` | `pin-sha256:` + base64 of exactly 32 bytes, or `sha1:` + 20 hex-byte pairs. Decoded and length-checked, not merely regex-matched |
| `--resolve` | `HOST:IP`; host per §7; IP parsed with `inet_pton` (AF_INET/AF_INET6) |
| `--route` | repeatable; §7 grammar; folded into one `--script` |
| `--tunable` | closed table, §9 |
| `--quiet` | boolean → `-q` |
| stdin | cookie: opaque bytes, length-capped (≤ 8 KiB), no NUL, no newline beyond a single trailing one; forwarded verbatim, never parsed, never logged |

**Absent by construction:** every credential, every path, every flag that names
a program, `--pid-file`, `--background`, `extraArgs`.

---

## 7. Validation is semantic, not regular

Revision 1 leaned on regular expressions. Several of those grammars accept
nonsense that a parser rejects — `999.999.999.999/99` matched revision 1's IPv4
pattern. Since the helper is compiled (§8.2), validation uses the libc parsers
that already get this right:

| Kind | Method |
|---|---|
| IPv4 / IPv6 literal | `inet_pton`; prefix length range-checked against the family (0–32 / 0–128) |
| Hostname | per-label: 1–63 bytes, `[A-Za-z0-9-]`, no leading/trailing `-`; total ≤ 253; at least one label; not all-numeric (that is an address, and must go through `inet_pton`) |
| Port | `strtol`, 1–65535, no trailing garbage |
| Base64 fingerprint | decode, then assert exact digest length |
| Integer tunables | `strtol` with explicit range, `errno` checked, no trailing garbage |

Every accepted value is additionally required to be printable ASCII with no
shell metacharacter, no whitespace, no control byte, and no leading `-`. That
last rule is what makes it impossible for a validated value to be re-read as a
flag by `openconnect`.

---

## 8. Implementation, ownership, and install location

### 8.1 The install path is a security requirement

The helper is worthless if it, or any directory above it, is writable by the
unprivileged user. That rules out the Homebrew prefix — including `/usr/local`
on Intel macOS, where Homebrew's prefix *is* the conventional `/usr/local`.

| Platform | Path |
|---|---|
| macOS | `/opt/vpn-up/bin/vpn-up-helper` (`/opt` is root-owned; `/opt/homebrew` being a sibling is irrelevant) |
| Linux | `/usr/local/libexec/vpn-up/vpn-up-helper` |

The load-bearing part is not the path but the **check**: the installer walks from
`/` to the target and refuses if any component is not root-owned or is
group/world-writable. The helper repeats the walk on its own path at startup.
Path choice is then only a default that passes the check.

### 8.2 Compiled, in C

Revision 1 proposed a root-owned shell script. That is now rejected, for two
reasons.

**The work is POSIX primitives.** `lstat`/`fstat`, `realpath`, `openat`,
`inet_pton`, `strtol`, `getpwuid`, `kill`, `execve`, `fcntl`, `proc_pidpath` —
the C versions are correct and direct; the shell versions are string manipulation
around subprocesses. Revision 1's own §5.1 wanted "dropping to that uid in a
forked child to test", which is a native `fork`/`setuid`/`access` sequence, not a
shell operation. §7's semantic validation is the same story.

**The interpreter is attack surface, and `BASH_ENV` cannot be fixed from
inside.** Bash evaluates `BASH_ENV` for a non-interactive shell *before* running
the script body, so "unset it as the first act" — revision 1's plan — is too
late by construction. `#!/bin/bash -p` (privileged mode) suppresses it, but
needing an obscure interpreter flag to close a startup-file hole is itself the
argument: a shell brings startup files, `IFS`, globbing, word splitting, and
`$PATH` into the boundary, and none of that is needed here.

Two-phase (§4) makes this cheaper, not more expensive: the helper that remains
is validation of about five scalars, two ownership walks, one state write, and
one `execve`. That is a small, auditable C program with no XML library, no crypto
library, no networking, and no extensible configuration.

The cost is real and belongs in §14.2: a pure-shell project installed by
`git clone` / brew tap gains a build step and per-architecture artefacts.

### 8.3 Environment

The sudoers rule must not use `setenv`, and `Defaults env_reset` must hold. A
compiled helper does not execute startup files, but it still: reads only
`SUDO_UID`/`SUDO_USER`, refusing to run if `SUDO_UID` is missing or unparseable;
builds phase two's environment explicitly rather than inheriting (`PATH`,
`IFS`, `LD_*`, `DYLD_*` never forwarded); and invokes `openconnect` by absolute
path. `openconnect` and `vpnc-script` receive a minimal, helper-constructed
environment.

### 8.4 A root-owned OpenConnect is required — decision on revision 1's §12.1

Revision 1 left this open and leaned toward "Linux-first, macOS honestly
downgraded". **Rejected.** The claim is preserved instead of weakened:

> **Helper mode requires a root-owned OpenConnect installation on every
> platform. Homebrew OpenConnect is explicitly unsupported for helper mode.
> Homebrew remains fully supported for prompt mode.**

Rationale: handing root to a binary the calling user can replace accomplishes
nothing, so "helper mode on Homebrew" would be a security claim that isn't true.
Better to refuse the configuration than to describe the boundary as merely
"narrowing the argument surface".

Before every `execve`, and again at install time, the helper verifies that the
`openconnect` binary, the `vpnc-script` it passes explicitly (never the
compiled-in default), and every parent directory of both are root-owned and not
group/world-writable — and refuses otherwise. The same check applies to
`vpn-slice` when `--route` is used (§10), which matters because the usual
`pip install --user` vpn-slice is user-writable.

MacPorts is the candidate supported macOS source: it carries OpenConnect 9.21,
installs under a root-owned `/opt/local` via `sudo port install`, and is
package-managed, so security updates keep arriving — unlike copying a binary at
install time, which would trade a privilege bug for a patching bug. The helper
must still run its own ownership checks rather than trusting the package manager;
"MacPorts" is a recommendation for how to obtain a passing installation, not an
exemption from the check. Verifying a real MacPorts install against the checks is
an implementation prerequisite (§14.1).

Resulting support matrix:

| OpenConnect installation | Prompt mode | Helper mode |
|---|---|---|
| Linux distro package, checks pass | yes | **yes** |
| macOS MacPorts, checks pass | yes | **yes** |
| Manually installed root-owned, checks pass | yes | **yes** |
| macOS Homebrew | yes | **no** |
| Any user-writable installation | yes, with the §1 caveat understood | **no** |

`vpn-up doctor` reports which cell the machine is in, and why.

---

## 9. `extraArgs`, and the policy that resolves the tension

`extraArgs` cannot be passed through the helper — that would recreate the
vulnerability with extra steps. The policy:

> **Arbitrary OpenConnect arguments require interactive `sudo`. Passwordless
> operation requires the helper's closed schema.**

Typing the sudo password *is* the authorisation for doing something arbitrary as
root. The bug is arbitrary root becoming *ambient*. So `vpn-up` keeps two modes:

- **prompt mode** (default, unchanged) — `sudo openconnect`, `extraArgs`
  honoured verbatim, single-phase, sudo prompts. Anyone needing an exotic flag
  keeps working exactly as today, at the cost of a password per connect.
- **helper mode** — `sudo -n vpn-up-helper`, two-phase, closed schema, no
  `extraArgs`. Required for the login service.

A profile using `extraArgs` in helper mode gets a clear error naming the flag and
the two ways forward. To keep helper mode useful, a **tunable table**, defined in
the helper and grown only by review, covers flags that cannot express a program:

| Tunable | Type | Emits |
|---|---|---|
| `no-dtls` | boolean | `--no-dtls` |
| `no-http-keepalive` | boolean | `--no-http-keepalive` |
| `disable-ipv6` | boolean | `--disable-ipv6` |
| `mtu` | int 576–9000 | `--mtu=N` |
| `base-mtu` | int 576–9000 | `--base-mtu=N` |
| `reconnect-timeout` | int 1–3600 | `--reconnect-timeout=N` |
| `dpd` | int 0–3600 | `--dpd=N` |

`--os` and `--useragent` move to **phase one**, where they belong — they affect
authentication, not the tunnel, and outside the boundary they need no grammar at
all.

---

## 10. Split tunnelling without reopening the hole

Two dangers, both easy to miss:

1. **`--script` is shell-evaluated.** OpenConnect runs it as
   `execl("/bin/sh", "/bin/sh", "-c", script, NULL)` ([`script.c`][ocscript]), so
   validating a *path* is insufficient — the whole assembled string must be
   incapable of expressing anything else.
2. **`vpn-slice` runs as root**, so it must be root-owned. A
   `pip install --user` vpn-slice is disqualified by §8.4's check.

[ocscript]: https://gitlab.com/openconnect/openconnect/blob/master/script.c

Interface — the caller passes routes, never a script:

```
--route 10.0.0.0/8  --route %192.168.99.0/24  --route wiki=wiki.corp=192.168.1.5
```

Each token is validated independently and semantically (§7): address or CIDR via
`inet_pton` with a family-checked prefix; hostname per label; `%` prefix for
exclusion; `alias=host[=ip]` with each component validated by its own rule. No
token may contain a space, quote, `$`, backtick, `;`, `|`, `&`, `(`, `)`, `<`,
`>`, `\`, or newline — so no token can alter the command.

The `vpn-slice` path is **fixed and VPN Up-controlled** rather than configurable,
which removes any question of shell-significant characters in the path itself:
`/opt/vpn-up/libexec/vpn-slice` (macOS), `/usr/local/libexec/vpn-up/vpn-slice`
(Linux), ownership-checked like any other pinned executable. The helper emits
`--script "<fixed path> <validated tokens>"` and nothing else can appear in that
string.

For the "keep the gateway's `vpnc-script` and adjust routes afterwards" recipe in
`docs/split-tunnel.md`, the helper-mode answer is the existing **hooks**
mechanism, which runs unprivileged and is already ownership-checked. The docs
will need to say which recipe belongs to which mode.

A future `--route-script NAME` resolved inside a root-owned `scripts.d` is
deliberately **not** in v1: it is safe in principle but is the feature most
likely to be mis-installed by a user with `sudo`, and vpn-slice does not need it.

---

## 11. CSD / trojan execution — why the invariant holds

Worth recording because it could have invalidated the invariant: OpenConnect
deliberately does **not** execute a gateway-downloaded Cisco Secure Desktop
trojan unless `--csd-user` or `--csd-wrapper` is supplied, precisely for this
reason ([upstream CSD notes][ocsd]). Allowing `--protocol=anyconnect` therefore
does not hand a malicious gateway an automatic root execution mechanism.

[ocsd]: https://www.infradead.org/openconnect/csd.html

That property is conditional on those two flags being absent, which is why
neither is in the schema (§6) and why both are now flagged in prompt mode's
`extraArgs` warning. CSD support in helper mode is out of scope for v1; a profile
needing it uses prompt mode.

---

## 12. Installation, migration, uninstall

`vpn-up install-helper` — interactive `sudo`, once:

1. Walk and verify the target directory chain (§8.1); create root-owned if
   absent; refuse on any user-writable component.
2. Install the helper `0755` root-owned.
3. Verify the `openconnect` and `vpnc-script` paths to be pinned (§8.4) and
   **refuse to install** if they fail, naming what is wrong and how to obtain a
   passing installation (MacPorts on macOS, distro package on Linux).
4. Write `/etc/sudoers.d/vpn-up` containing only the helper rule, `0440`,
   validated with `visudo -cf` **before** being moved into place.
5. Remove the legacy `openconnect` grant — **conservatively**, see below.

### Conservative sudoers migration

Leaving the legacy rule in place makes the helper pointless, since the old
primitive still exists. But rewriting an administrator's policy is not VPN Up's
business. So:

- **Remove only** a rule VPN Up can identify as its own with certainty: the file
  `/etc/sudoers.d/vpn-up`, matching the exact single-line form this project has
  documented. Anything else in that file, or any deviation, means hands off.
- **Detect and report** equivalent grants elsewhere — other `sudoers.d` includes,
  `/etc/sudoers` itself, `ALL` grants, group- or alias-based rules — and then
  **refuse to declare the installation secure**, rather than attempting to edit
  them. `doctor` reports the same finding independently.

That distinction matters: silently deleting lines from `/etc/sudoers` during a
"security fix" is a worse failure mode than telling the user their old grant is
still open.

`vpn-up doctor` gains: legacy-grant detection, the §8.4 ownership checks, the
default-`vpnc-script` check from §1.3, and the support-matrix verdict — whether
or not the helper is installed.

`vpn-up uninstall-helper` removes the sudoers file and the helper and reports
what it removed. `setup.sh --uninstall` calls it.

Note that the sudoers rule for the helper still cannot constrain arguments, and
that is fine by §2: the helper *is* the argument filter, and sudoers only has to
name a program that is safe for all inputs.

---

## 13. Service behaviour

Shape unchanged: the launchd agent / systemd user unit supervises a foreground
process and restarts it on drop. What it supervises becomes `vpn-up` in helper
mode, which performs phase one and then execs `sudo -n vpn-up-helper connect …`;
with `--background` gone (§5) there is no daemonization anywhere in the chain.

Each restart re-runs phase one, so it needs the stored password or a TOTP seed —
already the case today, and already unprivileged. (Duo `push` profiles issue a
new push per reconnect. That is today's behaviour too, not a regression, but it
is worth documenting for flapping links.)

`service install` preflight gains: helper installed; helper rule present;
`sudo -n` works against the helper; §8.4 checks pass; and the profile is
expressible in the closed schema (no `extraArgs`). Failing the last one is a
clear error at install time rather than a silent failure at login. Once the
service runs through the helper, the "not recommended" warning added in PR 1 can
be lifted for helper-mode services — and only for those.

---

## 14. Open questions

### 14.1 Verify a real MacPorts OpenConnect against the §8.4 checks

§8.4 makes MacPorts the recommended macOS source on the strength of its
documented root-owned `/opt/local` prefix. Before that goes in a README, an
actual install needs checking: the binary, its parent chain, the `vpnc-script`
MacPorts configures, and the dylib closure — the last because a root-owned binary
loading a user-writable library is the same bug wearing a hat. If MacPorts fails,
macOS helper mode has no packaged source and the decision returns to the table.

### 14.2 Build and distribution for a compiled helper

C is decided (§8.2); how it ships is not. Compile at install time (needs a
toolchain — Xcode CLT on macOS, `cc` on Linux) or ship prebuilt per-architecture
artefacts (needs signing, notarization on macOS, and a release pipeline this
project does not have)? Compiling from source at `install-helper` time is my
inclination: the source is small and auditable, the user is already running an
interactive `sudo` operation, and it avoids shipping binaries. But it makes the
toolchain a hard dependency of helper mode.

### 14.3 Does any protocol need the client certificate at connect, not just auth?

Two-phase assumes the cookie alone suffices for phase two, which is what
upstream's non-root example does. If some gateway configuration requires the
client certificate for the tunnel connection as well (mutual TLS at connect, not
only at authentication), then client-certificate profiles in helper mode would
need certificate path handling back inside the boundary — the one piece of
revision 1's §5.1 that would return. This needs checking per protocol before v1
scope is fixed, because it is the only identified case where §4's simplification
might not fully hold.

### 14.4 Cookie lifetime versus service restarts

Phase one's cookie may have a short server-side validity. For interactive use
this is invisible. For a service that restarts on drop it is fine too, since each
restart re-authenticates. The question is whether any protocol's cookie is
single-use in a way that makes a fast restart loop fail confusingly — and whether
`vpn-up` should back off rather than re-authenticating in a tight loop.

### 14.5 Migration for existing service users

Installing the helper and removing the legacy grant breaks any service configured
against `openconnect`. Decision: **refuse and explain, do not silently
reinstall.** A security migration should not mutate launchd/systemd state behind
the user's back; `install-helper` lists affected services and the exact commands
to reinstall them. Recorded here as settled unless someone objects.

### 14.6 Endpoint authorization — which VPN may be established without a password?

The invariant permits any caller to ask the helper for a tunnel to any endpoint
that satisfies the schema. Not code execution, but it grants any process running
as the user passwordless, privileged, system-wide route/DNS/interface changes
through a gateway of its choosing. §4 makes this the most significant remaining
exposure, since server identity now comes from the caller.

- **Model A — generic VPN privilege.** Any process as this user may establish any
  tunnel satisfying the closed schema. Simple; no root-owned registry.
- **Model B — approved VPN privilege.** Only endpoints previously approved
  interactively and recorded in root-owned state. A small registry keyed by
  `(SUDO_UID, profile-id) → (host, fingerprint)`, written during an interactive
  `sudo` approval, checked at connect. Turns `--profile-id` into a real
  capability key and reduces a compromised user process to "reconnect the VPN you
  already approved".

Proposal: **v1 ships Model A, with the registry designed for but not
implemented**, and the threat model states the exposure plainly. Model B is the
natural v2. What must not happen is shipping Model A while describing the
boundary as though it were Model B.

### 14.7 v1 scope

Proposed cut: `connect` + `stop` + `version`; two-phase authentication for
password, TOTP, SSO, and client-certificate/PKCS#11 profiles (all handled in
phase one, so all "free" from the helper's perspective); §9's tunable table;
`--route` for vpn-slice; Model A. Deferred: `--route-script`, CSD/trojan support
in helper mode, Model B, and any privilege-dropping inside the boundary (no
longer needed, since nothing that needed it remains).

---

## 15. Test plan sketch

- **Grammar, per field**: accept valid forms; reject empty, leading `-`,
  whitespace, newline, NUL, control bytes, shell metacharacters, `..`,
  over-length, `999.999.999.999/99`, `10.0.0.1/33`, all-numeric hostnames,
  non-`https` connect URLs, userinfo in URLs, fingerprints of the wrong decoded
  length, and every flag deleted from the schema in §4 and §6.
- **`--route` injection corpus**: `; rm -rf /`, `$(id)`, backticks, `|`, `&&`,
  newline, `--script=`, quotes, unicode lookalikes — each refused, and the
  assembled `--script` string asserted byte-exact.
- **Ownership checks**: a fixture tree with a user-owned component, a
  group-writable parent, and a symlinked component must make both
  `install-helper` and the helper's startup check refuse. Explicitly: a Homebrew
  `openconnect` path must be refused in helper mode (§8.4) and accepted in prompt
  mode.
- **`stop`**: a pid from a user-writable file is never honoured; a recycled pid
  (same number, different process, different start time) is never signalled; a
  pid belonging to another `SUDO_UID`'s state is never reachable.
- **Environment**: `BASH_ENV`, `IFS`, `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`
  set hostile at the call site must not change behaviour. Missing or garbage
  `SUDO_UID` must refuse.
- **Phase-one parsing**: an `--authenticate` output fixture containing extra
  keys, duplicate keys, shell substitutions, a newline-injected `COOKIE`, and
  `KEY=value; rm -rf /` must be rejected field-by-field and must never reach a
  shell.
- **Cookie handling**: never appears in argv, in any log, or in `ps` output;
  over-length and NUL-containing cookies refused.
- **Argv assertion**: phase two's argv compared element-by-element against a
  fixture per profile shape (password, SSO, client cert, PKCS#11, routes, each
  tunable) — the technique `tests/extraargs.bats` already uses.
- **Prompt mode unchanged**: the existing suite must still pass, since prompt
  mode is the compatibility path for `extraArgs`.
