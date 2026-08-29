# Privileged Helper — Security Design

> **Status: revision 3 — approved for implementation.**
> Security-relevant changes to the helper ABI, the privileged TCB, the approval
> model, or the accepted OpenConnect options require a **new design review**.
> This exists because implementation otherwise accumulates apparently harmless
> conveniences — *"could we also pass this flag?"*, *"could `approve` just be
> another helper subcommand?"* — and those are precisely the changes that
> undermine a closed privileged interface.

**Supersedes:** the current `sudo openconnect` invocation model.
**Context:** [SECURITY.md → Known limitations](SECURITY.md#known-limitations).

## What changed in revision 3

Revision 2 established two-phase OpenConnect, a compiled helper, and a
root-owned OpenConnect requirement. Revision 3 does not redesign any of that. It
closes the gaps found in review, and every change narrows the privileged surface
or removes ambiguity that the implementation would otherwise have to invent:

- **The helper is not the whole TCB** (§2, §11.4). The root TCB also contains
  OpenConnect, its dynamic-library closure, `/bin/sh`, `vpnc-script`, whatever
  that script *sources*, the utilities it resolves through `PATH`, and the
  network configuration the VPN server supplies. Ownership of two files is not
  the invariant; a **trusted execution closure** is.
- **Two privileged binaries** (§5). A NOPASSWD binary that can approve endpoints
  is a NOPASSWD binary that can approve anything, so approval moves to a
  separate executable that is never passwordless.
- **Model B in v1** (§7). Endpoints are approved once, interactively, into
  root-owned state — which also restores the server-identity check that
  two-phase gave up.
- **The helper never consumes stdin** (§8). Reading the cookie to validate it
  would consume the bytes OpenConnect needs, so it does not read them;
  `--non-inter` prevents any root-side prompt instead.
- **`--route`/vpn-slice removed from v1** (§12), because a root-owned Python
  entry point drags an interpreter and its whole import closure into the TCB.
- **Installation is opt-in about privilege, mandatory about retirement**
  (§14, amended during the installer step). `install-helper` retires the legacy
  `NOPASSWD: openconnect` rule on every run and writes a passwordless rule only
  with `--passwordless`; installation's own trust assumption is stated rather
  than implied, and §17.2/§17.6 record how it ships and what would close the gap.
- Plus a set of specification fixes: `CONNECT_URL` required, full-length
  canonical fingerprints, `--force-dpd`, proxy preserved, `--useragent`
  restored, IPv6 authorities, semantic rather than shell-shaped validation.

## Verified facts this design rests on

Checked directly against OpenConnect 9.21 and its shipped `vpnc-script`. Where
the design looks paranoid, this table is usually why.

| Fact | Evidence |
|---|---|
| `vpnc-script` **sources** hook files | `HOOKS_DIR=/etc/vpnc`; `run_hooks()` does `. $script` over `${HOOKS_DIR}/${HOOK}.d/*` — the execute bit is irrelevant, and the *directory* is what must be trusted |
| `vpnc-script` extends `PATH` | `PATH=/sbin:/usr/sbin:$PATH` — an empty inherited `PATH` becomes `/sbin:/usr/sbin:`, and a trailing colon means **the current directory** |
| OpenConnect runs the script through a shell | `execl("/bin/sh", "/bin/sh", "-c", script, NULL)` — a validated *path* is not sufficient; the whole string is shell input |
| `--authenticate` output is shell-shaped | Single-quoted `KEY='value'` lines, five keys, and the documented example is `FINGERPRINT='469bb424…'` — a **bare 40-hex** value with no prefix |
| Older OpenConnect omits `CONNECT_URL` | The manual notes earlier versions produced only `HOST`, without `CONNECT_URL` or `RESOLVE` |
| `--servercert` accepts **partial** hashes | "a partial match of the hash will also be accepted, if it is at least 4 characters past the prefix" — so `sha256:abcd` pins almost nothing |
| `--servercert` implies `--no-system-trust` | Documented, so supplying it *is* the server-identity decision |
| `--useragent` can affect **connect**, not just auth | "Some VPN servers may require specific values … in order to successfully authenticate **or connect**" |
| The flag is `--force-dpd` | `--force-dpd=INTERVAL` exists; there is no `--dpd` |
| A Homebrew `openconnect` runs user-writable code as root | Its compiled-in default `vpnc-script` lives inside the user-owned Homebrew prefix and is executed as root on every connect |

---

## 1. The problem being solved

`vpn-up` runs `sudo openconnect`. To run non-interactively — the login service,
or simply not typing a password per connect — users are told to install:

```
user ALL=(root) NOPASSWD: /path/to/openconnect
```

That rule is equivalent to passwordless root for the account, for three
independent reasons:

1. **sudoers does not constrain arguments.** A rule naming a command with no
   arguments permits any arguments. `openconnect` executes a program as root via
   `--script`/`-s`, `--script-tun`/`-S`, `--csd-wrapper`, `--external-browser`
   (the SSO opener) and `--csd-user` (which enables the gateway-supplied CSD
   binary; `=root` runs it as root); `--config` and `--xmlconfig`/`-x` can name
   those from a file.
2. **The permitted binary may be user-writable.** Homebrew installs with the
   installing user as owner, so the binary can be replaced outright.
3. **The default `vpnc-script` may be user-writable**, and it is executed as
   root on every connect. No unusual arguments are needed at all.

Point 3 is why this design cannot be only an argument filter, and why §11.4 is a
hard requirement rather than a recommendation.

---

## 2. Threat model

### Caller identity is not trusted or authenticated; arbitrary-caller safety is required

The helper is invoked via `sudo` by an unprivileged user, and **any** process
running as that user can invoke it exactly as `vpn-up` does. There is no
distinguishable "real `vpn-up`" to authenticate: request signing, shared secrets
and parent-process inspection are all defeated by an attacker calling the helper
the same way. Caller authentication is therefore not attempted.

The requirement that replaces it is stronger, not weaker:

> **The helper must remain safe when invoked maliciously, with arbitrary
> arguments and arbitrary stdin, by any process running as the calling user.**

### The invariant

> **For every input the helper accepts, from any caller, the privileged actions
> it performs are confined to establishing or tearing down a VPN tunnel that has
> been approved for that user.**

The final clause is new in revision 3 and comes from Model B (§7).

What this protects: the *rule* must not become a general-purpose root primitive
usable by a compromised shell, a malicious package postinstall, a stolen SSH
session, or anything that can write `~/.config/vpn-up` — none of which involve
the user's participation. It does not attempt to stop the user themselves from
obtaining root by legitimate means. Passwordless VPN should cost
passwordless-VPN privilege, not passwordless-root privilege.

### `vpn-up-helper` is the policy gate, not the whole TCB

The correction that drove most of revision 3. The privileged chain is:

```
vpn-up-helper                     ← the policy gate: this is what we write
      │
      ▼
openconnect ──── dynamic library closure
      │
      ▼
/bin/sh
      │
      ▼
vpnc-script
      │
      ├── /etc/vpnc/*.d            ← sourced, therefore executed as root
      ├── PATH-resolved utilities  ← route, ifconfig, ip, resolvconf, networksetup…
      └── server-supplied route / DNS / interface data
```

Everything below the gate runs as root. A perfect policy gate in front of a
user-writable `vpnc-script`, or a `PATH` that resolves to a user-writable
directory, protects nothing.

### The VPN server is an untrusted input to the privileged TCB

Also new in revision 3. Phase two's **server responses and tunnel
configuration** cross into the privileged TCB: `vpnc-script` consumes
server-supplied variables — addresses, routes, DNS — inside a root shell, with
some unquoted expansions. That is upstream's code, but upstream's code is in
*our* root TCB.

This does not hand a gateway code execution (§13), and hardening `vpnc-script`
is upstream's business rather than ours. What follows for us is narrower and
concrete: **which gateway may be reached without a password is itself a security
decision**, which is why Model B is in v1 rather than deferred.

### What the profile store's integrity does and does not affect

> **The profile store does not need to be trusted by the privileged helper for
> privilege-boundary safety.**

Editing `profiles.xml` can only produce inputs the helper already has to be safe
against, so it cannot yield root. That is a narrow claim, deliberately. Profile
integrity still matters for **credential theft** (a rewritten `<host>` harvests
the password during phase-one authentication), **server redirection** and **VPN
configuration integrity**. Those are addressed by the existing ownership and
permission checks on `~/.config/vpn-up`, and now partly by Model B. They are
simply not root-escalation concerns.

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
   │   normalises the fingerprint and the endpoint origin                    │
   │   opens the log file as itself                                          │
   └────────────────────────────────┬───────────────────────────────────────┘
                                    │ argv: session descriptor, no credentials
                                    │ stdin: the cookie — NOT read by the helper
                                    │ fd 1/2: caller-opened log
                                    ▼
                             sudo (env_reset)
   ┌──────────────────────────── privileged (uid 0) ────────────────────────┐
   │ vpn-up-helper (compiled)                                               │
   │   validates every argv field semantically                               │
   │   matches the request against the root-owned approval registry           │
   │   reads NO user-writable file                                           │
   │   verifies the trusted execution closure                                 │
   │   takes the per-(uid, profile) lock; records its own pid                 │
   │                                                                         │
   │ PHASE TWO: execve openconnect --cookie-on-stdin --non-inter (foreground) │
   └────────────────────────────────┬───────────────────────────────────────┘
                                    ▼
                        tunnel  ←──  untrusted server configuration (§2)
```

Inputs crossing the boundary — all untrusted: **argv**, **environment**
(neutralised by `env_reset`, §11.3), **inherited fds** (harmless: opened by the
caller, so they name only what the caller could already write), and **the
server's phase-two responses**. Passing *through* unread: **stdin**. Not
crossing at all: the profile XML, the secrets backend,
`~/.config/vpn-up/config`, hooks, `$PATH`, and every credential.

### Why the helper does not read the profile XML

Rejected outright: it would mean parsing an attacker-controlled XML document as
root, with `xmlstarlet` and a full XML parser inside the boundary. Parsing stays
unprivileged; the helper receives already-extracted scalars.

This costs nothing. Because the helper must be safe for arbitrary argv anyway
(§2), moving the parse outside gives up no security and removes an entire parser
from the boundary.

---

## 4. Two-phase OpenConnect

OpenConnect separates authentication from tunnel establishment, and upstream
documents this as the way to keep authentication unprivileged — specifically
citing PKCS#11 token access and SAML/browser flows.

**Phase one, unprivileged**, as the user, in the user's session:

```
openconnect --authenticate --protocol=… --user=… [--authgroup=…]
            [--certificate=… --sslkey=…] [--token-mode=…]
            [--external-browser=…] [--os=…] host
```

**Phase two, privileged** — the helper's entire job:

```
openconnect --cookie-on-stdin --non-inter --protocol=…
            --servercert=<approved canonical fingerprint>
            --script <pinned vpnc-script>
            [--proxy=… | --no-proxy] [--resolve=…] [--useragent=…]
            [tunables] <CONNECT_URL>
```

### What this deletes from the privileged surface

Gone from the root schema: `--user`, `--authgroup`, `--certificate`, `--sslkey`,
`--pin-source`, `--token-mode`, `--sso`, `--external-browser`, `--os`.

Consequently: no certificate or key path is read as root, so the confused-deputy
problem that revision 1 mitigated with `SUDO_UID` read-tests and symlink
resolution **does not exist** rather than being handled; the PKCS#11 PIN never
crosses the boundary, so there is no transient `pin-source` file to create or
shred; and there is no external-browser executable inside the boundary at all.
The Linux "root-spawned browser cannot reach the user's session" caveat also
disappears — the browser now runs as the user by construction, which is a
functional improvement as much as a security one.

### Parsing phase one's output

Upstream's example is `eval $( … )`. **Do not.** The output is a network-facing
program's stdout; treat it as untrusted data. Parse the small language
OpenConnect actually emits — not shell:

- exactly `KEY='VALUE'` per line, single-quoted;
- exactly the five recognised keys `COOKIE`, `HOST`, `CONNECT_URL`,
  `FINGERPRINT`, `RESOLVE`;
- no duplicate keys, no embedded newline, no trailing characters after the
  closing quote;
- **no shell escape interpretation of any kind** — a backslash, `$`, or backtick
  inside the value is a literal byte, not an operator;
- anything unrecognised is a hard failure, not a skipped line.

The cookie is a bearer credential: it goes to the helper on **stdin**, never
argv, and is never logged.

### `CONNECT_URL` is required — no legacy `HOST` fallback

Upstream's compatibility idiom is `${CONNECT_URL:-$HOST}`. Helper mode does not
adopt it. If authentication returns only the legacy `HOST`, refuse:

```
OpenConnect too old for hardened helper mode
```

Rationale: Model B binds an approved endpoint origin, and collapsing to a
numeric `HOST` discards exactly the origin information being bound. Upstream
itself notes that `HOST` alone can break connections through proxies and for
some protocols. This detects the required *output contract* rather than guessing
a minimum version number. Prompt mode keeps legacy compatibility.

### Fingerprint normalisation happens unprivileged

`--authenticate` emits a bare hex digest. The unprivileged parser normalises it
so the helper never has to widen its schema:

| Input | Canonical form |
|---|---|
| bare 40 hex | `sha1:<40 lowercase hex>` |
| bare 64 hex | `sha256:<64 lowercase hex>` |
| `sha1:` / `sha256:` prefixed | lowercased, length-asserted |
| `pin-sha256:<base64>` | decode → require **exactly 32 bytes** → re-encode canonically |

There is **exactly one** canonical representation per digest, and the registry
stores and compares only that. For `pin-sha256` the as-supplied string is never
compared, so two logically identical pins with different base64 formatting
cannot behave differently.

### What two-phase does not fix on its own

The helper no longer performs any server authentication of its own — it pins
whatever fingerprint it is given. Without Model B, a compromised user process
could therefore stand up a root-configured tunnel to a gateway of its choosing.
That is the reason Model B is in v1 (§7) rather than deferred: it is what makes
the §2 invariant's "that has been approved for that user" clause true.

---

## 5. Two privileged binaries, one NOPASSWD rule

**Invariant.** Model B collapses if the passwordless binary can also grant
approvals: a NOPASSWD binary that can approve endpoints is a NOPASSWD binary
that can approve anything.

```
vpn-up-helper   connect | stop | version     ← the ONLY NOPASSWD executable
vpn-up-admin    approve | revoke | list      ← NEVER NOPASSWD
```

- `/etc/sudoers.d/vpn-up` names `vpn-up-helper` and nothing else.
- `vpn-up-admin` is reached only through an interactive `sudo vpn-up-admin …`,
  so every approval costs a real password prompt. `vpn-up approve-profile`
  remains the user-facing command and invokes it internally.
- `install-helper` installs both, with different privileges.
- **`doctor` fails if `vpn-up-admin` is authorized by any effective `NOPASSWD`
  rule.** The check is about *passwordless reachability*, not mention: an
  ordinary authenticated rule (`user ALL=(root) …/vpn-up-admin`) is legitimate
  administrator policy and is not a boundary failure.

Both binaries share the validation and closure-checking code; only
`vpn-up-helper` is ever passwordless.

---

## 6. Operations

| Verb | Binary | Privileged action |
|---|---|---|
| `connect` | helper | take the lock, record own pid, `execve` a validated foreground `openconnect` |
| `stop` | helper | signal **one** pid from root-owned state, verified still to be that `openconnect` |
| `version` | helper | print version and pinned paths; no privileged effect (for `doctor`) |
| `approve` / `revoke` / `list` | admin | write or read the approval registry |

Not offered anywhere: reading logs (user-owned already), editing profiles,
installing services, running hooks, arbitrary `kill`.

### No `--background`

The helper always `execve`s a **foreground** `openconnect`. `execve` replaces
the process image rather than forking, so:

- **the helper's pid becomes the `openconnect` pid**, which means the helper can
  write `getpid()` into root-owned state *before* exec'ing and the recorded pid
  is exactly right — no `--pid-file`, no race, and no scanning the process table
  as `core.sh` does today;
- interactive `vpn-up` backgrounds and supervises the helper process itself if
  the user asked for background;
- launchd/systemd supervises the helper directly, which is what they want.

### `stop`

An unprivileged parent cannot signal its own root child, so `stop` stays a
privileged verb. The helper never accepts a pid on argv: it reads the pid from
its own root-owned state and, before signalling, verifies the process is still
the same one — the pinned `openconnect` path (`/proc/<pid>/exe` on Linux,
`proc_pidpath` on macOS) **and** a recorded start time, so a recycled pid is
never signalled. Then `SIGTERM`, wait, `SIGKILL`.

This also closes an existing hole: `core.sh` currently runs `sudo kill "$pid"`
with a pid from a user-writable file, which under a broad sudoers rule is
arbitrary-signal-as-root.

### Root-owned state, and one tunnel per profile

```
/run/vpn-up/<SUDO_UID>/<profile-id>/{lock,pid,started,endpoint}      # Linux
/var/run/vpn-up/<SUDO_UID>/<profile-id>/{lock,pid,started,endpoint}  # macOS
```

Root-owned, `0700` per-uid directory. The `SUDO_UID` component matters: without
it, if more than one user is granted the helper rule, user A could address user
B's identically-named profile. `SUDO_UID` is trustworthy here precisely because
`env_reset` holds — sudo strips the caller's copy and sets its own from the real
invoking uid — and the helper **refuses to run** if it is absent or unparseable
rather than defaulting to anything.

Concurrent connects to the same profile are serialised by an `flock`/`fcntl`
lock on `lock`, taken before the state write. `FD_CLOEXEC` is cleared so the
descriptor survives `execve`, and the kernel releases the lock when OpenConnect
exits. This gives exactly one active tunnel per profile identity with no
process-table race, and makes stale state self-healing: the next connect takes
the lock, validates or prunes the recorded pid, and rewrites it.

> Implementation check, not an assumption: an integration test must confirm
> OpenConnect does not close inherited descriptors it does not own. Source
> inspection is not a contract.

**Confirmed in step 11**, against OpenConnect 9.21, by holding an `flock`,
clearing `FD_CLOEXEC`, `exec`ing OpenConnect, and testing the lock from a
separate open file description:

```
while OpenConnect runs   the inherited lock is STILL HELD
after it exits           the lock is released
```

Both halves hold, so the model above works as described. The check lives in
`helper/t/integration/openconnect-probe.sh` so it is re-answered per version
rather than once.

---

## 7. Model B — approved VPN privilege

The registry answers "which VPN may this account establish **without a
password**". Approval authorizes a specific privileged capability, not merely a
certificate.

### Record

```
SUDO_UID
profile UUID
protocol
approved HTTPS origin   (scheme + canonical host + effective port)
server fingerprint      (full canonical digest, §4)
proxy URL or NONE
```

Every field is checked at connect; any mismatch refuses. Approving one profile
must not let a compromised process later switch protocol or substitute a proxy.

`profile-id` is **the stable identifier for an approved capability record**. It
is not secret and confers nothing by itself — it names which record to check.

### Origin, not URL

The registry stores an origin — `https://vpn.example.com:443` — never a literal
`CONNECT_URL`. A post-authentication URL may carry a gateway- or
session-dependent path and query, so binding it would bind runtime data. At
connect the helper compares only the origin:

```
CONNECT_URL = https://vpn.example.com/some/runtime/path?session=…
              └────── approved origin ──────┘   ← must match
```

`https://other.example.com/…` is refused however the caller supplies it. The
path and query are forwarded but never authorized. If some protocol later shows
that path binding carries security significance, that becomes protocol-specific
policy — it is not a v1 requirement.

### Canonicalisation of the origin

Specified here so the implementation cannot invent it:

| Component | v1 rule |
|---|---|
| scheme | exactly `https` |
| userinfo | forbidden |
| host — DNS | ASCII only, lowercased, trailing dot stripped |
| host — IPv4 | `inet_pton` then `inet_ntop` |
| host — IPv6 | bracketed in the URL; `inet_pton` then `inet_ntop` |
| port | absent → `443`; explicit `443` → `443`; any other valid TCP port retained |
| fragment | forbidden (not meaningful to the HTTP request) |
| path / query | accepted and forwarded; **not** part of the comparison |

**Unicode/IDNA hostnames are out of scope for helper v1.** ASCII DNS names
compare safely; IDNA needs deliberate canonicalisation and is separate work. A
non-ASCII host is refused in helper mode.

### What Model B buys back

Two-phase moved server authentication out of the boundary, and Model B returns
it — from root-owned state rather than from the caller. The helper's
`--servercert` value and the endpoint it connects to both come from the
registry's record, so **a compromised user process cannot substitute a gateway**
even if it controls DNS or supplies its own `RESOLVE`. It is reduced to
reconnecting a VPN the user already approved.

### Lifecycle

`approve` (interactive, records the origin and fingerprint observed during a
real authentication), `list`, `revoke`. Certificate rotation is **re-approval**,
never a silent update: a fingerprint that no longer matches is a refusal with a
message telling the user to re-approve, so a gateway key change is always
something a human saw.

---

## 8. Request schema

`connect` accepts exactly this. Anything unrecognised is a hard error; no
pass-through, ever. Empty values are rejected rather than silently dropped.

```
vpn-up-helper connect
    --profile-id <UUID>
    --protocol <enum>
    --connect-url <URL>
    [--resolve <HOST:IP>]
    [--proxy <URL>]
    [--useragent <string>]
    [--tunable <K=V> ...]
    [--quiet]
stdin: the session cookie — passed through unread
```

| Option | Validation |
|---|---|
| `--profile-id` | RFC 4122 UUID or 32 hex chars; canonicalised, never path-joined from raw input |
| `--protocol` | closed enum: `anyconnect nc gp pulse f5 fortinet array`; must equal the approved record |
| `--connect-url` | full URL grammar (§9); its origin must equal the approved origin |
| `--resolve` | `HOST:IP`; bound semantically (§9) |
| `--proxy` | `http://host:port` or `socks5://host:port` (§9); must equal the approved record |
| `--useragent` | printable ASCII, 1–128 bytes |
| `--tunable` | closed table (§10) |
| `--quiet` | boolean → `-q` |

The **fingerprint is not an option**: it comes from the registry, not the
caller.

### Repeated flags are refused — amended during step 9

The closed schema accepts each recognised flag **at most once**, and the same
tunable may not be named twice. Last-wins was the original behaviour, and Model
B would still have caught an endpoint substitution at the policy check — but a
request whose meaning cannot be read off the request is not a closed schema, and
appending to a command line is a weaker capability than rewriting one.

`--tunable mtu=1400 --tunable mtu=1500` is the clearest case: both values are
individually valid, so nothing downstream objected, and which one took effect
was OpenConnect's business rather than ours.

### stdin is not read

The helper leaves stdin untouched and `execve`s OpenConnect, which reads the
cookie via `--cookie-on-stdin`. Reading it in order to validate it would consume
the bytes OpenConnect needs, and buffering them back through a pipe and a writer
child would trade the single-`execve` model for machinery that buys nothing —
the helper never interprets the cookie, so there is nothing for validation to
protect.

What replaces that validation is `--non-inter`, **fixed and always present**, so
OpenConnect cannot fall back to prompting root-side if the cookie is missing or
rejected; it exits instead. The cookie never appears in argv, in a log, or in
`ps`.

### Absent by construction

Every credential; every caller-supplied path; `--script`, `--script-tun`,
`--csd-wrapper`, `--csd-user`, `--config`, `--xmlconfig`, `--external-browser`;
`--pid-file`; `--background`; `--route`; `extraArgs`.

---

## 9. Validation is semantic, not shell-shaped

Revision 2 applied a blanket "no shell metacharacters, no leading `-`" rule to
every field. **Both are dropped.** `execve` argv elements never meet a shell, so
`?`, `&`, `=`, `$` and `;` are not dangerous there, and since every generated
element is `--flag=<validated-value>`, a `-` inside a value cannot become
another option. Blanket shell rules on fields that never encounter a shell made
legitimate URLs unrepresentable while protecting nothing.

The replacement rule: **validate according to the parser that actually consumes
the value.**

| Field | Method |
|---|---|
| IPv4 / IPv6 literal | `inet_pton`, then `inet_ntop` to canonicalise |
| Hostname | per-label 1–63 bytes of `[A-Za-z0-9-]`, no leading/trailing `-`, total ≤ 253, ASCII only; an all-numeric label is an address and must go through `inet_pton` |
| Port | `strtol`, 1–65535, no trailing garbage |
| URL | scheme/authority/path/query decomposed and each part validated; origin canonicalised per §7 |
| Fingerprint | prefix recognised, decoded, **exact** digest length asserted, re-encoded canonically |
| Integer tunables | `strtol` with an explicit range, `errno` checked, no trailing garbage |
| Enums | exact match against a closed list |

Only one field is shell-bound, and it takes no caller input at all: the
`--script` value (§12).

### Full-length fingerprints only

A hard rule, from the verified partial-match behaviour: `--servercert` accepts a
partial hash "at least 4 characters past the prefix", so a truncated value pins
almost nothing. The schema accepts only complete digests — 40 hex, 64 hex, or
base64 decoding to exactly 32 bytes — and a short value is refused rather than
forwarded.

Emitting `--no-system-trust` explicitly alongside `--servercert` is permitted
for readability but is **not** a requirement: the documented contract already
guarantees it.

### `--resolve` is bound, not merely well-formed

`--resolve=HOST:IP` tells OpenConnect to resolve `HOST` to that address, so a
syntactically perfect value naming an *unrelated* host is still wrong:

```
approved-origin.host
      │
      ├── canonical(CONNECT_URL.host)  must match
      └── canonical(RESOLVE.host)      must match, when RESOLVE is present
```

`RESOLVE.ip` must parse as a numeric IPv4 or IPv6 address. The address itself
may legitimately change between authentications — the approved fingerprint
remains the cryptographic identity check.

### Proxy

`http://host:port` and `socks5://host:port` only, with an explicit port. No
credentials, no userinfo, no path, query or fragment, and `--proxy-auth` is not
accepted. **`https://` is not in v1** until an integration test proves the
installed OpenConnect treats that scheme as intended (§17).

When the approved record says `proxy = NONE`, the helper passes **`--no-proxy`**
explicitly, so environment-driven proxy discovery cannot change phase-two
behaviour.

Proxy support is in v1 because `<proxy>` is already a shipped, tested profile
field; dropping it would silently break working configurations, and "partially
works" is the one outcome to avoid.

---

## 10. `extraArgs`, and the policy that resolves the tension

`extraArgs` cannot be passed through the helper — that would recreate the
vulnerability with extra steps. The policy:

> **Arbitrary OpenConnect arguments require interactive `sudo`. Passwordless
> operation requires the helper's closed schema.**

Typing the sudo password *is* the authorisation for doing something arbitrary as
root. The bug is arbitrary root becoming *ambient*. So `vpn-up` keeps two modes:

- **prompt mode** (default, unchanged) — `sudo openconnect`, `extraArgs`
  honoured verbatim, single-phase, sudo prompts. Anyone needing an exotic flag
  keeps working exactly as today, at the cost of a password per connect.
- **helper mode** — `sudo vpn-up-helper`, two-phase, closed schema, no
  `extraArgs`, Model B enforced. Required for the login service.

  Plain `sudo`, not `sudo -n`. Since the passwordless rule became opt-in
  (`install-helper --passwordless`, §14), helper mode has two tiers: it is used
  interactively wherever it is merely installed, at the cost of one password,
  and without a prompt where the rule exists. `-n` would make the interactive
  tier fail at the moment of connecting — after phase one had already spent the
  user's password and second factor. The password is asked for *before* phase
  one instead, so a refusal costs nothing.

A profile using `extraArgs` in helper mode gets a clear error naming the flag
and the two ways forward. To keep helper mode useful, a **tunable table**,
defined in the helper and grown only by review, covers flags that cannot express
a program:

| Tunable | Type | Emits |
|---|---|---|
| `no-dtls` | boolean | `--no-dtls` |
| `no-http-keepalive` | boolean | `--no-http-keepalive` |
| `disable-ipv6` | boolean | `--disable-ipv6` |
| `mtu` | int 576–9000 | `--mtu=N` |
| `base-mtu` | int 576–9000 | `--base-mtu=N` |
| `reconnect-timeout` | int 1–3600 | `--reconnect-timeout=N` |
| `force-dpd` | int 0–3600 | `--force-dpd=N` |

`--os` stays in phase one, where it affects authentication. `--useragent` does
**not**: upstream documents servers that require a specific value to
authenticate *or connect*, so a phase-one-only user agent risks authenticating
and then failing to establish the tunnel. It is an HTTP header value and
harmless at the boundary, so it is a first-class schema field (§8).

---

## 11. Implementation, ownership, and the trusted execution closure

### 11.1 The install path is a security requirement

Both binaries are worthless if they, or any directory above them, are writable
by the unprivileged user. That rules out the Homebrew prefix — including
`/usr/local` on Intel macOS, where Homebrew's prefix *is* the conventional
`/usr/local`.

| Platform | Path |
|---|---|
| macOS | `/opt/vpn-up/bin/{vpn-up-helper,vpn-up-admin}` (`/opt` is root-owned; `/opt/homebrew` being a sibling is irrelevant) |
| Linux | `/usr/local/libexec/vpn-up/{vpn-up-helper,vpn-up-admin}` |

The load-bearing part is not the path but the **check**: the installer walks from
`/` to the target and refuses if any component is not root-owned or is
group/world-writable. Each binary repeats the walk on its own path.
Path choice is then only a default that passes the check.

#### When each binary performs the walk — amended during the installer step

Revision 3 said "at startup", which the implementation does not do, so the
specification is corrected to what the code guarantees:

> **All root-gated operational and admin commands perform the self-path trust
> walk before privileged work. `version` and unprivileged `verify-closure` are
> diagnostic exceptions and do not attest installation-path trust.**

The exemption is not a convenience. Those two commands exist to answer questions
about machines that have **no** installation — `doctor` asks an uninstalled binary
whether the closure would pass, and `sudo -k -n <bin> version` is how
passwordless reachability is probed — and neither claims anything about a path.
The consequence is that the two questions must not be conflated, and the
installer's own verification therefore uses `list`, which is root-gated:

| Question | Command | Why |
|---|---|---|
| may this run as root without a password? | `version` | Above the gate: sudo either authorizes the command or it does not, independent of what the program then does. `version` cannot fail on its own, so a non-zero exit means sudo refused. |
| does the installed path pass this check? | `list` | Below the gate, so it performs the walk on the real path as root. Read-only, and it succeeds on a fresh install (an absent approvals directory is "nothing approved yet", not an error). |

The walk also reads the running image from the OS (`/proc/self/exe`,
`proc_pidpath`) rather than `argv[0]`, which the caller controls entirely.

And it claims less than it appears to: it prevents a **legitimate** binary being
run as root from an untrusted path. It says nothing about a malicious binary
already installed as root — code cannot attest to its own provenance. That gap is
the install-time trust assumption in §14.

### 11.2 Compiled, in C

The work is POSIX primitives — `lstat`/`fstat`, `realpath`, `openat`,
`inet_pton`/`inet_ntop`, `strtol`, `flock`, `kill`, `execve`, `fcntl`,
`proc_pidpath` — where the C versions are correct and direct while the shell
versions are string manipulation around subprocesses. §9's semantic validation
is the same story.

Equally decisive: **a shell interpreter is itself attack surface, and `BASH_ENV`
cannot be closed from inside the script.** Bash evaluates `BASH_ENV` for a
non-interactive shell *before* running the script body, so revision 1's "unset
it as the first act" was too late by construction. `#!/bin/bash -p` suppresses
it, but needing an obscure interpreter flag to close a startup-file hole is the
argument, not the rebuttal: a shell brings startup files, `IFS`, globbing, word
splitting and `$PATH` into the boundary, and none of that is needed here.

Two-phase (§4) plus the deferrals in §12 make this cheap: what remains is
validation of a handful of scalars, a registry lookup, the closure walk, a lock,
a state write, and one `execve`. No XML library, no crypto library, no
networking, no extensible configuration.

The cost is real and is tracked in §17: a pure-shell project installed by
`git clone` / brew tap gains a build step and per-architecture artefacts.

### 11.3 Environment and privileged-process hygiene

The sudoers rule must not use `setenv`, and `Defaults env_reset` must hold. A
compiled helper executes no startup files, but the following are **requirements,
not optional hardening**:

- `umask(077)`;
- `chdir("/")`;
- close every fd > 2 except the intentionally retained lock fd;
- `RLIMIT_CORE = 0` — the root process holds the bearer cookie;
- an **explicit, non-empty** `PATH`;
- an explicitly constructed environment: `IFS`, `LD_*`, `DYLD_*`, `BASH_ENV`,
  `CDPATH` never forwarded;
- `openconnect` invoked by absolute path;
- only `SUDO_UID`/`SUDO_USER` read from the environment, refusing to run if
  `SUDO_UID` is missing or unparseable.

Two of those are mandatory for a specific, verified reason: `vpnc-script` does
`PATH=/sbin:/usr/sbin:$PATH`, so an **empty** inherited `PATH` becomes
`/sbin:/usr/sbin:` — and a trailing colon means the current directory. Combined
with a caller-controlled working directory, that is a root-exec chain arriving
through a variable nobody set. `chdir("/")` and a non-empty `PATH` remove it.

### 11.4 The trusted execution closure

Revision 2 required that `openconnect` and `vpnc-script` be root-owned. That is
not sufficient. The requirement is:

> **Every executable, script, library, interpreter, sourced hook and search path
> reachable from the privileged OpenConnect execution must be outside the
> caller's write control.**

Concretely, all of these are checked:

| Object | Why |
|---|---|
| the `openconnect` binary | executed as root |
| its **dynamic library closure** | a root-owned binary loading a user-writable library is the same bug wearing a hat |
| `/bin/sh` | OpenConnect runs the script through it |
| the pinned `vpnc-script` | executed as root on every connect |
| `/etc/vpnc` and its `*.d` directories | `run_hooks()` **sources** their contents, so the execute bit is irrelevant and *directory* writability is what matters — a user who can add a file there gets root |
| every entry in the `PATH` the helper constructs | `vpnc-script` resolves `route`, `ifconfig`, `ip`, `resolvconf`, `networksetup` through it |

Each is verified root-owned and not group/world-writable, along with every
parent directory, at install time and again before every `execve`.

#### Symlink policy — amended during step 5

An earlier draft of this section said "every component opened with
`O_NOFOLLOW`". **That cannot work, and the implementation corrected it.** On
macOS `/var` is itself a symlink (`-> private/var`), so a blanket no-follow walk
refuses `/var/run/vpn-up` before it starts. (BSD returns `ENOTDIR` rather than
`ELOOP` for `O_NOFOLLOW|O_DIRECTORY` on a link, which is how it surfaced.)

The policy is narrower, and the distinction is security-relevant:

- **A symlink at the leaf is refused.** The leaf is the component we create, and
  following it would mean root writing wherever the link points. Every
  directory and file the helper creates — the state root, the per-uid directory,
  the per-profile directory, the lock — is the leaf of exactly one such check.
- **A symlink in the parent chain is followed.** For directories we own this is
  safe, because each was already verified as a real root-owned `0700` directory
  by its own check, so no unprivileged party can plant a link inside the chain.
  Above the state root the prefix is system infrastructure; if that is
  subverted, nothing here helps.

Callers therefore build the chain one owned directory at a time rather than
recursing, which also keeps the complete set of directories this program will
ever create visible at the call site.

#### macOS state root

Also found while verifying paths: `/var/run` is `drwxrwxr-x root:daemon` — group
writable. Our own directory is still required to be root-owned `0700`, so a
squatted `/var/run/vpn-up` makes the helper **fail closed** rather than trust
it. That is correct but is a denial-of-service vector, and `/var/db` is
`root:wheel 0755`. Revisit the macOS state root at step 13.

#### State verification on `stop` — amended during step 9

The `/var/run` note above said a squatted `/var/run/vpn-up` makes the helper
**fail closed**. That was true of `connect`, which builds the tree through
`vu_dir_ensure` and therefore verifies every directory it uses. It was **not
true of `stop`**, which read the pid file without checking the tree at all — the
adversarial corpus found it.

The consequence, on macOS specifically: a process in group `daemon` can create
`/var/run/vpn-up` itself, plant a `pid` and a `started` file, and have root
signal a process of its choosing. The executable-path and start-token checks
narrow that to processes whose executable is the pinned OpenConnect, which is a
real constraint but not a boundary — both values are readable from the process
table by anyone.

Two corrections, both narrowing:

- **`stop` verifies the state chain before reading anything inside it**, using a
  verify-only variant that does not create the tree. An absent tree means "no
  tunnel recorded"; a tree that exists and is not ours is a refusal, and nothing
  inside it is read.
- **The state files themselves are checked for ownership and mode**, exactly as
  registry records already were: a regular file, owned by root, with no group or
  other access. Redundant while the containing directory is `0700` root-owned —
  and that redundancy is the point, since `stop` reached those files without
  having established the directory was.

#### Standard descriptors — amended during step 9

Added to §11.3's requirements: **descriptors 0, 1 and 2 must be confirmed open
before the privileged process opens anything**, with `/dev/null` substituted for
any that is not.

Verified failure: invoked as `sudo vpn-up-helper connect ... 0<&-`, the lock file
lands on descriptor 0, because `open()` returns the lowest free descriptor. The
helper then `execve`s OpenConnect with `--cookie-on-stdin`, so **OpenConnect
reads the lock file as the session cookie**. The same shape with stderr closed
points the process's own diagnostics at a root-owned state file.

Neither is a privilege escalation. Both make a privileged program's behaviour
depend on how its caller arranged its descriptors, which is a property no
privileged program should have.

#### The library closure, as implemented in step 10

The table above says "its dynamic library closure" without saying how. The
implementation chose a different shape from the obvious one, and the choice is
the interesting part:

**It does not enumerate and verify every library. It verifies every directory the
loader will search.**

With `LD_LIBRARY_PATH` and `LD_PRELOAD` stripped by the constructed environment
(§11.3), a library can only be loaded from `DT_RPATH`/`DT_RUNPATH`,
`/etc/ld.so.preload`, or the `ld.so.conf`-configured and default directories.
Verify that set, and every library that *can* be loaded is covered — including
ones this code has never heard of, anything `dlopen`'d at runtime, and whatever
the next version links against. Enumerating a dependency graph would be larger,
slower, and weaker.

What is checked on Linux:

| Object | Why |
|---|---|
| `DT_RPATH` / `DT_RUNPATH` entries, `$ORIGIN` expanded | searched *before* the system directories, so a writable entry here beats everything else |
| `/etc/ld.so.preload` and every path in it | loaded into every process, as root |
| `/etc/ld.so.conf`, `/etc/ld.so.conf.d` and the directories they name | the directory matters as much as the contents: whoever can add a `.conf` file adds a search directory |
| the loader's default directories that exist | `/lib`, `/usr/lib`, and the multiarch variants |

Two deliberate refusals rather than guesses:

- **`$LIB` and `$PLATFORM` in a search path are refused.** Expanding them needs
  the loader's own notion of the machine, and a directory we cannot resolve is
  one we must not claim to have verified.
- **`include` lines in `ld.so.conf` are reported as unexpanded**, not followed.
  They are globs; an unexpanded glob is a set of directories the report should
  admit it did not check.

Also checked, and easy to miss: **the vpnc-script's shebang**. OpenConnect runs
the script through `execl("/bin/sh", "-c", …)`, so `/bin/sh` is the interpreter
that matters and is checked unconditionally — but the shebang is what runs if the
script is ever executed directly, and one naming a user-writable prefix says
something about the installation either way.

macOS is unimplemented and therefore **fails closed**, with §11.7's wording, as
a report row rather than a special case at the call site. Mach-O `LC_LOAD_DYLIB`,
the dyld shared cache and the `DYLD_*` rules are a different mechanism from ELF
and `ld.so`, not a port of it. That is step 13.

**Verified against a real installation**, which is what §11.6 rested on until
now. Pointed at this machine's Homebrew install, the check reports:

```
[!!] openconnect binary (executed as root)   /opt/homebrew/bin/openconnect
     trust: '/opt/homebrew' is owned by uid 501, expected 0 or root
[!!] vpnc-script (executed as root ...)      /opt/homebrew/etc/vpnc/vpnc-script
     trust: '/opt/homebrew' is owned by uid 501, expected 0 or root
```

It names the prefix rather than the Cellar target because the walk reports the
leftmost failing component, which is the useful answer: the whole prefix belongs
to the installing user.

### 11.5 Ownership and mode bits are not sufficient: the effective-writability test

Root ownership plus `0755` does not prove non-writability, because both macOS and
Linux support ACLs: a file can be `root:wheel 0755` while an ACL grants the
invoking user write access.

For the small, **fixed** set of trusted objects above, the check is therefore
effective rather than nominal: fork a child, drop supplementary groups, GID and
UID to `SUDO_UID`, and test effective write access on the object and its
parents.

Stated honestly: this is a TOCTOU check, so it is **defence-in-depth detection,
not enforcement**. The primary protection remains that the parent directories are
root-owned. A small piece of revision 1's uid-dropping logic returns here — but
only for two or three fixed paths, never for caller-supplied ones, which is
exactly the distinction that made revision 1's version untenable.

#### The probe drops to SUDO_UID, not to the owner — corrected during step 11

The paragraph above says "drop supplementary groups, GID and UID to `SUDO_UID`".
Step 10 implemented it with the required *owner* instead, which is 0 — so the
probe dropped privilege to root and then asserted it could not regain root. It
regained it trivially and reported could-not-drop-privilege, every time, on every
machine.

It went unnoticed because the probe only runs as root and nothing had run as root
until step 11's integration script did. The first CI report read it as a missing
Linux capability in the runner; it was neither environmental nor
capability-related.

Two corrections, and the second is the one that stops a recurrence:

- The caller's uid is threaded through to the probe, so it asks the question §11.5
  actually poses: can **the caller** write this object despite its mode bits.
- `vu_writable_by` **refuses `as_uid == 0` outright**, and `vu_closure_check`
  refuses `probe && probe_uid == 0` before forking. A meaningless question now
  produces a clear refusal instead of a confusing failure four frames down.

Where the probe cannot be performed — unprivileged, or root with no `SUDO_UID` —
it is skipped and the report says so. A check that could not run must never be
reported as having passed.

### 11.6 A root-owned OpenConnect is required on every platform

> **Helper mode requires a root-owned OpenConnect installation whose whole
> execution closure passes §11.4. Homebrew OpenConnect is explicitly unsupported
> for helper mode. Homebrew remains fully supported for prompt mode.**

Handing root to a binary the calling user can replace accomplishes nothing, so
"helper mode on Homebrew" would be a security claim that is not true. Refusing
the configuration is better than describing the boundary as merely "narrowing
the argument surface".

MacPorts is the candidate supported macOS source: it carries OpenConnect 9.21,
installs under a root-owned `/opt/local` via `sudo port install`, and is
package-managed, so security updates keep arriving — unlike copying a binary at
install time, which would trade a privilege bug for a patching bug. The helper
still runs its own checks; "MacPorts" is a recommendation for how to obtain a
passing installation, not an exemption.

| OpenConnect installation | Prompt mode | Helper mode |
|---|---|---|
| Linux distro package, closure passes | yes | **yes** |
| macOS MacPorts, closure passes | yes | **yes** (pending §17.1) |
| Manually installed root-owned, closure passes | yes | **yes** |
| macOS Homebrew | yes | **no** |
| Any user-writable installation | yes, with the §1 caveat understood | **no** |

`doctor` reports which row the machine is in, and why.

### 11.7 Staged delivery, and macOS fails closed

The closure work does not block starting the helper. It is staged, and until the
macOS stage is proven, macOS helper mode is **unavailable** rather than
weakened:

```
helper mode unavailable: trusted OpenConnect execution closure could not be established
```

The stages are steps 4–14 of §16.

---

## 12. Split tunnelling: prompt mode only in v1

`--route` and vpn-slice are **removed from helper v1**.

A root-owned `vpn-slice` is not sufficient, which is the point that removes it
from v1 rather than merely constraining it. vpn-slice is a Python entry point, so
the privileged closure would grow to include the interpreter, its
`PATH`/`PYTHONPATH`/`PYTHONHOME` resolution, the standard library, and every
imported package — and the usual `pip install --user` installation is
user-writable throughout. That is a second security project, not a flag.

A v2 model must pin: the interpreter by absolute path, isolated startup (`-I`,
`-S`), an explicit `PYTHONHOME`, and ownership over the entire import closure.
Until then split tunnelling works in prompt mode, so the product capability is
not lost.

The helper still passes `--script <pinned vpnc-script>` **explicitly**, rather
than relying on the compiled-in default, because that default may live in a
user-writable prefix (§1.3). Since OpenConnect runs the value through
`execl("/bin/sh", "-c", …)`, note that the path is fixed and VPN Up-controlled,
takes no caller input, and must itself contain no shell-significant character.

For the "keep the gateway's `vpnc-script` and adjust routes afterwards" recipe in
`docs/split-tunnel.md`, the helper-mode answer is the existing **hooks**
mechanism, which runs unprivileged and is already ownership-checked. The docs
need to say which recipe belongs to which mode.

---

## 13. CSD / trojan execution — why the invariant holds

Recorded because it could have invalidated the invariant: OpenConnect
deliberately does **not** execute a gateway-downloaded Cisco Secure Desktop
trojan unless `--csd-user` or `--csd-wrapper` is supplied. Allowing
`--protocol=anyconnect` therefore does not hand a malicious gateway an automatic
root execution mechanism.

That property is conditional on those two flags being absent, which is why
neither is in the schema and why both are flagged in prompt mode's `extraArgs`
warning. CSD support in helper mode is out of scope for v1; a profile needing it
uses prompt mode.

---

## 14. Installation, migration, uninstall

`vpn-up install-helper` — interactive `sudo`, once:

1. Walk and verify the target directory chain (§11.1); create root-owned if
   absent; refuse on any user-writable component.
2. Install `vpn-up-helper` and `vpn-up-admin`, `0755` root-owned.
3. Verify the full trusted execution closure (§11.4, §11.5) and **refuse to
   install** if it fails, naming exactly what failed and how to obtain a passing
   installation (MacPorts on macOS, distro package on Linux).
4. Write `/etc/sudoers.d/vpn-up` naming **only** `vpn-up-helper`, `0440`,
   validated with `visudo -cf` **before** being moved into place.
5. Remove the legacy `openconnect` grant — conservatively, below.

### Conservative sudoers migration

Leaving the legacy rule in place makes the helper pointless, since the old
primitive still exists. But rewriting an administrator's policy is not VPN Up's
business:

- **Remove only** a rule VPN Up can identify as its own with certainty: the file
  `/etc/sudoers.d/vpn-up`, matching the exact single-line form this project has
  documented. Anything else in that file, or any deviation, means hands off.
- **Detect and report** equivalent grants elsewhere — other `sudoers.d`
  includes, `/etc/sudoers` itself, `ALL` grants, group- or alias-based rules —
  and then **refuse to declare the installation secure**, rather than editing
  them. `doctor` reports the same finding independently.

Silently deleting lines from `/etc/sudoers` during a "security fix" is a worse
failure mode than telling the user their old grant is still open.

`vpn-up doctor` gains: legacy-grant detection; the passwordless-reachability
check on `vpn-up-admin` (§5); the closure checks; the default-`vpnc-script`
check from §1.3; and the §11.6 support-matrix verdict — whether or not the helper
is installed.

`vpn-up uninstall-helper` removes the sudoers file, both binaries, and (on
request) the approval registry, reporting what it removed. `setup.sh --uninstall`
calls it.

### Install-time trust — amended during the installer step

Everything above describes what installation *does*. This is what it *assumes*,
and it needs saying plainly because the installer is the mechanism that turns
this design into a standing root trust boundary:

> The runtime boundary defends against an arbitrary process running as the
> invoking user **after** installation. Installation itself does not. The
> interactive installation ceremony assumes the source tree and the build
> artefacts are not being maliciously modified by another process running as that
> user while it runs.

An unprivileged build followed by a privileged install does not close that: a
same-UID process can replace `helper/build/vpn-up-helper` in the window before
`install` runs, and root would then bless it, on the trusted path, where the
§11.1 self-check cannot help — the attacker wrote the code performing it.

Provenance root could verify independently is not reachable inside this
repository, because any key, manifest or formula VPN Up ships lives in a
user-writable tree. Real provenance means a distribution channel: a distro
package, or a release signed with a key obtained out of band. That is §17.6.

Four consequences, which are requirements and not preferences:

1. **Passwordless authorization is opt-in.** `install-helper` installs the
   binaries and writes **no** sudoers rule; `install-helper --passwordless` adds
   one. Without it, connecting costs one interactive password and still gets the
   closed schema, Model B binding and the closure check. A locally built binary
   does not become root-reachable-without-a-password as a side effect of an
   install.

2. **Legacy retirement is NOT opt-in.** Every run inspects
   `/etc/sudoers.d/vpn-up` and retires an exactly-matching legacy
   `NOPASSWD: …/openconnect` rule. Installing a hardened boundary while leaving
   the old arbitrary-root grant in place is worse than either alone, because it
   looks fixed:

   ```
   before                    install-helper           + --passwordless
   NOPASSWD openconnect  ->  no NOPASSWD rule     ->  NOPASSWD vpn-up-helper
   (arbitrary root)          (interactive sudo)       (helper only, one uid)
   ```

   Retirement is announced and confirmed, and says so when a login service is
   installed — that user loses unattended reconnects until `--passwordless` plus
   an approval is in place.

3. **Per-UID sudoers files.** New rules go to `/etc/sudoers.d/vpn-up-<uid>`,
   matching a registry and state root that are already `SUDO_UID` namespaced, so
   a second user on the machine does not collide with the first's file. The
   subject is written numerically (`#<uid> ALL=(root) NOPASSWD: …`), which
   sudoers supports explicitly and which removes username quoting from the
   problem. The shared legacy path stays known only as a thing to *retire*.

4. **Rollback is asymmetric.** If a post-activation check fails — for example
   `vpn-up-admin` turns out to be passwordless-reachable through some other rule
   — the run removes the rule **it** created, leaves the binaries installed, and
   exits non-zero. It never restores a retired legacy rule: rolling back into
   arbitrary root because a later check failed would undo the one unambiguous
   improvement of the run. The transaction rolls back to *no VPN Up NOPASSWD
   rule*, never to an insecure state.

One measured fact behind the directory rule, because it is easy to get backwards:
`install -d -m 0755` applied to a directory that is **already** mode 700 leaves it
**755**. So an installer that runs `install -d -o 0 -g 0 -m 0755` over its whole
target chain rewrites administrator-owned directories to fit — and can loosen a
deliberately tight one. `install-helper` therefore **verifies** every existing
component and **creates** only missing ones; an existing component that fails the
walk is a refusal, not something to normalise.

Uninstall inherits the ordering: **privilege comes down before the binaries do**,
and the destructive half is gated on proving it came down. If passwordless
reachability of the helper cannot be disproved afterwards — another rule names it —
the binaries stay. A stale grant pointing at this constrained helper is safer
than one pointing at a path whose lifecycle nobody controls any more.

Two things every privilege question here must respect, because both produced
green results that meant nothing before they were fixed:

- **`sudo -n` is not a policy probe.** It answers "can this run right now
  without prompting", which is also true for minutes after the user
  authenticates — and this installer guarantees a warm cache. Every passwordless
  probe uses `sudo -k -n`, which ignores the cached credentials without
  invalidating them.
- **Never execute a possibly user-writable binary to discover whether it can be
  executed as root.** Our own binaries are root-owned on a trusted path and are
  probed by execution; `openconnect` is probed by policy listing only, and an
  unlistable or unrecognised answer is reported as *cannot prove absence*, never
  as absence.

The sudoers rule for the helper still cannot constrain arguments, and that is
fine by §2: the helper *is* the argument filter, and sudoers only has to name a
program that is safe for all inputs.

---

## 15. Service behaviour

Shape unchanged: the launchd agent / systemd user unit supervises a foreground
process and restarts it on drop. What it supervises becomes `vpn-up` in helper
mode, which performs phase one and then execs
`sudo vpn-up-helper connect …`; with `--background` gone there is no
daemonization anywhere in the chain.

The service depends on the passwordless rule, but it does not get there by
passing `-n`: `helper_mode_usable()` sends any run without a terminal to prompt
mode precisely so nothing can block on a prompt nobody will answer, and a
service run therefore reaches the helper only when `helper_mode_available()` —
the cache-independent `sudo -k -n` probe — already said the policy is
passwordless.

Each restart re-runs phase one, so it needs the stored password or TOTP seed —
already the case today, and already unprivileged. Duo `push` profiles issue a
new push per reconnect, which is what makes §15.1's rate limiter necessary
rather than cosmetic: without it, a rejected or ignored push costs nothing to
repeat every 30 s, forever.

`service install` preflight gains: helper installed; helper rule present;
`sudo -k -n` works against the helper; the closure checks pass; the profile is
expressible in the closed schema (no `extraArgs`, no `--route`); and an approval
record exists for it. Failing any of those is a clear error at install time
rather than a silent failure at login.

### 15.1 The unattended authentication attempt rate limiter

`§17.4`'s open question — is any protocol's cookie single-use in a way that
makes a fast restart loop fail confusingly, and what should the backoff be —
is answered here, alongside the runtime bug it surfaced: `KeepAlive`/
`Restart=always` relaunch `vpn-up start <profile>` on any exit, including a
clean one, with no bound on how often that re-authenticates. A rejected or
ignored Duo push cost nothing to repeat every 30 s.

**The central design decision:** the limiter gates *admission* of an
unattended attempt. It never classifies what OpenConnect returned, never
waits for it, and OpenConnect's eventual exit status never changes how much
rate-limit budget was spent — verified directly against OpenConnect 9.21,
which returns the identical `rc=1` for a DNS failure, a TLS failure, and a
rejected credential, so no taxonomy exists to classify against in the first
place. Budget is charged the instant VPN Up decides to attempt an unattended
authentication, before any credential or one-time value is touched — a Duo
push is what the limiter protects against, and a Duo push is spent at that
moment regardless of what happens afterward.

**The eight rate-limiter security invariants**, each independently
regression-tested (`tests/attemptguard.bats`, `tests/totpstep.bats`) and each
a plausible thing for a future change to erode without noticing:

1. OpenConnect's outcome never changes admission history.
2. An unattended attempt is charged the moment it is admitted, before
   authentication begins — not on OpenConnect's outcome.
3. Only one process per profile may hold attempt ownership at a time.
4. No one-time factor (TOTP) is generated before exclusive ownership and the
   TOTP step reservation are both held.
5. Any wait invalidates every decision made before it; the next action
   begins with a fresh locked read, never a resumed one.
6. This state is never consumed by `vpn-up-helper` or `vpn-up-admin` as
   authorization input.
7. A live attempt owner is never reclaimed merely because the connection has
   run for a long time — only a demonstrably dead owner is stale.
8. A service attempt is admitted only after every locally decidable,
   non-authenticating prerequisite has already succeeded (a bad certificate,
   an unsupported SSO/service or Duo-passcode/service combination, a missing
   dependency, a missing stored password, a missing TOTP seed, unready
   sudo/helper privilege policy) — those are configuration or policy
   failures, not attempts, and consume no budget. This is a snapshot
   guarantee: it holds at the moment preflight is evaluated, not
   continuously through however long admission might then have to wait. A
   stale rejection surfacing after admission is charged as an ordinary
   attempt outcome, not un-charged — re-checking and un-charging would
   resurrect invariant 1's problem one step later.
   Certificate preflight itself makes one further distinction: failing to
   obtain a certificate from the gateway at all (unreachable, timed out) is
   transient and reported as `VPN_RC_NO_NETWORK`, never charged as a
   configuration failure — only a certificate that *was* obtained and then
   fails trust-store or pin validation is `VPN_RC_CONFIG`. Because
   reachability and trust are checked as two separate TLS transactions, a
   gateway that disappears between them is treated as transient too: an
   unpinned profile only reports a genuine certificate failure if the
   gateway is confirmed still reachable at the moment trust validation
   fails. Unpinned-profile trust validation also checks that the
   certificate is valid for the configured host itself
   (`-verify_hostname`/`-verify_ip`), not only that it chains to a trusted
   CA — a certificate issued for a different hostname is exactly the kind
   of locally-decidable rejection this invariant exists to catch before
   admission, rather than leaving it for OpenConnect's own (real) hostname
   check to discover after a credential has already been spent.
   The password/TOTP-seed existence checks distinguish "genuinely not
   stored" from "the secrets backend itself could not be read" (a vault
   decrypt failure, a keyring not yet unlocked): only the former is
   `VPN_RC_CONFIG`; the latter is `VPN_RC_SECRETS_UNAVAILABLE`, a transient
   code that never terminally stops the service over what may be a
   momentary backend problem.

**The state file** (`${DATA_DIR}/state/<slug>.<sha256>.state`, per profile,
mode `0600`) is a new input that gates whether an unattended attempt is
admitted — worth recording explicitly as a security invariant rather than
left implicit in a code comment: it is user-owned and same-UID-writable, and
**no privileged component ever reads it or treats it as authorization
input**. A same-UID attacker can deny availability (a poisoned
`open_until_epoch`, clamped to at most an hour) or disable the guard entirely
(clearing the attempt history), restoring exactly the unguarded behaviour
that UID already had — neither path grants additional VPN or helper
authority. The file also carries a TOTP step index (`last_totp_step`) next
to the profile's other secrets-adjacent state; the index itself is not a
secret (`floor(time/30)` is derivable by anyone with a clock), only the code
generated from it is, and that code is never written to disk.

**Exit-status semantics changed to carry this.** Under `VPN_UP_SERVICE`,
`vpn-up`'s exit status is now a supervisor instruction, not a Unix
success/failure claim: exit 0 means *stop supervising* (a permanent,
human-actionable condition — reflected in launchd's `KeepAlive` moving from
the bare boolean to the `SuccessfulExit=false` dictionary, and systemd's
`Restart=always` becoming `Restart=on-failure`), any other exit means
*restart*. Only two conditions are terminal — a config/profile problem that
needs a human, and a sudo/helper policy refusal before any tunnel — and
reaching either requires the whole call tree beneath `start()` to route
every failure through this mapping rather than `exit` directly, which two
call sites used to do (`require_bin`, `check_file_existence`) and one path
had no guard at all (a service with no configuration file entering the
interactive setup wizard). **Fixing a stopped service requires an explicit
restart afterward** once the underlying problem is fixed (the same operational
step the passwordless-sudoers case already requires) — building an automatic
"a relevant secret changed → restart the stopped service" path is deferred,
not built.

`connect()` is now a four-phase pipeline — `connection_preflight` (mode
selection, dependency/compatibility/certificate checks, all non-authenticating),
`admit_attempt` (the serialized rate-limiter transaction above), and
`run_admitted_connection` (privilege authorization, credential retrieval,
TOTP/Duo-passcode value entry, dispatch, and the epilogue that releases
attempt ownership exactly once) — rather than one function that used to spend
a TOTP code or read a Duo passcode before any of those checks ran.

**What the attempt-owner marker does not, and should not, try to
guarantee:** it serializes *VPN Up's own* authentication processes against
each other. It says nothing about whether a privileged tunnel could outlive
the VPN Up process that started it — if the supervised shell were killed
unexpectedly after a helper-mode tunnel came up, a replacement process could,
in principle, reclaim ownership and start a new attempt while an orphaned
tunnel still existed. `ensure_profile_not_running()` only observes the
user-side OpenConnect PID file, not root-owned helper state. This is a real
boundary, not a gap in the rate limiter specifically — reconciling it belongs
with §17.7's tunnel-up signal and helper-lifecycle work, not with admission.

### Release gate

The "login service not recommended" warning stays until **both** the helper is
in place **and** the encrypted-vault write bug is fixed. Unattended operation
depends on stored credentials, and today `_vault_encrypt` ignores `openssl`'s
exit status and ends in `chmod … || true`, so a secret can be reported as saved
when encryption failed. A service that silently has no usable credential is not
a service. That fix is tracked as its own change, ahead of helper
implementation (§16 step 3).

---

## 16. Implementation order

1. Finish and merge **PR 1** (documentation retraction, `extraArgs` warning,
   secrets off argv, profile-deletion leak)
2. Commit **this revision** and hold the freeze
3. **Vault atomicity / error propagation** — the §15 release gate
4. **C parser + validators**, in an entirely unprivileged test harness
5. Root state and locking primitives
6. **`vpn-up-admin`** + the Model B registry
7. **`vpn-up-helper connect/stop/version`**
8. Two-phase shell integration in `vpn-up`
9. Adversarial helper tests
10. Linux trusted-execution-closure checks — the §11.4 walk, including the
    library search paths (see §11.4's step 10 subsection)
11. Real OpenConnect integration environment — the two §18 items marked
    "integration test, not source inspection", plus the OpenConnect facts §6
    and §17.5 depend on
12. **`install-helper` / `uninstall-helper`** — §14, plus the §11.1 self-path
    check in both binaries. Not numbered in revision 3, but it belongs here:
    everything above is inert until the binaries sit on a root-owned path, and
    step 13's service preflight ("helper installed; helper rule present;
    `sudo -n` works") cannot be exercised before it exists.
13. **Hardened service (Linux classification tier)** — the rate limiter,
    outcome codes and TOTP-step fix (§15.1) already shipped cross-platform,
    ahead of this step; what remains here is Linux-first *outcome fidelity*
    (helper mode's structural `PREAUTH`/`POLICY` distinction) and the closure
    work below, not the limiter itself.
14. MacPorts / macOS closure research and implementation
15. macOS hardened service — inherits §15.1 automatically once step 14 lands,
    since the limiter does not depend on helper mode being available.

Steps 4–7 encode a deliberate rule: **build and break the policy engine before
introducing root execution.** Feed it hostile argv, registry, URL, proxy and
fingerprint inputs as an ordinary process first; wire `execve()` and the
privileged filesystem operations around it only once the validator is hard to
break.

---

## 17. Open questions

These are the only questions left open. Everything else in this document is
settled, and reopening any of it needs a new review (see the status banner).

### 17.1 Verify a real MacPorts OpenConnect against §11.4, dylib closure included

§11.6 makes MacPorts the recommended macOS source on the strength of its
root-owned `/opt/local` prefix. Before that reaches a README, an actual install
must be checked: the binary, its parent chain, the `vpnc-script` MacPorts
configures, `/etc/vpnc`, and **the dynamic library closure** — a root-owned
binary loading a user-writable library fails the invariant just as surely. If
MacPorts fails, macOS helper mode has no packaged source and §11.6's matrix row
changes.

### 17.2 Build and distribution for the compiled binaries — **ANSWERED, installer step**

**Compile at install time, unprivileged; install privileged.** `install-helper`
runs `make` as the invoking user and hands only the resulting artefacts to
`sudo`.

Compiling rather than shipping binaries, because the only distribution channel
this project has is `release-tap.yml`, which rewrites a Homebrew formula's `url`
and `sha256` to point at a source tarball. Prebuilt artefacts would need
per-architecture builds, macOS code signing and notarization, and a release
pipeline that does not exist — while the source is a few thousand lines of
dependency-free C99 that a reviewer can read. The cost is real and is stated in
the docs: **helper mode requires a C toolchain** (Xcode CLT on macOS, `cc` on
Linux).

The build being unprivileged is the security half of the answer. A root compile
would put `CC`, `CPATH`, `LIBRARY_PATH`, compiler spec files and any wrapper
earlier in `PATH` inside the root TCB, for nothing: the source tree is writable
by the user either way, which is exactly what §14's install-time trust assumption
concedes. `make` as you, `install` as root — and no shell script and no compiler
runs as root at any point, which is what keeps §11.2's argument intact.

This does **not** make installation safe against a same-UID adversary. See §14
and §17.6.

### 17.3 Does any protocol need the client certificate at connect, not just auth?

Two-phase assumes the cookie alone suffices for phase two, which is what
upstream's non-root example does. If some gateway configuration requires the
client certificate for the tunnel connection as well — mutual TLS at connect,
not only at authentication — then client-certificate profiles in helper mode
would need certificate path handling back inside the boundary, the one piece of
revision 1's path logic that would return. Check per protocol before v1 scope is
frozen; it is the only identified case where §4's simplification might not fully
hold.

### 17.4 Cookie lifetime versus service restart loops — **ANSWERED, §15.1**

The backoff is specified: a sliding 2-hour attempt window, exponential delay
(1m → 2m → 4m → 8m → 16m → 30m), and a temporary 1-hour breaker past six
attempts within the window — see §15.1. The fast-restart-loop half of the
question resolved into something more specific than "does a cookie replay":
**TOTP codes can collide across a restart**, not because of anything
protocol-specific about a cookie, but because launchd's `ThrottleInterval` has
no floor after a session that ran long enough (a drop-and-respawn inside the
same 30 s RFC 6238 step regenerates the code the gateway just consumed).
Fixed by reserving the TOTP step before generating a code from it, not after
— see the reserve-before-generate discussion in §15.1 and
`tests/totpstep.bats`. Whether a *cookie* itself is single-use per protocol
remains unverified by direct probe, but no longer matters for the restart-loop
concern the question was originally about: the rate limiter bounds the loop
regardless of cookie semantics.

### 17.5 Does `https://` work as a proxy scheme? — **ANSWERED, step 11**

**No, and the v1 schema is not conservative — it is exactly right.**

Asked of the installed OpenConnect 9.21 rather than reasoned about:

```
http://    accepted (reaches the connection attempt)
socks5://  accepted (reaches the connection attempt)
https://   "Only http or socks(5) proxies supported"
socks4://  "Only http or socks(5) proxies supported"
```

The helper's proxy validator and OpenConnect's own support matrix therefore agree
exactly. `https://` is not something to add pending evidence; it is something
OpenConnect itself refuses.

Kept as a test (`helper/t/integration/openconnect-probe.sh`) rather than written
down as a fact, because the answer is version-dependent: if a future OpenConnect
adds the scheme, this section says to consider adding it too, and a test will say
so where a note in a document would not.

### 17.6 Provenance root can verify independently

§14 concedes a trusted workspace for the duration of the interactive
installation, because nothing shipped inside a user-writable checkout can
authenticate that checkout. Closing it needs an input root can verify without
trusting the invoking user:

- a **distro package** — root-owned, signed by the distribution, and patched by
  it, which also solves the update problem this project does not otherwise have;
- or a **signed release** verified against a key obtained out of band, which
  implies a release pipeline with signing (and notarization on macOS).

Until one exists, the passwordless rule stays opt-in (§14). When one does, the
rule can reasonably default on for installations that came through it, and the
assumption paragraph in `SECURITY.md` changes rather than being deleted: an
install from a user-writable checkout will still carry it.

### 17.7 A structured tunnel-up/down signal

Nothing in §15.1's rate limiter depends on knowing whether a tunnel actually
came up — that is the whole point of gating admission rather than trying to
classify outcomes. But a real signal would still let step 13 do better:
accurate `connected`/`disconnected` hooks, real diagnostics, and a way to
answer §15.1's closing question (whether an orphaned privileged tunnel can
outlive the VPN Up process that started it) instead of merely documenting the
boundary.

OpenConnect invokes `--script` with `$reason=connect/disconnect/reconnect`,
which the helper already pins (`helper/src/exec.c:82`) — well positioned,
since the script path is already part of the closed, root-verified schema.
**Prompt mode must not get an equivalent**: OpenConnect runs as root there, so
a user-writable script executed as root is the exact arbitrary-root
escalation this project exists to eliminate. The helper's state root is
root-owned 0700 (`helper/src/state.c:307-309`), so any such channel is a
deliberate, reviewed addition to the privileged ABI, not an incidental one —
observability upgrade only, never a safety dependency.

---

## 18. Test plan

- **Grammar, per field**: accept valid forms; reject empty, whitespace, newline,
  NUL, control bytes, over-length, `..`, `999.999.999.999/99`, `10.0.0.1/33`,
  all-numeric hostnames, non-ASCII hosts, non-`https` connect URLs, userinfo,
  fragments, and every flag deleted from the schema in §4 and §8.
- **Fingerprints**: a truncated `sha256:abcd` must be **refused**, not
  forwarded — the partial-match behaviour makes this a boundary condition, not
  validation polish. Two differently formatted encodings of the same
  `pin-sha256` must canonicalise to one value and compare equal; anything
  decoding to other than 32 bytes must be refused.
- **Origin binding**: `CONNECT_URL` whose origin differs from the approved
  record (different host, different port, `http`, added userinfo) must be
  refused; a differing path or query must be **accepted** and forwarded.
- **`--resolve` binding**: a well-formed `--resolve` naming an unrelated host
  must be refused; a changed IP for the approved host must be accepted.
- **Model B**: protocol substitution, proxy substitution, proxy-to-NONE and
  NONE-to-proxy, an unapproved profile-id, and another uid's profile-id must all
  be refused. A rotated fingerprint must refuse with a re-approval message, never
  update silently.
- **Privilege separation**: `vpn-up-helper` must reject `approve`/`revoke`
  entirely, and `doctor` must fail when `vpn-up-admin` is reachable through a
  NOPASSWD rule while passing when it appears in an authenticated rule.
- **Phase-one parsing**: fixtures with extra keys, duplicate keys, a
  newline-injected `COOKIE`, `KEY=value; rm -rf /`, unquoted values, and
  backslash escapes must each be rejected field-by-field and must never reach a
  shell. A legacy `HOST`-only fixture must produce the "too old" refusal.
- **Closure checks**: fixture trees where the binary is user-owned, a parent is
  group-writable, a component is a symlink, `/etc/vpnc/connect.d` is
  user-writable, or a `PATH` entry is user-writable must each make both
  `install-helper` and the startup check refuse. Explicitly: a Homebrew
  `openconnect` must be refused in helper mode and accepted in prompt mode. An
  ACL granting the caller write access on an otherwise `root:wheel 0755` file
  must be detected.
- **Environment**: `BASH_ENV`, `IFS`, `PATH` (empty and hostile), `LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES` set at the call site must not change behaviour; an
  empty `PATH` must never reach `vpnc-script`. Missing or garbage `SUDO_UID`
  must refuse. The working directory must be `/` in the exec'd process.
- **Locking**: two concurrent connects to one profile — exactly one proceeds;
  the lock survives `execve` and is released when OpenConnect exits (integration
  test, not source inspection).
- **`stop`**: a pid from a user-writable file is never honoured; a recycled pid
  (same number, different start time) is never signalled; another `SUDO_UID`'s
  state is unreachable.
- **Cookie handling**: never in argv, never in a log, never in `ps`; stdin is
  passed through unread, so a cookie longer than any buffer still works.
- **Argv assertion**: phase two's argv compared element-by-element against a
  fixture per profile shape (password, SSO, client cert, PKCS#11, proxy, NONE
  proxy, each tunable), asserting `--non-inter` and `--servercert` are always
  present and that `--servercert` came from the registry rather than the request.
- **Prompt mode unchanged**: the existing suite must still pass, since prompt
  mode is the compatibility path for `extraArgs` and split tunnelling.
