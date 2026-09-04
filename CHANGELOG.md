# Changelog
All notable changes to **VPN Up for OpenConnect** will be documented in this file.

The format is inspired by *Keep a Changelog* and this project adheres to **Semantic Versioning**.

---

## [Unreleased]
### Fixed

- **Distinct profile names that collapse to the same filesystem slug (e.g.
  `"Work VPN"` and `"Work/VPN"`, both slugging to `Work_VPN`) could share a
  PID file, connection-state file, log file, and — for login services — the
  same launchd `Label`/plist or systemd unit file, now that multiple
  simultaneous VPN connections are supported.** Every per-profile path
  (`profile_pid_file`/`profile_state_file`/`profile_log_file`, `logging.sh`;
  `_service_path_for`/`_service_log_file`, `service.sh`) now includes a full
  SHA-256 digest of the exact profile name alongside the (still lossy, now
  merely cosmetic) slug, mirroring the scheme the TOTP rate-limiter's
  `attempt_state_file` already used. A pre-fix (slug-only) pid/state pair left
  on disk is still recognized — `resolve_profile_runtime_files` reads it,
  verifies ownership via the state file's `profile=` line, and retires it once
  confirmed dead — but is never renamed into the new scheme, since a live
  pid file is written directly by `openconnect` itself and can't be safely
  raced against. `stop <profile>`, `remove_profile`, and `ensure_profile_not_running`
  now fail closed (refuse, rather than guess) when a legacy pid file's
  ownership can't be positively established. Installing/uninstalling a login
  service for a profile that collides with an existing legacy-named one now
  verifies the on-disk definition's embedded profile name before touching it
  — refusing outright, rather than warning and proceeding, when that
  ownership can't be verified at all — and activation is staged/validated,
  with rollback that both restores the previous definition's file and
  verifies it actually reloads (a `systemctl --user daemon-reload` failure no
  longer lets a later `enable --now` silently activate stale daemon state).
  The rate-limiter's admission gate (`admit_attempt`) now consults the same
  tri-state resolver directly instead of its boolean wrapper, closing a gap
  where ambiguous runtime state read as "not running" and let admission
  continue; `remove_profile` now aborts (instead of continuing on to delete
  the secret and XML block) if removing the login service fails; and
  `service_uninstall` verifies its own removal actually succeeded rather than
  assuming it did, and now fails closed (instead of a silent no-op) when a
  legacy-named service file's owner can't be verified. Service-migration
  rollback now uses the same verified stop check everywhere, including when
  recovering from a failed load — never restoring a previous definition
  alongside a broken replacement that couldn't be confirmed inactive — and a
  crashed prior install (`target.old` left on disk) is now detected even when
  `target` itself is also missing, not just when both are present. A same-
  profile legacy service left over from an interrupted earlier migration is
  now reconciled (verified stop + verified removal) by the next successful
  `service install`, regardless of which code path performed it, instead of
  persisting unnoticed indefinitely.

### Added

- **TOTP 2FA now supports SHA256/SHA512, a custom digit count, and a custom
  time step** — `oathtool`'s own `--totp=SHA1|SHA256|SHA512`, `-d/--digits`,
  and `-s/--time-step-size` were previously hardcoded to their implicit
  defaults. Three new optional profile fields (`totpAlgorithm`, `totpDigits`,
  `totpStepSeconds`) configure them per profile; left empty or absent, they
  default to `SHA1`/`6`/`30`, so every existing TOTP profile behaves exactly
  as before. The `add-profile` wizard offers these behind an opt-in "advanced
  TOTP options" prompt, so the common case stays a single choice. The
  step-reservation mechanism that prevents a code from being regenerated
  within the same window (`totp_wait_for_fresh_step`) now uses each profile's
  configured step length instead of always the 30s global default.
  (The TOTP seed itself already goes to `oathtool` on stdin, never argv —
  fixed and covered by tests in a prior release; unaffected by this change.)

---

## [v3.13.0] — 2026-09-03
### Added

- **Helper mode now works on macOS.** The privileged helper's dynamic-library
  closure check — the piece that proves every library OpenConnect will load is
  outside your write control — was ELF/Linux only; macOS always fell back to
  the deprecated, unrestricted raw-`openconnect` NOPASSWD rule for passwordless
  service mode. A new Mach-O parser and recursive closure walk close that gap,
  handling fat/universal binaries, `@rpath`/`@loader_path`/`@executable_path`,
  and the dyld shared cache (verified via `_dyld_shared_cache_contains_path`,
  no subprocess, no private header). Verified end-to-end against a real
  MacPorts `openconnect` install: `vpn-up-admin verify-closure` now correctly
  resolves the full 35-object transitive dependency graph.
- **`vpn-up status` and connection hooks now distinguish a proven connection
  from a guess.** A new root-owned `vpnc-script` wrapper records
  connect/disconnect/reconnect telemetry, and `vpn-up-helper` exposes it
  read-only via a new `event-status` verb. Helper-mode connections get a
  genuine, script-confirmed tunnel-up signal instead of the old "OpenConnect
  process still exists after 3 seconds" heuristic — `status` now shows
  `(verified: OpenConnect connect event observed for this session)` or
  `(unverified: process liveness only)` next to `Since:`, and the `connected`
  hook only fires on the genuine signal when one is available. Prompt/SSO
  mode keeps the heuristic (there's no root-owned component there to confirm
  it), and is now labeled as such rather than implied to be proven.
- **A login service that keeps failing to authenticate now pauses instead of
  retrying forever.** The auth-rate breaker already throttled unattended
  retries (v3.12.0); it's now also bounded in *duration*: past three full
  breaker cycles with zero genuinely-verified connects in between, the
  service pauses and asks a human to intervene (fix the credential, or
  `vpn-up start` manually), rather than quietly resuming the retry curve
  forever. Uses the new tunnel-up signal above, and only ever acts strictly
  after an attempt already admitted has finished — it cannot change whether
  or how long any single attempt is made to wait.

### Fixed

- **A profile using the `pulse` protocol could select browser SSO**, even
  though only `anyconnect`/`gp` support it per `docs/protocols.md`; `pulse`
  and `nc` use password/Duo flows. The SSO check existed twice (`setup.sh`,
  `core.sh`), each independently denylisting only `nc`, which is how they
  drifted from the docs in the first place — replaced with one shared
  capability check.
- **The compiled-in `vpnc-script` path for macOS was wrong.** It named
  `/opt/local/etc/vpnc/vpnc-script`, which the real `vpnc-scripts` MacPorts
  port (a declared dependency of `openconnect`) never creates — the actual
  install path is `/opt/local/etc/vpnc-scripts/vpnc-script`. Found while
  verifying the Mach-O closure work above against a real install.

### Docs

- Cross-referenced `usage.md`/`split-tunnel.md` with the fact that
  `install-helper`'s closed argument schema refuses `--script`,
  `--csd-wrapper`, `--config`, and `--xmlconfig` outright, and documented the
  `VPN_UP_FORCE_PROMPT_MODE=TRUE` escape hatch for split-tunnelling setups
  that need them.

## [v3.12.0] — 2026-08-30
### Added

- **`vpn-up install-helper` / `uninstall-helper` — helper mode is now
  installable, so the privilege boundary is real rather than latent.** The
  installer builds the two binaries from this checkout *as you*, installs them
  root-owned on a path it has verified from `/` downward, and refuses outright on
  a machine whose OpenConnect execution closure it cannot verify — which today
  means macOS is refused and Homebrew is refused everywhere, rather than helper
  mode claiming a boundary nobody has checked. Needs a C toolchain.
  - **The legacy `NOPASSWD: openconnect` rule is retired on every run**, whether
    or not you ask for a passwordless helper rule. Installing a hardened boundary
    while leaving the old arbitrary-root grant in place is worse than either
    alone, because it looks fixed. Only a file that byte-matches one this
    project's own documentation produced is touched; anything else is reported
    and left strictly alone.
  - **Passwordless authorization is opt-in** (`--passwordless`), and writes
    `/etc/sudoers.d/vpn-up-<uid>` naming *only* `vpn-up-helper`, with a numeric
    uid subject. Without it you still get the closed argument schema, the
    approved-endpoint binding and the closure check, at the cost of one password
    per connect. `SECURITY.md` now states what installation itself assumes and
    why that makes the rule opt-in.
  - If a post-install check finds the boundary broken — `vpn-up-admin`
    passwordless-reachable through some other rule — the run removes the rule *it*
    created and fails. It never restores a retired legacy rule: rollback goes to
    *no* passwordless rule, never back to arbitrary root.
  - `uninstall-helper` removes privilege before it removes the executable, and
    keeps the binaries if it cannot prove the helper is no longer
    passwordless-reachable. `--purge` removes only the invoking user's approvals.
  - `--dry-run` shows the intended changes and makes none, and says plainly that
    it read no root-only state and is not a security verdict.

- **A login service can no longer retry unattended authentication forever,
  including a rejected Duo push, with nothing to slow it down.** `KeepAlive`/
  `Restart=always` used to relaunch `vpn-up start <profile>` every 30s
  unconditionally; a denied or ignored MFA push cost nothing to repeat. A new
  admission gate (`outcome.sh`) now limits how often an unattended attempt may
  *begin*, before any credential is touched — a sliding 2-hour window, an
  exponential backoff (1m → 2m → 4m → 8m → 16m → 30m), and a temporary
  1-hour breaker past six attempts. It never asks whether OpenConnect
  actually succeeded: that question has no reliable answer (OpenConnect 9.21
  returns the same exit code for a DNS failure, a TLS failure and a rejected
  credential), so the design deliberately avoids depending on it.
  - launchd's `KeepAlive` is now the `SuccessfulExit=false` dictionary and
    systemd's is `Restart=on-failure`, not `Restart=always`: exiting 0 now
    means *stop supervising* (a permanent, human-actionable condition — a
    missing dependency, a rejected certificate, an unproven sudo policy),
    and any other exit means *restart* (self-healing conditions, including
    "no network" and "already running", both of which are free — they never
    touch the admission gate at all).
  - TOTP codes are now reserved a step *before* being generated, exclusively:
    a session that ran long enough to respawn with no delay (`launchd`'s
    `ThrottleInterval` has no floor after that) could otherwise regenerate
    the exact code the gateway just consumed.
  - **Fixing a stopped service requires an explicit restart afterward**
    (`launchctl kickstart` / `systemctl --user restart`) once the underlying
    problem is fixed — same as the existing sudoers-rule case. A missing
    TOTP seed is the one common case this applies to; `vpn-up set-secret`
    does not restart a stopped service on its own.
  - The state this keeps (`${DATA_DIR}/state/`) is per-profile, user-owned,
    and never read by `vpn-up-helper` or `vpn-up-admin` as authorization
    input — it is an availability-only, same-UID-writable advisory to the
    unprivileged process, not a privileged control.
  - A service profile with no stored password (and no client certificate)
    now fails preflight with `VPN_RC_CONFIG` instead of discovering the
    problem after an attempt has already been admitted — one more
    locally-decidable, non-authenticating prerequisite alongside the
    existing certificate and TOTP-seed checks. A secrets-backend read
    failure (a vault decrypt error, a keyring not yet unlocked) while
    checking for a stored password or TOTP seed is reported as a distinct,
    transient `VPN_RC_SECRETS_UNAVAILABLE` rather than being read the same
    way as "nothing is stored" — the latter would otherwise permanently
    stop the service over what may resolve itself on the next attempt. This
    distinction is now made per-backend rather than by a single generic exit
    status: Keychain's own "item not found" result (a specific, verified
    exit code) is read as genuinely absent rather than as a backend error,
    and Linux Secret Service — whose `secret-tool` cannot tell "not found"
    from "backend error" apart by exit code alone — is read via whether the
    lookup itself printed an error message to stderr (verified directly
    against libsecret's own source: only its error branch prints one; a
    genuinely absent secret returns the same exit code silently), which
    distinguishes the two without depending on whether the Secret Service is
    merely *reachable* — a reachable service can still fail one specific
    lookup for an unrelated reason. Each backend's check is now a single
    round-trip that both learns the status and returns the value on
    success, rather than a check followed by a separate fetch — the
    previous two-call shape left a real gap where the backend could fail
    between them, and for the openssl vault backend meant decrypting (and
    prompting for the passphrase) twice. The same distinction now also
    carries through to the actual credential fetch after admission (not
    just preflight's existence check), since admission may have waited and
    the backend can fail in the interim — without blocking a fallback that
    doesn't need the backend at all (a legacy plaintext password already on
    the profile, or a client certificate). A failed migration write no
    longer scrubs the legacy plaintext password it was meant to replace —
    only a confirmed-successful write does — so a backend hiccup during
    migration can no longer delete the only surviving copy of the
    credential. The Keychain backend no longer deletes an existing item
    before writing its replacement (`security add-generic-password -U`
    already updates in place); the pre-delete gained nothing and meant a
    failed write left nothing behind where a valid item had stood a moment
    earlier.
  - Certificate preflight distinguishes "could not reach the gateway to
    obtain a certificate at all" (transient, `VPN_RC_NO_NETWORK`) from "got
    one, and it failed trust or pin validation" (`VPN_RC_CONFIG`) — a
    gateway that is merely down no longer permanently stops the service.
    For an unpinned profile, trust validation now also checks the
    certificate is valid for the configured host itself, not only that it
    chains to a trusted CA — capability-detected rather than assumed, since
    this project's own documented macOS install gets LibreSSL, which
    rejects the hostname-verification flags outright; on Darwin without
    them, the platform's own certificate evaluator is used instead of
    silently falling back to chain-only trust.
  - The on-disk state write is now atomic against a partial write (a disk
    full mid-write, a vanishing state directory, ...): the write is
    verified before the file is put in place, so a fault can no longer
    install a truncated state file while still reporting success — which
    would otherwise have silently dropped fields like the attempt owner or
    the TOTP step reservation to their fail-open defaults on the next read.
    The lock that guards every state transaction has the same guarantee for
    its own ownership metadata: acquiring the lock can no longer be
    reported as successful without the owner file that later proves it —
    otherwise unlockable, permanently wedging that profile's admission. An
    infrastructure failure creating the state directory itself (permission
    denied, no space) used to be indistinguishable from ordinary lock
    contention — both simply polled forever with no diagnostic; it now
    retries every iteration (so a transient condition can still self-heal)
    and warns once the condition has persisted long enough to rule out an
    ordinary race, without changing the lock's "never gives up" guarantee.
    That warning is now correctly written to stderr; writing it unredirected
    corrupted the very token `_state_lock`'s caller reads back through
    command substitution, silently wedging the lock the warning was meant to
    explain.
  - A genuinely absent TOTP seed at the actual fetch (not just preflight) now
    refuses a service outright instead of falling through to an interactive
    prompt with no controlling tty — preflight is only a snapshot, and the
    seed can be deleted during an admission wait.
  - A stored PKCS#11 PIN (`key_password`) is now fetched once, centrally, and
    shared by both the prompt-mode and (previously unsupported) helper-mode
    dispatch paths, using the same present/absent/backend-error distinction
    as the password and TOTP seed. The preferred helper path had no PIN
    handling at all before this, so a service using a PKCS#11 certificate
    through helper mode could never actually supply a stored PIN, silently
    contradicting the documented unattended-service PKCS#11 feature.
  - A local I/O failure while classifying a Secret Service lookup (an
    unwritable state/secrets directory) no longer reads as "secret not
    stored" — it's reported as a backend error, like any other environment
    problem that has nothing to do with whether the secret actually exists.
  - **Staging a PKCS#11 PIN into its transient pin-source file is now checked
    at every step, and only reported successful once the file actually exists
    on disk.** A missing `${DATA_DIR}/pids` directory, a failed `mkdir`, or a
    failed write used to be silently ignored — the function still returned
    success with a path that pointed at a file that was never created,
    which would have handed OpenConnect a `pin-source` for a nonexistent
    file. A service now retries (`VPN_RC_SECRETS_UNAVAILABLE`) rather than
    dispatching with a phantom PIN file; an interactive caller falls back to
    OpenConnect's own PIN prompt, same as when no PIN is stored at all. The
    file is also now staged with `mktemp` under a random name rather than a
    deterministic, profile-name-derived one — a secret-bearing file
    shouldn't risk the same name collision the state-file identity fix
    exists to avoid for two different profiles.
  - **A service using a PKCS#11 client certificate with no stored PIN was
    only discovered after admission had already charged an unattended
    attempt** (and, for a profile also using TOTP, after a step had already
    been reserved). Preflight now checks for a stored PIN up front, exactly
    like the existing password and TOTP-seed checks, so a misconfigured
    unattended PKCS#11 profile spends neither.
  - **The PKCS#11 PIN is now fetched and staged before a TOTP code is
    generated or a Duo passcode is entered, not after.** Fetching the PIN can
    call out to Keychain, Secret Service, or the encrypted vault and do
    filesystem I/O — none of it instant — so doing it after a one-time value
    had already been produced left that value sitting idle, exactly the kind
    of staleness the TOTP step-reservation wait already exists to prevent.
  - **A stored PKCS#11 PIN was only ever attached when the client
    *certificate* itself was a `pkcs11:` URI**, missing the equally valid,
    documented configuration of a file-path certificate paired with a
    PKCS#11 private key. One predicate (`_pkcs11_pin_needed`) now checks
    both the certificate and the key, and is shared by the setup wizard's
    PIN offer, `service install`'s preflight diagnostics, the runtime
    preflight check above, and the phase-4 fetch — previously each of the
    first two had its own, narrower, cert-only check.
  - `service install`'s preflight diagnostics for a stored password, TOTP
    secret, or PKCS#11 PIN now use the same backend-aware present/absent/
    error distinction as the runtime preflight, instead of a raw lookup that
    read a transient backend error the same way as "nothing stored."
  - **An empty stored secret read as PRESENT on Keychain and Secret Service,
    but as ABSENT on the OpenSSL/file backend — the two native tri-state
    probes never checked for emptiness.** Reproduced directly against a real
    Keychain: `security add-generic-password -w ""` succeeds, and the later
    lookup returns success with an empty value; the same is true of
    `secret-tool`. Every field this gates (password, TOTP seed, PKCS#11 PIN)
    is unusable empty, so a service with an accidentally-empty stored secret
    on either native backend sailed past preflight's existence check — for
    TOTP specifically, reaching an interactive prompt with no tty to answer
    it, exactly the bypass the existence check exists to prevent. Both native
    probes now treat an empty value the same as "not found"; `set-secret` also
    now refuses to store an empty value in the first place.
  - **A PKCS#11 PIN, staged in a plaintext transient file for the life of a
    connection attempt, was cleaned up only when `run_admitted_connection`
    returned normally** — an abnormal termination (a supervisor's TERM, a
    crash) left the file on disk indefinitely, since nothing else ever ran
    that cleanup. `run_admitted_connection` now installs a TERM/INT handler
    the moment the PIN is staged that removes the file (this needs no lock,
    unlike releasing attempt ownership); the helper-mode path additionally
    removes it as soon as a session cookie is obtained, since the privileged
    tunnel phase never touches the certificate/key/PIN again after that
    point. `vpn-up doctor` also now reports (never auto-clears) a PIN file
    whose owning process — its pid is embedded in the filename — is no
    longer alive, the same liveness-not-age test already used for attempt-
    owner reclaim.
  - **A PKCS#11 PIN file's path was embedded in the `pin-source=file:...`
    URI attribute completely unescaped**, even though `DATA_DIR` (and so the
    PIN file's path) is configurable via `VPN_UP_HOME`/`XDG_CONFIG_HOME` and
    is not guaranteed to be URI-safe: a space is not a valid character there,
    and `&`/`#`/`%` are themselves pkcs11-URI delimiters. The path is now
    percent-encoded before it's appended.
  - **Correcting a wrong stored PKCS#11 PIN via `set-secret ... key_password`
    left the rate limiter's attempt history untouched** — `secrets_set`'s
    field switch cleared history on a corrected `password` or `token_secret`
    but had no case for `key_password` at all, so a service stuck in backoff
    over a bad stored PIN would stay asleep for the rest of an already-open
    breaker even after the PIN was fixed. `key_password` now clears history
    the same way `password` does (no TOTP-step reset is needed for a PIN
    change).
  - **A PKCS#11 URI could embed its own PIN directly (RFC 7512's `pin-value`
    or `pin-source` query attributes), completely bypassing the managed
    `key_password`/`_prepare_pkcs11_pin` path.** Reproduced directly:
    `clientCertificate="pkcs11:id=%01?pin-value=918273"` reached
    `run_openconnect`'s argv verbatim — the PIN ended up in `profiles.xml`
    *and* on OpenConnect's own process arguments, in the clear, and (per
    GnuTLS's own PKCS#11 code, which checks `pin-value` before `pin-source`)
    would silently have overridden a correctly-managed stored PIN rather
    than merely coexisting with it. `connection_preflight` now refuses any
    profile whose certificate or key URI embeds either attribute, in both
    `SERVICE` and `INTERACTIVE` modes — unlike a merely-missing PIN, this is
    an active misconfiguration that leaks a credential in *either* mode, not
    only when unattended. The setup wizard refuses it too, so a profile can
    never be created this way in the first place.
  - **The TERM/INT cleanup added for an abandoned PKCS#11 PIN file (above)
    had two of its own signal-timing windows.** *Window A*: the trap was
    installed only after `_prepare_pkcs11_pin` returned, so a signal landing
    anywhere during the PIN's own staging (write, `chmod`) — reproduced
    directly by injecting `TERM` during that `chmod 600` — still left the
    plaintext file behind. *Window B*: the epilogue tore the trap down
    *before* shredding the file, so a signal landing in between — reproduced
    directly the same way — hit the default (untrapped) disposition with the
    file still on disk. Fixed by installing the trap the moment the file is
    created (before any write, while it's still empty) and by shredding
    before removing the trap, not after, in the epilogue.
  - **The staged PIN file's embedded owning-process pid used `$$`, which
    `doctor_pin_files`' liveness check reads as the owner — but `$$` names
    the *originating* shell even from inside a subshell**, unlike
    `$BASHPID`, which the TERM/INT trap itself already (correctly) uses to
    re-raise against itself. Fixed to use `$BASHPID` too, captured into a
    plain variable before the `mktemp` call: writing `$BASHPID` directly
    inside that command substitution turned out to re-introduce the exact
    same class of bug one level deeper, since `$(...)` forks its own
    subshell for the whole substitution — reproduced directly, an inline
    `$BASHPID` there embedded a *third*, already-dead pid distinct from
    both `$$` and the calling function's own `$BASHPID`.

### Fixed

- **`run_openconnect` always returned 0, regardless of whether OpenConnect
  actually connected.** Its stdin pipeline ended on `tee`, whose own exit
  status (not OpenConnect's) is what a pipeline reports by default, and the
  function's last statement was an `unset` that always succeeds — so nothing
  a service supervisor asked ever reflected reality. Every branch now
  captures `PIPESTATUS` at the right index and returns a real outcome code.
- **A service could enter the interactive setup wizard with no terminal to
  answer it**, and two other places (`require_bin`, `check_file_existence`)
  terminated the process directly rather than returning a status a service
  supervisor could act on — both found while making the above fix meaningful
  end to end. Neither is a regression from today's unconditional restart
  behaviour, but both are exactly the terminal cases this change exists to
  handle correctly, so both are fixed alongside it.
- **`sudo -n -v` in prompt mode's own service-mode check (`run_openconnect`)
  read a possibly-warm sudo credential cache, not policy** — a third,
  previously unfixed instance of the same cache-vs-policy bug already fixed
  elsewhere in this project (`service.sh`, `twophase.sh`). Routed through the
  same cache-independent, listing-only probes (`vu_helper_passwordless`,
  `vu_legacy_grant_state`) used everywhere else.

- **Interactive helper mode could not actually connect.** Making the passwordless
  rule opt-in gave helper mode a second tier — installed, but reached through a
  normal `sudo` prompt — and the two places that actually invoke `sudo` were left
  passing `-n`, which means *fail rather than prompt*. So `install-helper` without
  `--passwordless` selected helper mode and then refused itself: connect failed
  **after** phase one had already spent the password and second factor, with no
  fallback, and stop could not stop a tunnel the same session had started. It
  failed only intermittently, which is why it went unnoticed — a warm sudo
  credential cache makes `-n` succeed, and the installer leaves one warm. Connect
  and stop now use plain `sudo`; the probes that ask about *policy* keep
  `sudo -k -n`, which is a different question.
- **The sudo password is asked for before phase one, not after it.** A refusal now
  costs nothing; previously it arrived once a Duo push had already been sent and a
  TOTP code already consumed.
- **A refusal is no longer announced as a disconnection.** When sudo or the helper
  turned the connect away, `vpn-up` still cleared the connection state, notified
  "Disconnected", and ran the user's `disconnected` hooks — for a tunnel that had
  never existed. The announcement now requires evidence that the tunnel ran; a run
  that produced only `sudo:` or `vpn-up-helper:` refusal lines is not a session
  that ended. Silence stays ambiguous and is treated as a session, since `--quiet`
  is supported.
- **`sudo -n` was being read as "is this passwordless?" — it is not.** sudo
  caches a successful authentication, so anything you are merely *allowed* to run
  looks passwordless for minutes after you type your password. `doctor` could
  therefore report the helper as available on a machine where a login service
  would hang at boot on a password prompt, and could print
  `[OK] vpn-up-admin is not reachable without a password` when the check had
  simply failed. Every passwordless probe now uses `sudo -k -n`, which ignores
  the cached credentials, and an unprovable answer is reported as unprovable
  instead of as a pass.
- Both privileged binaries now re-verify their own install path before doing any
  privileged work (design §11.1), so a root-owned helper sitting under a
  directory you can write is refused rather than trusted.

- **Two-phase OpenConnect plumbing (not yet switchable on).** `vpn-up` can now
  authenticate *unprivileged* with `openconnect --authenticate`, parse the
  resulting session descriptor without `eval`, and hand only the cookie to a
  privileged helper that establishes the tunnel. The password, TOTP seed, client
  certificate, PKCS#11 PIN and SSO browser therefore never cross the privilege
  boundary — and on Linux the SSO browser now opens in your own session rather
  than root's, which fixes a long-standing annoyance as a side effect.
  - Profiles gain an immutable `<profileId>`, generated and persisted on first
    use. It is the stable identity an endpoint approval is keyed to, so renaming
    a profile no longer silently changes which endpoint is authorised.
  - `vpn-up approve-profile <profile>` records an endpoint and its certificate
    as approved. It deliberately asks for your password: approving an endpoint
    must never be possible without one.
  - Existing `<extraArgs>` keep working in helper mode where they can be
    translated to the closed tunable table (`--no-dtls`, `--mtu`, …). Flags that
    can name a program to run (`--script`, `--csd-wrapper`, …) are refused with
    the flag named and a pointer to prompt mode.
  - **Helper mode is inert until the privileged binaries are installed**, and
    there is no installer yet. Nothing changes for existing users: without the
    helper, `vpn-up` takes exactly the path it always has.
  - An adversarial test corpus for the privileged half (`helper/t/test_adversarial.c`)
    and the unprivileged half (`tests/twophase_adversarial.bats`), organised by
    attack rather than by function. The phase-one output format has two decoders
    — the shell one that runs in production and the C reference — so both are now
    driven by one shared fixture set (`helper/t/fixtures/auth/`), and a
    divergence between them fails a test.
  - `helper/t/README` records the environment the corpus assumes: why fixtures
    live in `$HOME` rather than `/tmp` (mode 1777 fails the trusted-path walk),
    which compiler diagnostics only exist on GCC and therefore only fail in CI,
    and why `make asan` is Linux-only.
  - `vpn-up-admin verify-closure`, which reports the closure row by row. It
    needs no password: it writes nothing and reads only ownership and mode bits,
    so asking "is this machine eligible?" should not cost an authentication.
  - An integration harness (`helper/t/integration/`): a compiled stand-in for
    OpenConnect that reports exactly what crossed the privilege boundary, an
    opt-in end-to-end run of the real binaries as root against it, and a probe
    for the OpenConnect behaviours the design depends on. The end-to-end script
    creates and removes a single dedicated prefix and touches nothing else.
  - An ELF reader (`helper/src/elf.c`) for the library search paths, tested
    against ELF images the corpus builds byte by byte — the only way to produce a
    truncated header, an unmapped string table or a big-endian ELF32 on demand.
    `make test-elf-closure` runs the corpus with that path forced on, so
    Linux-only code is compiled and exercised on macOS too instead of first
    meeting a compiler in CI.

### Security

- **Two claims the design marked "integration test, not source inspection" are
  now tested with a real `execve` into a real second process.** The per-profile
  lock survives the `execve` into OpenConnect and is released by the kernel when
  it exits — so "one tunnel per profile" holds with no reaper and no pid file —
  and a 100000-byte cookie (larger than every buffer in this project, and larger
  than a pipe) passes through stdin byte-for-byte. A marker buried in the middle
  of that cookie must appear nowhere in the child's argv, environment, or
  `/proc/self/cmdline`, which is what `ps` reads.

  Both were verified to actually discriminate rather than merely pass: putting
  `FD_CLOEXEC` back on the lock descriptor makes the lock assertion fail, and
  putting the cookie on argv or in the environment makes the marker assertion
  fail.

- **Answered against the real OpenConnect: `https://` is not a usable proxy
  scheme.** OpenConnect 9.21 replies `Only http or socks(5) proxies supported`,
  so the helper's `http://`-and-`socks5://`-only rule is not a conservative
  guess — it matches OpenConnect's own support matrix exactly. Kept as a test
  rather than a note, because the answer is version-dependent.

- **Also answered: OpenConnect leaves an inherited locked descriptor alone.**
  The whole locking model depends on it, and it was previously an assumption
  flagged in the design as needing a test rather than source inspection.

- **Fixed: the effective-writability probe dropped privilege to root instead of
  to the calling user**, so it failed every time it ran. §11.5 asks whether the
  *caller* can write a trusted object despite its mode bits; the implementation
  passed the required owner (0) rather than `SUDO_UID`, which made the check ask
  whether root can regain root. It went unnoticed because the probe only runs as
  root, and nothing ran as root until the integration test did. The probe now
  refuses uid 0 outright rather than attempting a question with no answer.

- **The trusted execution closure is now checked in full, not just the two
  pinned files.** A root-owned `openconnect` that loads a user-writable library,
  or sources a user-writable hook, is the same bug as a user-writable
  `openconnect`. Before every connect the helper now verifies the binary, its
  library search paths, `/bin/sh`, the vpnc-script and its shebang interpreter,
  the hook directories whose contents vpnc-script *sources*, and every entry in
  the `PATH` it hands over — and prints the failing rows, because a closure
  failure is something you have to fix on the machine.

  The library half deliberately verifies **every directory the loader will
  search** rather than enumerating libraries: with `LD_LIBRARY_PATH` and
  `LD_PRELOAD` stripped, a library can only come from `DT_RPATH`/`DT_RUNPATH`,
  `/etc/ld.so.preload`, or the `ld.so.conf`-configured and default directories.
  That covers libraries nobody listed, anything `dlopen`'d, and whatever the next
  version links against.

- **`vpn-up doctor` reports whether this machine can run helper mode, and why
  not.** It runs the same C walk the helper runs, so the answer is not a shell
  approximation of it. Pointed at a Homebrew install it says exactly what is
  wrong — `'/opt/homebrew' is owned by uid 501, expected 0 or root` — which is
  the claim SECURITY.md has been making since the first of these releases,
  now checked rather than asserted. A failing closure does not fail `doctor`:
  helper mode is still inert, and macOS fails closed by design until the dyld
  work lands.

- **macOS helper mode now fails closed in code, not only in the design.** The
  macOS dynamic library closure needs Mach-O and dyld rather than ELF and
  `ld.so`, and until that exists the check refuses with
  `trusted OpenConnect execution closure could not be established`. There is a
  test asserting that behaviour, so it cannot quietly become a skipped row.

- **`vpn-up doctor` now checks the privilege boundary, and fails when it is
  broken.** The whole point of two privileged binaries is that `vpn-up-admin`
  (which grants approvals) is never reachable without a password, while
  `vpn-up-helper` (which only establishes an already-approved tunnel) is. Doctor
  asks `sudo` itself — `sudo -n -l <command>` — rather than grepping
  `/etc/sudoers.d`, because rules can arrive from LDAP, includes, aliases or
  `Defaults targetpw`, none of which a grep sees. `vpn-up-admin` appearing in an
  ordinary *authenticated* rule is legitimate administrator policy and passes;
  only passwordless reachability fails, and it makes `doctor` exit non-zero
  rather than printing a warning in a wall of green.

- **Fixed: `vpn-up-helper stop` trusted state it had never verified.** `connect`
  builds its state directories and verifies each one is root-owned `0700`;
  `stop` read the recorded pid without checking the tree at all. On Linux that
  was academic — `/run` is writable only by root — but macOS `/var/run` is
  `drwxrwxr-x root:daemon`, so a process in group `daemon` could create
  `/var/run/vpn-up`, plant a pid, and have root signal a process of its
  choosing. `stop` now verifies the chain before reading anything inside it, and
  the pid and start-token files are themselves checked for ownership and mode.
  Found by the new adversarial corpus; helper mode is not yet switchable on, so
  no released configuration was affected.

- **Fixed: the privileged binaries depended on how their caller arranged file
  descriptors.** Invoked with stdin closed (`sudo vpn-up-helper connect … 0<&-`),
  the lock file landed on descriptor 0 — `open()` returns the lowest free one —
  and OpenConnect, run with `--cookie-on-stdin`, would then read the lock file
  as the session cookie. Both binaries now confirm descriptors 0, 1 and 2 are
  open before opening anything else.

- **Fixed: an empty `proxy=` line in an approval record was read as "no
  proxy".** That made a truncated or hand-edited record silently authorise a
  direct connection, in a parser whose stated rule is one spelling per record.
  `NONE` is now the only spelling accepted.

- **The helper's closed argv schema refuses a repeated flag.** Previously the
  last one won, so `--connect-url` could be named twice and the request would
  not mean what a reader of the command line would expect. Model B still refused
  a substituted endpoint at the policy check; this closes the gap one level
  earlier. The same tunable may no longer be given twice either — `--tunable
  mtu=1400 --tunable mtu=1500` used to reach OpenConnect as both.

- **The phase-one decoder now validates `CONNECT_URL` and `RESOLVE`** with the
  same validators the helper uses, as it already did the fingerprint. A gateway
  returning something malformed is now reported against the gateway, by the
  unprivileged process that read it, instead of surfacing later as a refusal
  from the privileged one.

- **Retracted the claim that a `NOPASSWD` sudoers rule for `openconnect` is
  safely "scoped to one binary."** It is not: sudoers constrains the *command*,
  not its *arguments*, and `openconnect`'s `--script`, `--script-tun`,
  `--csd-wrapper`, `--config`, and `--xmlconfig` flags execute a program as root.
  Such a rule is therefore equivalent to passwordless root for the invoking
  account, usable by any process running as that user without going through
  `vpn-up`. On macOS it is weaker still — Homebrew's prefix is owned by the
  installing user, so the permitted binary can simply be replaced. `SECURITY.md`
  now carries a *Known limitations* section covering both, and README,
  `docs/usage.md`, `docs/troubleshooting.md`, `docs/vpn-at-login.md`, and
  `docs/split-tunnel.md` are consistent with it. A root-owned privileged helper
  (`vpn-up-helper`), with sudoers permitting only the helper, is the planned fix
  and the next security milestone.
- **Documented that a Homebrew `openconnect` executes a user-writable script as
  root on every connect.** Its compiled-in default `vpnc-script` lives inside the
  Homebrew prefix (`/opt/homebrew/etc/vpnc/vpnc-script`), which is owned by the
  installing user. No unusual arguments are needed to reach root there, so
  argument filtering — by `vpn-up` or by any future helper — is not sufficient on
  its own. Users are now told to verify the path with `openconnect --version`.
- **The login service is documented as not recommended** until that helper
  lands, since it cannot run without the sudoers rule.
- **`extraArgs` entries that execute programs as root now print a loud warning.**
  `--script`/`-s`, `--script-tun`/`-S`, `--csd-wrapper`, `--csd-user`,
  `--config`, `--xmlconfig`/`-x`, and `--external-browser` raise a distinct
  danger-level message (previously `--script` and `--csd-wrapper` were not
  flagged at all). Short forms are covered because they reach root identically;
  `--external-browser` is included because openconnect launches the SSO opener as
  root; `--csd-user` because it enables execution of the gateway-supplied CSD
  binary (`--csd-user=root` as root). The arguments are still passed
  through — split tunnelling and CSD need them — and this remains a footgun
  guardrail, **not** a security boundary: while the sudoers rule permits
  `openconnect` itself, no client-side filtering can enforce anything.
- **The TOTP seed no longer reaches a command line.** `SECURITY.md` claims
  secrets are never passed on command lines, but `generate_totp` and the
  `add-profile` validation both passed the base32 seed as an `oathtool`
  argument, where it was visible to every user on the machine through `ps`.
  Both call sites now pipe it on stdin (`oathtool --totp -b -`), which
  `oathtool`'s own help recommends over an argv key on multi-user systems. The
  seed still never reaches `openconnect`; only the short-lived code transits.
- **Prompt mode is documented as the safer default, not "safe".** It avoids
  passwordless root becoming *ambient*, but it is a compatibility mode rather
  than a hardened boundary: a user-writable `openconnect` is a poor `sudo`
  target even with a password prompt, since a process running as the user can
  replace the binary and wait for the next legitimate `sudo openconnect`.

### Fixed

- **The encrypted vault could report a write that never happened.**
  `_vault_encrypt` wrote `openssl`'s output straight over the only copy of the
  vault, ignored `openssl`'s exit status, and ended in `chmod … || true` — so it
  always returned success. A failed or partial encryption therefore truncated
  the vault while `set-secret` printed "Saved". It now encrypts to a temp file,
  checks the exit status, refuses empty output, **decrypts the result and
  compares it to what was handed in**, and only then renames it into place, so a
  failure leaves the previous vault untouched. `secrets_delete_file` had the
  same class of bug — it ended in `chmod`, which swallowed a failed rename.
  Failures now propagate to `set-secret`, `delete-secret`, and the add-profile
  wizard, which previously reported success unconditionally.
- **Deleting a profile left its other secrets behind.** `remove-profile`
  cleared only the `password`, so a profile's `token_secret` (TOTP seed) and
  `key_password` (PKCS#11 PIN) stayed in the keychain or vault with nothing
  referencing them. A new `secrets_delete_profile` clears every field from one
  `SECRET_FIELDS` list, and a test cross-checks that list against every field
  the codebase actually stores.
- **Stale macOS `openconnect` path in the sudoers examples.** They named
  `/opt/homebrew/sbin/openconnect`; current Homebrew installs to
  `/opt/homebrew/bin/openconnect`, so the documented rule silently did nothing.
  All examples now tell you to confirm the path with `command -v openconnect`.
- **Stale instruction for finding the default `vpnc-script`.** `SECURITY.md`
  said `openconnect --version`; it is printed by `openconnect --help`, under
  "VPN configuration script".

---

## [v3.11.1] — 2026-06-19
### Fixed

- **Service file XML escaping on bash ≥ 5.2.** `_xml_escape` built entities with
  bash `${var//pat/repl}` substitution, but bash 5.2+ enables `patsub_replacement`
  by default, so an unescaped `&` in the replacement expands to the matched text —
  turning `<`/`>` into `<lt;`/`>gt;` instead of `&lt;`/`&gt;`. A VPN profile name
  containing `<` or `>` therefore produced a malformed launchd plist / systemd unit.
  Escaping now uses `sed` (`\&` is an unambiguous literal across bash versions).

---

## [v3.11.0] — 2026-06-19
### Added

- **Multiple simultaneous tunnels**. `vpn-up start` now allows different profiles
  to run side by side using the existing per-profile PID/state/log layout, while
  still refusing to start the same profile twice. `status`, `stop [profile]`, and
  `logs [profile]` remain profile-aware.

### Changed

- Foreground, service, and SSO sessions now record their PID by matching the
  openconnect process launched with that profile's `--pid-file`, instead of
  assuming the newest openconnect process belongs to the current start command.

---

## [v3.10.0] — 2026-06-18
### Added

- **First-class HTTP/SOCKS proxy** per profile (`<proxy>`, also an optional prompt in
  `add-profile`). Set a proxy URL — e.g. `http://proxy.corp:8080` or
  `socks5://127.0.0.1:1080` — and `vpn-up` passes it to openconnect's `--proxy` (it
  previously required `<extraArgs>`). The URL is an identifier, not a secret, so it
  lives in the profile XML; embedding inline `user:pass@` credentials is discouraged
  since they would reach the command line.

---

## [v3.9.2] — 2026-06-18
### Changed

- Commands that read the profiles file (`list`, the interactive `start` menu,
  `add-profile`, `remove-profile`, `pin --save`, `service install`) now **fail
  gracefully on a malformed profiles file** with a single clear message ("Your
  profiles file isn't valid XML …") instead of leaking raw `xmlstarlet`/libxml2
  parser errors. A malformed file is also no longer silently misread as "no
  profiles" (which previously could wrongly trigger the first-run wizard). New
  internal `profiles_xml_ok` guard, with tests.

---

## [v3.9.1] — 2026-06-18
### Fixed

- The default profiles template (`config/vpn-up.command.profiles.default`) could not
  be parsed by `xmlstarlet`: its `<extraArgs>` comments contained `--` (e.g.
  `--no-dtls`, `--protocol`), which the XML spec forbids inside comments and modern
  libxml2 rejects as a fatal error. Users who **edit the seeded template by hand**
  (rather than using `add-profile`, which generates comment-free XML) hit
  `Double hyphen within comment` errors and an empty list from `vpn-up list` and the
  interactive `start` menu, and silent "no profiles" detection. Reworded the comments
  to be `--`-free; added a regression test that parses the shipped template.

---

## [v3.9.0] — 2026-06-18
### Client-certificate authentication

### Added
- **Client-certificate authentication** (`<clientCertificate>` / `<clientKey>`,
  also prompted by `add-profile`). Authenticate with an X.509 cert/key **file** or
  a **PKCS#11 URI** (smartcard / **YubiKey PIV**), on its own (cert-only) or
  alongside a password, Duo, TOTP, or SSO — it's additive and doesn't change the
  auth precedence. The cert/key **path or URI is not a secret** (it stays in the
  profile); a key passphrase or PKCS#11 PIN **never reaches openconnect's argv**.
  An encrypted key/token prompts interactively; for unattended/login-service use,
  store a PKCS#11 PIN (`vpn-up set-secret '<profile>' key_password`) and `vpn-up`
  feeds it through a transient `0600` `pin-source` file, shredded after the session.
- `doctor` now reports **PKCS#11** (`p11-kit`/`p11tool`) availability; `service`
  preflight understands cert-only and PKCS#11 profiles.

### Documented
- **FIDO2 / passkeys / YubiKey-WebAuthn already work with SSO** — because the
  browser-based SAML/SSO login runs in your real browser, no extra configuration is
  needed. New [client-certificate](https://sorinipate.github.io/vpn-up-for-openconnect/client-certificate-auth/)
  docs page; SSO page notes the WebAuthn support.

---

## [v3.8.0] — 2026-06-18
### TOTP 2FA & Argument Passthrough Update

### Added
- **TOTP authenticator-app 2FA** (`<tokenMode>totp</tokenMode>`). For gateways
  that prompt for a time-based code (Google Authenticator / Authy / hardware
  TOTP), store the base32 seed once (`vpn-up set-secret '<profile>' token_secret`,
  or via the `add-profile` wizard) and `vpn-up` generates the current code with
  `oathtool` at connect time and feeds it as the 2FA answer. The **seed never
  reaches openconnect's argv or disk** — only the short-lived code transits on
  stdin (we deliberately avoid `--token-secret`, which would expose it). Because
  it needs no interaction, a TOTP profile **can run as a login service with
  auto-reconnect** (unlike Duo-passcode and SSO). New `oathtool` dependency
  (TOTP only); surfaced by `doctor`; shown in `vpn-up list`.
- **Extra openconnect arguments** per profile (`<extraArgs>`, also an optional
  prompt in `add-profile`). Power-user passthrough for flags vpn-up doesn't model
  (`--no-dtls`, `--os=win`, `--csd-wrapper`, proxies, MTU, …). Tokenized with
  `xargs` so quotes are respected without `eval`; appended verbatim before the
  gateway host. Duplicating a flag vpn-up already manages prints a warning but is
  still passed.

---

## [v3.7.0] — 2026-06-16
### Browser-based SSO Login Update

### Added
- **SSO / external-browser authentication** for gateways that force a
  browser-based SAML/SSO login (Okta, Azure AD, Ping Identity — typically with
  an embedded Duo iframe). Set `<authMode>sso</authMode>` on a profile (or answer
  the new prompt in `add-profile`) and `vpn-up` connects via OpenConnect's
  `--external-browser`: no password is piped, the login happens in the browser,
  and the tunnel comes up afterward. Requires openconnect ≥ 9.0 (surfaced by
  `doctor`); supported for `anyconnect`/`gp`. SSO profiles run in the foreground
  and cannot run as a login service (interactive session required). The browser
  opener defaults to `open`/`xdg-open` and is overridable with
  `VPN_UP_EXTERNAL_BROWSER` (useful on Linux, where the root/sudo process may not
  reach the desktop session). New `AUTH` column in `vpn-up list`.

---

## [v3.6.0] — 2026-06-13
### First-Run Usability & Docs Update

### Added
- `LICENSE` file (MIT — previously only claimed in the README) and
  `CONTRIBUTING.md` with the PR/CI workflow and development setup.

### Changed
- First run of `start` with no profiles now offers the `add-profile` wizard
  interactively instead of dead-ending into "edit the XML template by hand"
  (scripts and service mode still get the template-seeding behavior).
- Setup wizard: removed the "Use sudo?" question — the `SUDO` config value
  has been dead since v3.0.0 (nothing reads it); all wizard prompts now use
  the `[Y/n]` style (y/n/true/false all accepted, as before).
- User-facing messages and usage text now say `vpn-up` (matching the
  Homebrew command) instead of the internal `vpn-up.command` name; data file
  names and the Keychain namespace are unchanged.
- README restructured: badges, table of contents, scannable feature list,
  quick start, usage examples, and a roadmap section.

---

## [v3.5.1] — 2026-06-13
### Review & Coverage Update

### Fixed
- Homebrew installs: the `vpn-up` wrapper now resolves through the stable
  `opt` path, so login services installed from a brew copy survive
  `brew upgrade` (previously the LaunchAgent pointed at a versioned Cellar
  path). Tap formula change; reinstall or upgrade picks it up.
- `service status` matched launchd labels as a regex; now an exact match.
- Config validation fails closed if file permissions cannot be determined.
- After a `Login failed` connection attempt, the error now points at
  `delete-secret` so a mistyped stored password isn't silently reused.

### Added
- Test coverage across the whole application: CLI dispatch, status/stop scan
  logic, config safety checks, log selection, notifications/banner gating,
  setup templating, secrets backend selection, service install/uninstall,
  and helper parsing — 71 bats tests total (up from 29), run on macOS and
  Ubuntu in CI.

---

## [v3.5.0] — 2026-06-12
### Lifecycle & Maintenance Update

### Added
- `remove-profile <name>` — removes the XML block, the stored secret, the
  per-profile PID/state/log files, and any installed login service in one
  confirmed step; refuses while the profile is connected.
- Lifecycle hooks: executable scripts in `~/.config/vpn-up/hooks/connected.d/`
  and `disconnected.d/` run on tunnel up/down with `VPN_EVENT`, `VPN_NAME`,
  and `VPN_HOST` in the environment. Hooks must be user-owned and not
  group/world-writable or they are skipped; failures never block the VPN.
- Release automation: publishing a GitHub release now updates the Homebrew
  tap formula (url + sha256) automatically.

### Changed
- CI runs the test suite on macOS as well as Ubuntu (added post-v3.4.0
  along with portable stat helpers that fixed config validation on Linux).

---

## [v3.4.0] — 2026-06-12
### Service & Notifications Update

### Added
- `service install|uninstall|status` — run a profile as a login service with
  auto-reconnect: launchd user agent on macOS, systemd user unit on Linux.
  The service manager supervises openconnect in the foreground and restarts
  it if the tunnel drops (30s throttle). Preflight checks catch missing
  passwordless sudo, missing stored password, and passcode-2FA profiles.
- Desktop notifications on connect/disconnect/failure (macOS Notification
  Center via osascript, Linux via notify-send); new `NOTIFICATIONS` setting
  (default `TRUE`), prompted in setup and shown by `doctor`.
- Foreground sessions now record their own PID/state (openconnect only
  writes `--pid-file` when daemonizing), so `status` and `stop` work during
  foreground and service sessions too.

### Changed
- Service mode (`VPN_UP_SERVICE=1`) fails fast with clear errors instead of
  prompting: non-interactive `sudo -n`, stored-secret requirement, and a
  passcode-2FA guard.

---

## [v3.3.0] — 2026-06-12
### Profiles & Completion Update

### Added
- `add-profile` — guided profile creation: validates inputs, appends a
  well-formed `<VPN>` block, and optionally stores the password in the
  secrets backend and saves the gateway's certificate pin in one flow.
- Bash/zsh tab completion (`completions/vpn-up.bash`) for commands and
  profile names, including names with spaces.
- Per-profile PID, state, and log files — `status` reports every running
  connection, `stop [profile]` and `logs [-f] [profile]` target a specific
  one, and `logs` with no argument shows the most recent log.

### Changed
- Stale PID/state files are cleaned up automatically during `status`.
- One-connection-at-a-time policy is kept: `start` refuses while any VPN is
  running (the per-profile files make the bookkeeping accurate, not the
  tunnels concurrent).

---

## [v3.2.0] — 2026-06-12
### Scriptability & CLI Update

### Added
- `start [profile]` / `restart [profile]` — connect directly by profile name,
  no interactive menu; with a stored secret the only interaction left is 2FA.
- `list` — tabular overview of configured profiles (name, protocol, host,
  2FA method; no secrets shown).
- `logs [-f]` — show the connection log, or follow it live.
- `pin --save <profile>` — fetch the gateway's `pin-sha256` and write it into
  the profile's `<serverCertificate>` directly.
- Richer `status`: connected profile, gateway, connect time, and uptime
  (recorded in a state file at connect, removed on stop).

### Changed
- A `duo2FAMethod` of `passcode` now prompts for the one-time code at connect
  time instead of reading a stale value from the XML.

---

## [v3.1.0] — 2026-06-12
### UI Update

### Added
- `SHOW_BANNER` configuration setting (default `TRUE`) to control the
  start-up ASCII banner (PR #22).
- Setup wizard prompt for the banner preference; `doctor` includes
  `SHOW_BANNER` in its config preview (PR #22).
- ASCII banner displayed at the top of the README (PR #23).

### Changed
- `QUIET` now governs only openconnect's output verbosity; it no longer
  hides the banner. Existing configs without `SHOW_BANNER` default to
  showing it (PR #22).

---

## [v3.0.0] — 2026-06-12
### Security Hardening Release

### Breaking
- **Stored sudo password support removed.** Storing it defeated sudo's
  protection; use the scoped `sudoers.d` rule documented in the README for
  passwordless operation. Any previously stored sudo password is deleted on
  the next `setup`, and `set-secret` refuses `sudo_password`.
- **User state moved to `~/.config/vpn-up`** (config, profiles, secrets
  vault, logs, PID files) — override with `VPN_UP_HOME`/`XDG_CONFIG_HOME`.
  Legacy files in the in-repo `config/` directory migrate automatically on
  first run.
- **Server identity now fails closed**: without a `pin-sha256` pin in
  `<serverCertificate>`, the gateway certificate must validate against the
  system trust store. Legacy SHA1 pins still work but warn.

### Added
- `pin <host[:port]>` command — prints the gateway's RFC 7469 `pin-sha256`
  value and reports whether the certificate also chain-validates.
- CI: shellcheck, bats test suite (secret backends + profile parsing), and
  gitleaks secret scanning on every push/PR.
- `SECURITY.md` with reporting instructions and the security model.

### Fixed
- `stop` could never actually stop the VPN: it killed the root-owned
  openconnect process without sudo, then deleted the PID file anyway. Now
  `sudo kill` with PID-identity verification and a SIGKILL fallback.
- Stored secrets were unretrievable on the OpenSSL-vault and plain-file
  backends (keys contain `=`, which broke the field-based lookup).
- `delete-secret` on Linux was a silent no-op; now uses `secret-tool clear`.
- Empty profile fields (e.g. a blanked `<password>`) shifted every following
  field during XML parsing.
- The shell hung forever after a successful background-mode connect (the
  daemonized child kept the log pipe open).
- openconnect's stderr was not captured in the log, and the log was created
  root-owned.
- A wrong vault passphrase silently re-encrypted an empty vault (data loss);
  it now aborts.

### Security
- Plaintext `<password>` values are blanked in the profile XML after
  migration to the secrets backend; the field is deprecated.
- Secrets no longer enter child-process environments or appear on command
  lines (process table); vault contents never touch disk decrypted.
- The config file is only sourced if owned by the current user and not
  group/world-writable; data files are created `600`, directories `700`.
- Leaked credentials were purged from the published git history; GitHub
  secret scanning and push protection are enabled on the repository.

---

## [v2.0.0] — 2025-12-16
### Secure & Modern Bash Release

### Added
- Secure secrets management using:
  - macOS **Keychain**
  - Linux **Secret Service**
  - OpenSSL-encrypted vault fallback (AES-256-CBC + PBKDF2)
- Interactive setup wizard (`setup`)
- Secrets management commands:
  - `set-secret`
  - `delete-secret`
- Environment diagnostics command (`doctor`)
- Bash version guard (requires **Bash ≥ 4**)
- Modular architecture (`core`, `profiles`, `encryption`, `ui`, etc.)
- Duo 2FA support:
  - `push`, `phone`, `sms`, or 6-digit passcode
  - Empty 2FA field allows gateway auto-push
- Optional secure storage of sudo password (`__GLOBAL__.sudo_password`)

### Changed
- OpenConnect execution now uses **argv arrays** (no `eval`)
- AuthGroup (`--authgroup`) is passed before stdin authentication
- Profile XML parsing now supports both legacy and modern tags:
  - `username | user`
  - `group | authGroup`
  - `duo2FAMethod | duoMethod`
- Plaintext passwords in profiles are automatically migrated to secure storage
- UI banner rendering isolated in `ui.sh` and shown only when interactive

### Fixed
- Authentication failures caused by AuthGroup prompts consuming password input
- Duo 2FA input being misinterpreted as AuthGroup selection
- Quoting and injection issues from `eval`
- Inconsistent behavior across macOS and Linux
- Bash 3.2 incompatibilities on macOS

### Security
- Passwords are **never stored in plaintext**
- `ENCRYPTION_KEY` configuration is intentionally ignored to avoid insecure key storage
- Secrets are always retrieved from OS-level secure storage when available

### Known Issues
- Some AnyConnect gateways emit an initial “Unexpected 404” banner; this is benign if the connection proceeds successfully

---

## [v1.6-alpha] — 2023-12-06
### Cross-Platform Compatibility Update

### Added
- macOS and Linux compatibility improvements
- Automatic dependency checks and installation prompts
- Homebrew integration for macOS
- Improved user prompts and feedback
- Enhanced error handling and logging

### Changed
- Simplified setup process for new users
- Improved script robustness across environments

---

## [v1.5]
### Configuration & Authentication Enhancements

### Added
- XML-based configuration for VPN profiles
- Duo 2FA support
- Support for multiple VPN protocols:
  - AnyConnect
  - Juniper Network Connect
  - Palo Alto GlobalProtect
  - Pulse Secure

---

## [v1.0]
### Initial Release

### Added
- Basic OpenConnect wrapper
- Interactive VPN selection
- Background execution support
- Status and stop commands

---
