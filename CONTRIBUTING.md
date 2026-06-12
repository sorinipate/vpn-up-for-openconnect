# Contributing to VPN Up for OpenConnect

Thanks for considering a contribution! This project is small and security-sensitive, so the bar is simple but firm.

## Workflow

- `main` is locked — all changes land via pull request.
- CI must be green before merge. Every PR runs:
  - **shellcheck** — `shellcheck --shell=bash --external-sources vpn-up.command *.sh`
  - **bats test suite** — `bats tests/` (runs on both macOS and Ubuntu; mind GNU vs BSD differences in `stat`, `ps`, `sed`)
  - **gitleaks** — secret scanning; never commit credentials, even in test fixtures

## Development setup

```bash
# macOS
brew install bash shellcheck bats-core xmlstarlet openconnect

# Debian / Ubuntu
sudo apt install bash shellcheck bats xmlstarlet openconnect openssl
```

Run the checks locally before pushing:

```bash
shellcheck --shell=bash --external-sources vpn-up.command *.sh completions/vpn-up.bash
bats tests/
```

## Guidelines

- **Tests required**: behavior changes need a matching test in `tests/*.bats`. Network, sudo, keychain, and launchd/systemd interactions are stubbed in tests — see existing files for the pattern.
- **Bash ≥ 4**, no `eval`, secrets never on command lines or in exported environment variables, user files created with `600`/`700` permissions.
- Security-sensitive areas (secrets storage, sudo handling, TLS validation, hooks) get extra scrutiny in review — explain your reasoning in the PR description.
- **Vulnerabilities**: please report privately via [SECURITY.md](SECURITY.md), not as public issues.

## Releases (maintainer)

Publishing a GitHub release automatically updates the Homebrew tap formula — no manual steps.
