# service.sh - run a profile as a login service with auto-reconnect
# macOS: launchd user agent (~/Library/LaunchAgents)
# Linux: systemd user unit (~/.config/systemd/user)
#
# Service mode runs openconnect in the FOREGROUND under the service manager;
# KeepAlive/Restart relaunches it if the tunnel drops. Requirements:
#   - a passwordless sudoers rule for openconnect (see README)
#   - the profile's password stored in the secrets backend
#   - a non-interactive 2FA method (push/phone/sms — not passcode)

LAUNCH_AGENT_DIR="${VPN_UP_LAUNCH_AGENT_DIR:-$HOME/Library/LaunchAgents}"
SYSTEMD_USER_DIR="${VPN_UP_SYSTEMD_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}"
SERVICE_LABEL_PREFIX="com.sorinipate.vpn-up"

_xml_escape() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }

_service_path_for() {
  local slug; slug="$(profile_slug "$1")"
  if [ "$(uname)" = "Darwin" ]; then
    printf '%s/%s.%s.plist' "$LAUNCH_AGENT_DIR" "$SERVICE_LABEL_PREFIX" "$slug"
  else
    printf '%s/vpn-up-%s.service' "$SYSTEMD_USER_DIR" "$slug"
  fi
}

# Generate the launchd plist for a profile to stdout.
write_launch_agent_plist() {
  local profile="$1" slug bash_bin oc_dir
  slug="$(profile_slug "$profile")"
  bash_bin="${BASH:-$(command -v bash)}"
  oc_dir="$(dirname "$(command -v openconnect)")"
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_LABEL_PREFIX}.${slug}</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(_xml_escape "$bash_bin")</string>
    <string>$(_xml_escape "${PROGRAM_PATH}/${PROGRAM_NAME}")</string>
    <string>start</string>
    <string>$(_xml_escape "$profile")</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>VPN_UP_SERVICE</key>
    <string>1</string>
    <key>PATH</key>
    <string>$(_xml_escape "$oc_dir"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>StandardOutPath</key>
  <string>$(_xml_escape "${DATA_DIR}/logs/service.${slug}.log")</string>
  <key>StandardErrorPath</key>
  <string>$(_xml_escape "${DATA_DIR}/logs/service.${slug}.log")</string>
</dict>
</plist>
PLIST
}

# Generate the systemd user unit for a profile to stdout.
write_systemd_unit() {
  local profile="$1" bash_bin oc_dir
  bash_bin="${BASH:-$(command -v bash)}"
  oc_dir="$(dirname "$(command -v openconnect)")"
  cat <<UNIT
[Unit]
Description=VPN Up for OpenConnect (${profile})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${bash_bin} ${PROGRAM_PATH}/${PROGRAM_NAME} start "${profile}"
Environment=VPN_UP_SERVICE=1
Environment=PATH=${oc_dir}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
UNIT
}

# Sanity checks before installing a service for a profile.
_service_preflight() {
  local profile="$1"
  profiles_xml_ok || return 1
  if ! profile_exists "$profile"; then
    print_danger "Unknown profile '%s'.\n" "$profile"
    return 1
  fi
  local authmode
  authmode="$(xmlstarlet sel -t -m "//VPN[name=$(xpath_literal "$profile")]" -v 'authMode | authmode' "$PROFILES_FILE" 2>/dev/null)"
  if [ "$authmode" = sso ]; then
    print_danger "Profile '%s' uses SSO (interactive browser); it cannot run as a login service.\n" "$profile"
    return 1
  fi
  if ! sudo -n -v 2>/dev/null; then
    print_warning "No passwordless sudo detected. Service mode requires a sudoers rule for openconnect (see README); the service will fail until it exists.\n"
  fi
  local clientcert
  clientcert="$(xmlstarlet sel -t -m "//VPN[name=$(xpath_literal "$profile")]" -v 'clientCertificate | clientcertificate' "$PROFILES_FILE" 2>/dev/null)"
  # A cert-only profile needs no stored password, so only warn about a missing
  # password when there is no client certificate to authenticate with.
  if [ -z "$clientcert" ] && [ -z "$(secrets_get "$profile" "password" 2>/dev/null)" ]; then
    print_warning "No stored password for '%s'. Store one first: %s set-secret '%s' password\n" "$profile" "${DISPLAY_NAME}" "$profile"
  fi
  local duo
  duo="$(xmlstarlet sel -t -m "//VPN[name=$(xpath_literal "$profile")]" -v 'duo2FAMethod | duoMethod' "$PROFILES_FILE" 2>/dev/null)"
  if [ "$duo" = "passcode" ]; then
    print_danger "Profile '%s' uses a Duo passcode (interactive); it cannot run as a service.\n" "$profile"
    return 1
  fi
  # TOTP is non-interactive (the code is generated from a stored seed), so it CAN
  # run as a service — but only if the seed is stored and oathtool is available.
  local tokenmode
  tokenmode="$(xmlstarlet sel -t -m "//VPN[name=$(xpath_literal "$profile")]" -v 'tokenMode | tokenmode' "$PROFILES_FILE" 2>/dev/null)"
  if [ "$tokenmode" = totp ]; then
    if [ -z "$(secrets_get "$profile" "token_secret" 2>/dev/null)" ]; then
      print_danger "Profile '%s' uses TOTP but has no stored secret; a service can't prompt. Store it first: %s set-secret '%s' token_secret\n" "$profile" "${DISPLAY_NAME}" "$profile"
      return 1
    fi
    command -v oathtool >/dev/null 2>&1 || print_warning "'oathtool' not found; the TOTP service will fail until it's installed (brew install oath-toolkit | apt-get install oathtool).\n"
  fi
  # Client-certificate auth works as a service only when no interactive prompt is
  # needed. A PKCS#11 token needs a stored PIN (key_password); a file-based key
  # must be unencrypted (a passphrase prompt has no TTY under launchd/systemd).
  if [ -n "$clientcert" ]; then
    case "$clientcert" in
      pkcs11:*)
        if [ -z "$(secrets_get "$profile" "key_password" 2>/dev/null)" ]; then
          print_warning "Profile '%s' uses a PKCS#11 client certificate; a service can't enter the PIN. Store it first: %s set-secret '%s' key_password\n" "$profile" "${DISPLAY_NAME}" "$profile"
        fi
        ;;
      *)
        print_warning "Profile '%s' uses a client-certificate file. If the private key is passphrase-protected it cannot run as a service (no TTY to prompt); use an unencrypted 0600 key.\n" "$profile"
        ;;
    esac
  fi
  return 0
}

service_install() {
  local profile="$1"
  [ -n "$profile" ] || { echo "Usage: ${DISPLAY_NAME} service install <profile>" >&2; return 1; }
  _service_preflight "$profile" || return 1
  local target; target="$(_service_path_for "$profile")"
  if [ "$(uname)" = "Darwin" ]; then
    mkdir -p "$LAUNCH_AGENT_DIR"
    write_launch_agent_plist "$profile" > "$target"
    launchctl unload "$target" 2>/dev/null || true
    if launchctl load -w "$target"; then
      print_success "Installed and loaded launch agent: %s\n" "$target"
      print_warning "The VPN will now connect at login and auto-reconnect if it drops. Remove with: %s service uninstall '%s'\n" "${DISPLAY_NAME}" "$profile"
    else
      print_danger "Wrote %s but could not load it; load manually with: launchctl load -w '%s'\n" "$target" "$target"
      return 1
    fi
  else
    mkdir -p "$SYSTEMD_USER_DIR"
    write_systemd_unit "$profile" > "$target"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --user daemon-reload
      if systemctl --user enable --now "$(basename "$target")"; then
        print_success "Installed and started systemd user unit: %s\n" "$target"
      else
        print_danger "Wrote %s but could not start it; check: systemctl --user status %s\n" "$target" "$(basename "$target")"
        return 1
      fi
    else
      print_warning "Wrote %s; systemctl not found, enable it manually.\n" "$target"
    fi
  fi
}

service_uninstall() {
  local profile="$1"
  [ -n "$profile" ] || { echo "Usage: ${DISPLAY_NAME} service uninstall <profile>" >&2; return 1; }
  local target; target="$(_service_path_for "$profile")"
  if [ ! -f "$target" ]; then
    print_warning "No service installed for '%s' (%s).\n" "$profile" "$target"
    return 0
  fi
  if [ "$(uname)" = "Darwin" ]; then
    launchctl unload -w "$target" 2>/dev/null || true
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now "$(basename "$target")" 2>/dev/null || true
  fi
  rm -f "$target"
  print_success "Removed service for '%s'.\n" "$profile"
  print_warning "If the VPN is still connected, stop it with: %s stop '%s'\n" "${DISPLAY_NAME}" "$profile"
}

service_status() {
  local found=0 f
  if [ "$(uname)" = "Darwin" ]; then
    for f in "$LAUNCH_AGENT_DIR/$SERVICE_LABEL_PREFIX".*.plist; do
      [ -e "$f" ] || continue
      found=1
      local label; label="$(basename "$f" .plist)"
      if launchctl list 2>/dev/null | grep -qF "$label"; then
        print_success "loaded   %s\n" "$f"
      else
        print_warning "unloaded %s\n" "$f"
      fi
    done
  else
    for f in "$SYSTEMD_USER_DIR"/vpn-up-*.service; do
      [ -e "$f" ] || continue
      found=1
      local unit; unit="$(basename "$f")"
      if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet "$unit" 2>/dev/null; then
        print_success "active   %s\n" "$f"
      else
        print_warning "inactive %s\n" "$f"
      fi
    done
  fi
  [ "$found" -eq 0 ] && print_warning "No VPN services installed.\n"
  return 0
}