#!/usr/bin/env bash
# Render assets/social-preview.html → assets/social-preview.png at 1280x640.
# Uses headless Google Chrome (rendered at 2x for a crisp 2560x1280 source;
# GitHub downscales to its display size).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
[ -x "$chrome" ] || chrome="$(command -v google-chrome || command -v chromium || true)"
[ -n "$chrome" ] || { echo "Chrome/Chromium not found" >&2; exit 1; }

"$chrome" --headless=new --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 \
  --window-size=1280,640 \
  --screenshot="${here}/social-preview.png" \
  "file://${here}/social-preview.html"

echo "Wrote ${here}/social-preview.png"
