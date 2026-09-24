#!/usr/bin/env bash
# Re-renders the README's watchtower:simulate image from the real command.
# Needs Chrome (or Chromium), ImageMagick, and network for the web font.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
chrome="${CHROME:-$(command -v google-chrome || command -v chromium || command -v chromium-browser)}"
page="$(mktemp --suffix=.html)"
shot="$(mktemp --suffix=.png)"
trap 'rm -f "$page" "$shot"' EXIT

php "$dir/simulate.php" > "$page"

# Oversized transparent canvas at 2x, then trimmed to the card and its shadow.
"$chrome" --headless=new --disable-gpu --hide-scrollbars \
    --force-device-scale-factor=2 --window-size=1400,1000 \
    --default-background-color=00000000 --virtual-time-budget=5000 \
    --screenshot="$shot" "file://$page" 2>/dev/null

convert "$shot" -trim +repage -strip "$dir/simulate.png"
