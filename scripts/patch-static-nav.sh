#!/usr/bin/env bash
# patch-static-nav.sh — Inject AI Chat link into existing static HTML files
# Run once after deploying the server update.
set -euo pipefail

SERVE="/var/lib/netwatchm"
AI_LINK='  <a href="/ai.html" style="color:#58a6ff;font-weight:bold">&#129302; AI Chat</a>'

echo "Patching static HTML files in $SERVE..."

# analytics.html — nav ends with </nav>
if grep -q "ai\.html" "$SERVE/analytics.html" 2>/dev/null; then
  echo "  analytics.html — already patched, skipping"
else
  sudo sed -i "s|<a href=\"/connection-report.html\">&#8592; Connection Report</a>\n</nav>|<a href=\"/connection-report.html\">&#8592; Connection Report</a>\n  <a href=\"/inventory.html\">Inventory</a>\n  <a href=\"/events.html\">Events</a>\n  <a href=\"/history.html\">History</a>\n$AI_LINK\n</nav>|" "$SERVE/analytics.html" 2>/dev/null || true
  # fallback: Python-based patch (handles multi-line reliably)
  sudo python3 - "$SERVE/analytics.html" <<'PYEOF'
import sys, re
path = sys.argv[1]
html = open(path).read()
if '/ai.html' in html:
    print(f"  {path} — already patched")
    sys.exit(0)
patched = html.replace(
    '<a href="/connection-report.html">&#8592; Connection Report</a>\n</nav>',
    '<a href="/connection-report.html">&#8592; Connection Report</a>\n'
    '  <a href="/inventory.html">Inventory</a>\n'
    '  <a href="/events.html">Events</a>\n'
    '  <a href="/history.html">History</a>\n'
    '  <a href="/ai.html" style="color:#58a6ff;font-weight:bold">&#129302; AI Chat</a>\n'
    '</nav>'
)
open(path, 'w').write(patched)
print(f"  {path} — patched")
PYEOF
fi

echo "Done. Run 'bash scripts/hotdeploy.sh' to also deploy the server update."
