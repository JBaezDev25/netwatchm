#!/usr/bin/env bash
# =============================================================================
# scripts/update-oui-db.sh
#
# PURPOSE
#   Download the IEEE MA-L OUI registry and build a fast MAC-vendor lookup
#   database at /var/lib/netwatchm/oui.json.
#
# WHAT THIS SCRIPT DOES
#   1. Downloads oui.csv from the IEEE standards registry (38,000+ entries)
#   2. Parses the OUI prefix (first 3 octets) and vendor name from each row
#   3. Writes /var/lib/netwatchm/oui.json as { "aa:bb:cc": "Vendor Name", ... }
#
# WHEN TO RUN
#   - Once after install to seed the database
#   - Periodically (e.g. monthly) to pick up new assignments
#   - After running harden-service-user.sh (file will be owned correctly)
#
# OUTPUT
#   /var/lib/netwatchm/oui.json  (~3 MB, ~38k entries)
#
# DEPENDENCIES
#   curl, python3 (stdlib only — no pip required)
# =============================================================================
set -euo pipefail

DATA_DIR="/var/lib/netwatchm"
OUI_JSON="$DATA_DIR/oui.json"
OUI_URL="https://standards-oui.ieee.org/oui/oui.csv"
TMP_CSV="$(mktemp /tmp/oui-XXXXXX.csv)"

echo "=== NetWatchM OUI database update ==="

# --- Step 1: Download IEEE OUI CSV ---
echo "[1/3] Downloading IEEE OUI registry from $OUI_URL …"
if ! curl -fsSL --connect-timeout 15 --max-time 60 -o "$TMP_CSV" "$OUI_URL"; then
    echo "ERROR: Failed to download OUI database. Check network connectivity."
    rm -f "$TMP_CSV"
    exit 1
fi
ROWS=$(wc -l < "$TMP_CSV")
echo "      Downloaded $ROWS rows."

# --- Step 2: Parse CSV and build JSON ---
echo "[2/3] Parsing OUI entries and building JSON …"
sudo mkdir -p "$DATA_DIR"
python3 - "$TMP_CSV" "$OUI_JSON" <<'PYEOF'
import csv
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
db = {}
with open(src, newline="", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        # IEEE format: Registry, Assignment (e.g. "30C6F7"), Organization Name
        assignment = row.get("Assignment", "").strip()
        org = row.get("Organization Name", "").strip()
        if len(assignment) == 6 and org:
            # Convert "30C6F7" → "30:c6:f7"
            oui = ":".join(
                assignment[i:i+2].lower() for i in range(0, 6, 2)
            )
            db[oui] = org

# Write atomically
import tempfile, os, pathlib
tmp = dst + ".tmp"
pathlib.Path(tmp).write_text(json.dumps(db, separators=(",", ":")), encoding="utf-8")
os.replace(tmp, dst)
print(f"      Wrote {len(db):,} OUI entries to {dst}")
PYEOF

# --- Step 3: Set ownership so netwatchm user can read it ---
echo "[3/3] Setting file ownership …"
if id netwatchm &>/dev/null; then
    sudo chown netwatchm:netwatchm "$OUI_JSON"
fi
sudo chmod 644 "$OUI_JSON"

rm -f "$TMP_CSV"
echo ""
echo "=== Done. OUI database ready at $OUI_JSON ==="
SIZE=$(du -sh "$OUI_JSON" 2>/dev/null | cut -f1)
echo "    File size: $SIZE"
