#!/usr/bin/env bash
ERRORS=0

echo "=== Phase 7: Migration Verification ==="
echo ""

# 1. Services running
echo "--- Services ---"
for svc in netwatchm netwatchm-web; do
    if systemctl is-active "$svc" --quiet; then
        echo "PASS: $svc is active"
    else
        echo "FAIL: $svc is not active"
        ERRORS=$((ERRORS+1))
    fi
done

# 2. SQLite databases readable
echo ""
echo "--- Databases ---"
for db in flows events flow-history; do
    path="/mnt/jbaez_data/netwatchm/${db}.db"
    if sudo sqlite3 "$path" "SELECT COUNT(*) FROM sqlite_master;" > /dev/null 2>&1; then
        size=$(sudo du -sh "$path" 2>/dev/null | cut -f1)
        echo "PASS: ${db}.db readable ($size)"
    else
        echo "FAIL: ${db}.db not readable at $path"
        ERRORS=$((ERRORS+1))
    fi
done

# 3. Correct WorkingDirectory in use
echo ""
echo "--- Service config ---"
if systemctl show netwatchm-web --property=WorkingDirectory | grep -q "jbaez_data"; then
    echo "PASS: WorkingDirectory points to data disk"
else
    echo "FAIL: WorkingDirectory not updated"
    ERRORS=$((ERRORS+1))
fi

# 4. Log path updated in yaml
if sudo grep -q "jbaez_data" /etc/netwatchm/netwatchm.yaml 2>/dev/null; then
    echo "PASS: Log path updated in netwatchm.yaml"
else
    echo "FAIL: Log path not updated in netwatchm.yaml"
    ERRORS=$((ERRORS+1))
fi

# 5. Web server API responds
echo ""
echo "--- API ---"
if curl -sk --max-time 5 https://localhost:8765/api/events > /dev/null 2>&1; then
    echo "PASS: Web server API responding"
else
    echo "FAIL: Web server API not responding"
    ERRORS=$((ERRORS+1))
fi

# 6. Main drive freed up
echo ""
echo "--- Disk usage ---"
df -h /dev/sda2 /dev/sdb1 | awk 'NR==1 || /sda2/ || /sdb1/ {printf "%-20s %5s %5s %5s %4s\n", $1, $2, $3, $4, $5}'

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "=== All checks passed — migration complete ==="
else
    echo "=== $ERRORS check(s) FAILED ==="
fi
