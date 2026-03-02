#!/usr/bin/env python3
"""Temporarily sets some devices to HIGH/MEDIUM threat for testing. Pass --revert to restore."""
import json, sys

path = "/var/lib/netwatchm/inventory.json"

with open(path) as f:
    devices = json.load(f)

if "--revert" in sys.argv:
    for d in devices:
        d["threat_level"] = "LOW"
    print(f"Reverted all {len(devices)} devices to LOW")
else:
    for i, d in enumerate(devices):
        if i < 2:
            d["threat_level"] = "HIGH"
        elif i < 5:
            d["threat_level"] = "MEDIUM"
    print(f"Set 2 HIGH, 3 MEDIUM, {len(devices)-5} LOW")

with open(path, "w") as f:
    json.dump(devices, f)
