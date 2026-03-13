# IP Investigation Log — Real Example

This document shows a real IP investigation step-by-step, using an actual case from NetWatchM.

---

## Case: 51.11.192.51 — Investigation Log

### Initial Alert

NetWatchM showed a connection:
```
51.11.192.51    192.168.1.180    80    50387
```

The user wanted to know:
1. What is this IP?
2. Is it legitimate or suspicious?
3. Could it be spoofed?

---

### Step 1: Who owns this IP?

Command:
```bash
whois 51.11.192.51 | head -20
```

Result:
```
inetnum:        51.11.0.0 - 51.11.255.255
netname:        cloud
country:        EU
admin-c:        DH5439-RIPE
tech-c:         MRPA3-RIPE
status:         LEGACY
mnt-by:         MICROSOFT-MAINT
abuse-contact:  'abuse@microsoft.com'
```

**Finding:** Owned by Microsoft — likely Azure cloud.

---

### Step 2: Reverse DNS Lookup

Command:
```bash
host 51.11.192.51
```

Result:
```
Host 51.192.11.51.in-addr.arpa. not found: 3(NXDOMAIN)
```

**Finding:** No reverse DNS — common for Azure IPs.

---

### Step 3: Cloud Provider Check

Command:
```bash
curl -s https://ipinfo.io/51.11.192.51/json
```

Result:
```json
{
  "ip": "51.11.192.51",
  "city": "Paris",
  "region": "Île-de-France",
  "country": "FR",
  "loc": "48.8534,2.3488",
  "org": "AS8075 Microsoft Corporation",
  "postal": "75000",
  "timezone": "Europe/Paris"
}
```

**Finding:** 
- **AS8075** = Microsoft Corporation
- **Location:** Paris, France (Azure data center)
- This is **Azure France**

---

### Step 4: Check Active Connections

Command:
```bash
sudo conntrack -L -p tcp --state ESTABLISHED | grep "51.11.192.51"
```

Result: (no output)

**Finding:** Connection already closed — it was a brief request.

---

### Step 5: Check NetWatchM Events

Command:
```bash
sqlite3 /var/lib/netwatchm/events.db "SELECT * FROM events WHERE src_ip='51.11.192.51' OR dst_ip='51.11.192.51';"
```

Result:
```
1502|1773369756.92098|NEW_IP|LOW|51.11.192.51||New IP address observed: 51.11.192.51
```

**Finding:** Only alert was `NEW_IP` (LOW threat) — just informing about new external IP.

---

### Step 6: Identify Source Device

Command:
```bash
cat /var/lib/netwatchm/inventory.json | grep "192.168.1.180"
```

Result:
```json
{
  "ip": "192.168.1.180",
  "hostname": "ai-rnd-01",
  "first_seen": "2026-02-21T16:29:32",
  "last_seen": "2026-03-12T23:32:09"
}
```

**Finding:** Source is **ai-rnd-01** — the NetWatchM server itself!

---

### Step 7: Live Traffic Capture

Command:
```bash
sudo tcpdump -i any port 80 or port 443 -nn -c 20
```

Result (captured other traffic):
```
23:35:40.081421 enp6s0 Out 192.168.1.180.43458 > 52.168.117.171.443: Flags [P.]
23:35:40.199594 enp6s0 Out 192.168.1.180.44990 > 140.82.112.25.443: Flags [.]
23:35:45.752543 enp6s0 In  54.175.191.201.443 > 192.168.1.180.52838: Flags [.]
```

Other IPs seen:
| IP | Service |
|----|---------|
| 140.82.112.25 | GitHub |
| 52.168.117.171 | AWS/Azure |
| 54.175.191.201 | AWS |
| 2606:4700::6812:17de | Cloudflare |

**Finding:** Normal server traffic — package updates, cloud APIs, CDN.

---

### Conclusion

**VERDICT: LEGITIMATE**

- IP is Microsoft Azure (France)
- Source is the NetWatchM server itself (ai-rnd-01)
- Connection was outbound HTTP request to Azure service
- Likely causes: apt update check, pip/uv checking packages, cloud SDK

---

## Investigation Summary

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `whois <IP>` | Find owner/organization |
| 2 | `host <IP>` | Reverse DNS lookup |
| 3 | `curl ipinfo.io/<IP>/json` | Quick cloud provider check |
| 4 | `sudo conntrack -L ...` | Check active connections |
| 5 | `sqlite3 events.db ...` | Check NetWatchM alerts |
| 6 | `inventory.json` | Identify source device |
| 7 | `sudo tcpdump ...` | Live traffic capture |

---

## Common Legitimate Cloud IPs

Based on this investigation, these are typical legitimate cloud IPs your server may connect to:

| Provider | Example IPs | Purpose |
|----------|-------------|---------|
| Microsoft Azure | 51.x.x.x, 52.x.x.x, 40.x.x.x | Cloud services |
| AWS | 3.x.x.x, 52.x.x.x, 54.x.x.x | Cloud services |
| GitHub | 140.82.112.x | Package downloads |
| Cloudflare | 2606:4700::..., 1.1.1.x | DNS, CDN |
| PyPI | 151.101.x.x | Python packages |

---

## Map Location

**Coordinates:** 48.8534, 2.3488 (Paris, France)

- [Google Maps](https://www.google.com/maps?q=48.8534,2.3488)
- [OpenStreetMap](https://www.openstreetmap.org/?mlat=48.8534&mlon=2.3488#map=12/48.8534/2.3488)

---

## Files Updated

- `docs/ip-investigation-qrcards.md` — Added tcpdump port 80/443 command to Quick Reference Card
- `docs/ip-investigation-log.md` — This file (real investigation example)
