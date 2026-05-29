# Portal verification screenshots

Headless-Chrome renders of the live portal (`https://localhost:8765`) captured
to verify the Session 33 deploy (SIEM forwarding + alert triage + GRC).

> ⚠️ These images contain real LAN inventory data (device hostnames, internal
> IPs). Private repo only — do not publish.

| File | Page | Verifies |
|------|------|----------|
| `grc-dashboard.png` | `/grc.html` | GRC scorecards (60% compliance), CIS control table, device risk register with labeled/verified devices |
| `incidents-triage.png` | `/incidents.html` | Triage toolbar (status + priority filters, admin-token field), GRC nav link |
| `events.png` | `/events.html` | Event feed + GRC nav link |

Captured 2026-05-29. No app-level JS console errors in any render.
