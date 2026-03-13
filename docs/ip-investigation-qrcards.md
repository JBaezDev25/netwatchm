# IP Investigation Reference Guide

This guide helps you investigate suspicious IP addresses to determine if they're legitimate or malicious.

---

## Table of Contents
1. [Quick Info Commands](#quick-info-commands)
2. [Network Connection Commands](#network-connection-commands)
3. [Understanding Ports](#understanding-ports)
4. [Spoofing vs Legitimate](#spoofing-vs-legitimate)
5. [NetWatchM Commands](#netwatchm-commands)
6. [Common Cloud Provider IPs](#common-cloud-provider-ips)
7. [Service Identification](#service-identification)
8. [Whitelist an IP](#whitelist-an-ip)

---

## Quick Info Commands

### 1. Check IP Ownership (ASN/Organization)

The `whois` command queries the regional internet registry (RIR) to find who owns an IP address.

```bash
whois 51.11.192.51
```

**Key fields to look for:**
- `Organization` or `OrgName` — who owns the IP
- `Country` — registration country
- `netrange` or `CIDR` — IP range
- `origin` or `OriginAS` — Autonomous System Number

**Filtered output:**
```bash
whois 51.11.192.51 | grep -E "origin|org|AS|Organization|Country|netrange|descr"
```

**Example output for Azure IP:**
```
OrgName:        Microsoft Corporation
OrgId:          MSFT
OriginAS:       AS8075
Country:        FR
```

### 2. Reverse DNS Lookup

Reverse DNS (PTR record) maps an IP to a hostname. Legitimate services usually have reverse DNS.

```bash
host 51.11.192.51
dig +short -x 51.11.192.51
nslookup 51.11.192.51
```

**What to look for:**
- Azure IPs often show: `*.cloudapp.azure.com` or `*.azureedge.net`
- AWS IPs: `*.compute.amazonaws.com`
- Google Cloud: `*.googleusercontent.com`
- No reverse DNS: Could be legitimate but uncommon

### 3. Check Microsoft IP Ranges

Verify the IP is in Microsoft's official IP ranges.

```bash
# Microsoft's official IP ranges (JSON)
curl -s "https://ip-ranges.amazonaws.com/ip-ranges.json" | grep "51.11.192"

# Azure specific
curl -s "https://ip-ranges.azure.com/" | jq -r '.prefixes[] | select(.ip_prefix | contains("51.11"))'

# Or use a third-party service
curl -s "https://ipinfo.io/51.11.192.51/json"
```

### 4. Check HTTP/HTTPS Service

Connect to the IP and see what service responds. This reveals what website/service is there.

**HTTP (port 80):**
```bash
curl -I -v http://51.11.192.51:80 2>&1 | head -50
```

**HTTPS (port 443):**
```bash
curl -Ik -v https://51.11.192.51:443 2>&1 | head -50
```

**What to look for in response:**
- `Server:` header — identifies the web server (nginx, Apache, Azure, etc.)
- `X-Powered-By:` — technology stack
- `Location:` for redirects — shows the actual domain
- `Content-Security-Policy:` — security headers

**Example legitimate response:**
```
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Content-Type: text/html
```

### 5. Check SNI (Server Name Indication)

For HTTPS connections, check what domain the server presents.

```bash
# Using OpenSSL
openssl s_client -connect 51.11.192.51:443 -servername 51.11.192.51 2>&1 | grep -E "subject|issuer|Subject|Issuer"

# More detailed
echo | openssl s_client -connect 51.11.192.51:443 2>&1 | openssl x509 -noout -text | grep -A2 "Subject:"
```

---

## Network Connection Commands

### 6. Check Active Connections with ss

The `ss` command shows socket statistics. It replaces the older `netstat`.

**All established connections:**
```bash
sudo ss -tan state established
```

**Filter by destination IP:**
```bash
sudo ss -tan state established | grep "51.11.192.51"
```

**Filter by source IP (your internal device):**
```bash
sudo ss -tan state established | grep "192.168.1.180"
```

**Filter by port:**
```bash
# All HTTP connections
sudo ss -tan state established | grep ":80"

# All HTTPS connections
sudo ss -tan state established | grep ":443"

# Show process info
sudo ss -tanp state established
```

**Understanding the output:**
```
State      Recv-Q     Send-Q         Local Address:Port          Peer Address:Port
ESTAB      0          0              192.168.1.180:50387          51.11.192.51:80
```
- `State: ESTAB` — Connection is established (active)
- `Local` — Your device IP and source port
- `Peer` — Remote IP and destination port

### 7. Check conntrack (Connection Tracking)

`conntrack` shows connections tracked by the Linux kernel firewall. More detailed than ss.

**All established TCP connections:**
```bash
sudo conntrack -L -p tcp --state ESTABLISHED
```

**Filter by destination IP:**
```bash
sudo conntrack -L -p tcp --state ESTABLISHED | grep "51.11.192.51"
```

**Filter by source IP:**
```bash
sudo conntrack -L -p tcp | grep "192.168.1.180"
```

**Check all states (not just ESTABLISHED):**
```bash
sudo conntrack -L -p tcp | head -20
```

**Show connection count:**
```bash
sudo conntrack -L -p tcp --state ESTABLISHED | wc -l
```

**Example output:**
```
tcp      6 431997 ESTABLISHED src=192.168.1.180 dst=51.11.192.51 sport=50387 dport=80 src=51.11.192.51 dst=192.168.1.180 sport=80 dport=50387 [ASSURED]
```

### 8. Live Capture with tcpdump

`tcpdump` captures packets in real-time. Essential for catching connections as they happen.

**Capture all HTTP/HTTPS traffic:**
```bash
sudo tcpdump -i any port 80 or port 443 -nn
```

**Capture specific IP:**
```bash
sudo tcpdump -i any host 51.11.192.51 -nn
```

**Capture specific IP + port:**
```bash
sudo tcpdump -i any host 51.11.192.51 and port 80 -nn
```

**Capture with timestamps and ASCII:**
```bash
sudo tcpdump -i any host 51.11.192.51 -ttttnn -A
```

**Save to file for later analysis:**
```bash
sudo tcpdump -i any host 51.11.192.51 -w /tmp/capture.pcap
```

**Read saved capture:**
```bash
sudo tcpdump -r /tmp/capture.pcap -nn
```

**What to look for in tcpdump output:**
```
21:45:30.123456 IP 192.168.1.180.50387 > 51.11.192.51.80: Flags [S], seq 12345678
21:45:30.234567 IP 51.11.192.51.80 > 192.168.1.180.50387: Flags [S.], seq 87654321, ack 12345679
21:45:30.345678 IP 192.168.1.180.50387 > 51.11.192.51.80: Flags [.], ack 87654322
```

Flags: `[S]` = SYN, `[S.]` = SYN-ACK, `[.]` = ACK, `[P]` = PSH, `[F]` = FIN

### 9. Check Process Using Connection

Find which process is making the connection.

```bash
# Show process for specific IP
sudo netstat -tnp | grep "51.11.192.51"

# Show all processes with connections
sudo netstat -tanp

# Using ss with process info
sudo ss -tnp
```

**Example output:**
```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.180:50387     51.11.192.51:80         ESTABLISHED 1234/firefox
```

---

## Understanding Ports

### Source vs Destination Port — Why It Matters

```
┌─────────────────────────────────────────────────────────────────────┐
│  Your PC (192.168.1.180:50387)  ──────>  Azure Server             │
│                                        (51.11.192.51:80)            │
│         ^source port (ephemeral)               ^destination port   │
└─────────────────────────────────────────────────────────────────────┘
```

**Source Port (50387):**
- Random number your OS assigns
- Changes every new connection
- Like a return address on mail
- Called "ephemeral port"

**Destination Port (80):**
- Fixed for the SERVICE
- Identifies WHAT you're connecting to
- This is the IMPORTANT one!

### Common Service Ports

| Port  | Service           | Description                          |
|-------|-------------------|--------------------------------------|
| 20    | FTP Data          | File Transfer (data)                |
| 21    | FTP Control       | File Transfer (commands)            |
| 22    | SSH               | Secure Shell login                   |
| 23    | Telnet            | Unencrypted remote login            |
| 25    | SMTP              | Email sending                        |
| 53    | DNS               | Domain Name System                   |
| 80    | HTTP              | Web (unencrypted)                   |
| 110   | POP3              | Email retrieval (unencrypted)       |
| 143   | IMAP              | Email retrieval                     |
| 443   | HTTPS             | Web (encrypted)                     |
| 445   | SMB               | Windows file sharing                 |
| 3306  | MySQL             | MySQL database                       |
| 3389  | RDP               | Windows Remote Desktop              |
| 5432  | PostgreSQL        | PostgreSQL database                  |
| 8080  | HTTP Alt          | Alternative HTTP (proxies)           |
| 8443  | HTTPS Alt         | Alternative HTTPS                    |

### Ephemeral Port Range

Your OS assigns random ports from a range:
- Linux: 32768-60999
- Windows: 49152-65535
- macOS: 49152-65535

These are NOT service ports — ignore them for identification!

---

## Spoofing vs Legitimate

### What is IP Spoofing?

IP spoofing = forging the source IP address to make traffic appear to come from somewhere else.

**Attacker sends packets with FAKE source IP:**
```
Attacker (real IP: 10.0.0.50)
        |
        |---spoofed packet---> [src=51.11.192.51] ---> Victim
```

### Can You Spoof Easily?

**UDP:** Easy — no verification, attacker never gets response
**TCP:** Hard — requires completing 3-way handshake

### How to Tell If Spoofed

#### 1. Check Direction

| Direction | Likelihood of Spoofing |
|-----------|------------------------|
| INBOUND (stranger connecting to you) | Possible — harder to verify |
| OUTBOUND (your device connecting out) | Very unlikely — you'd need to spoof YOUR own IP |

If YOUR device initiated the connection, it's almost certainly REAL.

#### 2. Check TCP Handshake

Real TCP connection = 3-way handshake:
```
1. Your PC --SYN--> Server
2. Server --SYN-ACK--> Your PC  
3. Your PC --ACK--> Server
```

If spoofed:
- Server responds to FAKE IP
- Response goes to fake IP, never reaches attacker
- Attacker never completes handshake
- Connection never established

**If you see ESTABLISHED connection, IP is REAL.**

#### 3. Check for Responses

```bash
# Ping the IP - do you get responses?
ping -c 5 51.11.192.51
```

If you get responses, the IP is real.

#### 4. Check Traffic Patterns

**Legitimate:**
- Regular intervals (polling)
- Expected destinations (known services)
- Both directions have traffic

**Spoofed:**
- One-way traffic only
- Irregular timing
- Often part of attack (DDoS, scanning)

### Spoofing Red Flags

- Many connections from same source but different ports
- SYN flood without SYN-ACK responses
- Traffic from unusual/unrelated IPs
- Connection attempts to random ports
- High volume of connections from suspicious IP ranges

### Legitimate Indicators

- Established connection exists
- Outbound from your device
- Known cloud provider (Azure, AWS, Google)
- Matches expected service (HTTP/HTTPS to known domain)
- Reasonable timing (not attack pattern)
- Two-way communication

---

## NetWatchM Commands

### Check Events for Specific IP

Search NetWatchM's event database for alerts involving an IP.

```bash
# All events for an IP (as source or destination)
sqlite3 /var/lib/netwatchm/events.db "SELECT * FROM events WHERE src_ip='51.11.192.51' OR dst_ip='51.11.192.51';"

# Show last 10 events for IP
sqlite3 /var/lib/netwatchm/events.db "SELECT timestamp, src_ip, dst_ip, alert_type, threat_level FROM events WHERE src_ip='51.11.192.51' OR dst_ip='51.11.192.51' ORDER BY timestamp DESC LIMIT 10;"

# Count events by type
sqlite3 /var/lib/netwatchm/events.db "SELECT alert_type, COUNT(*) FROM events WHERE src_ip='51.11.192.51' OR dst_ip='51.11.192.51' GROUP BY alert_type;"
```

### Deep Inspect an IP

Run a comprehensive inspection on an IP.

```bash
uv run netwatchm deep-inspect --target 51.11.192.51 --output /tmp/report.html
```

This generates a report with:
- GeoIP location
- Port scan results
- Service detection (SSH, HTTP, RDP, SMB)
- Security findings

### Connection Report

See all traffic to/from devices.

```bash
# 5 second capture
uv run netwatchm --interface lo report --duration 5

# Save to file
uv run netwatchm report --duration 10 --output /tmp/connections.html
```

### Inventory Search

Check if IP is in your device inventory.

```bash
# View inventory
uv run netwatchm inventory

# Filter by subnet
uv run netwatchm inventory --filter 192.168.1
```

### Check Threat Level

```bash
# Check current threat level
curl -sk https://localhost:8765/api/threat-level
```

---

## Common Cloud Provider IPs

### Microsoft Azure

| Range | Description |
|-------|-------------|
| 40.x.x.x | Azure |
| 51.x.x.x | Azure |
| 52.x.x.x | Azure |
| 104.x.x.x | Azure CDN |

**Reverse DNS pattern:** `*.cloudapp.azure.com`, `*.azureedge.net`

### Amazon Web Services (AWS)

| Range | Description |
|-------|-------------|
| 3.x.x.x | AWS |
| 52.x.x.x | AWS |
| 54.x.x.x | AWS |
| 18.x.x.x | AWS |
| 44.x.x.x | AWS |

**Reverse DNS pattern:** `*.compute.amazonaws.com`

### Google Cloud

| Range | Description |
|-------|-------------|
| 35.x.x.x | Google Cloud |
| 34.x.x.x | Google Cloud |
| 104.x.x.x | Google Cloud |

**Reverse DNS pattern:** `*.googleusercontent.com`

### Cloudflare

| Range | Description |
|-------|-------------|
| 1.1.1.x | Cloudflare DNS |
| 172.x.x.x | Cloudflare |
| 104.x.x.x | Cloudflare |

**Reverse DNS pattern:** `*.cloudflare.com`

### How to Identify Any Cloud Provider

```bash
# Using ASN
whois 51.11.192.51 | grep -i "AS.*8075"

# Using ipinfo
curl -s https://ipinfo.io/51.11.192.51/json
```

---

## Service Identification

### What Service Is Running on Port 80/443?

```bash
# Basic check
curl -I http://51.11.192.51

# Verbose with headers
curl -Iv http://51.11.192.51

# Follow redirects
curl -IL http://51.11.192.51

# Check HTTPS certificate
echo | openssl s_client -connect 51.11.192.51:443 2>&1 | head -20
```

### Common Server Headers

| Server Header | What It Means |
|---------------|---------------|
| Microsoft-IIS | Windows Server + IIS |
| Apache | Apache HTTP Server |
| nginx | nginx Web Server |
| cloudflare | Behind Cloudflare |
| BigIP | F5 Load Balancer |
| gunicorn | Python web app |
| Werkzeug | Python Flask |
| Node.js | JavaScript runtime |

### Identify by SSL Certificate

```bash
# Get certificate details
echo | openssl s_client -connect 51.11.192.51:443 2>&1 | openssl x509 -noout -text | grep -A3 "Subject:"

# Get certificate issuer
echo | openssl s_client -connect 51.11.192.51:443 2>&1 | openssl x509 -noout -text | grep -A3 "Issuer:"

# Check all SANs (Subject Alternative Names)
echo | openssl s_client -connect 51.11.192.51:443 2>&1 | openssl x509 -noout -text | grep -A10 "Subject Alternative Name"
```

---

## Whitelist an IP in NetWatchM

If you've verified an IP is safe, add it to whitelist.

### 1. Edit Config File

```bash
sudo nano /etc/netwatchm/netwatchm.yaml
```

Add to whitelist section:

```yaml
whitelist:
  - 51.11.192.51          # Single IP
  - 192.168.1.0/24       # Entire subnet (CIDR notation)
  - 10.0.0.0/8           # Class A subnet
```

### 2. Per-Detector Whitelist

If only specific detectors should ignore:

```yaml
detector_whitelist:
  PORT_SCAN:
    - 51.11.192.51
  BRUTE_FORCE:
    - 192.168.1.100
```

### 3. Restart Service

```bash
sudo systemctl restart netwatchm
```

Or for web server only:
```bash
sudo systemctl restart netwatchm-web
```

---

## Map Links

### Coordinates to Maps

- **Google Maps:** https://www.google.com/maps?q=48.8558,2.3494
- **OpenStreetMap:** https://www.openstreetmap.org/?mlat=48.8558&mlon=2.3494#map=12/48.8558/2.3494
- **Bing Maps:** https://www.bing.com/maps?l=48.8558,2.3494

---

## Quick Reference Card

```bash
# 1. Who's this IP?
whois 51.11.192.51 | head -20

# 2. What's the hostname?
host 51.11.192.51

# 3. What service?
curl -I http://51.11.192.51

# 4. Is it a cloud provider?
curl -s https://ipinfo.io/51.11.192.51/json

# 5. Any active connections?
sudo conntrack -L -p tcp --state ESTABLISHED | grep "51.11.192.51"

# 6. See it live? (specific IP)
sudo tcpdump -i any host 51.11.192.51 -nn

# 7. Watch all HTTP/HTTPS traffic (20 packets)
sudo tcpdump -i any port 80 or port 443 -nn -c 20

# 8. Check NetWatchM events
sqlite3 /var/lib/netwatchm/events.db "SELECT * FROM events WHERE src_ip='51.11.192.51' OR dst_ip='51.11.192.51';"

# 9. Check device inventory
uv run netwatchm inventory | grep 51.11.192.51
```
