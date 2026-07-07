# Network Detector

A comprehensive Windows desktop application built with **Electron + React + Express** for real-time network diagnostics, ISP performance analysis, and security threat detection — no browser needed, no cloud, everything runs locally on your machine.

---

## Features

### 📊 **Overview** — Network Snapshot
Real-time monitoring of your connection health with 6 live cards:
- **Wi-Fi Info**: SSID, signal quality, link speed, security protocol
- **Live Bandwidth**: Download/upload speeds (updates every second)
- **IP & DHCP**: Local network configuration, DNS servers, lease times
- **Latency**: Gateway + external ping with packet loss and jitter
- **Public Details**: External IP, ISP/ASN, geolocation
- **Connection Health**: Stability score (0-100) with local/ISP breakdown

### 🎯 **ISP Truth** — Routing Analysis
Expose ISP performance issues with evidence-based metrics:
- **Multi-Region Latency Matrix**: Ping local exchange, Singapore (1.1.1.1), US East (8.8.8.8), US West (208.67.222.222)
- **CDN Speed Test**: Download 10MB from Cloudflare edge servers
- **DNS Hijacking Detector**: Compare system DNS vs DoH (Cloudflare)
- **Copy Evidence Report**: Export all metrics to clipboard for ISP support tickets

### � **Wi-Fi Analyzer** — Signal & Channels
Professional wireless diagnostics that rival commercial Wi-Fi analyzers:
- **Signal Analysis**: SSID, BSSID, band (2.4/5 GHz), channel, signal %, **RSSI (dBm)**
- **Standard Detection**: 802.11ax (Wi-Fi 6) / ac (Wi-Fi 5) / n (Wi-Fi 4)
- **Link Rates**: Real negotiated Receive/Transmit rates
- **Channel Interference Scan**: Counts networks per channel, recommends the clearest 2.4 GHz channel (1/6/11)
- **Nearby Networks**: Lists surrounding APs sorted by signal strength

### ❤ **Health & Tips** — Scores & Advice
Per-category scoring and intelligent recommendations:
- **8 Category Scores** (0-100): Internet, Wi-Fi, Latency, Stability, Security, DNS, Streaming, Gaming
- **Intelligent Recommendations**: Plain-English, actionable advice based on measured results
- **DNS Provider Benchmark**: Times Cloudflare, Google, Quad9, OpenDNS — recommends the fastest
- **Detailed Local Health**: Gateway ping with avg/min/max/median/**p95**/jitter/loss over 20 samples
- **Device Health**: CPU load, RAM usage, and power state that can throttle Wi-Fi

### �🛡️ **Security** — Threat Scanner
Advanced network security auditing:
- **MITM Check**: Detect man-in-the-middle attacks (combines ARP + DNS + TLS checks)
- **ARP Spoofing**: Identify duplicate MAC addresses (classic MITM signature)
- **WiFi Security Audit**: Score your wireless encryption (WPA3/WPA2/WPA/WEP/Open)
- **DNS Leak Test**: Check if DNS queries bypass VPN/privacy resolvers
- **Port Scanner**: List all open listening ports on your machine
- **Firewall Status**: Windows Defender state for all profiles
- **SSL/TLS Verification**: Certificate validation for known-good sites
- **Encryption Analysis**: Cipher suite strength (TKIP vs AES/CCMP)

### 📡 **Devices** — Connected Devices
Live enumeration of all devices on your network:
- IP address, MAC address, hostname (reverse DNS)
- **Vendor lookup** via MAC OUI database (Apple, Samsung, Intel, TP-Link, etc.)
- Device type classification (gateway, router, PC, phone, smart device)
- Gateway highlighted with visual indicator
- One-click rescan

### ⚙️ **Diagnostics** — Deep Inspect
Detailed network interface analysis:
- Interface details (protocol, band, channel, BSSID)
- DHCP lease information
- DNS configuration with resolution times
- Performance metrics (throughput, jitter, packet loss)
- Network device count from ARP table
- Wireless signal strength trends

### 📖 **How to Use** — Metric Guide
Built-in documentation explaining:
- What each metric measures
- How to interpret results (good/warning/critical thresholds)
- Actionable recommendations for issues
- Glossary of networking terms

### 🚀 **Speed & Stability** — Phases & Bufferbloat
On-demand deep speed analysis:
- **Connection phase breakdown** — times DNS, TCP, TLS, and time-to-first-byte during a real download to pinpoint where slowness starts
- **Bufferbloat grade (A–F)** — measures latency increase under load (critical for calls/gaming)
- **60-second stability test** — pings every second with a live graph, counting drops and reconnects

### 🗺 **Route Trace** — Hop-by-Hop Path
- Full traceroute with per-hop latency
- **Geolocation** of each public hop (ISP/organisation, city, country)
- Automatic detection of the largest latency jump (the bottleneck)

### 📈 **Trends** — History & Graphs
- Samples download, upload, latency, and Wi-Fi signal every 30 seconds
- Stored **locally** on your device (no cloud) — capped at the last 200 samples
- Inline SVG sparkline charts to spot recurring drop-outs and peak-hour congestion

### 🐧 **WSL Tools** — Linux Networking (auto-detected)
Appears only when **WSL (Windows Subsystem for Linux)** is installed. Provides Linux-native tools that use different probe types than Windows — revealing hops and issues Windows tools miss:
- **mtr** — combined traceroute + ping showing per-hop packet loss and jitter (10 probes per hop)
- **dig** — DNSSEC validation (AD flag / RRSIG records)
- **traceroute** — UDP-based path trace (different from ICMP-only Windows `tracert`)
- **nmap LAN scan** — host discovery using multiple probe types; finds phones, smart TVs, and devices Windows ARP misses
- **IPv6 test** — checks whether your ISP provides working IPv6 connectivity
- **HTTP Header Inspector** — fetches response headers to detect ISP proxy injection, identify CDN/edge server, and spot privacy-relevant fields
- One-click copy of the install command if tools aren't present yet

---

## Recent Updates

### v1.3.0 (Latest) — **Accuracy Fixes & WSL Power Tools**

**Bug fixes (based on ChatGPT analysis of the generated report):**
- 🐛 **ARP spoofing false positive fixed** — the previous detection flagged any MAC with multiple IPs (normal for VMs / VPN adapters). Rewritten to track the **gateway MAC over time**; only fires High when the gateway IP changes to a different MAC — a genuine MITM indicator. Downgraded single-occurrence duplicate MACs to Medium.
- 🐛 **Stability rating now accurate** — "Poor — occasional drops" was shown even when there were **zero drops** (just high jitter). New tier: "Fair — high jitter (no drops)" when loss=0 but jitter ≥30 ms.
- 🐛 **DNS benchmark anomalies labelled** — values >200 ms are now annotated with "⚠ slow (possible cache miss or resolver congestion)" in the report so they aren't misread as typical latency.
- 🐛 **LAN device scan improved** — now performs a parallel **ping sweep** of the /24 subnet before reading the ARP cache. Devices that haven't communicated recently (phones on standby, smart TVs) now appear correctly.
- 🔧 **Report clarifications** — Throughput now shows a note explaining it's the live NIC rate, not a speed test result; channel-overlap warning added for non-standard 2.4 GHz channels; signal quality labelled (Excellent / Very Good / Good / Fair / Poor).

**New WSL tools (4 additions):**
- 🐧 **traceroute** — UDP-based path analysis (complementary to Windows ICMP tracert)
- 🐧 **nmap LAN scan** — discovers phones, smart TVs, and isolated devices ARP misses
- 🐧 **IPv6 connectivity test** — verifies dual-stack connectivity
- 🐧 **HTTP Header Inspector** — detects ISP proxy injection, CDN/edge identification

### v1.2.4 — **Performance: TCP Ping Engine**
- ⚡ **Stability test now exactly 60 seconds** — replaced `ping.exe` subprocess (200ms+ spawn overhead, 2–4s under load) with a **Node.js TCP socket ping** (~50ms, no subprocess). Previously the test could take 5+ minutes under load.
- ⚡ DNS benchmark providers now tested in parallel.
- ⚡ Geo-lookup cache — repeat route traces are instant (no redundant ipinfo.io calls).
- ⚡ Health check ping count reduced (10→6) — saves ~4s per run.

### v1.2.3 — **Report Quality Fixes**
- Fixed DNS benchmark showing "N/A" (was reading wrong field name).
- Fixed Health Scores showing 100/100 (was using a different scoring path than the Health tab).
- Fixed "Local IP: N/A" in report.
- Fixed "loss 0% loss" double word.
- Added System Resources (CPU/RAM/battery) and more sections to the report.

### v1.2.2 — **Performance: Connection Pool Fix**
- Root cause fix for "buttons don't work while scans run" — 14 aggressive polling intervals saturated Chromium's 6-connection limit. All intervals lengthened, startup burst staggered into 4 phases.
- Stability test converted to recursive timeout (prevented pile-up on cold start).

### v1.2.0 — **Speed Phases, Route Tracing, Trends & WSL**

---

## How It Works

### Data Collection
All measurements run **locally** — no data leaves your machine except:
- `ipinfo.io` for geolocation of public IPs (route trace only, cached in memory)
- `speed.cloudflare.com` for the speed test download
- Cloudflare DoH (`1.1.1.1`) for DNS hijacking comparison

### Measurement Methods

| Check | Method | Notes |
|---|---|---|
| Ping (gateway / external) | `ping -n N <target>` | Windows ICMP; 1s per packet |
| Stability test ping | TCP socket connect to port 53 | No subprocess; ~50ms per sample |
| Speed phases | `curl.exe -w timing_format` | Times DNS/TCP/TLS/TTFB/total |
| Route trace | `tracert -d -h 15 -w 500` | Windows ICMP; geo-enriched in parallel |
| LAN devices | Ping sweep + `arp -a` | 254-host parallel ping then ARP read |
| ARP spoofing | Gateway MAC history | Only flags when gateway MAC **changes** between readings |
| WSL tools | `wsl.exe -d <distro> -- <tool>` | Direct execFile (no cmd.exe wrapper, windowsHide) |

### WSL Tool Detection
1. **`detectWsl()`** — runs `wsl -l -q` (lists distros, **never boots**). Used for tab visibility.
2. **`checkWslTools()`** — boots the distro, runs `command -v` checks. Only called on explicit user click.
3. Each tool function runs via `execFile(wsl.exe, [...args], { windowsHide: true })` to suppress the console window.

### Security Detection Logic
- **ARP Spoofing**: Maintains an in-process `Map<gatewayIP, Set<mac>>`. High risk only when the same gateway IP has been seen with ≥2 different MACs across readings.
- **DNS Hijacking**: Compares system DNS resolution vs Cloudflare DoH. Only flags if IPs belong to different organizations (not CDN load-balancing).
- **MITM Check**: Combines ARP spoofing + DNS hijacking + TLS certificate validity checks.

---

## What It Measures

| Category | Metric | Description |
|---|---|---|
| **Wi-Fi** | SSID / BSSID | Network name and access point hardware address |
| | Protocol / Band / Channel | Radio type (802.11ax), frequency band (2.4/5 GHz), channel number |
| | Signal Quality | Wireless signal strength (green ≥ 70%, yellow ≥ 40%, red < 40%) |
| | Link Speed | Physical Rx/Tx rate between NIC and router (not internet speed) |
| | Security | Authentication + cipher (WPA3/WPA2-Personal, AES/CCMP/TKIP) |
| **Bandwidth** | Download / Upload | Real-time throughput across all interfaces (Mbps) — updates every second |
| **Network Config** | IPv4 / Subnet / Gateway | Local network addressing |
| | DHCP Server / Lease | DHCP server IP and lease validity window |
| | DNS Servers | Configured name servers |
| **Latency** | Gateway Ping | Round-trip to router (healthy < 5 ms) with packet loss % and jitter |
| | External Ping | Round-trip to 8.8.8.8 (excellent < 50 ms) with jitter/loss |
| | DNS Resolution | Time to resolve `google.com` (healthy < 20 ms) |
| **Public Info** | Public IPv4 | Externally-visible IP (via ipinfo.io) |
| | ISP / ASN | Internet service provider and autonomous system number |
| | Location / Timezone | City, country, timezone from geolocation |
| **Health Score** | Connection Stability | 0-100 score: 30% local (WiFi signal + gateway ping), 70% ISP (jitter/loss/latency) |
| **ISP Truth** | Multi-Region Latency | Ping to local exchange + Singapore + US East + US West |
| | CDN Speed Test | 10MB download from Cloudflare edge servers |
| | DNS Hijacking | Compare system DNS vs DoH for IP/timing differences |
| **Security** | MITM Detection | Combines ARP spoofing + DNS hijacking + TLS cert checks |
| | ARP Spoofing | Scans for duplicate MAC addresses in ARP table |
| | WiFi Security Score | Rates encryption strength (WPA3=100, WPA2=80, WPA=50, WEP=10, Open=0) |
| | DNS Leak | Checks if DNS bypasses VPN/privacy resolvers |
| | Port Scan | Lists all open listening ports |
| | Firewall Status | Windows Defender state (Domain/Private/Public profiles) |
| **Devices** | Connected Devices | IP, MAC, hostname, vendor (via OUI lookup), device type |

### Polling Intervals

| Data | Refresh Rate |
|---|---|
| Live Bandwidth | 1 second |
| Wi-Fi / IP Info | 3 seconds |
| Gateway / External Ping / DNS | 5 seconds |
| Multi-Region Latency | 10 seconds |
| ARP / DNS Hijacking | 30 seconds |
| Security Scans / Public IP | 60 seconds |

---

## Architecture

```
network-detector/
├── main.js               # Electron entry point — creates main window (1200x800) + toolbar window (390x38)
├── package.json          # Root — Electron + electron-builder config
├── backend/
│   ├── server.js         # Express API server (port 3001), serves frontend/dist + toolbar HTML
│   ├── networkScanner.js # All network diagnostics (netsh, ipconfig, ping, tracert, arp, netstat)
│   └── ipc-bridge.js     # Event bus for toolbar ↔ main window communication
└── frontend/
    ├── src/
    │   ├── App.jsx        # Main React component with sidebar navigation + 6 tabs
    │   ├── components/
    │   │   └── StatusCard.jsx  # Reusable metric card component
    │   └── index.css      # All styles (modern sidebar + glassmorphic cards + animations)
    └── vite.config.js     # Vite build config
```

**Data flow:**
```
Electron main.js
  └── spawns backend/server.js  (Express on :3001)
        └── networkScanner.js     (Windows CLI: netsh, ipconfig, ping, tracert, arp, netstat)
  └── BrowserWindow (main) → http://localhost:3001
        └── serves frontend/dist  (pre-built React SPA with 6 tabs)
              └── polls /api/network/* endpoints (staggered intervals: 1s–60s)
  └── BrowserWindow (toolbar) → http://localhost:3001/toolbar
        └── floating always-on-top bar with network status + controls
```

### Key Technologies
- **Electron 25.0.0**: Desktop app framework (Chromium + Node.js)
- **React 18+**: Frontend UI with hooks (useState, useEffect, useRef)
- **Vite 8.0.16**: Fast frontend build tool
- **Express.js**: REST API server (port 3001)
- **systeminformation**: Cross-platform system stats (bandwidth throughput)
- **Windows CLI**: netsh wlan, ipconfig /all, ping, tracert, arp -a, netstat
- **External Services**: ipinfo.io (geolocation), Cloudflare DoH (DNS-over-HTTPS), Cloudflare CDN (speed test)

### Security Checks
- **ARP Spoofing**: Scans `arp -a` for duplicate MAC addresses (MITM signature)
- **DNS Hijacking**: Compares system DNS (dns.promises) vs Cloudflare DoH (HTTPS)
- **WiFi Security**: Analyzes encryption (WPA3 > WPA2 > WPA > WEP > Open), cipher (AES/CCMP > TKIP)
- **DNS Leak**: Checks if configured DNS matches privacy resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9)
- **Port Scan**: Lists open ports from `netstat -ano | findstr LISTENING`
- **Firewall**: Checks Windows Defender state via `netsh advfirewall`
- **TLS/SSL**: Validates certificates for known-good sites (google.com)
- **MAC Vendor Lookup**: Built-in OUI database with ~100 manufacturers

---

## 🚀 Getting Started (End Users)

**Latest Release:** v1.3.0

1. Download **Network Detector Setup 1.3.0.exe** from `dist-electron/`
2. Run the installer (Windows may show SmartScreen warning — click "More info" → "Run anyway")
3. App opens automatically after installation
4. Navigate tabs via the sidebar:
   - **Overview**: Network snapshot (connection, WiFi, bandwidth, IP, latency, health, device)
   - **Wi-Fi Analyzer**: Signal/RSSI, channel interference, link rates
   - **ISP Truth**: Multi-region latency, CDN speed test, DNS hijacking check
   - **Health & Tips**: Category scores, recommendations, DNS benchmark, gateway health
   - **Security**: MITM detection, ARP spoofing, WiFi audit, port scan
   - **Devices**: Connected devices with MAC vendor lookup
   - **Diagnostics**: Deep network interface inspection
   - **How to Use**: Complete guide explaining all metrics

### Troubleshooting

**"DNS Hijacking Detected" warning but I'm not being attacked:**
- **Fixed in v1.0.10!** Earlier versions had false positives due to CDN load-balancing.
- If you see: "Different IPs but same network (normal for CDN)" — this is **benign**.
- Only worry if it says: "IP from different organization" with High Risk.

**App shows blank window:**
- Make sure you're on **v1.0.10 or later** (fixed in v1.0.8+).
- Check if port 3001 is blocked by firewall or another app.

**Metrics not updating:**
- Requires Windows 10/11 with `netsh` and `ipconfig` available.
- Run app as Administrator if some features (like port scan) fail.

---

## Requirements

- **Windows 10 / 11** (uses `netsh`, `ipconfig`, PowerShell `Get-NetAdapter`)
- **Node.js 18+**
- **npm 9+**

---

## Development Setup

### 1. Install all dependencies

```bat
npm install
cd backend && npm install && cd ..
cd frontend && npm install && cd ..
```

### 2. Build the frontend

```bat
cd frontend && npm run build && cd ..
```

### 3. Run in development (Electron)

```bat
npm start
```

This starts the Electron shell, which boots the Express backend in-process and loads the pre-built frontend from `frontend/dist`.

---

## Build a Windows Installer

```bat
npm run build
```

Output: `dist-electron/Network Detector Setup <version>.exe` (NSIS installer)

This command:
1. Builds the React frontend with Vite (`frontend/dist`)
2. Packages everything with `electron-builder` into a standalone `.exe`

---

## API Endpoints

### Network Diagnostics
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/network/basic` | Wi-Fi stats + IP config |
| GET | `/api/network/ping-gateway` | Ping to default gateway |
| GET | `/api/network/ping-external` | Ping to 8.8.8.8 |
| GET | `/api/network/public-ip` | External IP + ISP/ASN + geolocation |
| GET | `/api/network/dns-time` | DNS resolution latency |
| GET | `/api/network/throughput` | Live bandwidth (Rx/Tx Mbps) |
| GET | `/api/network/arp-count` | Number of devices in ARP table |

### ISP Truth
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/network/ping-global` | Multi-region latency matrix (local exchange + 3 regions) |
| POST | `/api/network/speedtest-cdn` | 10MB download from Cloudflare CDN |
| GET | `/api/network/dns-hijacking` | Compare system DNS vs DoH |

### Advanced Diagnostics (v1.1.0)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/network/active-interface` | Detect active adapter (Wi-Fi/Ethernet/VPN) via default route |
| GET | `/api/network/gateway-health` | Detailed gateway ping (avg/min/max/median/p95/jitter/loss) |
| GET | `/api/network/wifi-analysis` | Wi-Fi band, channel, RSSI, standard, link rates |
| GET | `/api/network/wifi-scan` | Nearby networks + channel interference + recommendation |
| GET | `/api/network/dns-benchmark` | Benchmark public DNS resolvers, recommend fastest |
| GET | `/api/network/device-health` | CPU, RAM, and power/battery state |
| GET | `/api/network/health-breakdown` | Per-category scores + intelligent recommendations |

### Speed · Route · Stability · WSL (v1.2.0)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/network/speed-diagnostics` | Connection phase breakdown (DNS/TCP/TLS/TTFB) + bufferbloat grade |
| GET | `/api/network/route-analysis?target=&geo=` | Hop-by-hop traceroute with per-hop geolocation + bottleneck |
| GET | `/api/network/ping-once?target=` | Single ping (used by the 60-second stability test) |
| GET | `/api/network/wsl-status?force=` | Detect WSL, active distro, and available Linux tools |
| GET | `/api/network/wsl-mtr?target=` | Run `mtr` inside WSL (per-hop packet loss) |
| GET | `/api/network/wsl-dig?domain=` | Run `dig` inside WSL (DNSSEC validation) |

### Security
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/network/security-scan` | Windows Firewall + VPN + proxy + SSL/TLS check |
| POST | `/api/network/port-scan` | List all open listening ports |
| GET | `/api/network/connected-devices` | Enumerate devices with MAC vendor lookup |
| GET | `/api/network/arp-spoof-check` | Detect duplicate MAC addresses |
| GET | `/api/network/dns-leak` | Check if DNS uses privacy resolvers |
| GET | `/api/network/wifi-audit` | Score WiFi encryption strength |
| GET | `/api/network/mitm-check` | Combined MITM threat assessment |

### Toolbar
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/toolbar/status` | Get toolbar visibility/pin/opacity state |
| POST | `/api/toolbar/toggle` | Show/hide toolbar window |
| POST | `/api/toolbar/pin-toggle` | Toggle always-on-top |
| POST | `/api/toolbar/opacity` | Set transparency (20-100%) |

---

## Complete Version History

| Version | Date | Changes |
|---|---|---|
| **1.2.0** | 2026-06-28 | 🚀 **Speed phases, route tracing, trends & WSL**: new **Speed & Stability** tab (DNS/TCP/TLS/TTFB phase breakdown via `curl.exe`, bufferbloat grade A–F, 60-second stability test with live drop/reconnect graph); new **Route Trace** tab (hop-by-hop traceroute with per-hop geolocation + bottleneck detection); new **Trends** tab (local 30s-interval history with inline SVG sparklines); new **WSL Tools** tab (auto-detected — mtr per-hop loss + dig DNSSEC, with copy-paste install command); guide updated for all new tabs |
| **1.1.0** | 2026-06-28 | 🧭 **Major diagnostics upgrade**: Accurate active-interface detection (Wi-Fi/Ethernet/VPN via default route); new **Wi-Fi Analyzer** tab (RSSI dBm, channel interference scan, link rates); new **Health & Tips** tab (8 category scores + intelligent recommendations); detailed gateway health (avg/min/max/median/p95/jitter/loss); DNS provider benchmark; device health (CPU/RAM/power); JSON + Markdown report export |
| 1.0.10 | 2026-06-20 | 🐛 **Bug Fix**: DNS hijacking detector fixed to eliminate false positives — now only flags if IPs are from different organizations (not just different CDN servers); improved analysis messages to distinguish CDN load-balancing from actual hijacking |
| 1.0.9 | 2026-06-19 | Modern collapsible sidebar navigation; Connected Devices tab with MAC vendor lookup (~100 manufacturers); How to Use guide with comprehensive metric explanations; Advanced security suite (MITM, ARP spoofing, WiFi audit, DNS leak); Floating toolbar styling (sharp top corners) |
| 1.0.8 | 2026-06-18 | Added all advanced security endpoints; Fixed blank window bug (frontend referenced non-existent endpoints) |
| 1.0.7 | 2026-06-17 | ISP Truth tab: Multi-region latency matrix, CDN speed test, DNS hijacking detector; Split health score (30% local + 70% ISP); ISP Evidence Report copy button |
| 1.0.6 | 2026-06-16 | Toolbar opacity slider (20–100%) controlled from dashboard; jitter metric added to all pings (6-sample MAD); Connection Health Score card (stability 0–100 from loss+jitter+signal+latency); ISP/ASN + location + timezone in Public Details (ipinfo.io); LAN device count from ARP table; "How it Works" updated for all new features |
| 1.0.5 | 2026-06-15 | Fixed tray right-click crash: `isDestroyed()` guard on all BrowserWindow calls |
| 1.0.4 | 2026-06-14 | Toolbar toggle and always-on-top (TOP) controls added to dashboard header; toolbar width tightened; TOP button in toolbar itself; ipc-bridge event bus |
| 1.0.3 | 2026-06-13 | System tray: app stays alive in background; floating always-on-top toolbar; tray right-click menu |
| 1.0.2 | 2026-06-12 | Fixed card layout (2-col explicit grid, 1-col below 900px); fixed metric-row text wrapping; fixed status badge gap from title; full responsive breakpoints |
| 1.0.1 | 2026-06-11 | Added Latency & Ping to "How it Works"; fixed CSS bugs; security: ping target validated; DNS uses async/await; removed unused boilerplate |
| 1.0.0 | 2026-06-10 | Initial release |

---

## 💡 Usage Tips

### For ISP Troubleshooting
1. Go to **ISP Truth** tab
2. Run **CDN Speed Test** to check actual download speeds
3. Check **Multi-Region Latency** — high latency to local exchange indicates ISP routing issues
4. Click **Copy Evidence Report** to export all metrics for support tickets

### For Security Audits
1. Go to **Security** tab
2. Run **MITM Check** — should show "Low Risk" on clean networks
3. Check **WiFi Security Audit** — WPA2/WPA3 with AES is secure, WEP/Open is dangerous
4. Review **Port Scan** — only expected services should be listening
5. **Devices** tab shows all network devices — unknown MACs may indicate intruders

### For Performance Monitoring
1. **Overview** tab shows real-time connection health (0-100 score)
2. Watch **Live Bandwidth** for unexpected spikes (background downloads/uploads)
3. **Gateway Latency** should be <5ms — higher indicates WiFi interference
4. **External Latency** shows ISP quality — <50ms is excellent, >100ms is poor

### Understanding Security Warnings

| Warning | Meaning | Action |
|---|---|---|
| **DNS Hijacking Detected** | System DNS returns different IPs from trusted DoH | Check if using ISP DNS vs privacy resolvers; upgrade to v1.0.10 if seeing false positives |
| **ARP Spoofing Detected** | Multiple IPs bound to same MAC | Possible MITM attack — investigate duplicate MAC addresses |
| **MITM High Risk** | Multiple security checks failed | Avoid sensitive activities, check WiFi security, scan for rogue devices |
| **DNS Leak** | DNS bypassing VPN/privacy resolvers | VPN may not be protecting DNS queries |
| **WiFi Security: WEP/Open** | Weak or no encryption | Switch to WPA2/WPA3 immediately |

---

## 📄 License

This project is for personal/educational use. No warranty provided. Network scanning features require Windows 10/11 and may need Administrator privileges.

**External Services:**
- ipinfo.io: Geolocation (free tier)
- Cloudflare: DoH DNS queries and CDN speed tests
- Google/Cloudflare DNS: Latency benchmarks

---

**Built with ❤️ for network transparency**
