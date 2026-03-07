# Network Monitor

> [🇨🇳 中文](README.md) | 🇬🇧 English

A full-featured BitTorrent Tracker monitoring tool with TCP/UDP ping, multi-IP monitoring, IPv4+IPv6 dual-stack, uptime ranking, SOCKS5 proxy support, and multi-account permission management.

---

## ✨ Features

### Core Monitoring
- ✅ TCPing detection (HTTP/HTTPS Trackers)
- ✅ UDPing detection (UDP Tracker BEP 15 protocol handshake)
- ✅ Multi-IP monitoring per domain — expand rows to view per-IP details
- ✅ Full IPv4 + IPv6 dual-stack resolution and monitoring
- ✅ Direct `IP:port` format support
- ✅ 120-thread concurrent checks — handles large tracker lists quickly
- ✅ Auto-retry on failure (polling mode: 5s → 15s → 30s → 60s increasing intervals)

### Uptime Statistics
- ✅ 24-hour / 7-day / 30-day uptime rankings
- ✅ Separate stat period config for monitor list and ranking
- ✅ Persistent uptime history cache (survives restarts)
- ✅ Health color coding:
  - 🟢 Green: uptime >80%, or all IPs online
  - 🟡 Yellow: uptime 50–80%, or mixed (some online + some offline — takes priority)
  - 🔴 Red: uptime <50%, or all IPs offline
- ✅ Latency bar colors: green ≤500ms, yellow 500–1500ms, red >1500ms or timeout

### Dashboard
- ✅ 6-card live stats: Total IPs / Online IPs / Offline IPs / Avg Latency (with P95) / IPv4÷IPv6 / Active Alerts
- ✅ Uptime Ranking TOP10 (toggle Worst / Best)
- ✅ Alert Center: auto-triggers after ≥5 consecutive failures, shows IP location, ISP, current status
- ✅ Error log aggregation: deduplication with first occurrence time, count, and IP geolocation
- ✅ Quick Search (global): displays all monitored entries by default, paginated (10/page); click a domain to filter and show all its IPs
- ✅ Quick Search supports: domain / IP / ISP / country / status / protocol (http/https/udp)

### Proxy Support
- ✅ HTTP CONNECT proxy for HTTP/HTTPS Trackers
- ✅ SOCKS5 proxy for UDP Trackers (RFC 1928 manual implementation, no PySocks required)
- ✅ Persistent SOCKS5 long-connection: TCP control connection kept alive globally, all threads share one fixed UDP source port
- ✅ Fixed source port solves SOCKS5 relay source port filter packet drop
- ✅ `transaction_id` multiplexing — 120 concurrent threads without interference
- ✅ Proxy health state machine: 2 consecutive failures → 30s cooldown, probes skipped during cooldown (no stat pollution)
- ✅ Last-known state preserved when proxy is unavailable — **uptime data stays clean**
- ✅ Smart dual-stack proxy address: IPv6 preferred, auto-fallback to IPv4
- ✅ `localhost` dual-stack ambiguity handling (auto-switches to `127.0.0.1` if proxy only listens on IPv4)
- ✅ SO_KEEPALIVE to prevent silent NAT/firewall disconnection
- ✅ Auto-reconnect if TCP control connection drops

### DNS Resolution
- ✅ Three DNS modes: System DNS / dnspython / Custom DNS server
- ✅ Local hosts file support (via getaddrinfo native behavior)
- ✅ Re-resolves every check cycle — automatically detects IP changes
- ✅ Falls back to cached IPs on DNS failure — monitoring never stops

### UI & Interaction
- ✅ Monitor list columns: port, protocol (TCP/UDP), IP count, added time, last check time
- ✅ Expanded rows show per-IP status, latency, country, ISP
- ✅ TCP IPs auto-labeled HTTP / HTTPS (port 443 = HTTPS, others = HTTP)
- ✅ IP column header: tri-state click — expand ≤5 IPs / expand all / collapse all
- ✅ Protocol filter column (TCP / UDP / HTTP / HTTPS)
- ✅ Latency visualization bar (color changes dynamically with latency)
- ✅ Per-IP retry button for offline IPs (immediate, bypasses polling wait)
- ✅ Bulk add Trackers (multi-line paste, lines starting with `|` auto-skipped)
- ✅ Uptime ranking with minimum uptime filter
- ✅ `ESC` key clears any search box instantly
- ✅ Monitor list search: domain, IP, country, ISP, status, timestamp (`yyyy/mm/dd`)
- ✅ Log search: type `error` / `warn` / `info` to filter by log level directly
- ✅ URL Hash routing (`#/trackers`, `#/ranking`, etc.)
- ✅ Multi-language: 中文 / English / Русский / Français / 日本語 / 한국어
- ✅ Language preference saved via Cookie
- ✅ Toast notifications for operation feedback

### Account & Permissions
- ✅ Three-tier role system: admin / operator / viewer
  - `admin`: full access including config, user management, log clearing; no retry rate limit
  - `operator`: add/delete Trackers, retry (500ms cooldown)
  - `viewer`: read-only, retry (1s cooldown)
- ✅ Config auto-refreshes on login — no manual F5 needed
- ✅ Signed Session Cookie (`session_secret.key`), persists across restarts
- ✅ Error log export: one-click download of `error.log`; admin-only log clear
- ✅ Rate limiting to prevent abuse

### System & Operations
- ✅ Waitress production server (no Flask dev-mode warnings)
- ✅ All config persisted to `config.json`, loaded on restart
- ✅ Log levels: `none` / `info` / `error` / `debug`
- ✅ Config change logs only show actually-changed fields (with human-readable labels)
- ✅ Optional disk logging to `error.log`, filterable by level
- ✅ IP geolocation via ip-api.com (with local cache)

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install Flask flask-cors dnspython requests waitress
```

### 2. File structure

```
Network Monitor/
├── app.py
├── index.html
├── config.json          # auto-generated, config persistence
├── data.json            # auto-generated, monitoring data
├── error.log            # auto-generated (when disk logging is enabled)
├── session_secret.key   # auto-generated, ⚠️ DO NOT commit to public repos
└── requirements.txt
```

### 3. Run

```bash
python app.py
```

Open: http://localhost:443

### 4. Create a start.bat shortcut (Windows)

```batch
@echo off
cd /d "%~dp0"
python app.py
pause
```

---

## ⚠️ Security Notes

### `session_secret.key`

This file is the signing key for Flask Session Cookies. **Never commit it to a public repository.** If leaked, anyone can forge a Cookie and gain admin access without a password.

**Add to `.gitignore`:**

```gitignore
session_secret.key
config.json
data.json
error.log
```

**How to reset the key:**

```bash
# Option 1: delete the file — a new one is auto-generated on next start
del session_secret.key        # Windows
rm session_secret.key         # Linux/macOS

# Option 2: generate a new key manually
python -c "import os; open('session_secret.key','wb').write(os.urandom(32))"
```

After resetting, all active sessions are immediately invalidated — users must log in again.

### Default Credentials

**Change these immediately** after first run (Config → User Management):

| Account | Default Password | Role |
|---------|-----------------|------|
| admin | admin | Full access |
| operator | operator | Add/delete Trackers |
| viewer | viewer | Read-only |

---

## ⚙️ Configuration Reference

All settings are changed through the web config page and **automatically saved** to `config.json`.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `port` | `443` | Web server port (443 requires admin/root) |
| `check_interval` | `30` | Monitoring interval in seconds |
| `timeout` | `5` | TCP/UDP connection timeout (seconds) |
| `retry_mode` | `polling` | Retry mode: `polling` (5→15→30→60s) or fixed seconds |
| `retry_interval` | `5` | Fixed retry interval (when `retry_mode` ≠ `polling`) |
| `dns_mode` | `system` | DNS mode: `system` / `dnspython` / `custom` |
| `dns_custom` | empty | Custom DNS server(s), comma-separated |
| `tracker_stat_period` | `24h` | Uptime window for monitor list: `24h` / `7d` / `30d` |
| `rank_stat_period` | `24h` | Uptime window for rankings: `24h` / `7d` / `30d` |
| `cache_history` | `true` | Persist uptime history across restarts |
| `log_level` | `info` | Log verbosity: `none` / `info` / `error` / `debug` |
| `log_to_disk` | `false` | Write logs to `error.log` |
| `max_log_entries` | `2000` | Max log entries before auto-trimming |
| `page_refresh_ms` | `30000` | Frontend data refresh interval (ms), 0 = disabled |
| `http_proxy` | empty | HTTP/TCP proxy address |
| `udp_proxy` | empty | UDP proxy address (SOCKS5 only) |
| `proxy_enabled` | `false` | Enable proxy |

---

## 📡 Adding Trackers

Supported formats (paste multiple lines at once):

```
udp://open.stealth.si:80/announce
udp://tracker.opentrackr.org:1337/announce
http://tracker.mywaifu.best:6969/announce
https://shahidrazi.online:443/announce
1.2.3.4:6969
| Lines starting with | are auto-skipped (use as comments)
```

- One tracker per line, bulk paste supported
- Lines starting with `|` are skipped
- Plain `IP:port` format supported
- Empty lines ignored

---

## 🔒 Proxy Configuration

### UDP Proxy (SOCKS5)

UDP Tracker probing is forwarded via SOCKS5 UDP Associate, fully implementing RFC 1928 with no third-party dependencies.

```json
{
  "udp_proxy": "socks5://127.0.0.1:1080",
  "proxy_enabled": true
}
```

**How it works:**

The program establishes a persistent TCP control connection to the SOCKS5 proxy and negotiates a UDP relay address via UDP Associate. All 120 monitoring threads share one UDP socket with a fixed source port, using `transaction_id` to demultiplex responses.

**This design is necessary:** SOCKS5 relays only forward UDP packets from the negotiated source port. Using a random new port per probe causes the relay to drop all packets.

**Notes:**
- Proxy must support UDP Associate (CMD=0x03)
- Supports `localhost`, IPv4, IPv6 (`[::1]:port` format)
- `localhost` tries IPv6 (`::1`) first, auto-falls back to `127.0.0.1` if needed
- When proxy is unavailable, UDP checks are skipped and last-known status is preserved

### HTTP Proxy

```json
{
  "http_proxy": "http://127.0.0.1:7890",
  "proxy_enabled": true
}
```

---

## ❌ Offline Reason Reference

| Display | Meaning |
|---------|---------|
| `Timeout (>Xs)` | No response within the timeout window |
| `Port unreachable` | Target actively refused (ICMP Port Unreachable / TCP RST) |
| `Proxy connection failed` | SOCKS5 proxy itself failed to connect or handshake |
| `Proxy unavailable (retry in Xs)` | Proxy in cooldown; probe skipped, last state retained |
| `Invalid response` | Received reply but format doesn't match protocol |

---

## ❓ FAQ

**1. Can't start the server?**
```bash
pip install Flask flask-cors dnspython requests waitress
```

**2. `index.html` not found?**
Make sure `index.html` is in the same directory as `app.py`, or inside a `templates/` subdirectory.

**3. Port already in use?**
Edit `config.json` and change the `port` field, or change `DEFAULT_CONFIG['port']` in `app.py`.

**4. Rankings page is empty?**
Rankings require accumulated history. Newly added trackers need a few check cycles before appearing. Enable "Cache Uptime Stats" to retain history across restarts.

**5. Only some IPs resolved?**
Ensure your network supports IPv6, or switch DNS mode to `dnspython` or `custom`. The app queries both A (IPv4) and AAAA (IPv6) records simultaneously.

**6. UDP proxy shows all timeouts?**
Confirm your proxy software has UDP forwarding enabled. Many proxies only support TCP by default — UDP Associate must be explicitly enabled.

**7. Using `localhost` proxy but connection fails?**
The app tries IPv6 (`::1`) first. If your proxy only listens on IPv4, it auto-falls back to `127.0.0.1`. If still failing, use `socks5://127.0.0.1:port` directly.

**8. Large number of offline IPs when proxy is down?**
After 2 consecutive proxy failures, a 30s cooldown kicks in. All UDP probes are skipped during cooldown with last-known states preserved — no false offline reports, uptime data stays accurate.

**9. Config page doesn't update after login?**
Fixed in the latest version. Config is automatically re-fetched on login — no F5 needed.

**10. How to manage multi-user access?**
Go to Config → User Management to add accounts and assign roles: admin (full) / operator (add/delete trackers) / viewer (read-only).

---

## 🛠️ Tech Stack

| Component | Details |
|-----------|---------|
| Backend | Python 3.10+ / Flask + waitress |
| Frontend | Vue 3 + Bootstrap 5 + vue-i18n |
| DNS | dnspython (IPv4+IPv6 dual-stack) |
| IP Geolocation | ip-api.com free API (local cache) |
| Proxy | Manual SOCKS5 UDP Associate (RFC 1928), fixed source port + tid multiplexing |
| Persistence | JSON files (`config.json` + `data.json`) |
| Auth | Flask Session (signed Cookie, `session_secret.key` persisted locally) |

---

## 📄 License

MIT License

---

##### Project founder: rer
##### Contributors: minimaxi, Claude, Doubao
