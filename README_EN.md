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
- ✅ Configurable concurrent check threads (default 120, recommended 30–200)
- ✅ Auto-retry on failure (polling mode: 5s → 15s → 30s → 60s increasing intervals)
- ✅ Staggered batched dispatch: checks are submitted in batches with configurable delays to prevent burst load on local network or proxy (separate batch size and delay settings for proxy vs. direct modes)

### Uptime Statistics
- ✅ 24-hour / 7-day / 30-day uptime calculated against real time windows (not fixed round counts)
- ✅ Separate stat period config for monitor list and ranking
- ✅ History persisted to `history.json` (timestamp format, survives restarts, auto-GC clears records older than 30 days)
- ✅ Atomic write protection for `history.json`: data is written to a temp file first, then swapped in — a crash or interruption mid-save can never corrupt the existing file
- ✅ Invalid IP records (e.g. `[::]`, `127.0.0.1` from DNS hijacking) are automatically filtered on startup — no history pollution
- ✅ Domain-level uptime = total successes ÷ total checks across **all historical IPs** under that domain (including IPs removed by DNS rotation) — full historical accuracy regardless of IP changes
- ✅ Per-IP uptime tracked independently for each IP
- ✅ Health color coding:
  - 🟢 Green: uptime >80%, or all IPs online
  - 🟡 Yellow: uptime 50–80%, or mixed online/offline (takes priority display)
  - 🔴 Red: uptime <50%, or all IPs offline
- ✅ Latency bar colors: green ≤500ms, yellow 500–1500ms, red >1500ms or timeout

### Dashboard
- ✅ 6-card live stats, fully redesigned with a symmetric split-column layout:
  - **Card 1 Online/Total**: online count + online rate %, per-IPv4/IPv6 breakdown at the bottom
  - **Card 2 Offline/Unknown**: offline + unknown counts, per-IPv4/IPv6 breakdown; paused count shown in right column
  - **Card 3 Avg Latency**: five rows — Total / IPv4 / IPv6 / TCP / UDP — online IPs only (offline/timeout/paused excluded)
  - **Card 4 Net Health**: ✔/✗ centered; **hover to reveal probe detail tooltip** (8.8.8.8 / 1.1.1.1 / 114.114.114.114 each color-coded reachable/timeout)
  - **Card 5 TCP http/https**: Online / Total / Uptime% / Offline / Unknown
  - **Card 6 UDP**: Online / Total / Uptime% / Offline / Unknown
- ✅ Uptime Ranking TOP10 (toggle Worst / Best), fixed height precisely fitting 10 rows
- ✅ Alert Center: auto-triggers after ≥5 consecutive failures, shows IP location, ISP, current status
- ✅ Error log aggregation: deduplication with first occurrence time, count, and IP geolocation
- ✅ Quick Search (global): displays all monitored entries by default, paginated (10/page); click a domain to filter and show all its IPs
- ✅ Quick Search supports: domain / IP / ISP / country / status / protocol (http/https/udp)
- ✅ Quick Search status column **3-state sort** (cycles, no reset button):
  - `▼` Offline first (default): Offline → Online → Paused → Unknown
  - `?` Unknown first: Unknown → Paused → Offline → Online
  - `▲` Online first: Online → Paused → Unknown → Offline

### Proxy Support
- ✅ HTTP CONNECT proxy for HTTP/HTTPS Trackers
- ✅ SOCKS5 proxy for UDP Trackers (RFC 1928 manual implementation, no PySocks required)
- ✅ Persistent SOCKS5 connection: TCP control kept alive globally, all threads share one fixed UDP source port
- ✅ Fixed source port solves SOCKS5 relay source port filter packet drop
- ✅ `transaction_id` multiplexing — concurrent threads without interference
- ✅ Proxy health state machine: 2 consecutive failures → 30s cooldown, probes skipped during cooldown
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
- ✅ **Force TCP port 53 mode**: enable `dns_use_tcp` in dnspython/custom mode to send all DNS queries over TCP instead of UDP — fixes high packet loss on UDP DNS common in mainland China
- ✅ Per-server TCP override in custom DNS: prefix individual servers with `tcp://8.8.8.8` to force TCP, mixable with plain IPs
- ✅ DNS failure log deduplication: console and Web log output only once per failing domain; clears automatically on recovery — no log flooding

### Monitor List
- ✅ Card-style layout showing port, protocol (TCP/UDP), IP count, and added time
- ✅ Expanded rows show per-IP status, uptime, latency, country, ISP, and last check time
- ✅ Monospace IP display — IPv4 in green, IPv6 in indigo, with v4/v6 badge labels
- ✅ TCP IPs auto-labeled HTTP / HTTPS (port 443 = HTTPS)
- ✅ IP column header: tri-state click — expand all / collapse all / restore default (≤5 IPs auto-expanded)
- ✅ Removed (historical) IPs shown in translucent gray — can be hidden in config
- ✅ Toolbar filters: ALL / IPv4 / IPv6 · ALL / TCP / UDP / HTTP / HTTPS · status · keyword search
- ✅ Sorting: uptime / domain / latency / added time / last check / port, with asc/desc/reset tri-state
- ✅ Status/uptime column header shows current stat period (24h / 7d / 30d)
- ✅ Latency visualization bar (color changes dynamically with latency)
- ✅ Per-IP retry button for offline IPs (immediate, bypasses polling wait)
- ✅ Bulk add Trackers (multi-line paste, lines starting with `|` auto-skipped)
- ✅ Pause/resume monitoring (per IP, per domain, or all)

### Uptime Ranking
- ✅ Domain entries show TCP/UDP protocol tag + v4/v6 version badges
- ✅ Displays active IP count and online count
- ✅ Paused domains are automatically hidden from the ranking
- ✅ Minimum uptime filter (50% / 80% / 90% / 100%)
- ✅ Protocol filter: ALL / TCP / UDP
- ✅ IP version filter: ALL / IPv4 / IPv6
- ✅ One-click export (**what you see is what you export** — paused domains excluded)
- ✅ URL route: `/ranking`

### Tracker Export API
- ✅ Public API — no login required, anyone can GET a plain-text tracker list (one URL per line)
- ✅ Legacy path compatibility: `/trackers` and `/tracker.txt` forward directly to `/api/tracker` — no client-side redirect handling needed
- ✅ Paused domains are excluded from all export results
- ✅ Blank line between each domain entry — compatible with BT clients that require blank-line separation
- ✅ Parameter design:

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `day` | `24h` `7d` `30d` | `24h` | Uptime stats period to rank by |
| `uptime` | `0` `50` `80` `90` `100` | `0` | Minimum uptime % (0 = no filter) |
| `net` | `all` `tcp` `udp` | `all` | Protocol filter |
| `ip` | `all` `ipv4` `ipv6` | `all` | IP version filter |
| `url` | any string | `/announce` | Suffix appended to each tracker URL |

```bash
# All trackers, no filter
curl http://host/api/tracker

# 7-day uptime ≥ 90%, all protocols, all IPs
curl "http://host/api/tracker?day=7d&uptime=90"

# 30-day uptime ≥ 90%, TCP only, IPv4 only
curl "http://host/api/tracker?day=30d&uptime=90&net=tcp&ip=ipv4"

# Legacy path (forwards directly, no -L needed)
curl http://host/tracker.txt
```

### Single Host Query API (New)

A lightweight public query endpoint — no login required — for checking the current status, uptime, latency, and more for a single domain or IP.

- ✅ Query by domain name or IP address
- ✅ Response formats: plain text (default) or JSON
- ✅ Configurable return fields: `status` / `uptime` / `delay` / `location` / `checked`
- ✅ Rate limit: 66 requests per minute per IP

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `host` | domain or IP | required | Query target |
| `list` | `status,uptime,delay,location,checked` | `status,uptime,delay,checked` | Fields to return (comma-separated) |
| `type` | `txt` `json` | `txt` when only `host` given; `json` when `list` or `type` given | Response format |

```bash
# Simplest query (plain text)
curl "http://host/api/query?host=bt.rer.lol"
# → bt.rer.lol  Online  100.0%  1ms  2026-03-11T21:18:41.812562

# Query an IPv6 address
curl "http://host/api/query?host=2a06:1280:f115::2"
# → 2a06:1280:f115::2  Online  100.0%  310ms  2026-03-11T21:20:17.505961

# Specify fields + text format
curl "http://host/api/query?host=bt.rer.lol&list=status,uptime,delay,location,checked&type=txt"
# → bt.rer.lol  Online  100.0%  0ms  China · China Unicom Network  2026-03-11T20:46:18.974702

# JSON format
curl "http://host/api/query?host=bt.rer.lol&type=json"
# → {"host":"bt.rer.lol","status":"Online","uptime":"100.0%","delay":"1ms","checked":"..."}
```

### Network Health Detection
- ✅ Multi-target probes (8.8.8.8 / 1.1.1.1 / 114.114.114.114 :53) — **all targets probed simultaneously** (no early exit), each result recorded independently
- ✅ Any reachable = network OK; all unreachable = alert
- ✅ Dual safeguard: probe status + per-round failure rate (≥90% failures = local network issue)
- ✅ When network is unhealthy, round history is excluded from stats to prevent mass false data
- ✅ Dashboard card hover reveals a live tooltip showing the last probe result per IP (green = reachable, red = timeout)

### IP Geolocation
- ✅ Automatic country and ISP lookup via ip-api.com (locally cached)
- ✅ Background repair thread on startup: re-queries any Unknown IPs (10s delay, 0.5s/IP rate limit)
- ✅ Per-check auto-retry for still-Unknown IPs, runs outside the check lock (non-blocking)

### UI & Interaction
- ✅ Light/dark theme toggle — IPv4/IPv6 colors readable in both themes
- ✅ Page zoom (50%–100%) adjustable in the navbar, saved to Cookie; default also configurable (Cookie takes priority)
- ✅ Multi-language: 中文 / English / Русский / Français / 日本語 / 한국어 (including full API panel translation)
- ✅ URL routing (`/home`, `/trackers`, `/ranking`, `/logs`, `/config`)
- ✅ `ESC` key clears any search box instantly
- ✅ Log search: type `error` / `warn` / `info` to filter by log level directly
- ✅ Toast notifications for operation feedback
- ✅ gzip compression (HTML ~210KB → ~48KB) + ETag negotiation cache (304 when unchanged)

### Account & Permissions
- ✅ Three-tier role system: admin / operator / viewer
  - `admin`: full access including config, user management, log clearing; no retry rate limit
  - `operator`: add/delete Trackers, retry (500ms cooldown)
  - `viewer`: read-only, retry (1s cooldown)
- ✅ Password storage upgraded to PBKDF2-HMAC-SHA256 with random salt (200,000 rounds); backward-compatible with legacy SHA256 format (auto-migrated on next login)
- ✅ Config auto-refreshes on login — no manual F5 needed
- ✅ Login failure rate limiting (10 failures → 15-minute IP lockout) to prevent brute-force attacks
- ✅ Signed Session Cookie (`session_secret.key`), persists across restarts
- ✅ Unauthenticated users only receive the minimal public config fields — no operational details exposed
- ✅ Admin audit log: pause/resume operations record operator username + masked IP (Web shows `1.*.*.4`, console retains full IP)
- ✅ Security headers: `X-Frame-Options` / `X-Content-Type-Options` / `Referrer-Policy` / `Content-Security-Policy`
- ✅ HSTS (`Strict-Transport-Security`): auto-enabled only when `HTTPS_ENABLED=1` env var is set — LAN HTTP deployments unaffected
- ✅ `SESSION_COOKIE_SECURE` auto-detection via `HTTPS_ENABLED=1` env var — no code changes needed
- ✅ CSRF double-verification (Header `X-CSRFToken` + Session comparison)

### System & Operations
- ✅ Waitress production server (no Flask dev-mode warnings)
- ✅ Local static assets (`static/` directory) — fully offline deployment, no CDN required
- ✅ All config persisted to `config.json`, loaded on restart
- ✅ Log levels: `none` / `info` / `error` / `debug`
- ✅ Per-level log limits: Info / Success / Error each have independent caps — trimming one level does not affect others
- ✅ Config change logs only show actually-changed fields (with human-readable labels and units)
- ✅ Optional disk logging: `error.log` (error entries) + `access.log` (nginx-format access log)
- ✅ nginx / Cloudflare reverse proxy friendly: `trust_cf_ip` config controls whether `CF-Connecting-IP` / `X-Forwarded-For` is trusted for real client IP
- ✅ Rate-limit memory auto-cleanup: background thread periodically purges expired entries from `_rate_limit_store` / `_login_fail` / `_retry_throttle` dictionaries to prevent gradual memory growth; interval configurable via `cleanup_interval`

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
├── static/               # Local static assets (JS/CSS/fonts)
│   ├── vue.global.js
│   ├── vue-i18n.global.js
│   ├── axios.min.js
│   ├── chart.umd.min.js
│   ├── bootstrap.min.css
│   ├── bootstrap-icons.css
│   ├── bootstrap.bundle.min.js
│   └── fonts/
│       ├── bootstrap-icons.woff2
│       └── inter-*.woff2
├── config.json           # auto-generated, config persistence
├── data.json             # auto-generated, current state + summaries
├── history.json          # auto-generated, timestamp-based uptime history (primary data source)
│                         #   ⚠️ Do not hand-edit the compact format in Notepad — easy to break JSON
│                         #   Use fix_history.py to reformat it into a readable format first
├── error.log             # auto-generated (when disk logging is enabled)
├── access.log            # auto-generated (when disk logging is enabled, nginx format)
└── session_secret.key    # auto-generated, ⚠️ DO NOT commit to public repos
```

### 3. Run

```bash
python app.py
```

Access at: `http://localhost:443`

### 4. Windows quick-launch batch file

```batch
@echo off
cd /d "%~dp0"
python app.py
pause
```

### 5. HTTPS Support

The project supports enabling HTTPS via environment variables:

```bash
# Windows
set HTTPS_ENABLED=1 && python app.py

# Linux/macOS
export HTTPS_ENABLED=1 && python app.py
```

- When HTTPS is enabled for the first time, the system will automatically generate self-signed certificates (`cert.pem` and `key.pem`)
- Browsers will show a security warning, but data transmission is still encrypted
- You can customize the certificate file paths via environment variables:
  - `HTTPS_CERT`: Certificate file path (default: `cert.pem`)
  - `HTTPS_KEY`: Private key file path (default: `key.pem`)

---

## 🌐 Network Listen Settings

Changes to `listen_port`, `listen_ipv4`, or `listen_ipv6` require an **app restart** to take effect.

### IPv4 / IPv6 Listen Modes

| Mode | IPv4 Address | IPv6 Address | Use Case |
|------|-------------|-------------|----------|
| `global` | `0.0.0.0` | `[::]` | All interfaces (default — accessible from LAN and internet) |
| `local` | `127.0.0.1` | `[::1]` | Localhost only (use with a reverse proxy) |
| `custom` | set `listen_ipv4_custom` | set `listen_ipv6_custom` | Bind to a specific network interface IP |
| `disabled` | not bound | not bound | Disable one protocol stack for pure IPv4 or IPv6 deployments |

**Typical configuration examples:**

```json
// Standard public deployment — dual-stack, all interfaces (default)
{ "listen_ipv4": "global", "listen_ipv6": "global" }

// Localhost only + nginx reverse proxy
{ "listen_ipv4": "local", "listen_ipv6": "disabled" }

// IPv6-only public
{ "listen_ipv4": "disabled", "listen_ipv6": "global" }

// Specific LAN interface
{ "listen_ipv4": "custom", "listen_ipv4_custom": "192.168.1.10",
  "listen_ipv6": "disabled" }
```

> ⚠️ In `global` mode the service is exposed on all interfaces. Pair with a firewall rule or set `trust_cf_ip` appropriately.

---

## ⚠️ Security Notes

### `session_secret.key`

This file signs Flask Session Cookies. **Never commit it to a public repository.** If leaked, anyone can forge cookies and gain admin access.

**Add to `.gitignore`:**

```gitignore
session_secret.key
config.json
data.json
history.json
error.log
access.log
```

**How to reset the key:**

```bash
# Option 1: delete the file, a new one is generated on next startup
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
| `listen_port` | `443` | Web server port (443 requires admin/root) |
| `check_interval` | `30` | Monitoring interval in seconds |
| `timeout` | `5` | TCP/UDP connection timeout (seconds) |
| `retry_mode` | `polling` | Retry mode: `polling` (5→15→30→60s) or fixed seconds |
| `retry_interval` | `5` | Fixed retry interval (when `retry_mode` ≠ `polling`) |
| `monitor_workers` | `120` | Concurrent check threads (recommended 30–200) |
| `stagger_batch_proxy` | `5` | Batch size per dispatch in proxy mode (burst control) |
| `stagger_delay_proxy` | `150` | Delay between batches in proxy mode (ms) |
| `stagger_batch_direct` | `5` | Batch size per dispatch in direct mode |
| `stagger_delay_direct` | `100` | Delay between batches in direct mode (ms) |
| `dns_mode` | `system` | DNS mode: `system` / `dnspython` / `custom` |
| `dns_custom` | empty | Custom DNS server(s), comma-separated |
| `dns_use_tcp` | `false` | Force DNS queries over TCP port 53 (applies to `dnspython` and `custom` modes; no effect on system DNS mode) |
| `listen_ipv4` | `global` | IPv4 listen mode: `global` (0.0.0.0) / `local` (127.0.0.1) / `custom` (specific address) / `disabled` |
| `listen_ipv4_custom` | empty | Custom IPv4 address when `listen_ipv4=custom` |
| `listen_ipv6` | `global` | IPv6 listen mode: `global` ([::]) / `local` ([::1]) / `custom` (specific address) / `disabled` |
| `listen_ipv6_custom` | empty | Custom IPv6 address when `listen_ipv6=custom` |
| `refresh_geo_on_restart` | `true` | Auto-repair unknown IP geolocations on startup (background thread, starts after 10s, rate-limited to 0.5s/IP) |
| `tracker_stat_period` | `24h` | Uptime window for monitor list: `24h` / `7d` / `30d` |
| `dashboard_stat_period` | `24h` | Default uptime period for dashboard ranking (can be switched manually) |
| `cache_history` | `true` | Persist uptime history to `history.json` across restarts |
| `show_removed_ips` | `true` | Show removed historical IPs (translucent gray) |
| `default_layout_width` | `1700` | Default page zoom width (px); Cookie takes priority |
| `export_suffix` | `/announce` | Path suffix appended when exporting tracker lists |
| `log_level` | `info` | Log verbosity: `none` / `info` / `error` / `debug` |
| `log_to_disk` | `false` | Write logs to `error.log` + `access.log` |
| `max_log_info` | `1000` | Max Info-level log entries |
| `max_log_success` | `1000` | Max Success-level log entries |
| `max_log_error` | `1000` | Max Error-level log entries |
| `page_refresh_ms` | `30000` | Frontend data refresh interval (ms), 0 = disabled |
| `tab_switch_refresh` | `true` | Auto-refresh data when switching to dashboard/monitor tab |
| `http_proxy` | empty | HTTP/TCP proxy address |
| `http_proxy_enabled` | `false` | Enable HTTP proxy |
| `udp_proxy` | empty | UDP proxy address (SOCKS5 only) |
| `udp_proxy_enabled` | `false` | Enable UDP proxy |
| `allow_private_ips` | `false` | Allow adding private/LAN IPs (SSRF protection, disabled by default) |
| `min_password_length` | `8` | Minimum password length for user password changes |
| `cleanup_interval` | `3600` | Memory cleanup interval in seconds. Periodically purges expired entries from rate-limit and login-fail dictionaries to prevent gradual memory growth. Recommended: 1800–7200 |
| `trust_cf_ip` | `false` | Trust `CF-Connecting-IP` / `X-Forwarded-For` for real client IP. Set to `true` when deployed behind Cloudflare; keep `false` when directly exposed (prevents IP spoofing). LAN HTTP deployments work fine with `false` |

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
  "udp_proxy_enabled": true
}
```

**How it works:** The app establishes a persistent TCP control connection to the SOCKS5 proxy and negotiates a UDP relay address via UDP Associate. All monitoring threads share one UDP socket with a fixed source port, using `transaction_id` to demultiplex responses.

**Notes:**
- Proxy must support UDP Associate (CMD=0x03)
- Supports `localhost`, IPv4, IPv6 (`[::1]:port` format)
- `localhost` tries IPv6 (`::1`) first, auto-falls back to `127.0.0.1` if needed
- When proxy is unavailable, UDP checks are skipped and last-known status is preserved

### HTTP Proxy

```json
{
  "http_proxy": "http://127.0.0.1:7890",
  "http_proxy_enabled": true
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
Edit `config.json` and change the `listen_port` field, or change `DEFAULT_CONFIG['listen_port']` in `app.py`.

**4. Rankings page is empty?**
Rankings require accumulated history. Newly added trackers need a few check cycles before appearing. Enable "Cache Uptime Stats" to retain history across restarts.

**5. Some IP geolocations are empty?**
On startup, a background repair thread automatically re-queries any Unknown IPs (starts after 10s, rate-limited to 0.5s/IP). No manual action needed. You can verify ip-api.com connectivity with:
```bash
curl -s "http://ip-api.com/json/1.2.3.4?fields=country,countryCode,isp"
```

**6. Only some IPs resolved?**
Ensure your network supports IPv6, or switch DNS mode to `dnspython` or `custom`. The app queries both A (IPv4) and AAAA (IPv6) records simultaneously.

**7. UDP proxy shows all timeouts?**
Confirm your proxy software has UDP forwarding enabled. Many proxies only support TCP by default — UDP Associate must be explicitly enabled.

**8. Large number of offline IPs when proxy is down?**
After 2 consecutive proxy failures, a 30s cooldown kicks in. All UDP probes are skipped during cooldown with last-known states preserved — no false offline reports.

**9. How to manage multi-user access?**
Go to Config → User Management to add accounts and assign roles: admin (full) / operator (add/delete trackers) / viewer (read-only).

**10. Using `localhost` proxy but connection fails?**
The app tries IPv6 (`::1`) first. If your proxy only listens on IPv4, it auto-falls back to `127.0.0.1`. If still failing, use `socks5://127.0.0.1:port` directly.

**11. API export returns empty results?**
Paused domains are excluded from all export results. Check whether the target domains are in a paused state.

**12. `/trackers` or `/tracker.txt` returns a redirect?**
The current version serves content directly — no `-L` flag needed. If you still see a redirect, make sure you are running the latest `app.py`.

**13. Is domain uptime accurate after a restart?**
Yes. History is stored as timestamped records in `history.json` and recalculated against real time windows on each request. 24H/7D/30D windows are all preserved across restarts. IPs removed by DNS rotation also retain their history and are included in domain-level uptime calculations — historical failures are never lost due to IP changes.

**14. Will `history.json` grow indefinitely?**
No. The app runs an automatic GC every hour, removing records older than 30 days. When a domain is manually deleted, all its history is immediately purged as well.

**15. How do I get real client IPs when deployed behind Cloudflare?**
Set `trust_cf_ip` to `true` in the config page or `config.json`. When enabled, the app reads `CF-Connecting-IP`, which Cloudflare always overwrites with the real client IP — it cannot be spoofed by the client. Keep it `false` when the server is directly exposed to the internet (prevents IP header forgery to bypass rate limiting). LAN/HTTP deployments work fine with `false`.

**16. How do I enable Secure Cookie and HSTS when behind HTTPS / Cloudflare?**
Set the environment variable `HTTPS_ENABLED=1` before starting the app. The app will automatically set `SESSION_COOKIE_SECURE=True` and add the `Strict-Transport-Security` header to all responses. No code changes are needed. When this variable is not set (default), the app runs normally over plain HTTP — useful for local testing without certificates.

**17. How many failed logins trigger a lockout?**
10 consecutive failed login attempts from the same IP trigger a 15-minute lockout. During lockout, all login requests from that IP return 429. The lockout expires automatically after 15 minutes, or resets if the app is restarted.

**18. DNS keeps failing and flooding the console — what can I do?**
The app has built-in log deduplication: if the same domain fails DNS resolution, the error is only printed **once** to the console and Web log. Subsequent polling rounds are silently skipped. The `DNS ERR` badge in the Web UI still updates normally. Once the domain resolves successfully, the suppression is cleared — the next failure will be reported again. To test DNS reachability manually:
```bash
# Test over UDP (default)
nslookup retracker.lanta.me 8.8.8.8

# Test over TCP port 53 (matches behavior when dns_use_tcp is enabled)
nslookup retracker.lanta.me 8.8.8.8 -vc
```

**19. UDP DNS packet loss is high in mainland China — how do I fix it?**
In Config → DNS Settings:
1. Set **Resolve Mode** to **Custom**
2. Enter your DNS servers, e.g. `8.8.8.8,8.8.4.4`
3. Check **Force TCP port 53 queries**

TCP port 53 is far more reliable than UDP in China's network environment — GFW interference frequently drops UDP DNS packets. Switching to TCP typically resolves resolution failures immediately. You can also force TCP for individual servers only using the `tcp://8.8.8.8` prefix format (effective when the global toggle is off).

**20. Using Cloudflare's security DNS (e.g. `2606:4700:4700::1113`) causes many trackers to resolve to `[::]` or `127.0.0.1` — what should I do?**

This is Cloudflare's NXDOMAIN blocking behavior: when a tracker domain is flagged as malicious or non-existent, the DNS returns `[::]` (IPv6 null address) or `127.0.0.1` as a substitute, causing the monitor to show everything as online (but unreachable) or all offline, severely polluting uptime statistics.

**Solution:**
1. **Switch DNS servers**: In Config → DNS Settings, switch to a non-filtering DNS like `8.8.8.8` or `1.1.1.1` (the standard version, not the security variant)
2. **Clean up already-polluted history**: On startup, the app automatically filters out history records for invalid IPs (`[::]`, `127.0.0.1`, `0.0.0.0`, `::1`) — no manual action needed

**21. After manually editing `history.json`, the app fails to start with `Expecting ',' delimiter: line 1 column XXXXXXX` and all data is gone — what happened?**

The file's JSON structure was broken. `history.json` is stored in compact format (no newlines, no indentation) by default. On a large installation it can be several MB to tens of MB — nearly impossible to safely edit in Notepad or similar editors. A single stray or missing comma causes the entire file to fail parsing. When this happens, the app overwrites the broken file with `{}` on its next save, erasing all history.

**The right approach — use `fix_history.py`:**

```bash
# Place fix_history.py in the same directory as history.json, then run:
python fix_history.py
```

The tool will:
- Validate JSON integrity (reports exact error location if broken)
- Automatically filter `[::]`, `127.0.0.1`, and other invalid IPs
- Reformat the file so **each IP is on its own line** — easy to read and edit
- **Atomic write**: writes to a temp file first, then swaps it in — the original file is never at risk
- Auto-backup the original file as `history.json.bak`

Formatted file structure:
```json
{
  "tracker.example.com": {
    "ip:1.2.3.4": [[1700000000,1],[1700000030,0]],
    "ip:5.6.7.8": [[1700000000,1]]
  },
  "other.tracker.org": {
    "ip:2a06:1280::1": [[1700000000,1]]
  }
}
```
To delete an IP, remove the entire line. Note that the **last IP entry in a block must not have a trailing comma**.

**22. Why won't the updated `app.py` ever wipe `history.json` to `{}` again?**

The new `save()` method uses **atomic writes**:
1. Data is written to a temporary file `history.json.tmp` first
2. Once the write completes successfully, `os.replace()` atomically swaps it into place as `history.json`
3. If the app crashes or the system fails mid-write, the original `history.json` is completely untouched — the temp file is cleaned up on the next startup

`os.replace()` is an atomic operation on the same filesystem (POSIX `rename` semantics), so there is no possible "half-written" intermediate state.

---

## 🛠️ Tech Stack

| Component | Details |
|-----------|---------|
| Backend | Python 3.10+ / Flask + waitress |
| Frontend | Vue 3 + Bootstrap 5 + vue-i18n |
| DNS | dnspython (IPv4+IPv6 dual-stack) |
| IP Geolocation | ip-api.com free API (local cache, background repair on startup) |
| Proxy | Manual SOCKS5 UDP Associate (RFC 1928), fixed source port + tid multiplexing |
| Persistence | `config.json` (settings) + `data.json` (current state summaries) + `history.json` (timestamp uptime history) |
| Auth | Flask Session (signed Cookie, PBKDF2+salt password storage, `session_secret.key` persisted locally) |
| Security | CSP / HSTS / `SESSION_COOKIE_SECURE` auto-detection, CSRF double-verify, login lockout, `trust_cf_ip` CF-aware IP resolution |
| Compression | gzip response + ETag negotiation cache (304 Not Modified) |
| Access Logging | nginx-format `access.log` (when disk logging enabled) + leveled console output |

---

## 📄 License

MIT License

---

##### Project founder: rer
##### Contributors: minimaxi, Claude, Doubao、grok、deepseek、Trae(solo)