# 网络监控 - Network Monitor

> 🇨🇳 中文 | [🇬🇧 English](README_EN.md)

BitTorrent Tracker 全功能监控工具，支持 TCP/UDP Ping、多IP同时监控、IPv4+IPv6 双栈、可用率排行、SOCKS5 代理、多账户权限管理。

---

## ✨ 功能特性

### 核心监控
- ✅ TCPing 检测（HTTP/HTTPS Tracker）
- ✅ UDPing 检测（UDP Tracker BEP 15 协议握手）
- ✅ 同一域名多IP监控，展开查看每个IP详情
- ✅ IPv4 + IPv6 全解析，同时监控双栈
- ✅ 支持纯 `IP:端口` 模式直接添加
- ✅ 并发检测线程数可配置（默认120，建议30～200）
- ✅ 失败自动重试（轮询模式：5s → 15s → 30s → 60s 递增间隔）

### 可用率统计
- ✅ 24小时 / 7天 / 30天 可用率排行
- ✅ 监控列表与排行榜统计周期独立配置
- ✅ 可用率历史缓存持久化（重启不丢失历史数据）
- ✅ 健康状态颜色区分：
  - 🟢 绿色：可用率 >80%，或全部 IP 在线
  - 🟡 黄色：可用率 50～80%，或有 IP 在线同时有 IP 离线（亚健康，优先显示）
  - 🔴 红色：可用率 <50%，或所有 IP 全部离线
- ✅ 延迟进度条颜色：绿色 ≤500ms、黄色 500～1500ms、红色 >1500ms 或超时

### 仪表盘
- ✅ 6格动态统计卡：总IP数 / 在线IP / 故障IP / 平均延迟（含P95）/ IPv4÷IPv6 / 当前告警数
- ✅ 可用率排行 TOP10（最差/最佳一键切换）
- ✅ 告警中心：连续检测失败 ≥5 次自动触发，显示 IP 归属地、运营商、当前状态
- ✅ 错误日志聚合展示：相同错误去重，显示首次时间、出现次数、IP 归属地
- ✅ 快速搜索（全局）：默认展示所有监控项，支持翻页（10条/页），点击域名可筛选查看该域名所有IP详情
- ✅ 快速搜索支持：域名 / IP / 运营商 / 国家 / 状态 / 协议（http/https/udp）

### 代理支持
- ✅ HTTP/HTTPS Tracker 支持 HTTP CONNECT 代理
- ✅ UDP Tracker 支持 SOCKS5 代理（手动实现 RFC 1928，不依赖 PySocks）
- ✅ SOCKS5 长连接复用：TCP 控制连接全局保持，所有线程共享同一固定 UDP 源端口
- ✅ 固定源端口解决 SOCKS5 relay source port filter 丢包问题
- ✅ transaction_id 多路复用，并发线程互不干扰
- ✅ 代理健康状态机：连续失败 2 次进入 30s 冷却，冷却期内探测跳过不计入统计
- ✅ 代理不可用时保留上次检测状态，**不污染可用率数据**
- ✅ 代理地址智能双栈：IPv6 优先，IPv6 不可用自动 fallback 到 IPv4
- ✅ `localhost` 双栈歧义自动处理（系统默认解析到 `::1`，代理只监听 IPv4 时自动切换）
- ✅ SO_KEEPALIVE 保活，防止 NAT/防火墙静默断开长连接
- ✅ TCP 控制连接断开时自动重建，后台线程监控连接存活

### DNS 解析
- ✅ 三种 DNS 模式：系统 DNS / dnspython / 自定义 DNS 服务器
- ✅ 支持读取本地 hosts 文件（getaddrinfo 原生行为）
- ✅ 每轮检测前重新解析，自动感知 IP 变化
- ✅ DNS 解析失败时保留缓存 IP 继续检测，不中断监控

### 监控列表
- ✅ 卡片式布局，展示端口、协议（TCP/UDP）、IP数量、添加时间
- ✅ 展开行显示每个 IP 的状态、可用率、延迟、归属地、运营商、最后检查时间
- ✅ IP 地址等宽字体显示，IPv4 绿色、IPv6 紫蓝色，附 v4/v6 角标
- ✅ TCP 协议自动标注 HTTP / HTTPS（端口443 = HTTPS）
- ✅ IP 列头三态点击：展开全部 → 折叠全部 → 还原默认（≤5 IP 自动展开）
- ✅ 历史IP（已移除）半透明灰色显示，可在配置中关闭
- ✅ 工具栏筛选：ALL / IPv4 / IPv6 · ALL / TCP / UDP / HTTP / HTTPS · 当前状态 · 关键词搜索
- ✅ 排序：可用率 / 域名 / 延迟 / 添加时间 / 最后检查 / 端口，支持升序/降序/还原三态
- ✅ 状态/可用率列头显示当前统计周期（24h / 7d / 30d）
- ✅ 延迟可视化进度条（颜色随延迟动态变化）
- ✅ 离线 IP 显示重试按钮（精确到 IP 级别，立即执行，不触发轮询等待）
- ✅ 批量添加 Tracker（多行粘贴，`|` 开头自动跳过）
- ✅ 暂停/恢复监控（支持单IP、单域名、全部）

### 可用率排行榜
- ✅ 域名显示 TCP/UDP 协议标签 + v4/v6 版本角标
- ✅ 显示活跃IP数及在线数
- ✅ 已暂停的域名自动从排行榜隐藏
- ✅ 最低可用率筛选（50% / 80% / 90% / 100%）
- ✅ 协议筛选：ALL / TCP / UDP
- ✅ IP版本筛选：ALL / IPv4 / IPv6
- ✅ 一键导出（**所见即所导**：当前筛选结果直接下载，已暂停域名不包含在内）
- ✅ URL 路由：`/ranking`

### Tracker 导出 API
- ✅ 公开 API，无需登录，任何人均可 GET 请求获取在线 Tracker 列表（纯文本，每行一个 URL）
- ✅ 旧路径兼容：`/trackers`、`/tracker.txt` 自动转发到 `/api/tracker`，无需客户端处理跳转
- ✅ 已暂停域名不包含在导出结果中
- ✅ 域名之间自动添加空行，兼容需要空行分隔的 BT 客户端
- ✅ 参数设计：

| 参数 | 可选值 | 默认 | 说明 |
|------|--------|------|------|
| `day` | `24h` `7d` `30d` | `24h` | 按哪个周期可用率排序 |
| `uptime` | `0` `50` `80` `90` `100` | `0` | 最低可用率（0=不过滤）|
| `net` | `all` `tcp` `udp` | `all` | 协议过滤 |
| `ip` | `all` `ipv4` `ipv6` | `all` | IP 版本过滤 |
| `url` | 任意字符串 | `/announce` | 追加到每行 URL 末尾的后缀 |

```bash
# 全量，无过滤
curl http://host/api/tracker

# 7天可用率 ≥ 90%，全协议，全 IP
curl "http://host/api/tracker?day=7d&uptime=90"

# 30天可用率 ≥ 90%，仅 TCP，仅 IPv4
curl "http://host/api/tracker?day=30d&uptime=90&net=tcp&ip=ipv4"

# 旧路径兼容（自动转发，无需 -L）
curl http://host/tracker.txt
```

### 网络健康检测
- ✅ 多目标探针（8.8.8.8 / 1.1.1.1 / 114.114.114.114 :53），任一可达即视为网络正常
- ✅ 双重保障：探针状态 + 本轮失败率（≥90% 失败视为本地网络异常）
- ✅ 网络异常时本轮历史数据不计入统计，避免全局性误报污染数据

### IP 归属地
- ✅ 自动识别 IP 归属国家、运营商（ip-api.com，本地缓存）
- ✅ 启动后后台自动补查遗留的未知归属地（延迟10s开始，限速0.5s/IP）
- ✅ 每轮检测后若归属地仍为 Unknown，自动触发补查，不阻塞检测线程

### 界面与交互
- ✅ 日间/夜间主题切换，IPv4/IPv6 颜色在两种主题下均清晰可读
- ✅ 页面视野（50%～100%）可在导航栏实时调整，记录到 Cookie
- ✅ 多国语言：中文 / English / Русский / Français / 日本語 / 한국어（含 API 说明全文翻译）
- ✅ URL 路由（`/home`、`/trackers`、`/ranking`、`/logs`、`/config`）
- ✅ 所有搜索框支持 `ESC` 键一键清空
- ✅ 日志搜索：支持直接输入 `error` / `warn` / `info` 快速按级别过滤
- ✅ 操作反馈 Toast 通知
- ✅ gzip 压缩传输（HTML ~210KB → ~48KB）+ ETag 协商缓存（文件未变更返回 304）

### 账户与权限
- ✅ 三级角色权限：admin / operator / viewer
  - `admin`：完整权限，含配置页、用户管理、清空日志，重试不限速
  - `operator`：增删 Tracker、重试（500ms 冷却）
  - `viewer`：只读，重试（1s 冷却）
- ✅ 登录后自动刷新配置，无需手动 F5
- ✅ 登录失败次数限制，防止暴力破解
- ✅ Session Cookie 签名（`session_secret.key`），重启后登录状态保持
- ✅ 未登录用户仅返回前端必要的公开配置字段，不暴露运维信息
- ✅ 管理员操作日志：暂停/恢复操作记录操作者用户名 + 脱敏 IP（Web界面显示 `1.*.*.4`，控制台保留完整 IP）

### 系统与运维
- ✅ waitress 生产服务器（消除 Flask 开发警告）
- ✅ 静态资源本地化（`static/` 目录），支持完全离线部署，无需 CDN
- ✅ 配置全部持久化到 `config.json`，重启自动读取
- ✅ 控制台日志分级：`none` / `info` / `error` / `debug`
- ✅ 配置变更日志只输出实际改变的字段（含可读标签和单位）
- ✅ 日志可选写入磁盘（`error.log`），支持按级别过滤

---

## 🚀 快速部署

### 1. 安装依赖

```bash
pip install Flask flask-cors dnspython requests waitress
```

### 2. 文件结构

```
Network Monitor/
├── app.py
├── index.html
├── static/               # 本地静态资源（JS/CSS/字体）
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
├── config.json           # 自动生成，配置持久化
├── data.json             # 自动生成，监控数据
├── error.log             # 自动生成（启用日志存盘后）
└── session_secret.key    # 自动生成，⚠️ 勿上传至公开仓库
```

### 3. 运行

```bash
python app.py
```

访问：`http://localhost:443`

### 4. 创建 start.bat 快捷启动（Windows）

```batch
@echo off
cd /d "%~dp0"
python app.py
pause
```

---

## ⚠️ 安全注意事项

### `session_secret.key` 文件

此文件是 Flask Session Cookie 的签名密钥，**绝对不能上传到公开 Git 仓库**。一旦泄露，任何人都可以伪造 Cookie 绕过登录，直接获得 admin 权限。

**务必在 `.gitignore` 中添加：**

```gitignore
session_secret.key
config.json
data.json
error.log
```

**如何重置密钥：**

```bash
# 方法1：删除文件，下次启动自动重新生成
del session_secret.key        # Windows
rm session_secret.key         # Linux/macOS

# 方法2：手动生成新密钥
python -c "import os; open('session_secret.key','wb').write(os.urandom(32))"
```

重置密钥后，所有已登录用户的 Session 会立即失效，需要重新登录。

### 默认账户密码

首次运行后请立即修改默认密码（配置页 → 用户管理）：

| 账户 | 默认密码 | 权限 |
|------|----------|------|
| admin | admin | 完整权限 |
| operator | operator | 增删Tracker |
| viewer | viewer | 只读 |

---

## ⚙️ 配置参数说明

所有配置通过网页配置页面修改，**自动持久化**到 `config.json`，重启后自动读取。

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `port` | `443` | Web 服务端口（443 需要管理员权限） |
| `check_interval` | `30` | 监控间隔（秒） |
| `timeout` | `5` | TCP/UDP 连接超时（秒） |
| `retry_mode` | `polling` | 重试模式：`polling`（5→15→30→60s）或固定秒数 |
| `retry_interval` | `5` | 固定重试间隔（`retry_mode` 非 polling 时生效） |
| `monitor_workers` | `120` | 并发检测线程数（建议 30～200） |
| `dns_mode` | `system` | DNS 解析模式：`system` / `dnspython` / `custom` |
| `dns_custom` | 空 | 自定义 DNS 服务器（`custom` 模式，多个用逗号分隔） |
| `tracker_stat_period` | `24h` | 监控列表可用率统计周期：`24h` / `7d` / `30d` |
| `rank_stat_period` | `24h` | 排行榜默认打开的统计周期（进入后可手动切换） |
| `cache_history` | `true` | 可用率历史缓存持久化（重启不丢失） |
| `show_removed_ips` | `true` | 是否显示历史IP（已从DNS消失的IP，半透明灰色） |
| `default_layout_width` | `1700` | 默认页面视野宽度（px），Cookie 优先级更高 |
| `export_suffix` | `/announce` | 导出 Tracker 列表时追加的路径后缀 |
| `log_level` | `info` | 控制台日志级别：`none` / `info` / `error` / `debug` |
| `log_to_disk` | `false` | 日志是否写入磁盘（`error.log`） |
| `max_log_entries` | `2000` | 日志最大条目数 |
| `page_refresh_ms` | `30000` | 前端数据刷新间隔（毫秒），0 = 禁用 |
| `tab_switch_refresh` | `true` | 切换仪表盘/监控列表时是否自动刷新数据 |
| `http_proxy` | 空 | HTTP/TCP 代理地址 |
| `udp_proxy` | 空 | UDP 代理地址（仅支持 SOCKS5） |
| `proxy_enabled` | `false` | 是否启用代理 |

---

## 📡 添加 Tracker

支持以下格式（可批量粘贴多行）：

```
udp://open.stealth.si:80/announce
udp://tracker.opentrackr.org:1337/announce
http://tracker.mywaifu.best:6969/announce
https://shahidrazi.online:443/announce
1.2.3.4:6969
| 这行以|开头，会被自动跳过（注释用）
```

- 多行粘贴，每行一个 Tracker
- `|` 开头的行自动跳过
- 支持 `IP:端口` 直接添加
- 空行自动忽略

---

## 🔒 代理配置

### UDP 代理（SOCKS5）

UDP Tracker 探测通过 SOCKS5 UDP Associate 转发，完整实现 RFC 1928，不依赖第三方库。

```json
{
  "udp_proxy": "socks5://127.0.0.1:1080",
  "proxy_enabled": true
}
```

**技术原理：** 程序与 SOCKS5 代理建立一条长连接（TCP 控制连接），通过 UDP Associate 握手获取中继地址，之后所有检测线程共享同一 UDP socket（固定源端口），用 `transaction_id` 区分各线程收发包，互不干扰。

**注意事项：**
- 代理服务器必须支持 UDP Associate（CMD=0x03）
- 支持 `localhost`、IPv4、IPv6（`[::1]:port` 格式）
- `localhost` 默认优先尝试 IPv6（`::1`），若代理只监听 IPv4 自动 fallback 到 `127.0.0.1`
- 代理不可用时，UDP 检测自动跳过并保留上次状态，不影响可用率统计

### HTTP 代理

```json
{
  "http_proxy": "http://127.0.0.1:7890",
  "proxy_enabled": true
}
```

---

## ❌ 离线原因说明

| 显示 | 含义 |
|------|------|
| `超时(>Xs)` | 目标在超时时间内无响应 |
| `端口未开放` | 目标主动拒绝（ICMP Port Unreachable / TCP RST） |
| `代理连接失败` | SOCKS5 代理本身无法连接或握手失败 |
| `代理不可用(Xs后重试)` | 代理进入冷却期，当前跳过检测，保留上次状态 |
| `无效响应` | 收到回包但格式不符合协议 |

---

## ❓ 常见问题

**1. 无法启动？**
```bash
pip install Flask flask-cors dnspython requests waitress
```

**2. `index.html` 找不到？**
确保 `index.html` 与 `app.py` 在同一目录，或放在 `templates/` 子目录。

**3. 端口被占用？**
修改 `config.json` 中的 `port` 字段，或修改 `app.py` 中 `DEFAULT_CONFIG['port']`。

**4. 排行榜为空？**
排行榜需要积累历史记录，刚添加的 Tracker 需等待几轮检查后才会出现。开启「缓存统计可用率」可在重启后保留历史数据。

**5. 部分IP归属地显示为空？**
重启 app 后会自动启动后台补查线程（延迟10s开始），逐个查询未知归属地，无需手动干预。可用以下命令测试 ip-api.com 连通性：
```bash
curl -s "http://ip-api.com/json/1.2.3.4?fields=country,countryCode,isp"
```

**6. 只解析到部分 IP？**
确保网络支持 IPv6，或切换 DNS 模式为 `dnspython` 或 `custom`。程序同时查询 A 记录（IPv4）和 AAAA 记录（IPv6）。

**7. UDP 代理全部超时？**
确认代理软件已开启 UDP 转发功能。部分代理默认仅支持 TCP，需要在配置中单独开启 UDP Associate。

**8. 代理不可用时大量显示离线？**
代理连续失败 2 次后进入 30s 冷却期，冷却期内所有 UDP 探测自动跳过并保留上次状态，不产生误报。

**9. 多人使用时如何分配权限？**
在「配置 → 用户管理」中添加账户并分配角色：admin 完整权限 / operator 可增删Tracker / viewer 只读。

**10. 使用 `localhost` 代理但连接失败？**
程序优先尝试 IPv6（`::1`），若代理只监听 IPv4 会自动 fallback 到 `127.0.0.1`。若仍失败，可直接填写 `socks5://127.0.0.1:端口`。

**11. API 导出结果为空？**
已暂停的域名不会出现在 API 导出结果中。请检查目标域名是否处于暂停状态。

**12. `/trackers` 或 `/tracker.txt` 请求返回跳转？**
当前版本已改为直接返回内容，无需 `-L` 参数。如仍遇到问题，请确认使用的是最新版 `app.py`。

---

## 🛠️ 技术栈

| 组件 | 说明 |
|------|------|
| 后端 | Python 3.10+ / Flask + waitress |
| 前端 | Vue 3 + Bootstrap 5 + vue-i18n |
| DNS | dnspython（IPv4+IPv6 双栈） |
| IP归属地 | ip-api.com 免费 API（本地缓存，启动后自动补查未知IP） |
| 代理 | 手动实现 SOCKS5 UDP Associate（RFC 1928），固定源端口 + tid 多路复用 |
| 数据持久化 | JSON 文件（`config.json` + `data.json`） |
| 认证 | Flask Session（Cookie 签名，`session_secret.key` 本地持久化） |
| 压缩/缓存 | gzip 响应压缩 + ETag 协商缓存（304 Not Modified） |

---

## 📄 许可证

MIT License

---

##### 项目发起人：rer
##### 项目协作者：minimaxi、Claude、豆包