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
- ✅ 120线程并发检测，大量Tracker也能快速完成
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
- ✅ 6格动态统计卡：总IP数 / 在线IP / 故障IP / 平均延迟(含P95) / IPv4÷IPv6 / 当前告警数
- ✅ 可用率排行 TOP10（最差/最佳一键切换）
- ✅ 告警中心：连续检测失败 ≥5 次自动触发，显示 IP 归属地、运营商、当前状态
- ✅ 错误日志聚合展示：相同错误去重，显示首次时间、出现次数、IP 归属地
- ✅ 快速搜索（全局）：默认展示所有监控项，支持翻页（10条/页），点击域名筛选 → 显示该域名所有IP详情
- ✅ 快速搜索支持：域名 / IP / 运营商 / 国家 / 状态 / 协议（http/https/udp）

### 代理支持
- ✅ HTTP/HTTPS Tracker 支持 HTTP CONNECT 代理
- ✅ UDP Tracker 支持 SOCKS5 代理（手动实现 RFC 1928，不依赖 PySocks）
- ✅ SOCKS5 长连接复用：TCP 控制连接全局保持，所有线程共享同一固定 UDP 源端口
- ✅ 固定源端口解决 SOCKS5 relay source port filter 丢包问题
- ✅ transaction_id 多路复用，120 线程并发互不干扰
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

### 界面与交互
- ✅ 监控列表展示：端口、协议（TCP/UDP）、IP数量、添加时间、最后检查时间
- ✅ 展开行显示每个 IP 的状态、延迟、归属地、运营商
- ✅ TCP 协议 IP 展开后自动标注 HTTP / HTTPS（按端口443区分）
- ✅ IP 列头三态点击：展开 ≤5 IP 的域名 → 展开全部 → 全部收起
- ✅ 协议筛选列（含 HTTP/HTTPS/UDP/TCP）
- ✅ 延迟可视化进度条（颜色随延迟动态变化）
- ✅ 离线 IP 显示重试按钮（精确到 IP 级别，立即执行，不触发轮询等待）
- ✅ 批量添加 Tracker（多行粘贴，`|` 开头自动跳过）
- ✅ 可用率排行支持最低可用率筛选
- ✅ 所有搜索框支持 `ESC` 键一键清空
- ✅ 监控列表搜索：支持域名、IP、归属地、运营商、状态、时间（`yyyy/mm/dd`）
- ✅ 日志搜索：支持直接输入 `error` / `warn` / `info` 快速按级别过滤
- ✅ URL Hash 路由（`#/trackers`、`#/ranking` 等）
- ✅ 多国语言：中文 / English / Русский / Français / 日本語 / 한국어
- ✅ Cookie 自动记录语言偏好
- ✅ 操作反馈 Toast 通知

### 账户与权限
- ✅ 三级角色权限：admin / operator / viewer
  - `admin`：完整权限，含配置页、用户管理、清空日志，重试不限速
  - `operator`：增删 Tracker、重试（500ms 冷却）
  - `viewer`：只读，重试（1s 冷却）
- ✅ 登录后自动刷新配置，无需手动 F5
- ✅ Session Cookie 签名（`session_secret.key`），重启后登录状态保持
- ✅ 错误日志导出：一键下载 `error.log`，Admin 专属清空日志功能
- ✅ 操作频率限制（Rate Limiting）防止滥用

### 系统与运维
- ✅ waitress 生产服务器（消除 Flask 开发警告）
- ✅ 配置全部持久化到 `config.json`，重启自动读取
- ✅ 控制台日志分级：`none` / `info` / `error` / `debug`
- ✅ 配置变更日志只输出实际改变的字段（含可读标签和单位）
- ✅ 日志可选写入磁盘（`error.log`），支持按级别过滤
- ✅ IP 归属地自动识别（ip-api.com，带本地缓存）

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
├── config.json          # 自动生成，配置持久化
├── data.json            # 自动生成，监控数据
├── error.log            # 自动生成（启用日志存盘后）
├── session_secret.key   # 自动生成，⚠️ 勿上传至公开仓库
└── requirements.txt
```

### 3. 运行

```bash
python app.py
```

访问：http://localhost:443

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
# 方法1：直接删除文件，下次启动自动重新生成
del session_secret.key

# 方法2：手动生成新密钥
python -c "import os; open('session_secret.key','wb').write(os.urandom(32))"
```

重置密钥后，所有已登录用户的 Session 会立即失效，需要重新登录。

### 默认账户密码

首次运行后请立即修改默认密码（在配置页 → 用户管理）：

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
| `retry_mode` | `polling` | 重试模式：`polling`（5→15→30→60s 递增）或固定秒数 |
| `retry_interval` | `5` | 固定重试间隔（`retry_mode` 非 polling 时生效） |
| `dns_mode` | `system` | DNS 解析模式：`system` / `dnspython` / `custom` |
| `dns_custom` | 空 | 自定义 DNS 服务器地址（`custom` 模式时使用） |
| `tracker_stat_period` | `24h` | 监控列表可用率统计周期：`24h` / `7d` / `30d` |
| `rank_stat_period` | `24h` | 排行榜统计周期：`24h` / `7d` / `30d` |
| `cache_history` | `true` | 可用率历史缓存持久化（重启不丢失） |
| `log_level` | `info` | 控制台日志级别：`none` / `info` / `error` / `debug` |
| `log_to_disk` | `false` | 日志是否写入磁盘（`error.log`） |
| `max_log_entries` | `2000` | 日志最大条目数 |
| `page_refresh_ms` | `30000` | 前端数据刷新间隔（毫秒），0 = 禁用 |
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

**技术原理：**

程序与 SOCKS5 代理建立一条长连接（TCP 控制连接），通过 UDP Associate 握手获取中继地址（relay），之后所有 120 个检测线程共享同一个 UDP socket（固定源端口），用 `transaction_id` 区分各线程的收发包，互不干扰。

**注意事项：**
- 代理服务器必须支持 UDP Associate（CMD=0x03）
- 代理地址支持 `localhost`、IPv4、IPv6（`[::1]:port` 格式）
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

**2. index.html 找不到？**
确保 `index.html` 与 `app.py` 在同一目录，或放在 `templates/` 子目录。

**3. 端口被占用？**
修改 `config.json` 中的 `port` 字段，或修改 `app.py` 中 `DEFAULT_CONFIG['port']`。

**4. 排行榜为空？**
排行榜需要积累历史记录，刚添加的 Tracker 需等待几轮检查后才会出现。开启「缓存统计可用率」可在重启后保留历史数据。

**5. 只解析到部分 IP？**
确保网络支持 IPv6，或切换 DNS 模式为 `dnspython` 或 `custom`。程序同时查询 A 记录（IPv4）和 AAAA 记录（IPv6）。

**6. UDP 代理全部超时？**
确认代理软件已开启 UDP 转发功能。部分代理默认仅支持 TCP，需要在配置中单独开启 UDP Associate。

**7. 使用 `localhost` 代理但连接失败？**
程序优先尝试 IPv6（`::1`），若代理只监听 IPv4 会自动 fallback 到 `127.0.0.1`。若仍失败，可直接填写 `socks5://127.0.0.1:端口`。

**8. 代理不可用时大量显示离线？**
代理连续失败 2 次后进入 30s 冷却期，冷却期内所有 UDP 探测自动跳过并保留上次状态，不产生误报，不影响历史可用率。

**9. 登录后配置页内容没刷新？**
已在最新版本修复，登录后自动重新拉取配置，无需手动 F5。

**10. 多人使用时如何分配权限？**
在「配置 → 用户管理」中添加账户并分配角色：admin 完整权限 / operator 可增删Tracker / viewer 只读。

---

## 🛠️ 技术栈

| 组件 | 说明 |
|------|------|
| 后端 | Python 3.10+ / Flask + waitress |
| 前端 | Vue 3 + Bootstrap 5 + vue-i18n |
| DNS | dnspython（IPv4+IPv6 双栈） |
| IP归属地 | ip-api.com 免费 API（本地缓存） |
| 代理 | 手动实现 SOCKS5 UDP Associate（RFC 1928），固定源端口 + tid 多路复用 |
| 数据持久化 | JSON 文件（`config.json` + `data.json`） |
| 认证 | Flask Session（Cookie 签名，`session_secret.key` 本地持久化） |

---

## 📄 许可证

MIT License

---

##### 项目发起人：rer
##### 项目协作者：minimaxi、Claude、豆包