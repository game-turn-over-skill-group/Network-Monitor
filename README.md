# 网络监控 - Network Monitor

BitTorrent Tracker 监控工具，支持 TCP/UDP Ping、多IP、IPv4+IPv6、可用率排行。

## 功能特性

- ✅ 解析域名IP（IPv4 + IPv6 全解析）
- ✅ TCPing 检测（HTTP/HTTPS Tracker）
- ✅ UDPing 检测（UDP Tracker 协议握手）
- ✅ 同一域名多IP监控，展开查看每个IP详情
- ✅ 监控列表显示端口号和协议类型（TCP/UDP）
- ✅ 24小时/7天/30天 可用率排行（支持仅显示100%或全部）
- ✅ 离线IP单独显示重试按钮（精确到IP级别）
- ✅ 批量添加Tracker（多行粘贴，`|` 开头自动跳过）
- ✅ 支持纯IP:端口模式添加
- ✅ 日志功能（可选存储到磁盘，支持按级别过滤）
- ✅ 日志显示详细错误类型（超时/连接被拒绝/网络错误等）
- ✅ 多国语言切换（中文/英文/俄文/法文/日文/韩文）
- ✅ Cookie自动记录语言偏好
- ✅ 自动化IP归属地识别（ip-api.com）
- ✅ 代理支持（HTTP/HTTPS/SOCKS5）
- ✅ 失败自动重试
- ✅ **配置持久化**（修改配置后自动保存到 `network_monitor_config.json`）
- ✅ URL Hash 路由（切换页面时地址栏自动更新 `#/trackers` 等）
- ✅ waitress 生产服务器支持（消除 Flask 开发警告）

## 快速部署（Windows）

### 1. 安装依赖

```bash
pip install Flask flask-cors dnspython requests waitress
```

### 2. 文件结构

```
Network Monitor/
├── app.py
├── index.html          ← 与 app.py 同目录，或放在 templates/ 子目录
├── requirements.txt
```

### 3. 运行

```bash
python app.py
```

访问: http://localhost:443

### 4. 创建 start.bat 快捷启动

```batch
@echo off
cd /d "%~dp0"
python app.py
pause
```

## 配置参数说明

配置通过网页配置页面修改并**自动持久化**到 `network_monitor_config.json`，重启后自动读取。

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `port` | 443 | Web服务端口（443需要管理员权限） |
| `check_interval` | 30 | 监控间隔（秒） |
| `timeout` | 5 | TCP/UDP连接超时（秒） |
| `retry_interval` | 5 | 失败重试间隔（秒） |
| `max_history` | 288 | 历史点数量（24h × 12点/h） |
| `log_to_disk` | False | 日志是否写入磁盘 |
| `http_proxy` | 空 | HTTP代理地址 |
| `udp_proxy` | 空 | UDP代理地址（SOCKS5） |
| `proxy_enabled` | False | 是否启用代理 |

## 添加 Tracker

支持以下格式（可批量粘贴多行）：

```
udp://open.stealth.si:80/announce
udp://tracker.opentrackr.org:1337/announce
http://tracker.mywaifu.best:6969/announce
https://shahidrazi.online:443/announce
1.2.3.4:6969
| 这行以|开头，会被自动跳过
```

**规则：**
- 多行粘贴，每行一个Tracker
- `|` 开头的行自动跳过（用于注释/禁用）
- 支持 `IP:端口` 直接添加
- 空行自动忽略

## 代理配置

```python
# 在配置页面设置，或直接修改 network_monitor_config.json
{
  "http_proxy": "http://127.0.0.1:7890",
  "udp_proxy": "socks5://127.0.0.1:1080",
  "proxy_enabled": true
}
```

## 消除 Flask WARNING

安装 waitress 即可自动使用生产服务器：

```bash
pip install waitress
```

## 常见问题

**1. 无法启动？**
```bash
pip install Flask flask-cors dnspython requests
```

**2. index.html 找不到？**
确保 `index.html` 与 `app.py` 在同一目录，或放在 `templates/` 子目录。

**3. 端口被占用？**
修改 `app.py` 中 `DEFAULT_CONFIG['port']`，或运行一次后修改 `network_monitor_config.json`。

**4. 排行榜为空？**
排行榜数据需要积累历史记录，刚添加的tracker需等待几轮检查后才会出现。

**5. 只解析到部分IP？**
确保网络支持IPv6，或检查DNS服务器。程序会同时查询A记录（IPv4）和AAAA记录（IPv6）。

## 技术栈

- 后端: Python 3.8+ / Flask + waitress
- 前端: Vue 3 + Bootstrap 5 + vue-i18n
- DNS解析: dnspython（IPv4+IPv6）
- IP归属地: ip-api.com 免费API
- 数据持久化: JSON文件

## 许可证

MIT License

---
##### 项目发起人：rer
##### 项目协作者：minimaxi、Claude

