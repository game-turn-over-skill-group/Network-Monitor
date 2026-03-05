---
AIGC:
    ContentProducer: Minimax Agent AI
    ContentPropagator: Minimax Agent AI
    Label: AIGC
    ProduceID: fcd578d9fc70c4d2c166eaba35adb478
    PropagateID: fcd578d9fc70c4d2c166eaba35adb478
    ReservedCode1: 304402206b819f80a8629a99a99cd5c0e9cfd97148dfff7ec0b37af776154b9c699b78370220712f64c2a5e9171cc75b6d3bbea6b62d37295a191120baab9ab2291c2eeca127
    ReservedCode2: 30450221008faa6bce969d462e49841e38952a86dc88f50ac5d088dfde6e8aaee82d3505ed02202ff361570248743709cf0b9c1002f339b835810067a2b3846a9f1c26f47d2f09
---

# 网络监控 - Network Monitor

## 功能特性

- ✅ 解析域名IP（支持IPv4+IPv6）
- ✅ TCPing 检测
- ✅ UDPing 检测
- ✅ 同一域名多IP监控
- ✅ 24小时/7天/30天 100%可用率排行
- ✅ 日志功能（可选存储到磁盘）
- ✅ 多国语言切换（中文/英文/日文/韩文）
- ✅ Cookie自动记录语言偏好
- ✅ 自动化IP归属地识别
- ✅ 1域名+多IP行显示形式
- ✅ 代理支持（HTTP/HTTPS/SOCKS5）
- ✅ 失败自动重试
- ✅ 可自定义监控参数

## Windows部署方法

### 方法1：快速启动（推荐）

1. 安装 Python 3.8 或更高版本
   - 下载: https://www.python.org/downloads/
   - 勾选 "Add Python to PATH"

2. 安装依赖
   ```
   pip install -r requirements.txt
   ```

3. 运行程序
   ```
   python app.py
   ```

4. 打开浏览器访问: http://localhost:443

### 方法2：创建桌面快捷方式

1. 创建一个 `start.bat` 文件:
   ```batch
   @echo off
   cd /d "%~dp0"
   python app.py
   pause
   ```

2. 双击运行即可

## 配置参数说明

在 `app.py` 文件中有以下配置参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `port` | 8443 | Web服务端口（默认8443，443需要管理员权限） |
| `check_interval` | 30 | **监控间隔**（秒），默认30秒检测一次所有tracker |
| `timeout` | 5 | TCP/UDP连接**超时时间**（秒），最大等待时间 |
| `retry_interval` | 5 | **失败重试间隔**（秒），首次失败后5秒自动重试 |
| `max_history` | 288 | 历史记录数量，24小时 × 12 = 288（每5分钟存一个点，用于计算可用率） |
| `log_to_disk` | False | 是否将日志保存到硬盘 |
| `http_proxy` | 空 | HTTP代理地址，支持HTTP/HTTPS/SOCKS5 |
| `udp_proxy` | 空 | UDP代理地址（通常只支持SOCKS5） |
| `proxy_enabled` | False | 是否启用代理 |

### 参数详细说明

1. **check_interval（监控间隔）**
   - 含义：每隔多少秒检查一次所有tracker的状态
   - 默认：30秒
   - 可选：5秒、15秒、30秒、1分钟、5分钟、10分钟、30分钟、1小时
   - 注意：间隔越短，对服务器和网络负载越大

2. **max_history（历史记录数）**
   - 含义：用于计算可用率的历史数据点数量
   - 计算方式：24小时 × 12（每小时12个点，每5分钟一个）= 288
   - 这个数值决定可用率统计的精度

3. **timeout（超时时间）**
   - 含义：TCP/UDP连接最大等待时间
   - 默认：5秒
   - 可选：3秒、5秒、10秒

4. **retry_interval（失败重试间隔）**
   - 含义：首次检测失败后，等待多少秒自动重试
   - 默认：5秒
   - 说明：可以过滤掉短暂的网络抖动

## 代理配置说明

### HTTP代理
支持以下格式：
- HTTP代理：`http://127.0.0.1:7890`
- HTTPS代理：`https://127.0.0.1:7890`
- SOCKS5代理：`socks5://127.0.0.1:1080`

### UDP代理
UDP协议通常只支持SOCKS5代理：
- SOCKS5代理：`socks5://127.0.0.1:1080`

### 配置示例
```python
CONFIG = {
    'http_proxy': 'http://127.0.0.1:7890',  # HTTP代理
    'udp_proxy': 'socks5://127.0.0.1:1080',   # UDP代理
    'proxy_enabled': True,  # 启用代理
}
```

## 使用说明

### 添加Tracker

点击右上角 "添加" 按钮，输入Tracker URL:
- `udp://tracker.example.com:80/announce`
- `http://tracker.example.com:6969/announce`
- `https://tracker.example.com:443/announce`

### 查看状态

- 仪表盘: 查看总体统计
- Tracker列表: 查看所有监控的tracker，支持搜索，可展开查看每个IP详情
- 可用率排行: 查看100%可用率的tracker排行（24小时/7天/30天）
- 日志: 查看系统运行日志
- 配置: 设置监控参数、代理、日志存储等

### 多语言

点击右上角语言选择器切换语言，语言偏好会保存到Cookie中。

### 配置页面功能

1. **监控配置**
   - 监控间隔：设置自动检测的时间间隔
   - 连接超时：设置TCP/UDP超时时间
   - 失败重试间隔：设置首次失败后重试等待时间

2. **代理配置**
   - 启用/禁用代理
   - 设置HTTP代理地址
   - 设置UDP代理地址

3. **显示配置**
   - 页面自动刷新间隔（1秒、5秒、30秒、1分钟、禁用）
   - 日志是否存储到磁盘

## 示例Tracker URL

```
udp://open.stealth.si:80/announce
udp://tracker.opentrackr.org:1337/announce
http://tracker.mywaifu.best:6969/announce
https://shahidrazi.online:443/announce
```

## 常见问题

### 1. 无法启动？
确保已安装Python和依赖包:
```bash
pip install Flask flask-cors dnspython requests
```

### 2. 添加Tracker失败？
- 检查URL格式是否正确
- 检查网络连接
- 检查域名是否能解析

### 3. 端口被占用？
修改 `app.py` 中的端口配置:
```python
CONFIG = {
    'port': 443,  # 改为其他端口（如8080、8443等）
    ...
}
```

### 4. 需要使用代理？
在配置页面中启用代理并填写代理地址，或直接在 `app.py` 中修改配置。

## 技术栈

- 后端: Python Flask
- 前端: Vue 3 + Bootstrap 5
- DNS解析: dnspython
- IP归属地: ip-api.com (免费API)

## 许可证

MIT License


##### 项目发起人：rer
##### 项目协作者：minimaxi、Claude

