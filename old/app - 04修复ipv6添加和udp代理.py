# -*- coding: utf-8 -*-
"""
网络监控 - Network Monitor
Windows部署: pip install Flask flask-cors dnspython requests waitress && python app.py
"""

import os
import json
import time
import socket
import struct
import logging
import threading
import random
import re
from datetime import datetime
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import dns.resolver
import requests as req_lib

# ==================== 配置持久化 ====================
CONFIG_FILE  = 'network_monitor_config.json'
DEFAULT_CONFIG = {
    'port': 8443,
    'check_interval': 30,
    'timeout': 5,
    'retry_mode': 'polling',   # 'polling' | 固定秒数(int)
    'retry_interval': 5,       # 当 retry_mode != 'polling' 时使用
    'log_to_disk': False,
    'console_log_level': 'info',  # none | info | error | debug
    'log_file': 'network_monitor.log',
    'data_file': 'network_monitor_data.json',
    'max_history': 288,
    'http_proxy': '',
    'udp_proxy': '',
    'proxy_enabled': False,
}
POLLING_SEQUENCE = [5, 15, 30, 60]   # 轮询重试的秒数序列

def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            for k in ['check_interval','timeout','retry_mode','retry_interval',
                      'log_to_disk','console_log_level',
                      'http_proxy','udp_proxy','proxy_enabled']:
                if k in saved:
                    cfg[k] = saved[k]
    except Exception:
        pass
    return cfg

def persist_config(cfg):
    try:
        savable = {k: cfg[k] for k in ['check_interval','timeout','retry_mode','retry_interval',
                                        'log_to_disk','console_log_level',
                                        'http_proxy','udp_proxy','proxy_enabled']}
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(savable, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

CONFIG = load_config()

# ==================== Flask 初始化 ====================
app = Flask(__name__, static_folder='static')
CORS(app)

# 关闭 werkzeug 自带的 request log，我们自己处理
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ==================== 控制台输出工具 ====================
LEVEL_ORDER = {'none': 0, 'info': 1, 'error': 2, 'debug': 3}

def cprint(msg: str, level: str = 'info'):
    """根据 console_log_level 决定是否打印到控制台"""
    cl = CONFIG.get('console_log_level', 'info')
    # none: 不输出任何内容
    if cl == 'none':
        return
    lv = LEVEL_ORDER.get(level, 1)
    # info: 仅 info
    if cl == 'info' and level not in ('info',):
        return
    # error: info + error
    if cl == 'error' and level not in ('info', 'error'):
        return
    # debug: 全部
    ts = datetime.now().strftime('%H:%M:%S')
    prefix = {'info': '[INFO ]', 'error': '[ERROR]', 'debug': '[DEBUG]'}.get(level, '[INFO ]')
    print(f"  {ts} {prefix} {msg}", flush=True)

# ==================== 代理工具 ====================
def make_proxy_dict():
    """构建 requests 代理字典"""
    if not CONFIG.get('proxy_enabled'):
        return None
    p = CONFIG.get('http_proxy', '').strip()
    if not p:
        return None
    return {'http': p, 'https': p}

def get_requests_session():
    """返回带代理配置的 requests.Session（或 None 使用默认）"""
    proxies = make_proxy_dict()
    s = req_lib.Session()
    if proxies:
        s.proxies.update(proxies)
    return s

# ==================== 数据库 ====================
class TrackerDB:
    def __init__(self):
        self.lock  = threading.RLock()
        self.trackers = {}
        self.logs  = []
        self.stats = {'total': 0, 'alive': 0, 'ipv4': 0, 'ipv6': 0}

    # ---------- tracker 管理 ----------
    def add_tracker(self, domain, port, protocol, ip_list=None):
        with self.lock:
            if domain not in self.trackers:
                self.trackers[domain] = {
                    'domain': domain, 'port': port, 'protocol': protocol,
                    'ips': [], 'history_24h': [], 'history_7d': [], 'history_30d': [],
                    'added_time': datetime.now().isoformat()
                }
            else:
                self.trackers[domain]['port']     = port
                self.trackers[domain]['protocol'] = protocol
            if ip_list:
                existing = {x['ip'] for x in self.trackers[domain]['ips']}
                for info in ip_list:
                    if info['ip'] not in existing:
                        info.update({'status': 'unknown', 'latency': -1, 'last_check': None})
                        self.trackers[domain]['ips'].append(info)
            self._save()

    def update_status(self, domain, ip, status, latency):
        with self.lock:
            if domain in self.trackers:
                for info in self.trackers[domain]['ips']:
                    if info['ip'] == ip:
                        info['status']     = status
                        info['latency']    = latency
                        info['last_check'] = datetime.now().isoformat()
                        break
                self._push_history(domain, status)
                self._recalc()

    def _push_history(self, domain, status):
        t = self.trackers[domain]
        v = 1 if status == 'online' else 0
        for key, maxlen in [('history_24h', CONFIG['max_history']),
                             ('history_7d', 2016), ('history_30d', 8640)]:
            t[key].append(v)
            if len(t[key]) > maxlen:
                t[key].pop(0)

    def _recalc(self):
        total = alive = ipv4 = ipv6 = 0
        for d in self.trackers.values():
            for ip in d['ips']:
                total += 1
                if ip['status'] == 'online': alive += 1
                if ':' in ip['ip']: ipv6 += 1
                else: ipv4 += 1
        self.stats = {'total': total, 'alive': alive, 'ipv4': ipv4, 'ipv6': ipv6}

    def get_trackers(self):
        with self.lock: return dict(self.trackers)

    def get_stats(self):
        with self.lock: return dict(self.stats)

    def get_ranking(self, period='24h', limit=200, only_100=True):
        out = []
        with self.lock:
            for domain, d in self.trackers.items():
                h = d.get(f'history_{period}', [])
                uptime = (sum(h)/len(h)*100) if h else 0.0
                if only_100 and uptime < 100.0: continue
                out.append({'domain': domain, 'port': d.get('port',80),
                            'protocol': d.get('protocol','tcp'),
                            'uptime': round(uptime,2), 'ip_count': len(d['ips'])})
        out.sort(key=lambda x: (-x['uptime'], x['domain']))
        return out[:limit]

    # ---------- 日志 ----------
    def add_log(self, message, level='info'):
        entry = {'time': datetime.now().isoformat(), 'level': level, 'message': message}
        with self.lock:
            self.logs.append(entry)
            if len(self.logs) > 3000: self.logs.pop(0)
            if CONFIG.get('log_to_disk'):
                try:
                    with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
                        f.write(f"[{entry['time']}][{level.upper()}] {message}\n")
                except Exception: pass

    def get_logs(self, limit=300):
        with self.lock: return list(self.logs[-limit:])

    def clear_logs(self):
        with self.lock: self.logs = []

    # ---------- 持久化 ----------
    def _save(self):
        try:
            data = {}
            with self.lock:
                for d, t in self.trackers.items():
                    data[d] = {'domain':d,'port':t.get('port',80),
                               'protocol':t.get('protocol','tcp'),
                               'ips':t['ips'],'added_time':t['added_time']}
            with open(CONFIG['data_file'], 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception: pass

    def load(self):
        try:
            if not os.path.exists(CONFIG['data_file']): return False
            with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
                data = json.load(f)
            with self.lock:
                for d, t in data.items():
                    self.trackers[d] = {
                        'domain':d,'port':t.get('port',80),
                        'protocol':t.get('protocol','tcp'),'ips':t['ips'],
                        'history_24h':[],'history_7d':[],'history_30d':[],
                        'added_time':t.get('added_time',datetime.now().isoformat())
                    }
                self._recalc()
            return True
        except Exception: return False

db = TrackerDB()

# ==================== SOCKS5 UDP Associate（手动实现，支持IPv4/IPv6）====================
class Socks5UdpSocket:
    """
    手动完成 SOCKS5 UDP Associate 握手，不依赖 PySocks。
    支持代理地址为 IPv4/IPv6/域名，目标地址也可以是 IPv4/IPv6/域名。
    直接移植自 udping 项目。
    """
    def __init__(self, proxy_host, proxy_port, timeout=5):
        self.proxy_host  = proxy_host
        self.proxy_port  = proxy_port
        self.timeout     = timeout
        self._tcp_ctrl   = None
        self._udp_sock   = None
        self._relay_addr = None
        self._af         = None

    def connect(self):
        # 1. 解析代理地址（AF_UNSPEC 同时支持 IPv4/IPv6 代理）
        infos = socket.getaddrinfo(self.proxy_host, self.proxy_port,
                                   socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"无法解析代理地址: {self.proxy_host}")
        self._af, _, _, _, proxy_sockaddr = infos[0]

        # 2. TCP 控制连接
        self._tcp_ctrl = socket.socket(self._af, socket.SOCK_STREAM)
        self._tcp_ctrl.settimeout(self.timeout)
        self._tcp_ctrl.connect(proxy_sockaddr)

        # 3. 认证协商（无认证）
        self._tcp_ctrl.sendall(b'\x05\x01\x00')
        resp = self._tcp_ctrl.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
            raise OSError(f"SOCKS5 认证协商失败: {resp.hex()}")

        # 4. UDP ASSOCIATE 请求
        self._tcp_ctrl.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        reply = self._recv_exact(self._tcp_ctrl, 4)
        if reply[1] != 0x00:
            raise OSError(f"SOCKS5 UDP Associate 被拒绝, REP={reply[1]:#x}")

        atyp = reply[3]
        if atyp == 0x01:
            relay_ip   = socket.inet_ntop(socket.AF_INET, self._recv_exact(self._tcp_ctrl, 4))
            relay_port = struct.unpack('!H', self._recv_exact(self._tcp_ctrl, 2))[0]
        elif atyp == 0x04:
            relay_ip   = socket.inet_ntop(socket.AF_INET6, self._recv_exact(self._tcp_ctrl, 16))
            relay_port = struct.unpack('!H', self._recv_exact(self._tcp_ctrl, 2))[0]
        elif atyp == 0x03:
            name_len   = self._recv_exact(self._tcp_ctrl, 1)[0]
            relay_ip   = self._recv_exact(self._tcp_ctrl, name_len).decode()
            relay_port = struct.unpack('!H', self._recv_exact(self._tcp_ctrl, 2))[0]
        else:
            raise OSError(f"UDP Associate 回复中未知 ATYP: {atyp}")

        # 代理返回 0.0.0.0 或 :: 时，改用代理本身的 IP
        if relay_ip in ('0.0.0.0', '::'):
            relay_ip = proxy_sockaddr[0]
        self._relay_addr = (relay_ip, relay_port)

        # 5. 本地 UDP socket，地址族跟随代理
        self._udp_sock = socket.socket(self._af, socket.SOCK_DGRAM)
        bind_addr = '::'  if self._af == socket.AF_INET6 else ''
        self._udp_sock.bind((bind_addr, 0))
        self._tcp_ctrl.settimeout(None)
        return self

    @staticmethod
    def _recv_exact(sock, n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("SOCKS5 TCP 控制连接提前关闭")
            buf += chunk
        return buf

    def settimeout(self, t):
        if self._udp_sock:
            self._udp_sock.settimeout(t)

    def sendto(self, data, addr):
        """封装 SOCKS5 UDP 头后发往中继，自动识别 IPv4/IPv6/域名目标"""
        dst_host, dst_port = addr
        try:
            socket.inet_pton(socket.AF_INET6, dst_host)
            hdr = (b'\x00\x00\x00\x04'
                   + socket.inet_pton(socket.AF_INET6, dst_host)
                   + struct.pack('!H', dst_port))
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET, dst_host)
                hdr = (b'\x00\x00\x00\x01'
                       + socket.inet_pton(socket.AF_INET, dst_host)
                       + struct.pack('!H', dst_port))
            except OSError:
                host_bytes = dst_host.encode()
                hdr = (b'\x00\x00\x00\x03'
                       + bytes([len(host_bytes)])
                       + host_bytes
                       + struct.pack('!H', dst_port))
        self._udp_sock.sendto(hdr + data, self._relay_addr)

    def recvfrom(self, bufsize):
        """接收并剥离 SOCKS5 UDP 头"""
        raw, _ = self._udp_sock.recvfrom(bufsize + 300)
        atyp = raw[3]
        if atyp == 0x01:
            src_ip, src_port = socket.inet_ntop(socket.AF_INET, raw[4:8]), struct.unpack('!H', raw[8:10])[0]
            payload = raw[10:]
        elif atyp == 0x04:
            src_ip, src_port = socket.inet_ntop(socket.AF_INET6, raw[4:20]), struct.unpack('!H', raw[20:22])[0]
            payload = raw[22:]
        elif atyp == 0x03:
            name_len = raw[4]
            src_ip = raw[5:5 + name_len].decode()
            src_port = struct.unpack('!H', raw[5 + name_len:7 + name_len])[0]
            payload = raw[7 + name_len:]
        else:
            raise OSError(f"UDP 响应中未知 ATYP: {atyp}")
        return payload, (src_ip, src_port)

    def close(self):
        for s in (self._udp_sock, self._tcp_ctrl):
            if s:
                try: s.close()
                except: pass
        self._udp_sock = self._tcp_ctrl = None

# ==================== 网络工具 ====================
def get_geo(ip: str) -> dict:
    try:
        s = get_requests_session()
        r = s.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp", timeout=5)
        if r.status_code == 200:
            d = r.json()
            return {'country': d.get('country','Unknown'),
                    'country_code': d.get('countryCode','XX'),
                    'isp': d.get('isp','Unknown')}
    except Exception: pass
    return {'country':'Unknown','country_code':'XX','isp':'Unknown'}

def resolve(domain: str):
    ips = []
    for rtype, ver in [('A','ipv4'),('AAAA','ipv6')]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = CONFIG['timeout']
            resolver.lifetime = CONFIG['timeout']
            for rdata in resolver.resolve(domain, rtype):
                ip = str(rdata)
                ips.append({'ip':ip,'version':ver,'country':get_geo(ip)})
        except Exception as e:
            db.add_log(f"DNS {rtype} 解析失败 {domain}: {type(e).__name__}: {e}", 'debug')
    if not ips:
        db.add_log(f"DNS解析失败 {domain}: 无法获得任何IP", 'error')
        cprint(f"DNS解析失败 {domain}", 'error')
    return ips

def tcp_ping(ip, port):
    try:
        # getaddrinfo 会返回正确的地址元组（IPv4用2元组，IPv6用4元组）
        infos = socket.getaddrinfo(ip, port, type=socket.SOCK_STREAM)
        if not infos:
            return False, -1, "地址解析失败"
        fam, stype, proto, canonname, sockaddr = infos[0]
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(CONFIG['timeout'])
        t = time.time()
        s.connect(sockaddr)
        lat = int((time.time()-t)*1000)
        s.close()
        return True, lat, None
    except socket.timeout:
        return False, -1, f"超时(>{CONFIG['timeout']}s)"
    except ConnectionRefusedError:
        return False, -1, "连接被拒绝"
    except OSError as e:
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        return False, -1, f"{type(e).__name__}: {e}"

def parse_proxy_addr(proxy_url: str):
    """从 socks5://host:port 或 socks5://[IPv6]:port 中解析 (host, port)"""
    addr = proxy_url.strip()
    for scheme in ('socks5://', 'socks4://', 'http://', 'https://'):
        if addr.lower().startswith(scheme):
            addr = addr[len(scheme):]
            break
    m = re.match(r'^\[([0-9a-fA-F:]+)\]:(\d+)$', addr)
    if m:
        return m.group(1), int(m.group(2))
    m = re.match(r'^(.+):(\d+)$', addr)
    if m:
        return m.group(1), int(m.group(2))
    return addr, 1080


def parse_url(url: str):
    """解析 tracker URL，支持 IPv4/IPv6/域名，支持方括号 IPv6 格式"""
    url = url.strip()
    # 纯 IPv4:port  例: 1.2.3.4:6969
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$', url)
    if m:
        return 'tcp', m.group(1), int(m.group(2))
    # 纯 [IPv6]:port  例: [2001:db8::1]:6969
    m = re.match(r'^\[([0-9a-fA-F:]+)\]:(\d+)$', url)
    if m:
        return 'tcp', m.group(1), int(m.group(2))
    # scheme://[IPv6]:port/path  例: http://[2c0f:f4c0::108]:80/announce
    m = re.match(r'^(udp|http|https)://\[([0-9a-fA-F:]+)\](?::(\d+))?(/.*)?$', url, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        host   = m.group(2)
        port   = int(m.group(3)) if m.group(3) else (443 if scheme == 'https' else 80)
        return scheme, host, port
    # scheme://hostname:port/path
    m = re.match(r'^(udp|http|https)://([^:/\s\[\]]+)(?::(\d+))?(?:/.*)?$', url, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        host   = m.group(2)
        port   = int(m.group(3)) if m.group(3) else (443 if scheme == 'https' else 80)
        return scheme, host, port
    return None, None, None


def _udp_tracker_packet():
    """生成 BEP 15 UDP Tracker 握手包（同 udping 项目）
    格式: connect_id(8) + action(4) + transaction_id(4) = 16字节
    connect_id=0x41727101980 固定魔数, action=0 connect, tid=随机
    """
    return struct.pack('!QLL', 0x41727101980, 0, random.randint(0, 0xFFFFFFFF))


def udp_ping(ip, port):
    """UDP Tracker BEP 15 握手检测。
    代理路径: 使用 Socks5UdpSocket（手动SOCKS5协议，支持IPv4/IPv6目标，不依赖PySocks）。
    直连路径: 使用 getaddrinfo 获取正确 sockaddr，原生支持 IPv4/IPv6。
    """
    udp_proxy = CONFIG.get('udp_proxy', '').strip() if CONFIG.get('proxy_enabled') else ''
    packet  = _udp_tracker_packet()
    timeout = CONFIG['timeout']
    tid     = packet[12:16]  # transaction_id bytes，用于校验响应

    # ── SOCKS5 代理路径（Socks5UdpSocket，彻底绕开PySocks，原生IPv6支持）──
    if udp_proxy and 'socks5' in udp_proxy.lower():
        s = None
        try:
            proxy_host, proxy_port = parse_proxy_addr(udp_proxy)
            s = Socks5UdpSocket(proxy_host, proxy_port, timeout=timeout)
            s.connect()
            s.settimeout(timeout)

            t = time.time()
            s.sendto(packet, (ip, port))

            # 接收并校验 transaction_id（过滤旧包/预热包）
            deadline = time.time() + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise socket.timeout()
                s.settimeout(remaining)
                data, _ = s.recvfrom(1024)
                if len(data) >= 8 and data[4:8] == tid:
                    break

            lat = int((time.time() - t) * 1000)
            s.close()

            if len(data) >= 16 and struct.unpack('!L', data[:4])[0] == 0:
                return True, lat, None
            return False, -1, "无效响应"

        except socket.timeout:
            if s: s.close()
            return False, -1, f"超时(>{timeout}s)"
        except Exception as e:
            if s: s.close()
            return False, -1, f"SOCKS5代理错误: {type(e).__name__}: {e}"

    # ── 直连路径（getaddrinfo 自动处理 IPv4/IPv6 sockaddr 格式）──────────
    s = None
    try:
        infos = socket.getaddrinfo(ip, port, type=socket.SOCK_DGRAM)
        if not infos:
            return False, -1, "地址解析失败"
        fam, _, _, _, sockaddr = infos[0]

        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)

        t = time.time()
        s.sendto(packet, sockaddr)

        # 接收并校验 transaction_id
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise socket.timeout()
            s.settimeout(remaining)
            data, _ = s.recvfrom(1024)
            if len(data) >= 8 and data[4:8] == tid:
                break

        lat = int((time.time() - t) * 1000)
        s.close()
        if len(data) >= 16 and struct.unpack('!L', data[:4])[0] == 0:
            return True, lat, None
        return False, -1, "无效响应"

    except socket.timeout:
        if s: s.close()
        return False, -1, f"超时(>{timeout}s)"
    except OSError as e:
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        if s: s.close()
        return False, -1, f"{type(e).__name__}: {e}"


# ==================== 轮询重试逻辑 ====================
# 每个 domain 独立维护轮询步骤
_poll_step = {}
_poll_lock = threading.Lock()

def next_retry_wait(domain: str) -> int:
    """返回该 domain 下次重试的等待秒数（轮询模式）"""
    with _poll_lock:
        step = _poll_step.get(domain, 0)
        wait = POLLING_SEQUENCE[step % len(POLLING_SEQUENCE)]
        _poll_step[domain] = (step + 1) % len(POLLING_SEQUENCE)
    return wait

def get_retry_wait(domain: str) -> int:
    if CONFIG.get('retry_mode') == 'polling':
        return next_retry_wait(domain)
    return int(CONFIG.get('retry_interval', 5))

# ==================== 监控逻辑 ====================
def check_ip(domain, ip_info, retry=True):
    ip   = ip_info['ip']
    with db.lock:
        td       = db.trackers.get(domain, {})
        port     = td.get('port', 80)
        protocol = td.get('protocol', 'tcp')

    fn = udp_ping if protocol == 'udp' else tcp_ping
    ok, lat, err = fn(ip, port)

    if not ok and retry:
        wait = get_retry_wait(domain)
        cprint(f"首次失败 {domain}:{port} ({ip}) 等待{wait}s重试 | {err}", 'debug')
        time.sleep(wait)
        ok, lat, err = fn(ip, port)

    status = 'online' if ok else 'offline'
    db.update_status(domain, ip, status, lat)
    return status, lat, err

def monitor_loop():
    db.add_log("监控服务启动", 'info')
    cprint("监控服务启动", 'info')
    while True:
        try:
            snapshot = db.get_trackers()
            for domain, data in snapshot.items():
                port     = data.get('port', 80)
                protocol = data.get('protocol','tcp').upper()
                for ip_info in data['ips']:
                    ip = ip_info['ip']
                    try:
                        status, lat, err = check_ip(domain, ip_info, retry=True)
                        lat_s = f"{lat}ms" if lat >= 0 else "N/A"
                        if status == 'online':
                            msg = f"✓ {protocol}://{domain}:{port} ({ip}) {lat_s}"
                            db.add_log(msg, 'debug')
                            cprint(msg, 'debug')
                        else:
                            reason = f" | {err}" if err else ""
                            msg = f"✗ {protocol}://{domain}:{port} ({ip}) 离线{reason}"
                            db.add_log(msg, 'error')
                            cprint(msg, 'error')
                    except Exception as e:
                        msg = f"检查异常 {domain}:{port} ({ip}): {type(e).__name__}: {e}"
                        db.add_log(msg, 'error')
                        cprint(msg, 'error')
            s = db.get_stats()
            summary = f"轮检完成 | 总:{s['total']} 在线:{s['alive']} v4:{s['ipv4']} v6:{s['ipv6']}"
            db.add_log(summary, 'info')
            cprint(summary, 'info')
        except Exception as e:
            msg = f"监控线程错误: {type(e).__name__}: {e}"
            db.add_log(msg, 'error')
            cprint(msg, 'error')
        time.sleep(CONFIG['check_interval'])

# ==================== 请求日志中间件 ====================
@app.before_request
def log_request():
    """在控制台记录 HTTP 请求（info级别及以上可见）"""
    method = request.method
    path   = request.path
    remote = request.remote_addr
    cprint(f"← {remote} {method} {path}", 'info')

@app.after_request
def log_response(response):
    cprint(f"→ {response.status_code} {request.method} {request.path}", 'debug')
    return response

# ==================== HTML 路由 ====================
def find_html():
    base = os.path.dirname(os.path.abspath(__file__))
    for p in [os.path.join(base,'templates','index.html'), os.path.join(base,'index.html')]:
        if os.path.exists(p): return p
    return None

@app.route('/')
def index():
    p = find_html()
    if not p: return "index.html not found.", 404
    with open(p, 'r', encoding='utf-8') as f:
        content = f.read()
    return make_response(content, 200, {'Content-Type':'text/html; charset=utf-8'})

# ==================== API ====================
@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())

@app.route('/api/trackers')
def api_trackers():
    return jsonify(db.get_trackers())

@app.route('/api/tracker/add', methods=['POST'])
def api_add():
    raw = (request.json or {}).get('urls', (request.json or {}).get('url',''))
    if not raw:
        return jsonify({'error':'URL不能为空'}), 400
    lines   = raw.replace('\r\n','\n').replace('\r','\n').split('\n')
    results, errors = [], []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('|'): continue
        scheme, host, port = parse_url(line)
        if not host:
            errors.append(f"无效格式: {line}"); continue
        protocol = 'udp' if scheme=='udp' else 'tcp'
        is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host)) or ':' in host
        if is_ip:
            geo  = get_geo(host)
            ver  = 'ipv6' if ':' in host else 'ipv4'
            ips  = [{'ip':host,'version':ver,'country':geo}]
        else:
            ips = resolve(host)
            if not ips:
                errors.append(f"DNS解析失败: {host}"); continue
        db.add_tracker(host, port, protocol, ips)
        msg = f"添加 {protocol.upper()}://{host}:{port} 解析{len(ips)}个IP"
        db.add_log(msg, 'info')
        cprint(msg, 'info')
        def bg(d=host):
            with db.lock:
                td  = db.trackers.get(d,{})
                ipl = list(td.get('ips',[]))
            for ipi in ipl:
                try: check_ip(d, ipi, retry=False)
                except Exception: pass
        threading.Thread(target=bg, daemon=True).start()
        results.append({'domain':host,'port':port,'protocol':protocol,'ip_count':len(ips)})
    if not results and errors:
        return jsonify({'error':'; '.join(errors)}), 400
    return jsonify({'success':True,'added':len(results),'results':results,'errors':errors})

@app.route('/api/tracker/delete', methods=['POST'])
def api_delete():
    domain = (request.json or {}).get('domain','').strip()
    with db.lock:
        if domain in db.trackers:
            del db.trackers[domain]
            db._recalc()
            db._save()
            msg = f"删除 {domain}"
            db.add_log(msg, 'info')
            cprint(msg, 'info')
            return jsonify({'success':True})
    return jsonify({'error':'不存在'}), 404

@app.route('/api/tracker/check', methods=['POST'])
def api_check():
    domain    = (request.json or {}).get('domain','').strip()
    target_ip = (request.json or {}).get('ip', None)
    with db.lock:
        if domain not in db.trackers:
            return jsonify({'error':'不存在'}), 404
        port     = db.trackers[domain].get('port', 80)
        protocol = db.trackers[domain].get('protocol','tcp')
        ips_snap = list(db.trackers[domain]['ips'])
    tag = f" IP:{target_ip}" if target_ip else " 全部IP"
    msg = f"手动重试: {protocol.upper()}://{domain}:{port}{tag}"
    db.add_log(msg, 'info')
    cprint(msg, 'info')
    results = []
    for ipi in ips_snap:
        if target_ip and ipi['ip'] != target_ip: continue
        status, lat, err = check_ip(domain, ipi, retry=True)
        lat_s = f"{lat}ms" if lat>=0 else "N/A"
        reason = f" | {err}" if err and status=='offline' else ""
        res_msg = f"重试结果: {protocol.upper()}://{domain}:{port} ({ipi['ip']}) → {status} {lat_s}{reason}"
        db.add_log(res_msg, 'info')
        cprint(res_msg, 'info')
        results.append({'ip':ipi['ip'],'status':status,'latency':lat,'error':err})
    return jsonify({'success':True,'domain':domain,'port':port,'protocol':protocol,'results':results})

@app.route('/api/ranking/<period>')
def api_ranking(period):
    if period not in ('24h','7d','30d'): period='24h'
    only100 = request.args.get('only100','true').lower()=='true'
    return jsonify({'period':period,'ranking':db.get_ranking(period,200,only100)})

@app.route('/api/logs')
def api_logs():
    limit = request.args.get('limit', 300, type=int)
    return jsonify(db.get_logs(limit))

@app.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    db.clear_logs()
    return jsonify({'success':True})

@app.route('/api/config', methods=['GET','POST'])
def api_config():
    if request.method == 'POST':
        data = request.json or {}
        for k in ['check_interval','timeout','retry_mode','retry_interval',
                  'log_to_disk','console_log_level','http_proxy','udp_proxy','proxy_enabled']:
            if k in data:
                CONFIG[k] = data[k]
        persist_config(CONFIG)
        msg = f"配置已更新: console_log={CONFIG['console_log_level']} retry_mode={CONFIG['retry_mode']}"
        db.add_log(msg, 'info')
        cprint(msg, 'info')
        return jsonify({'success':True,'config':{k:CONFIG[k] for k in
            ['check_interval','timeout','retry_mode','retry_interval',
             'log_to_disk','console_log_level','http_proxy','udp_proxy','proxy_enabled']}})
    safe = {k:v for k,v in CONFIG.items() if k not in ('data_file','log_file')}
    return jsonify(safe)

# ==================== 主程序 ====================
if __name__ == '__main__':
    db.load()
    db.add_log("网络监控服务启动", 'info')

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    print(f"\n{'='*58}")
    print(f"  网络监控 - Network Monitor")
    print(f"{'='*58}")
    print(f"  访问地址       : http://localhost:{CONFIG['port']}")
    print(f"  监控间隔       : {CONFIG['check_interval']}秒")
    print(f"  超时时间       : {CONFIG['timeout']}秒")
    print(f"  重试模式       : {CONFIG['retry_mode']}")
    print(f"  控制台日志级别 : {CONFIG['console_log_level']}")
    print(f"  磁盘日志       : {'开启' if CONFIG['log_to_disk'] else '关闭'}")
    print(f"  代理           : {'启用 '+CONFIG.get('http_proxy','') if CONFIG['proxy_enabled'] else '关闭'}")
    print(f"{'='*58}")
    print(f"  日志级别说明:")
    print(f"    none  - 不输出任何内容")
    print(f"    info  - 仅输出访问日志 + 轮检摘要（默认）")
    print(f"    error - info + 所有失败/超时错误")
    print(f"    debug - 全部（含每个IP成功结果）")
    print(f"{'='*58}\n")

    try:
        from waitress import serve
        print("  使用 waitress 生产服务器\n")
        serve(app, host='0.0.0.0', port=CONFIG['port'], threads=8)
    except ImportError:
        print("  提示: pip install waitress 可消除开发警告\n")
        app.run(host='0.0.0.0', port=CONFIG['port'], debug=False)