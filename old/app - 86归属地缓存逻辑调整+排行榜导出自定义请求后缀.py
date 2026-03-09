# -*- coding: utf-8 -*-
"""
网络监控 - Network Monitor
Windows部署: pip install Flask flask-cors dnspython requests waitress && python app.py
"""

import queue
import os
import json
import time
import socket
import struct
import logging
import threading
import random
import re
import hashlib
import secrets
from datetime import datetime
from flask import Flask, jsonify, request, make_response, session, g
from flask_cors import CORS
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests as req_lib

# ==================== 配置持久化 ====================
CONFIG_FILE  = 'config.json'
DEFAULT_CONFIG = {
    'port': 443,
    'check_interval': 30,
    'timeout': 5,
    'retry_mode': 'polling',   # 'polling' | 固定秒数(int)
    'retry_interval': 5,       # 当 retry_mode != 'polling' 时使用
    'monitor_workers': 120,    # 并发检测线程数（可配置，建议 30~200）
    'log_to_disk': False,
    'log_level': 'info',  # none | info | error | debug（原 console_log_level）
    'log_file': 'error.log',
    'data_file': 'data.json',
    'max_history': 2880,  # history_24h 上限：24h × 3600s ÷ 30s间隔 = 2880点
    'http_proxy': '',
    'udp_proxy': '',
    'proxy_enabled': False,
    'dns_mode': 'system',      # system | dnspython | custom
    'dns_custom': '8.8.8.8',   # 自定义DNS时使用，支持多个用逗号分隔
    'max_log_entries': 2000,    # 日志最大条目数
    'page_refresh_ms': 30000,   # 前端页面自动刷新间隔(ms)，0=禁用
    'cache_history': True,      # 是否缓存历史可用率到JSON（重启不丢失）
    'tracker_stat_period': '24h', # 监控列表可用率统计周期：24h | 7d | 30d
    'rank_stat_period': '24h',    # 可用率排行统计周期：24h | 7d | 30d
    'tab_switch_refresh': True,   # 切换仪表盘/监控列表时是否刷新数据
    'export_suffix': '/announce',   # 导出 tracker 列表时追加的路径后缀
    'show_removed_ips': True,       # 是否显示已移除的历史IP（前端控制）
    'users': [
        {"username": "admin",    "password": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", "role": "admin"},
        {"username": "operator", "password": "06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23", "role": "operator"},
        {"username": "viewer",   "password": "d35ca5051b82ffc326a3b0b6574a9a3161dee16b9478a199ee39cd803ce5b799",  "role": "viewer"},
    ],
}
POLLING_SEQUENCE = [5, 15, 30, 60]   # 轮询重试的秒数序列

def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            for k in ['check_interval','timeout','retry_mode','retry_interval',
                      'monitor_workers',
                      'log_to_disk','log_level','console_log_level',
                      'http_proxy','udp_proxy','proxy_enabled',
                      'dns_mode','dns_custom','max_log_entries','page_refresh_ms',
                      'tracker_stat_period','rank_stat_period','cache_history','tab_switch_refresh','export_suffix','show_removed_ips','users']:
                if k in saved:
                    cfg[k] = saved[k]
            # 向后兼容：旧配置文件用 console_log_level，迁移到 log_level
            if 'log_level' not in cfg and 'console_log_level' in cfg:
                cfg['log_level'] = cfg['console_log_level']
    except Exception:
        pass
    return cfg

def persist_config(cfg):
    try:
        savable = {k: cfg[k] for k in ['check_interval','timeout','retry_mode','retry_interval',
                                        'monitor_workers',
                                        'log_to_disk','log_level',
                                        'http_proxy','udp_proxy','proxy_enabled',
                                        'dns_mode','dns_custom','max_log_entries','page_refresh_ms',
                                        'tracker_stat_period','rank_stat_period','cache_history',
                                        'tab_switch_refresh','export_suffix','show_removed_ips','users']
                   if k in cfg}
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(savable, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

CONFIG = load_config()

# ==================== Flask 初始化 ====================
app = Flask(__name__, static_folder='static')
# CORS: 允许携带 Cookie（Session认证需要），不开放跨域
# same-origin 请求本身不经过 CORS 拦截，此配置仅影响真正的跨域场景
CORS(app, supports_credentials=True)

# Session 签名密钥：持久化到 config，重启后 session 仍有效
_SK_FILE = 'session_secret.key'
def _get_secret_key():
    if os.path.exists(_SK_FILE):
        with open(_SK_FILE, 'r') as f:
            return f.read().strip()
    k = secrets.token_hex(32)
    with open(_SK_FILE, 'w') as f:
        f.write(k)
    return k

app.secret_key = _get_secret_key()

# Session 安全配置
app.config['SESSION_COOKIE_HTTPONLY']  = True   # 防止 JS 读取 Cookie (XSS防护)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 基础防护
# 注意：SESSION_COOKIE_SECURE=True 需要 HTTPS，本地HTTP部署时不开启
# 如果使用 HTTPS 反向代理，请手动改为 True
app.config['SESSION_COOKIE_SECURE']   = False
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7  # Session 有效期 7天
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024    # 请求体上限 1MB，防 DoS

# 关闭 werkzeug 自带的 request log，我们自己处理
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ==================== 权限工具 ====================
def _hash_pw(pw: str, salt: str = None) -> tuple:
    """返回 (hash_hex, salt_hex)。
    使用 PBKDF2-HMAC-SHA256 + 随机盐，防彩虹表攻击。
    salt=None 时自动生成新盐。
    """
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt.encode(), 200000)
    return h.hex(), salt

def _hash_pw_legacy(pw: str) -> str:
    """旧版 SHA256 无盐哈希，仅用于向后兼容迁移判断"""
    return hashlib.sha256(pw.encode()).hexdigest()

def _verify_pw(pw: str, stored_hash: str, stored_salt: str = None) -> bool:
    """验证密码。支持旧版（无盐SHA256）和新版（PBKDF2+盐）格式。"""
    if stored_salt:
        # 新版：PBKDF2
        h, _ = _hash_pw(pw, stored_salt)
        return secrets.compare_digest(h, stored_hash)
    else:
        # 旧版：SHA256 无盐（兼容迁移）
        return secrets.compare_digest(_hash_pw_legacy(pw), stored_hash)

def _find_user(username: str):
    for u in CONFIG.get('users', []):
        if u['username'] == username:
            return u
    return None

def _current_role() -> str:
    """从 session 读取当前用户角色，未登录返回 None"""
    return session.get('role')

def _require_role(*roles):
    """装饰器：要求指定角色之一，否则返回 403"""
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            role = _current_role()
            if role not in roles:
                return jsonify({'error': '权限不足', 'require_login': True}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# operator 重试限流：{username: last_retry_time}
_retry_throttle: dict = {}
_retry_throttle_lock = threading.Lock()

# 登录暴力破解防护：{ip: [fail_count, lockout_until]}
_login_fail: dict = {}
_login_fail_lock = threading.Lock()
_LOGIN_MAX_FAIL  = 10          # 最大连续失败次数
_LOGIN_LOCKOUT_S = 600         # 锁定时长（秒）= 10分钟

# 日志写入锁：防止多线程并发写入造成行截断
_log_write_lock = threading.Lock()

def _login_check_and_record(ip: str, success: bool) -> tuple:
    """检查是否被锁定，并记录结果。
    返回 (is_locked, seconds_remaining)。
    locked_until=0 表示未锁定。
    warned=True 表示本次锁定已打印过告警，不再重复。"""
    now = time.time()
    with _login_fail_lock:
        rec = _login_fail.get(ip, [0, 0, False])  # [fail_count, locked_until, warned]
        fail_count, locked_until, warned = rec[0], rec[1], rec[2] if len(rec) > 2 else False
        # 已在锁定期内
        if locked_until > now:
            return True, int(locked_until - now)
        # 锁定已过期，重置
        if locked_until and locked_until <= now:
            fail_count, locked_until, warned = 0, 0, False
        if success:
            _login_fail[ip] = [0, 0, False]
            return False, 0
        fail_count += 1
        new_warned = warned
        if fail_count >= _LOGIN_MAX_FAIL and not warned:
            locked_until = now + _LOGIN_LOCKOUT_S
            new_warned = True
            # 只打印一次，后续同一IP被拒绝时静默（nginx access log 照常记录 429）
            cprint(f'[auth] IP {ip} 登录失败 {fail_count} 次，锁定 {_LOGIN_LOCKOUT_S//60} 分钟', 'info')
        _login_fail[ip] = [fail_count, locked_until, new_warned]
        return False, 0

def _check_retry_throttle(interval_ms: float) -> bool:
    """检查当前用户是否超过重试频率限制。True=允许，False=拒绝"""
    username = session.get('username', session.get('remote', request.remote_addr))
    now = time.time()
    with _retry_throttle_lock:
        last = _retry_throttle.get(username, 0)
        if now - last < interval_ms / 1000:
            return False
        _retry_throttle[username] = now
        return True

# ==================== 控制台输出工具 ====================
LEVEL_ORDER = {'none': 0, 'info': 1, 'error': 2, 'debug': 3}

# 完全静默的路径（前端内部轮询/导航，不是真实用户请求）
_NOISY_PATHS = {'/api/auth/whoami', '/api/nav'}

_ACCESS_LOG_FILE = 'access.log'

def cprint(msg: str, level: str = 'info', raw: bool = False):
    """根据 log_level 决定是否打印到控制台。加锁保证多线程下不截断。
    raw=True：原样输出（nginx access log 格式，不加前缀）
    raw=False：加 YYYY/M/D HH:MM:SS [LEVEL] 前缀；info级别同步写入 access.log
    """
    cl = CONFIG.get('log_level', CONFIG.get('console_log_level', 'info'))
    if cl == 'none':
        return
    if level == 'success':
        return
    if cl == 'info' and level not in ('info',):
        return
    if cl == 'error' and level not in ('info', 'error'):
        return
    if raw:
        with _log_write_lock:
            print(msg, flush=True)
    else:
        now = datetime.now()
        ts = f"{now.year}/{now.month}/{now.day} {now.strftime('%H:%M:%S')}"
        prefix = {'info': '[INFO]', 'error': '[ERROR]', 'debug': '[DEBUG]'}.get(level, '[INFO]')
        line = f"  {ts} {prefix} {msg}"
        with _log_write_lock:
            print(line, flush=True)
            # info 级别写入 access.log；error 已有 error.log，不重复写入
            if level == 'info' and CONFIG.get('log_to_disk'):
                try:
                    with open(_ACCESS_LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(line + '\n')
                except Exception:
                    pass

def _write_access_log(line: str):
    """把一行 nginx 格式日志写入 access.log（仅 log_to_disk=True 时）。加锁防截断。"""
    if CONFIG.get('log_to_disk'):
        with _log_write_lock:
            try:
                with open(_ACCESS_LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
            except Exception:
                pass

def access_log(msg: str):
    """业务操作日志（登录/登出/添加/删除/重试/配置变更等）。
    控制台沿用带前缀的内部格式；写盘统一交给 after_request 的 nginx 行处理。
    这里只负责打印到控制台，不再自己写 access.log。
    """
    cprint(msg, 'info')

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
                    'added_time': datetime.now().isoformat(),
                    'dns_error': False
                }
            else:
                self.trackers[domain]['port']     = port
                self.trackers[domain]['protocol'] = protocol
            if ip_list:
                existing = {x['ip'] for x in self.trackers[domain]['ips']}
                for info in ip_list:
                    if info['ip'] not in existing:
                        info.update({'status': 'unknown', 'latency': -1, 'last_check': None,
                                     'added_time': datetime.now().isoformat()})
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
                self._push_history(domain, ip, status)
                self._recalc()

    def _push_history(self, domain, ip, status):
        """把历史记录写入对应的 IP 对象（IP级可用率）。
        同时更新域名级汇总历史（用于排行榜）。
        跳过 removed IP，避免污染统计。"""
        t = self.trackers[domain]
        ip_obj = None
        for info in t['ips']:
            if info['ip'] == ip:
                if info.get('removed', False):
                    return
                ip_obj = info
                break
        if ip_obj is None:
            return
        v = 1 if status == 'online' else 0
        maxlens = [('history_24h', CONFIG['max_history']),
                   ('history_7d', 20160),
                   ('history_30d', 86400)]
        # ── IP 级历史（精确到每个 IP）──────────────────────────
        for key, maxlen in maxlens:
            lst = ip_obj.setdefault(key, [])
            lst.append(v)
            if len(lst) > maxlen:
                lst.pop(0)
        # ── 域名级汇总历史（排行榜用，取活跃IP的平均在线状态）──
        active = [i for i in t['ips'] if not i.get('removed')]
        if active:
            agg = 1 if any(i.get('status') == 'online' for i in active) else 0
            for key, maxlen in maxlens:
                lst = t.setdefault(key, [])
                lst.append(agg)
                if len(lst) > maxlen:
                    lst.pop(0)

    def _recalc(self):
        total = alive = ipv4 = ipv6 = 0
        alive_v4 = alive_v6 = 0
        # TCP（含 tcp/http/https）和 UDP 分类统计
        tcp_total = tcp_alive = udp_total = udp_alive = 0
        for d in self.trackers.values():
            proto = d.get('protocol', 'tcp')
            is_udp = (proto == 'udp')
            for ip in d['ips']:
                if ip.get('removed'): continue
                total += 1
                is6 = ':' in ip['ip']
                if is6: ipv6 += 1
                else:   ipv4 += 1
                online = ip['status'] == 'online'
                if online:
                    alive += 1
                    if is6: alive_v6 += 1
                    else:   alive_v4 += 1
                if is_udp:
                    udp_total += 1
                    if online: udp_alive += 1
                else:
                    tcp_total += 1
                    if online: tcp_alive += 1
        self.stats = {
            'total': total, 'alive': alive,
            'ipv4': ipv4, 'ipv6': ipv6,
            'alive_v4': alive_v4, 'alive_v6': alive_v6,
            'tcp_total': tcp_total, 'tcp_alive': tcp_alive,
            'udp_total': udp_total, 'udp_alive': udp_alive,
        }

    def get_trackers(self):
        """返回 tracker 字典，IP 对象附带 ip_uptime（各统计周期的可用率百分比）"""
        with self.lock:
            result = {}
            period = CONFIG.get('tracker_stat_period', '24h')
            for domain, t in self.trackers.items():
                t_copy = dict(t)
                ips_copy = []
                for ip_obj in t.get('ips', []):
                    ip_copy = {k: v for k, v in ip_obj.items()
                               if k not in ('history_24h','history_7d','history_30d')}
                    # 附加当前统计周期的 IP 级可用率
                    h = ip_obj.get(f'history_{period}', [])
                    ip_copy['ip_uptime'] = round(sum(h)/len(h)*100, 1) if h else None
                    # 兼容旧数据：IP 没有 added_time 时，用域名的 added_time 代替
                    if 'added_time' not in ip_copy:
                        ip_copy['added_time'] = t.get('added_time')
                    # 同时附加三个周期（前端可按需使用）
                    for pk in ('24h','7d','30d'):
                        ph = ip_obj.get(f'history_{pk}', [])
                        ip_copy[f'uptime_{pk}'] = round(sum(ph)/len(ph)*100, 1) if ph else None
                    # IP 级末尾连续失败次数（告警用，每个IP独立计算）
                    ip_h24 = ip_obj.get('history_24h', [])
                    ip_consec = 0
                    for v in reversed(ip_h24):
                        if v == 0: ip_consec += 1
                        else: break
                    ip_copy['consec_fail'] = ip_consec
                    ips_copy.append(ip_copy)
                t_copy['ips'] = ips_copy
                # 域名级：用预计算的百分比代替巨大0/1数组，大幅压缩体积
                # 各周期可用率（成功次数/总次数，前端直接用，不需要原始数组）
                for pk in ('24h', '7d', '30d'):
                    ph = t.get(f'history_{pk}', [])
                    if ph:
                        ok = sum(ph)
                        t_copy[f'uptime_{pk}'] = round(ok / len(ph) * 100, 1)
                        t_copy[f'ok_{pk}']     = ok
                        t_copy[f'total_{pk}']  = len(ph)
                    else:
                        t_copy[f'uptime_{pk}'] = None
                        t_copy[f'ok_{pk}']     = 0
                        t_copy[f'total_{pk}']  = 0
                # 趋势图已移除，不再传输原始0/1点位数据
                # 删除所有原始0/1数组，不传给前端
                for k in ('history_24h', 'history_7d', 'history_30d'):
                    t_copy.pop(k, None)
                result[domain] = t_copy
            return result

    def get_stats(self):
        with self.lock: return dict(self.stats)

    def get_ranking(self, period='24h', limit=200, min_uptime=0.0):
        out = []
        with self.lock:
            for domain, d in self.trackers.items():
                h = d.get(f'history_{period}', [])
                uptime = (sum(h)/len(h)*100) if h else None
                if uptime is None and min_uptime > 0: continue
                if uptime is not None and uptime < min_uptime: continue
                online_count = sum(1 for ip in d['ips'] if ip.get('status') == 'online' and not ip.get('removed'))
                out.append({'domain': domain, 'port': d.get('port',80),
                            'protocol': d.get('protocol','tcp'),
                            'uptime': round(uptime,2) if uptime is not None else None,
                            'ip_count': len(d['ips']),
                            'online_count': online_count})
        # 主排序：可用率高→低；同可用率：在线数多→少；再同：名称字母序
        out.sort(key=lambda x: (-(x['uptime'] if x['uptime'] is not None else -1), -x['online_count'], x['domain']))
        return out[:limit]

    # ---------- 日志 ----------
    def add_log(self, message, level='info'):
        entry = {'time': datetime.now().isoformat(), 'level': level, 'message': message}
        with self.lock:
            self.logs.append(entry)
            max_e = CONFIG.get('max_log_entries', 2000)
            if len(self.logs) > max_e: self.logs.pop(0)
            # 磁盘日志只写 error 级别，避免成功结果和轮检摘要塞满日志文件
            if CONFIG.get('log_to_disk') and level == 'error':
                try:
                    with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
                        f.write(f"[{entry['time']}][{level.upper()}] {message}\n")
                except Exception: pass

    def get_logs(self, limit=2000):
        with self.lock: return list(self.logs[-limit:])

    def clear_logs(self):
        with self.lock: self.logs = []

    # ---------- 持久化 ----------
    def update_ips(self, domain, new_ip_list, dns_error=False):
        """每轮解析后更新 IP 列表：
        - 合并新IP（保留历史状态）
        - 标记消失的旧IP为 removed（不立即删除，保留检测到下次重启）
        - 记录 DNS 错误状态
        """
        with self.lock:
            if domain not in self.trackers:
                return
            td = self.trackers[domain]
            td['dns_error'] = dns_error
            if dns_error or not new_ip_list:
                # DNS 失败：保留旧 IP 继续检测，仅标记错误
                return
            existing = {x['ip']: x for x in td['ips']}
            new_ips  = {x['ip'] for x in new_ip_list}
            # 添加新出现的 IP
            for ip_info in new_ip_list:
                if ip_info['ip'] not in existing:
                    ip_info.update({'status': 'unknown', 'latency': -1, 'last_check': None})
                    td['ips'].append(ip_info)
            # 标记消失的旧 IP（不删除，仅 removed 标记；重启时会清除）
            changed = False
            for ip_obj in td['ips']:
                if ip_obj['ip'] not in new_ips:
                    if not ip_obj.get('removed'):
                        ip_obj['removed'] = True
                        changed = True
                else:
                    if ip_obj.pop('removed', None):
                        changed = True
            if changed:
                self._save()  # 把 removed 标记持久化到 JSON

    def _save(self):
        try:
            data = {}
            cache_hist = CONFIG.get('cache_history', True)
            with self.lock:
                for d, t in self.trackers.items():
                    # IP 列表：存储时把 IP 级历史转成紧凑计数器格式
                    ips_to_save = []
                    for ip_obj in t['ips']:
                        ip_entry = {k: v for k, v in ip_obj.items()
                                    if k not in ('history_24h','history_7d','history_30d')}
                        if cache_hist:
                            for key in ('history_24h','history_7d','history_30d'):
                                h = ip_obj.get(key, [])
                                ip_entry[key] = {'total': len(h), 'ok': sum(h), 'fail': len(h)-sum(h)}
                        ips_to_save.append(ip_entry)
                    entry = {'domain':d,'port':t.get('port',80),
                             'protocol':t.get('protocol','tcp'),
                             'ips':ips_to_save,'added_time':t['added_time']}
                    if cache_hist:
                        # 域名级汇总历史（排行榜用）
                        for key in ('history_24h','history_7d','history_30d'):
                            h = t.get(key, [])
                            entry[key] = {'total': len(h), 'ok': sum(h), 'fail': len(h)-sum(h)}
                    data[d] = entry
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
                    clean_ips = [ip for ip in t.get('ips', [])
                                 if not ip.get('removed', False)]
                    removed_count = len(t.get('ips', [])) - len(clean_ips)
                    if removed_count:
                        cprint(f"[load] {d}: 清除 {removed_count} 个过时IP", 'debug')
                    def _restore(raw, maxlen):
                        if isinstance(raw, dict):
                            ok   = int(raw.get('ok', 0))
                            fail = int(raw.get('fail', 0))
                            arr = [0]*fail + [1]*ok
                            return arr[-maxlen:] if len(arr) > maxlen else arr
                        elif isinstance(raw, list):
                            return raw[-maxlen:] if len(raw) > maxlen else raw
                        return []
                    # 恢复每个 IP 的独立历史
                    for ip_obj in clean_ips:
                        for key, maxlen in [('history_24h', CONFIG['max_history']),
                                            ('history_7d', 20160),
                                            ('history_30d', 86400)]:
                            ip_obj[key] = _restore(ip_obj.get(key, []), maxlen)
                    self.trackers[d] = {
                        'domain':d,'port':t.get('port',80),
                        'protocol':t.get('protocol','tcp'),'ips':clean_ips,
                        # 域名级汇总历史（排行榜用）— 兼容旧 data.json
                        'history_24h': _restore(t.get('history_24h',[]), CONFIG['max_history']),
                        'history_7d':  _restore(t.get('history_7d',[]),  20160),
                        'history_30d': _restore(t.get('history_30d',[]), 86400),
                        'added_time':t.get('added_time',datetime.now().isoformat()),
                        'dns_error': t.get('dns_error', False)
                    }
                self._recalc()
            # 预热 geo 缓存：把 data.json 中已有的有效 country 数据加载到内存缓存
            # 只预热成功的（countryCode != XX），失败的允许下次重新查询
            warmed = 0
            with _geo_cache_lock:
                for td in self.trackers.values():
                    for ip_obj in td.get('ips', []):
                        ip  = ip_obj.get('ip', '')
                        geo = ip_obj.get('country')
                        if ip and geo and geo.get('country_code','XX') != 'XX' and ip not in _geo_cache:
                            _geo_cache[ip] = geo
                            warmed += 1
            if warmed:
                cprint(f"[geo] 预热归属地缓存 {warmed} 条（重启无需重新查询）", 'info')
            return True
        except Exception: return False

db = TrackerDB()

# ==================== SOCKS5 UDP Associate（手动实现，支持IPv4/IPv6）====================
# ==================== SOCKS5 UDP 连接池 ====================
# 代理故障冷却时间（秒）：代理连续失败后暂停探测，避免 120 线程全部堆积重试

# 代理连接/握手失败专用异常（区别于 UDP 探测超时）
class _ProxyConnectError(OSError):
    pass


# 代理故障冷却时间（秒）


class Socks5ProxySession:
    """
    SOCKS5 代理会话：一个固定 UDP socket，所有线程共享同一源端口。

    原因：SOCKS5 relay 会做 source port filter——只转发来自
    UDP Associate 时注册的那个源端口的包。每次 bind 新端口
    relay 会丢弃，导致所有包超时。

    多路复用：每个线程用唯一的 transaction_id 区分自己的包。
    接收循环：共享 socket 由调用线程自己 recvfrom，用 tid 过滤。
    线程安全：sendto 用锁串行化（UDP 发包本身不可中断），
              recvfrom 各线程独立等待，非目标包重新入队（pending）。
    """
    def __init__(self, tcp_ctrl, relay_addr, af, timeout):
        self._tcp_ctrl   = tcp_ctrl
        self.relay_addr  = relay_addr
        self.af          = af
        self.timeout     = timeout
        self.valid       = True

        # 共享 UDP socket（固定源端口）
        self._udp        = socket.socket(af, socket.SOCK_DGRAM)
        try:
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        bind_addr = '::' if af == socket.AF_INET6 else ''
        self._udp.bind((bind_addr, 0))
        self._udp.settimeout(0.1)   # 短超时，让 recv 线程可以定期检查 valid

        # 多路复用：tid(bytes) → queue.Queue，各调用线程等自己的包
        self._pending     = {}        # {tid: Queue}
        self._pend_lock   = threading.Lock()
        self._send_lock   = threading.Lock()

        # 启动后台接收分发线程
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

        # 监控 TCP 控制连接
        self._ctrl_thread = threading.Thread(target=self._monitor, daemon=True)
        self._ctrl_thread.start()

    # ── 后台线程 ──────────────────────────────────────────────────────────

    def _recv_loop(self):
        """持续接收 UDP 包，按 tid 分发给等待的线程"""
        while self.valid:
            try:
                raw, _ = self._udp.recvfrom(1324)
            except socket.timeout:
                continue
            except OSError:
                break
            # 剥离 SOCKS5 UDP 头
            data = _socks5_strip(raw)
            if not data or len(data) < 8:
                continue
            tid = data[4:8]
            with self._pend_lock:
                q = self._pending.get(tid)
            if q:
                q.put(data)
            # 无人等待的包直接丢弃（过期包/乱序包）

    def _monitor(self):
        """TCP 控制连接断开时将 session 标记为失效"""
        try:
            self._tcp_ctrl.settimeout(self.timeout)
            while self.valid:
                try:
                    b = self._tcp_ctrl.recv(1)
                    if b == b'':
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            self.valid = False
            try: self._udp.close()
            except: pass
            try: self._tcp_ctrl.close()
            except: pass
            # 唤醒所有等待线程
            with self._pend_lock:
                for q in self._pending.values():
                    q.put(None)   # None = session 失效信号

    # ── 公开 API（供 udp_ping 调用）─────────────────────────────────────

    def send_and_recv(self, packet: bytes, dst: tuple, timeout: float) -> bytes:
        """
        发送 UDP tracker 包并等待对应 tid 的回包。
        返回 payload bytes；超时抛 socket.timeout；session 失效抛 OSError。
        """
        tid = packet[12:16]
        q   = queue.Queue()

        with self._pend_lock:
            self._pending[tid] = q
        try:
            # 串行化发包（保证 SOCKS5 UDP 头完整发出）
            with self._send_lock:
                _socks5_sendto(self._udp, packet, dst, self.relay_addr)

            deadline = time.time() + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise socket.timeout()
                try:
                    data = q.get(timeout=min(remaining, 0.1))
                except queue.Empty:
                    if not self.valid:
                        raise OSError("SOCKS5 session 已失效")
                    continue
                if data is None:
                    raise OSError("SOCKS5 session 已失效")
                return data
        finally:
            with self._pend_lock:
                self._pending.pop(tid, None)

    def close(self):
        self.valid = False
        try: self._tcp_ctrl.close()
        except: pass
        try: self._udp.close()
        except: pass



class Socks5ProxyPool:
    """
    SOCKS5 代理连接池。
    缓存一个 ProxySession（TCP 控制连接 + relay 地址），
    每次探测用 session.make_udp_socket() 获取独立 UDP socket，
    彻底避免多线程共享同一 socket 互相抢包的问题。

    健康状态机：连续建连失败进入冷却期，期间快速失败不堆积。
    """
    _COOLDOWN = 30

    def __init__(self):
        self._lock           = threading.Lock()
        self._session        = None
        self._proxy          = ''
        self._timeout        = 0
        self._healthy        = True
        self._cooldown_until = 0.0
        self._fail_count     = 0
        self._building       = False   # 正在建连中，其他线程不重复建

    # ── 公开 API ──────────────────────────────────────────────────────────

    def check_healthy(self):
        """返回 (is_healthy, reason_str)"""
        with self._lock:
            if not self._healthy:
                remaining = self._cooldown_until - time.time()
                if remaining > 0:
                    return False, f"代理不可用，{remaining:.0f}s 后重试"
                self._healthy    = True
                self._fail_count = 0
            return True, ''

    def acquire_session(self, proxy_url: str, timeout: int) -> 'Socks5ProxySession':
        """
        获取有效 session。若无有效 session 则在锁外建连。
        同时只允许一个线程建连，其他线程等待结果。
        等待超时抛 _WaitTimeout（不计入代理失败计数）。
        """
        # 快路径：session 有效直接返回
        with self._lock:
            if (self._session and self._session.valid
                    and self._proxy == proxy_url
                    and self._timeout == timeout):
                return self._session
            if self._building:
                building = True
            else:
                self._building = True
                building = False

        if building:
            # 等待建连完成，等待时间 = timeout * 2（建连本身最多用 timeout）
            deadline = time.time() + timeout * 2
            while time.time() < deadline:
                time.sleep(0.05)
                with self._lock:
                    if not self._building:
                        if self._session and self._session.valid:
                            return self._session
                        # 建连线程失败了
                        raise _ProxyConnectError("代理建连失败")
            raise _ProxyConnectError("等待代理建连超时")

        # 本线程负责建连（锁外执行网络IO，不持锁）
        try:
            proxy_host, proxy_port = parse_proxy_addr(proxy_url)
            session = self._do_connect(proxy_host, proxy_port, timeout)
            with self._lock:
                if self._session:
                    self._session.close()
                self._session  = session
                self._proxy    = proxy_url
                self._timeout  = timeout
                self._building = False
            cprint(f'[SOCKS5Pool] 连接已建立 → {proxy_host}:{proxy_port}', 'debug')
            return session
        except Exception as e:
            with self._lock:
                self._session  = None
                self._building = False
            raise _ProxyConnectError(f"代理握手失败: {e}") from e

    def report_success(self):
        with self._lock:
            self._fail_count = 0
            self._healthy    = True

    def report_failure(self, reason: str):
        with self._lock:
            if self._session:
                try: self._session.close()
                except: pass
            self._session    = None
            self._fail_count += 1
            if self._fail_count >= 2 and self._healthy:
                self._healthy        = False
                self._cooldown_until = time.time() + self._COOLDOWN
                msg = (f"[SOCKS5Pool] 代理连续失败 {self._fail_count} 次，"
                       f"暂停 {self._COOLDOWN}s | 原因: {reason}")
                cprint(msg, 'error')
                db.add_log(msg, 'error')

    def invalidate(self):
        with self._lock:
            if self._session:
                self._session.close()
            self._session        = None
            self._healthy        = True
            self._fail_count     = 0
            self._cooldown_until = 0.0
            self._building       = False

    # ── 内部方法 ──────────────────────────────────────────────────────────

    @staticmethod
    def _do_connect(proxy_host, proxy_port, timeout) -> 'Socks5ProxySession':
        """建立 SOCKS5 TCP 控制连接，完成 UDP Associate 握手，返回 session。
        地址族选择：优先 IPv4（大多数本地代理只监听 127.0.0.1），
        IPv4 不可用时 fallback 到 IPv6。
        避免 localhost 在双栈系统默认解析到 ::1 但代理只监听 127.0.0.1 的问题。
        """
        infos = socket.getaddrinfo(proxy_host, proxy_port,
                                   socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"无法解析代理地址: {proxy_host}")
        # IPv6 优先：AF_INET6=10 > AF_INET=2，按 af 降序
        # IPv6 连接失败（端口未监听）时自动 fallback 到 IPv4
        # getaddrinfo 已读取 hosts 文件，localhost → ::1/127.0.0.1 均来自 hosts
        infos_sorted = sorted(infos, key=lambda x: x[0], reverse=True)

        last_err = None
        for af, _, _, _, proxy_sockaddr in infos_sorted:
            tcp = socket.socket(af, socket.SOCK_STREAM)
            tcp.settimeout(timeout)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  max(1, timeout))
                    tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                    tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
            except (OSError, AttributeError):
                pass
            try:
                tcp.connect(proxy_sockaddr)
                break   # 连接成功，跳出循环
            except OSError as e:
                last_err = e
                try: tcp.close()
                except: pass
                tcp = None
                continue
        else:
            raise OSError(f"代理连接失败（已尝试所有地址）: {last_err}")

        # TCP 连接成功，执行 SOCKS5 握手
        try:
            # 认证协商
            tcp.sendall(b'\x05\x01\x00')
            resp = Socks5ProxyPool._recv_exact(tcp, 2)
            if resp[0] != 0x05 or resp[1] != 0x00:
                raise OSError(f"SOCKS5 认证协商失败: {resp.hex()}")
            # UDP ASSOCIATE
            tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
            reply = Socks5ProxyPool._recv_exact(tcp, 4)
            if reply[1] != 0x00:
                raise OSError(f"SOCKS5 UDP Associate 被拒绝 REP={reply[1]:#x}")
            atyp = reply[3]
            if atyp == 0x01:
                relay_ip   = socket.inet_ntop(socket.AF_INET, Socks5ProxyPool._recv_exact(tcp, 4))
                relay_port = struct.unpack('!H', Socks5ProxyPool._recv_exact(tcp, 2))[0]
            elif atyp == 0x04:
                relay_ip   = socket.inet_ntop(socket.AF_INET6, Socks5ProxyPool._recv_exact(tcp, 16))
                relay_port = struct.unpack('!H', Socks5ProxyPool._recv_exact(tcp, 2))[0]
            elif atyp == 0x03:
                nlen       = Socks5ProxyPool._recv_exact(tcp, 1)[0]
                relay_ip   = Socks5ProxyPool._recv_exact(tcp, nlen).decode()
                relay_port = struct.unpack('!H', Socks5ProxyPool._recv_exact(tcp, 2))[0]
            else:
                raise OSError(f"未知 ATYP: {atyp}")
            if relay_ip in ('0.0.0.0', '::'):
                relay_ip = proxy_sockaddr[0]
            return Socks5ProxySession(tcp, (relay_ip, relay_port), af, timeout)
        except Exception:
            try: tcp.close()
            except: pass
            raise

    @staticmethod
    def _recv_exact(sock, n):
        buf = b''
        while len(buf) < n:
            c = sock.recv(n - len(buf))
            if not c:
                raise OSError("SOCKS5 TCP 控制连接提前关闭")
            buf += c
        return buf


# 全局连接池单例
_socks5_pool = Socks5ProxyPool()



class Socks5UdpSocket:
    """
    手动完成 SOCKS5 UDP Associate 握手，不依赖 PySocks。
    支持代理地址为 IPv4/IPv6/域名，目标地址也可以是 IPv4/IPv6/域名。
    TCP 控制连接启用 SO_KEEPALIVE，并由后台线程监控断开，断开时关闭 UDP socket
    使 recvfrom 立即抛出异常而不是永久阻塞。
    """
    def __init__(self, proxy_host, proxy_port, timeout=5):
        self.proxy_host  = proxy_host
        self.proxy_port  = proxy_port
        self.timeout     = timeout
        self._tcp_ctrl   = None
        self._udp_sock   = None
        self._relay_addr = None
        self._af         = None
        self._closed     = False
        self._monitor_thread = None

    def connect(self):
        # 1. 解析代理地址（AF_UNSPEC 同时支持 IPv4/IPv6 代理）
        infos = socket.getaddrinfo(self.proxy_host, self.proxy_port,
                                   socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"无法解析代理地址: {self.proxy_host}")
        self._af, _, _, _, proxy_sockaddr = infos[0]

        # 2. TCP 控制连接 + SO_KEEPALIVE
        self._tcp_ctrl = socket.socket(self._af, socket.SOCK_STREAM)
        self._tcp_ctrl.settimeout(self.timeout)
        # 启用 TCP keepalive，防止 NAT/防火墙静默断开
        self._tcp_ctrl.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            # Linux 精细参数：空闲 timeout 秒后开始探测，每 5s 一次，3 次失败则断
            if hasattr(socket, 'TCP_KEEPIDLE'):
                self._tcp_ctrl.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  max(1, self.timeout))
                self._tcp_ctrl.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                self._tcp_ctrl.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
        except (OSError, AttributeError):
            pass  # Windows 不支持精细参数，忽略
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

        # 6. TCP 控制连接改为带超时的阻塞读（原来是 None 无限阻塞）
        #    设成 timeout 秒，配合后台监控线程
        self._tcp_ctrl.settimeout(self.timeout)

        # 7. 启动后台线程监控 TCP 控制连接
        #    一旦代理断开 TCP，立即关闭 UDP socket，使 recvfrom 抛出异常
        self._monitor_thread = threading.Thread(
            target=self._ctrl_monitor, daemon=True)
        self._monitor_thread.start()

        return self

    def _ctrl_monitor(self):
        """监控 TCP 控制连接，断开时立即关闭 UDP socket 防止 recvfrom 永久阻塞"""
        try:
            while not self._closed:
                try:
                    # 尝试读1字节，正常代理不会主动发数据
                    # 返回空字节 = 连接已关闭
                    data = self._tcp_ctrl.recv(1)
                    if data == b'':
                        break  # 代理关闭了 TCP 控制连接
                except socket.timeout:
                    continue  # 超时正常，继续监控
                except OSError:
                    break     # 连接出错
        finally:
            # TCP 断开 → 强制关闭 UDP socket，让 recvfrom 立即报错
            if not self._closed and self._udp_sock:
                try: self._udp_sock.close()
                except: pass

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
        self._closed = True
        for s in (self._udp_sock, self._tcp_ctrl):
            if s:
                try: s.close()
                except: pass
        self._udp_sock = self._tcp_ctrl = None

# ==================== 网络工具 ====================
# GEO缓存：key=IP, value=geo dict。进程生命周期内永久缓存，重启自动清空。
_geo_cache: dict = {}
_geo_cache_lock = threading.Lock()

def _is_safe_public_ip(ip: str) -> bool:
    """校验 IP 是否为可公开查询的公网地址（排除内网/回环/链路本地）"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        # 排除：回环、私网、链路本地、多播、保留地址
        return (not addr.is_loopback and not addr.is_private and
                not addr.is_link_local and not addr.is_multicast and
                not addr.is_reserved and not addr.is_unspecified)
    except ValueError:
        return False  # 非IP格式（域名等）不查geo

def get_geo(ip: str) -> dict:
    # 先查缓存，命中直接返回，不发网络请求
    with _geo_cache_lock:
        cached = _geo_cache.get(ip)
        if cached and cached.get('country_code','XX') != 'XX':
            return cached   # 只用成功的缓存；XX 表示之前失败，允许重试
    result = {'country':'Unknown','country_code':'XX','isp':'Unknown'}
    # SSRF防护：仅对公网IP发起查询，私有/回环地址直接返回Unknown
    if not _is_safe_public_ip(ip):
        with _geo_cache_lock:
            _geo_cache[ip] = result
        return result
    # 未命中，请求 ip-api.com
    try:
        s = get_requests_session()
        import urllib.parse
        safe_ip = urllib.parse.quote(ip, safe=':.[]')
        r = s.get(f"http://ip-api.com/json/{safe_ip}?fields=country,countryCode,isp", timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get('countryCode') and d['countryCode'] != 'XX':
                result = {'country': d.get('country','Unknown'),
                          'country_code': d.get('countryCode','XX'),
                          'isp': d.get('isp','Unknown')}
                with _geo_cache_lock:
                    _geo_cache[ip] = result
                return result
    except Exception:
        pass
    # 失败时不写入缓存（下次检测轮次会重试）
    return result

def _resolve_system(domain: str):
    """模式1: 系统DNS — socket.getaddrinfo，与 nslookup/浏览器行为一致"""
    ips = []
    seen = set()
    for af, ver in [(socket.AF_INET, 'ipv4'), (socket.AF_INET6, 'ipv6')]:
        try:
            results = socket.getaddrinfo(domain, None, af, socket.SOCK_STREAM)
            for res in results:
                ip = res[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})
        except socket.gaierror:
            pass  # 无 IPv6/IPv4 记录属正常情况，不记日志
        except Exception as e:
            db.add_log(f"[system] DNS {ver} 异常 {domain}: {type(e).__name__}: {e}", 'debug')
    return ips


def _resolve_dnspython(domain: str):
    """模式2: dnspython 内置解析器（走 /etc/resolv.conf 或 Windows注册表DNS）"""
    ips = []
    seen = set()
    for rtype, ver in [('A', 'ipv4'), ('AAAA', 'ipv6')]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout  = CONFIG['timeout']
            resolver.lifetime = CONFIG['timeout']
            for rdata in resolver.resolve(domain, rtype):
                ip = str(rdata)
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass  # 无该类型记录，正常
        except Exception as e:
            db.add_log(f"[dnspython] DNS {rtype} {domain}: {type(e).__name__}: {e}", 'debug')
    return ips


def _resolve_custom(domain: str):
    """模式3: 自定义DNS服务器（支持多个，逗号分隔，如 8.8.8.8,8.8.4.4）"""
    servers_raw = CONFIG.get('dns_custom', '8.8.8.8').strip()
    servers = [s.strip() for s in servers_raw.replace('，', ',').split(',') if s.strip()]
    if not servers:
        servers = ['8.8.8.8']
    ips = []
    seen = set()
    for rtype, ver in [('A', 'ipv4'), ('AAAA', 'ipv6')]:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = servers
            resolver.timeout     = CONFIG['timeout']
            resolver.lifetime    = CONFIG['timeout']
            for rdata in resolver.resolve(domain, rtype):
                ip = str(rdata)
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            db.add_log(f"[custom:{','.join(servers)}] DNS {rtype} {domain}: {type(e).__name__}: {e}", 'debug')
    return ips


def resolve(domain: str):
    """根据 CONFIG['dns_mode'] 选择 DNS 解析策略"""
    mode = CONFIG.get('dns_mode', 'system')
    if mode == 'dnspython':
        ips = _resolve_dnspython(domain)
    elif mode == 'custom':
        ips = _resolve_custom(domain)
    else:  # 'system'（默认）
        ips = _resolve_system(domain)
    if not ips:
        db.add_log(f"DNS解析失败 {domain} [模式:{mode}]: 无结果", 'error')
        cprint(f"DNS解析失败 {domain} [模式:{mode}]", 'error')
    return ips

def _proxy_tcp_connect(ip, port, timeout):
    """通过 HTTP CONNECT 或 SOCKS5 代理建立 TCP 连接，返回已连接的 socket。
    支持:
      http://host:port   → HTTP CONNECT 隧道
      https://host:port  → HTTP CONNECT 隧道（同 http，SSL 由上层处理）
      socks5://host:port → SOCKS5 TCP 代理
      socks5://[IPv6]:port → SOCKS5 代理 IPv6 地址
    """
    proxy_url = CONFIG.get('http_proxy', '').strip()
    if not proxy_url:
        raise ValueError("no proxy configured")

    proxy_host, proxy_port = parse_proxy_addr(proxy_url)
    is_socks5 = 'socks5' in proxy_url.lower()

    # 连接到代理服务器（支持 IPv4/IPv6 代理地址）
    infos = socket.getaddrinfo(proxy_host, proxy_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"无法解析代理地址: {proxy_host}")
    paf, _, _, _, proxy_sockaddr = infos[0]
    s = socket.socket(paf, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(proxy_sockaddr)

    if is_socks5:
        # SOCKS5 握手: 认证协商
        s.sendall(b'\x05\x01\x00')
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
            s.close()
            raise OSError(f"SOCKS5 认证协商失败: {resp.hex()}")
        # SOCKS5 CONNECT 请求
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            # IPv6 目标 ATYP=0x04
            req = (b'\x05\x01\x00\x04'
                   + socket.inet_pton(socket.AF_INET6, ip)
                   + struct.pack('!H', port))
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET, ip)
                # IPv4 目标 ATYP=0x01
                req = (b'\x05\x01\x00\x01'
                       + socket.inet_pton(socket.AF_INET, ip)
                       + struct.pack('!H', port))
            except OSError:
                # 域名 ATYP=0x03
                host_b = ip.encode()
                req = (b'\x05\x01\x00\x03'
                       + bytes([len(host_b)]) + host_b
                       + struct.pack('!H', port))
        s.sendall(req)
        # 读取回复（至少10字节）
        reply = b''
        while len(reply) < 4:
            reply += s.recv(4 - len(reply))
        if reply[1] != 0x00:
            s.close()
            raise OSError(f"SOCKS5 CONNECT 被拒绝, REP={reply[1]:#x}")
        # 跳过剩余地址字段
        atyp = reply[3]
        if atyp == 0x01:   s.recv(4 + 2)
        elif atyp == 0x04: s.recv(16 + 2)
        elif atyp == 0x03:
            n = s.recv(1)[0]; s.recv(n + 2)
    else:
        # HTTP CONNECT 隧道
        # 目标地址: IPv6 需要方括号
        target = f"[{ip}]:{port}" if ':' in ip else f"{ip}:{port}"
        connect_req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n\r\n"
        s.sendall(connect_req.encode())
        # 读取响应头直到 \r\n\r\n
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = s.recv(256)
            if not chunk:
                s.close()
                raise OSError("HTTP CONNECT: 代理连接断开")
            buf += chunk
        first_line = buf.split(b'\r\n')[0].decode(errors='replace')
        # 检查 200 Connection established
        if '200' not in first_line:
            s.close()
            raise OSError(f"HTTP CONNECT 失败: {first_line}")

    return s  # 已通过代理建立的 TCP 连接


def tcp_ping(ip, port):
    """TCP 连接检测，支持 HTTP CONNECT 和 SOCKS5 代理，支持 IPv4/IPv6 目标。"""
    timeout = CONFIG['timeout']
    use_proxy = (CONFIG.get('proxy_enabled') and
                 CONFIG.get('http_proxy', '').strip())
    s = None
    try:
        if use_proxy:
            t = time.time()
            s = _proxy_tcp_connect(ip, port, timeout)
            lat = int((time.time() - t) * 1000)
        else:
            # 直连：getaddrinfo 自动处理 IPv4/IPv6 sockaddr 格式
            infos = socket.getaddrinfo(ip, port, type=socket.SOCK_STREAM)
            if not infos:
                return False, -1, "地址解析失败"
            fam, _, _, _, sockaddr = infos[0]
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(timeout)
            t = time.time()
            s.connect(sockaddr)
            lat = int((time.time() - t) * 1000)
        s.close()
        return True, lat, None
    except socket.timeout:
        if s:
            try: s.close()
            except: pass
        return False, -1, f"超时(>{timeout}s)"
    except ConnectionRefusedError:
        return False, -1, "连接被拒绝"
    except OSError as e:
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        if s:
            try: s.close()
            except: pass
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


def _socks5_sendto(udp_sock: socket.socket, data: bytes,
                   dst: tuple, relay_addr: tuple):
    """封装 SOCKS5 UDP 头并发往 relay，支持 IPv4/IPv6 目标"""
    dst_host, dst_port = dst
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
            hb  = dst_host.encode()
            hdr = (b'\x00\x00\x00\x03' + bytes([len(hb)]) + hb
                   + struct.pack('!H', dst_port))
    udp_sock.sendto(hdr + data, relay_addr)


def _socks5_strip(raw: bytes) -> bytes | None:
    """剥离 SOCKS5 UDP 头，返回 payload；格式错误返回 None"""
    if len(raw) < 10:
        return None
    atyp = raw[3]
    if atyp == 0x01:   # IPv4
        return raw[10:] if len(raw) >= 10 else None
    if atyp == 0x04:   # IPv6
        return raw[22:] if len(raw) >= 22 else None
    if atyp == 0x03:   # 域名
        nlen = raw[4]
        return raw[7 + nlen:] if len(raw) >= 7 + nlen else None
    return None


def udp_ping(ip, port):
    """UDP Tracker BEP 15 握手检测。
    代理路径: 使用 Socks5UdpSocket（手动SOCKS5协议，支持IPv4/IPv6目标，不依赖PySocks）。
    直连路径: 使用 getaddrinfo 获取正确 sockaddr，原生支持 IPv4/IPv6。
    """
    udp_proxy = CONFIG.get('udp_proxy', '').strip() if CONFIG.get('proxy_enabled') else ''
    packet  = _udp_tracker_packet()
    timeout = CONFIG['timeout']
    tid     = packet[12:16]  # transaction_id bytes，用于校验响应

    # ── SOCKS5 代理路径：每线程独立 UDP socket，共享 TCP 控制连接 ─────────
    if udp_proxy and 'socks5' in udp_proxy.lower():

        # 健康检查：代理冷却中 → 直接短路
        healthy, reason = _socks5_pool.check_healthy()
        if not healthy:
            return False, -1, f"{_PROXY_UNAVAIL_PREFIX}{reason}"

        for attempt in range(2):
            try:
                session = _socks5_pool.acquire_session(udp_proxy, timeout)
                if not session.valid:
                    raise _ProxyConnectError("session 已失效")

                t_start = time.time()
                cprint(f'[SOCKS5] → {ip}:{port} relay={session.relay_addr}', 'debug')
                data = session.send_and_recv(packet, (ip, port), timeout)

                lat = int((time.time() - t_start) * 1000)
                if len(data) >= 16 and struct.unpack('!L', data[:4])[0] == 0:
                    _socks5_pool.report_success()
                    return True, lat, None
                return False, -1, "无效响应"

            except socket.timeout:
                return False, -1, f"超时(>{timeout}s)"

            except _ProxyConnectError as e:
                if attempt == 0:
                    cprint(f'[SOCKS5Pool] 建连失败，重试: {e}', 'debug')
                    time.sleep(0.2)
                    continue
                _socks5_pool.report_failure(str(e))
                return False, -1, f"{_PROXY_UNAVAIL_PREFIX}代理连接失败"

            except Exception as e:
                err_str = f"{type(e).__name__}: {e}"
                _socks5_pool.report_failure(err_str)
                if attempt == 0:
                    cprint(f'[SOCKS5Pool] 通信异常，重建后重试: {err_str}', 'debug')
                    packet = _udp_tracker_packet()
                    continue
                return False, -1, f"代理通信失败: {err_str}"

    # ── 直连路径（getaddrinfo 自动处理 IPv4/IPv6 sockaddr 格式）──────────
    s = None
    try:
        infos = socket.getaddrinfo(ip, port, type=socket.SOCK_DGRAM)
        if not infos:
            return False, -1, "地址解析失败"
        fam, _, _, _, sockaddr = infos[0]

        s = socket.socket(fam, socket.SOCK_DGRAM)
        # 加大接收缓冲区，高并发时防止内核丢包
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError: pass

        # 显式 bind：固定本地监听端口，高并发时防止端口被OS回收或复用
        bind_addr = ('::' if fam == socket.AF_INET6 else '', 0)
        s.bind(bind_addr)
        # connect() 使 socket 进入"已连接"状态：
        # - Windows/Linux 都会把 ICMP Port Unreachable 反映为 socket 异常
        # - 对方端口关闭时立刻抛 ConnectionRefusedError，不傻等 timeout
        # - recv() 只接收来自目标地址的包，自动过滤无关UDP包
        s.connect(sockaddr)
        s.settimeout(timeout)

        t = time.time()
        s.send(packet)  # connect后用 send 代替 sendto

        # 接收并校验 transaction_id
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise socket.timeout()
            # 防止 remaining 极小时 settimeout 抖动触发误判
            s.settimeout(max(remaining, 0.05))
            data = s.recv(1024)  # connect后用 recv，ICMP错误会在这里抛出
            if len(data) >= 8 and data[4:8] == tid:
                break

        lat = int((time.time() - t) * 1000)
        if len(data) >= 16 and struct.unpack('!L', data[:4])[0] == 0:
            return True, lat, None
        return False, -1, "无效响应"

    except socket.timeout:
        return False, -1, f"超时(>{timeout}s)"
    except ConnectionRefusedError:
        return False, -1, "端口未开放"
    except OSError as e:
        # ICMP Port Unreachable 在 Windows 上表现为 WinError 10054
        if getattr(e, 'winerror', None) == 10054 or 'forcibly closed' in str(e).lower():
            return False, -1, "端口未开放"
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        return False, -1, f"{type(e).__name__}: {e}"
    finally:
        # 无论任何路径退出都确保 socket 关闭，彻底回收端口
        if s:
            try: s.close()
            except: pass


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
# 代理不可用时的哨兵错误前缀，check_ip/_check_one 识别后跳过状态更新
_PROXY_UNAVAIL_PREFIX = 'PROXY_UNAVAIL:'

def _is_proxy_unavail(err: str) -> bool:
    return bool(err and err.startswith(_PROXY_UNAVAIL_PREFIX))


def check_ip(domain, ip_info, retry=True):
    ip   = ip_info['ip']
    with db.lock:
        td       = db.trackers.get(domain, {})
        port     = td.get('port', 80)
        protocol = td.get('protocol', 'tcp')

    fn = udp_ping if protocol == 'udp' else tcp_ping
    ok, lat, err = fn(ip, port)

    # 代理不可用 → 跳过重试和状态更新，保留上次状态不变
    if not ok and _is_proxy_unavail(err):
        return 'skipped', lat, err

    if not ok and retry:
        wait = get_retry_wait(domain)
        cprint(f"首次失败 {domain}:{port} ({ip}) 等待{wait}s重试 | {err}", 'debug')
        time.sleep(wait)
        ok, lat, err = fn(ip, port)
        # 重试后再次判断
        if not ok and _is_proxy_unavail(err):
            return 'skipped', lat, err

    status = 'online' if ok else 'offline'
    db.update_status(domain, ip, status, lat)
    return status, lat, err

def _resolve_and_update(domain, port, protocol):
    """每轮检测前重新解析 DNS，更新 IP 列表（合并新IP，标记消失IP，DNS失败保留旧缓存）"""
    is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain)) or (':' in domain and '.' not in domain)
    if is_ip:
        return  # 纯 IP 模式无需解析
    try:
        new_ips = resolve(domain)
        db.update_ips(domain, new_ips, dns_error=(not new_ips))
        if new_ips:
            cprint(f"DNS刷新 {domain}: {len(new_ips)}个IP", 'debug')
        else:
            cprint(f"DNS刷新失败 {domain}: 无结果，保留缓存IP", 'error')
            db.add_log(f"DNS解析失败 {domain}: 保留缓存IP继续检测", 'error')
    except Exception as e:
        db.update_ips(domain, [], dns_error=True)
        cprint(f"DNS刷新异常 {domain}: {e}", 'error')


def _check_one(domain, ip_info):
    """单个 IP 检测任务，供线程池调用"""
    ip = ip_info['ip']
    # 已标记 removed 的 IP 仍然检测（保留到重启），只是在前端会标注
    with db.lock:
        td       = db.trackers.get(domain, {})
        port     = td.get('port', 80)
        protocol = td.get('protocol', 'tcp')
    proto_s = protocol.upper()
    try:
        status, lat, err = check_ip(domain, ip_info, retry=True)
        lat_s = f"{lat}ms" if lat >= 0 else "N/A"
        if status == 'skipped':
            cprint(f"⏭ {proto_s}://{domain}:{port} ({ip}) 跳过 | {err}", 'debug')
        elif status == 'online':
            msg = f"✓ {proto_s}://{domain}:{port} ({ip}) {lat_s}"
            db.add_log(msg, 'success')
            cprint(msg, 'success')
        else:
            reason = f" | {err}" if err else ""
            msg = f"✗ {proto_s}://{domain}:{port} ({ip}) 离线{reason}"
            db.add_log(msg, 'error')
            cprint(msg, 'error')
        # 若该 IP 归属地未知，顺带补查（锁外查询，避免长时间持锁）
        need_geo = False
        with db.lock:
            for ip_obj in db.trackers.get(domain, {}).get('ips', []):
                if ip_obj.get('ip') == ip:
                    need_geo = ip_obj.get('country', {}).get('country_code', 'XX') == 'XX'
                    break
        if need_geo:
            new_geo = get_geo(ip)  # 网络请求在锁外
            if new_geo.get('country_code', 'XX') != 'XX':
                with db.lock:
                    for ip_obj in db.trackers.get(domain, {}).get('ips', []):
                        if ip_obj.get('ip') == ip:
                            ip_obj['country'] = new_geo
                            break
    except Exception as e:
        msg = f"检查异常 {domain}:{port} ({ip}): {type(e).__name__}: {e}"
        db.add_log(msg, 'error')
        cprint(msg, 'error')


# ==================== 网络探针 ====================
# 双重网络健康判断：
#   方案A（探针）：后台定期 TCP 连接 8.8.8.8:53，维护 _probe_ok 状态
#   方案B（失败率）：monitor_loop 每轮统计，≥90% 失败视为本地网络异常
# 两种方案任一触发，即认定本地网络异常，跳过本轮历史写入

_probe_ok   = True    # 探针当前状态（True=可达，False=不可达）
_probe_lock = threading.Lock()

def _probe_loop():
    """后台探针线程：与监控间隔同步检测 8.8.8.8:53，更新 _probe_ok 状态。"""
    global _probe_ok
    _warned = False
    PROBE_HOST = '8.8.8.8'
    PROBE_PORT = 53
    PROBE_TIMEOUT = 3

    while True:
        probe_interval = CONFIG.get('check_interval', 30)  # 与监控间隔同步
        try:
            s = socket.create_connection((PROBE_HOST, PROBE_PORT), timeout=PROBE_TIMEOUT)
            s.close()
            reachable = True
        except Exception:
            reachable = False

        with _probe_lock:
            prev = _probe_ok
            _probe_ok = reachable

        if not reachable and not _warned:
            msg = f"[探针] 无法连接 {PROBE_HOST}:{PROBE_PORT}，本地网络可能异常"
            db.add_log(msg, 'error')
            cprint(msg, 'error')
            _warned = True
        elif reachable and _warned:
            msg = f"[探针] 网络已恢复，{PROBE_HOST}:{PROBE_PORT} 可达"
            db.add_log(msg, 'info')
            cprint(msg, 'info')
            _warned = False

        time.sleep(probe_interval)


# 立即检测触发器：启动时或添加 tracker 后置位，monitor_loop 检测到后立即执行（不等待 check_interval）
_check_now = threading.Event()

def monitor_loop():
    db.add_log("监控服务启动", 'info')
    cprint("监控服务启动", 'info')
    _net_warn_printed = False   # 本次网络异常告警只打一次，恢复后重置

    while True:
        try:
            snapshot = db.get_trackers()

            # ── 第一步：并行重新解析所有域名 DNS ─────────────────────────
            with ThreadPoolExecutor(max_workers=32) as dns_pool:
                dns_futures = {
                    dns_pool.submit(_resolve_and_update,
                                    domain,
                                    data.get('port', 80),
                                    data.get('protocol','tcp')): domain
                    for domain, data in snapshot.items()
                }
                for f in as_completed(dns_futures):
                    try: f.result()
                    except Exception as e:
                        cprint(f"DNS线程异常: {e}", 'error')

            # ── 第二步：并行检测所有 IP ───────────────────────────────────
            snapshot = db.get_trackers()
            tasks = []
            for domain, data in snapshot.items():
                if data.get('paused'):        # 整个域名暂停，跳过
                    continue
                for ip_info in data.get('ips', []):
                    if not ip_info.get('removed') and not ip_info.get('paused'):
                        tasks.append((domain, ip_info))

            # 用计数器收集本轮检测结果，检测完后判断网络健康度
            _round_ok  = [0]
            _round_fail = [0]
            _round_lock = threading.Lock()

            def _check_one_counted(domain, ip_info):
                ip = ip_info['ip']
                with db.lock:
                    td       = db.trackers.get(domain, {})
                    port     = td.get('port', 80)
                    protocol = td.get('protocol', 'tcp')
                proto_s = protocol.upper()
                try:
                    status, lat, err = check_ip(domain, ip_info, retry=True)
                    lat_s = f"{lat}ms" if lat >= 0 else "N/A"
                    if status == 'skipped':
                        cprint(f"⏭ {proto_s}://{domain}:{port} ({ip}) 跳过 | {err}", 'debug')
                    elif status == 'online':
                        msg = f"✓ {proto_s}://{domain}:{port} ({ip}) {lat_s}"
                        db.add_log(msg, 'success')
                        cprint(msg, 'success')
                        with _round_lock: _round_ok[0] += 1
                    else:
                        reason = f" | {err}" if err else ""
                        msg = f"✗ {proto_s}://{domain}:{port} ({ip}) 离线{reason}"
                        db.add_log(msg, 'error')
                        cprint(msg, 'error')
                        with _round_lock: _round_fail[0] += 1
                except Exception as e:
                    msg = f"检查异常 {domain}:{port} ({ip}): {type(e).__name__}: {e}"
                    db.add_log(msg, 'error')
                    cprint(msg, 'error')
                    with _round_lock: _round_fail[0] += 1

            with ThreadPoolExecutor(max_workers=max(8, CONFIG.get('monitor_workers', 120))) as chk_pool:
                futures = {chk_pool.submit(_check_one_counted, d, ipi): (d, ipi['ip'])
                           for d, ipi in tasks}
                for f in as_completed(futures):
                    try: f.result()
                    except Exception as e:
                        d, ip = futures[f]
                        cprint(f"检测线程异常 {d} ({ip}): {e}", 'error')

            # ── 第三步：网络健康判断（探针 + 失败率双重保障）────────────
            total_checked = _round_ok[0] + _round_fail[0]
            net_ok = True
            net_reason = ''

            # 方案A：探针状态（由 _probe_loop 后台维护）
            with _probe_lock:
                probe_reachable = _probe_ok
            if not probe_reachable:
                net_ok = False
                net_reason = '探针不可达(8.8.8.8:53)'

            # 方案B：本轮失败率 ≥ 90%（仅在探针正常时才额外判断，避免重复告警）
            if net_ok and total_checked >= 5:
                fail_rate = _round_fail[0] / total_checked
                if fail_rate >= 0.90:
                    net_ok = False
                    net_reason = f'失败率{fail_rate*100:.0f}%({_round_fail[0]}/{total_checked})'

            if not net_ok:
                if not _net_warn_printed:
                    warn_msg = (f"[网络异常] 疑似本地网络故障（{net_reason}），"
                                f"本轮历史数据不计入统计")
                    db.add_log(warn_msg, 'error')
                    cprint(warn_msg, 'error')
                    _net_warn_printed = True
                _check_now._net_bad = True
            else:
                if _net_warn_printed:
                    recover_msg = "[网络恢复] 探针与检测均正常，恢复历史数据统计"
                    db.add_log(recover_msg, 'info')
                    cprint(recover_msg, 'info')
                _net_warn_printed = False
                _check_now._net_bad = False

            s = db.get_stats()
            summary = (f"轮检完成 | "
                       f"总:{s['total']} [v4:{s['ipv4']} v6:{s['ipv6']}] | "
                       f"在线:{s['alive']} [v4:{s['alive_v4']} v6:{s['alive_v6']}]"
                       + (" | ⚠ 网络异常轮次，历史跳过" if not net_ok else ""))
            db.add_log(summary, 'info')
            if net_ok and CONFIG.get('cache_history', True):
                db._save()

        except Exception as e:
            msg = f"监控线程错误: {type(e).__name__}: {e}"
            db.add_log(msg, 'error')
            cprint(msg, 'error')
        # 等待下一轮：check_interval 秒超时，或被 _check_now 提前唤醒
        _check_now.wait(timeout=CONFIG['check_interval'])
        _check_now.clear()

# ==================== 请求日志中间件 ====================
# 批量请求去重：记录最近一次页面请求的时间戳，短时间内的 API 批量请求只打印一行摘要
_last_page_request = {'time': 0, 'remote': '', 'logged': False}
_page_req_lock = threading.Lock()

@app.before_request
def log_request():
    """记录初始化批量加载提示（仅在页面首次加载时）"""
    path   = request.path
    method = request.method
    remote = request.remote_addr
    now    = time.time()

    if path.startswith('/api/'):
        if path.split('?')[0].rstrip('/') in _NOISY_PATHS:
            return
        with _page_req_lock:
            is_init = (now - _last_page_request['time'] < 2.0 and
                       remote == _last_page_request['remote'])
            if is_init and not _last_page_request['logged']:
                _last_page_request['logged'] = True
    elif path == '/':
        with _page_req_lock:
            _last_page_request['time']   = now
            _last_page_request['remote'] = remote
            _last_page_request['logged'] = False

@app.after_request
def security_headers(response):
    # ── 安全响应头 ──
    response.headers['X-Frame-Options']        = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy']        = 'same-origin'
    # Server 头不暴露服务器特征，直接移除
    response.headers.remove('Server')

    path   = request.path
    method = request.method

    # ── 静态资源长缓存（JS/CSS/字体）：1年，CF 会缓存，极少回源 ──
    if path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return response

    # ── JSON API gzip 压缩（浏览器支持时，响应 >1KB 才压缩）──
    # 文件下载（Content-Disposition）跳过，避免对已压缩内容二次压缩
    ct = response.content_type or ''
    if ('application/json' in ct or 'text/plain' in ct) \
            and not response.headers.get('Content-Disposition'):
        accept_enc = request.headers.get('Accept-Encoding', '')
        if 'gzip' in accept_enc and not response.headers.get('Content-Encoding'):
            try:
                raw = response.get_data(as_text=False)
                if len(raw) > 1024:   # 小响应不压缩，省 CPU
                    gz = _gzip.compress(raw, compresslevel=6)
                    response.set_data(gz)
                    response.headers['Content-Encoding'] = 'gzip'
                    response.headers['Vary'] = 'Accept-Encoding'
                    response.headers['Content-Length'] = str(len(gz))
            except Exception:
                pass

    # 静默路径（前端内部轮询/导航）：不打印日志
    if path.split('?')[0].rstrip('/') in _NOISY_PATHS:
        return response

    # ── Nginx 风格访问日志 ──
    real_ip   = request.headers.get('X-Real-IP', request.remote_addr)
    cf_ip     = request.headers.get('CF-Connecting-IP', '-')
    now_str   = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0800')
    status    = response.status_code
    # send_file 等流式响应 get_data() 为空，优先从 Content-Length header 读
    try:
        cl_header = response.headers.get('Content-Length')
        if cl_header is not None:
            size = int(cl_header)
        else:
            data = response.get_data(as_text=False)
            size = len(data) if data else 0
    except Exception:
        size = 0
    full_path = request.full_path.rstrip('?') if request.query_string else path

    # 业务注解：路由函数可通过 g.access_note 附加一行说明（如登录用户、重试摘要）
    note = getattr(g, 'access_note', None)

    line = f'{real_ip} - {cf_ip} - - [{now_str}] "{method} {full_path} HTTP/1.1" {status} {size}'
    if note:
        line += f'  # {note}'

    cprint(line, 'info', raw=True)
    _write_access_log(line)   # 写盘（log_to_disk=True 时）

    return response

# ==================== HTML 路由 ====================
def find_html():
    base = os.path.dirname(os.path.abspath(__file__))
    for p in [os.path.join(base,'templates','index.html'), os.path.join(base,'index.html')]:
        if os.path.exists(p): return p
    return None

import gzip as _gzip

# ── HTML 内容缓存（避免每次读盘，mtime变化时自动失效）──
_html_cache = {'mtime': 0, 'raw': b'', 'gz': b'', 'etag': ''}

def _load_html(path: str) -> dict:
    """读取并缓存 HTML；文件修改时自动重新加载"""
    mtime = os.path.getmtime(path)
    if _html_cache['mtime'] == mtime and _html_cache['raw']:
        return _html_cache
    with open(path, 'rb') as f:
        raw = f.read()
    gz = _gzip.compress(raw, compresslevel=9)
    etag = hashlib.md5(raw).hexdigest()
    _html_cache.update({'mtime': mtime, 'raw': raw, 'gz': gz, 'etag': etag})
    return _html_cache

@app.route('/')
def index():
    p = find_html()
    if not p:
        return "index.html not found.", 404

    cache = _load_html(p)
    etag  = f'"{cache["etag"]}"'

    # ── ETag 缓存：若浏览器已有最新版本，返回 304 ──
    if request.headers.get('If-None-Match') == etag:
        resp = make_response('', 304)
        resp.headers['ETag'] = etag
        return resp

    # ── 判断浏览器是否支持 gzip ──
    accept_gz = 'gzip' in request.headers.get('Accept-Encoding', '')
    body      = cache['gz'] if accept_gz else cache['raw']

    resp = make_response(body, 200)
    resp.headers['Content-Type']  = 'text/html; charset=utf-8'
    resp.headers['ETag']          = etag
    resp.headers['Cache-Control'] = 'no-cache'   # 每次验证 ETag，命中则304
    if accept_gz:
        resp.headers['Content-Encoding'] = 'gzip'
        resp.headers['Vary']             = 'Accept-Encoding'
    return resp

# ==================== API ====================

# ── 认证 ──
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    client = _client_ip()
    # 先纯检查是否已被锁定（不记录失败次数）
    with _login_fail_lock:
        rec = _login_fail.get(client, [0, 0, False])
        locked_until = rec[1] if len(rec) > 1 else 0
        if locked_until > time.time():
            remaining = int(locked_until - time.time())
            # 锁定期间的重复请求：nginx access log 照常记 429，不额外 cprint（已打印过一次）
            return jsonify({'error': f'登录尝试过多，请 {remaining//60} 分 {remaining%60} 秒后再试'}), 429

    data = request.json or {}
    username = (data.get('username','') or '').strip()
    password = data.get('password','') or ''
    if not username or len(username) > 64 or len(password) > 256:
        _login_check_and_record(client, False)
        return jsonify({'error': '用户名或密码错误'}), 401
    user = _find_user(username)
    if not user:
        secrets.compare_digest('a', 'b')
        _login_check_and_record(client, False)
        return jsonify({'error': '用户名或密码错误'}), 401
    stored_salt = user.get('salt')
    if not _verify_pw(password, user['password'], stored_salt):
        _login_check_and_record(client, False)
        return jsonify({'error': '用户名或密码错误'}), 401
    # 登录成功：清除失败计数
    _login_check_and_record(client, True)
    if not stored_salt:
        new_hash, new_salt = _hash_pw(password)
        user['password'] = new_hash
        user['salt']     = new_salt
        persist_config(CONFIG)
        cprint(f'[auth] 用户 {username} 密码格式已迁移至 PBKDF2+盐', 'info')
    session['username'] = username
    session['role'] = user['role']
    session.permanent = True
    g.access_note = f"login [{username}] role={user['role']}"
    return jsonify({'success': True, 'username': username, 'role': user['role']})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    username = session.get('username','?')
    session.clear()
    g.access_note = f"logout [{username}]"
    return jsonify({'success': True})

@app.route('/api/auth/change-password', methods=['POST'])
def api_change_password():
    """已登录用户修改自己的密码，需验证旧密码"""
    role = session.get('role')
    if not role:
        return jsonify({'error': '请先登录'}), 403
    username = session.get('username')
    data = request.json or {}
    old_pw  = data.get('old_password', '')
    new_pw  = data.get('new_password', '')
    # 基本校验
    if not old_pw or not new_pw:
        return jsonify({'error': '旧密码和新密码不能为空'}), 400
    if len(new_pw) < 6:
        return jsonify({'error': '新密码长度不能少于6位'}), 400
    if len(new_pw) > 256:
        return jsonify({'error': '密码过长'}), 400
    user = _find_user(username)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    # 验证旧密码
    if not _verify_pw(old_pw, user['password'], user.get('salt')):
        g.access_note = f"chpw [{username}] 旧密码错误"
        return jsonify({'error': '旧密码错误'}), 401
    # 更新为新密码（PBKDF2+盐）
    new_hash, new_salt = _hash_pw(new_pw)
    user['password'] = new_hash
    user['salt']     = new_salt
    persist_config(CONFIG)
    g.access_note = f"chpw [{username}] 密码已更新"
    return jsonify({'success': True})

@app.route('/api/auth/whoami')
def api_whoami():
    role = session.get('role')
    if not role:
        return jsonify({'logged_in': False, 'role': None, 'username': None})
    return jsonify({'logged_in': True, 'role': role, 'username': session.get('username')})

@app.route('/api/stats')
def api_stats():
    s = db.get_stats()
    # 网络健康状态：探针 + 上一轮失败率综合判断
    with _probe_lock:
        probe_ok = _probe_ok
    s['net_probe_ok'] = probe_ok
    s['net_healthy']  = probe_ok and not getattr(_check_now, '_net_bad', False)
    # 今日告警次数：统计今日日志中 error 级别且含「离线」的条目
    today = datetime.now().strftime('%Y-%m-%d')
    logs = db.get_logs(limit=5000)
    s['today_alerts'] = sum(
        1 for l in logs
        if l.get('level') == 'error'
        and l.get('time', '').startswith(today)
        and ('离线' in l.get('message', '') or 'offline' in l.get('message', '').lower())
    )
    return jsonify(s)

@app.route('/api/trackers')
def api_trackers():
    return jsonify(db.get_trackers())



@app.route('/api/tracker/add', methods=['POST'])
@_require_role('admin', 'operator')
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
        protocol = scheme if scheme in ('udp','https') else 'tcp'  # https://xxx 记为 https
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
        db.add_log(f"[{_client_ip()}] {msg}", 'info')
        g.access_note = f"add {protocol.upper()}://{host}:{port} ({len(ips)} IPs)"
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
    # 触发 monitor_loop 立即进行下一轮全量检测（不等待 check_interval）
    _check_now.set()
    return jsonify({'success':True,'added':len(results),'results':results,'errors':errors})

@app.route('/api/tracker/delete', methods=['POST'])
@_require_role('admin', 'operator')
def api_delete():
    domain = (request.json or {}).get('domain','').strip()
    with db.lock:
        if domain in db.trackers:
            del db.trackers[domain]
            db._recalc()
            db._save()
            msg = f"删除 {domain}"
            db.add_log(f"[{_client_ip()}] {msg}", 'info')
            g.access_note = f"delete {domain}"
            return jsonify({'success':True})
    return jsonify({'error':'不存在'}), 404

@app.route('/api/tracker/pause', methods=['POST'])
@_require_role('admin', 'operator')
def api_pause():
    """暂停/恢复监控。支持：整个域名、域名下单个IP、全部域名。
    body: { action: 'pause'|'resume', domain?: str, ip?: str, all?: bool }
    """
    data   = request.json or {}
    action = data.get('action', 'pause')   # 'pause' | 'resume'
    paused = (action == 'pause')
    domain = data.get('domain', '').strip()
    ip     = data.get('ip', '').strip()
    all_   = data.get('all', False)

    changed = []
    with db.lock:
        if all_:
            # 全部域名暂停/恢复
            for d, td in db.trackers.items():
                td['paused'] = paused
                for ip_obj in td.get('ips', []):
                    ip_obj['paused'] = paused
                changed.append(d)
        elif domain and ip:
            # 单个 IP
            td = db.trackers.get(domain)
            if not td:
                return jsonify({'error': '域名不存在'}), 404
            for ip_obj in td.get('ips', []):
                if ip_obj['ip'] == ip:
                    ip_obj['paused'] = paused
                    changed.append(f"{domain}/{ip}")
                    break
        elif domain:
            # 整个域名
            td = db.trackers.get(domain)
            if not td:
                return jsonify({'error': '域名不存在'}), 404
            td['paused'] = paused
            for ip_obj in td.get('ips', []):
                ip_obj['paused'] = paused
            changed.append(domain)
        else:
            return jsonify({'error': '参数错误'}), 400

        db._save()

    label = '暂停' if paused else '恢复'
    target = 'ALL' if all_ else (f"{domain}/{ip}" if ip else domain)
    g.access_note = f"{label} {target}"
    db.add_log(f"[{_client_ip()}] 监控{label}: {target}", 'info')
    return jsonify({'success': True, 'paused': paused, 'changed': changed})

@app.route('/api/tracker/check', methods=['POST'])
@_require_role('admin', 'operator', 'viewer')
def api_check():
    role = _current_role()
    # viewer: 限速 1000ms；operator: 限速 500ms；admin: 不限
    if role == 'viewer':
        if not _check_retry_throttle(1000):
            return jsonify({'error': '操作过于频繁，请稍候'}), 429
    elif role == 'operator':
        if not _check_retry_throttle(500):
            return jsonify({'error': '操作过于频繁，请稍候'}), 429
    domain    = (request.json or {}).get('domain','').strip()
    target_ip = (request.json or {}).get('ip', None)
    with db.lock:
        if domain not in db.trackers:
            return jsonify({'error':'不存在'}), 404
        port     = db.trackers[domain].get('port', 80)
        protocol = db.trackers[domain].get('protocol','tcp')
        ips_snap = list(db.trackers[domain]['ips'])
    tag = f" IP:{target_ip}" if target_ip else " 全部IP"
    results = []
    for ipi in ips_snap:
        if target_ip and ipi['ip'] != target_ip: continue
        status, lat, err = check_ip(domain, ipi, retry=False)
        lat_s = f"{lat}ms" if lat>=0 else "N/A"
        now = datetime.now()
        ts = f"{now.year}/{now.month}/{now.day} {now.strftime('%H:%M:%S')}"
        if status == 'skipped':
            reason_clean = err.replace(_PROXY_UNAVAIL_PREFIX, '') if err else ''
            res_msg = f"重试结果: {protocol.upper()}://{domain}:{port} ({ipi['ip']}) → 跳过(代理不可用) | {reason_clean}"
            cprint(f"{ts} [INFO] 重试结果: {protocol.upper()}://{domain}:{port} ({ipi['ip']}) → 跳过(代理不可用)", 'info', raw=True)
        else:
            reason = f" | {err}" if err and status=='offline' else ""
            res_msg = f"重试结果: {protocol.upper()}://{domain}:{port} ({ipi['ip']}) → {status} {lat_s}{reason}"
            cprint(f"{ts} [INFO] 重试结果: {protocol.upper()}://{domain}:{port} ({ipi['ip']}) → {status} {lat_s}{reason}", 'info', raw=True)
        db.add_log(res_msg, 'info')
        results.append({'ip':ipi['ip'],'status':status,'latency':lat,'error':err})
    # after_request 自动输出 nginx 行，无需 g.access_note（避免重复信息）
    return jsonify({'success':True,'domain':domain,'port':port,'protocol':protocol,'results':results})

@app.route('/api/ranking/<period>')
def api_ranking(period):
    if period not in ('24h','7d','30d'): period='24h'
    min_uptime = request.args.get('min_uptime', 0, type=float)
    return jsonify({'period':period,'ranking':db.get_ranking(period, 200, min_uptime)})


@app.route('/api/ranking/export')
def api_ranking_export():
    """导出排行榜为纯文本，每行一个 tracker URL（含协议头），域名之间空一行分隔。
    参数:
      period    = 24h | 7d | 30d  (默认 24h)
      min_uptime= 0~100           (最低可用率过滤，默认 0)
      proto     = tcp | udp | all (协议过滤，默认 all)
      ip_ver    = ipv4 | ipv6 | all (IP版本过滤，默认 all)
      suffix    = /announce        (追加路径，默认 /announce)
    """
    period     = request.args.get('period', '24h')
    if period not in ('24h','7d','30d'): period = '24h'
    min_uptime = request.args.get('min_uptime', 0, type=float)
    proto      = request.args.get('proto', 'all').lower()      # tcp | udp | all
    ip_ver     = request.args.get('ip_ver', 'all').lower()     # ipv4 | ipv6 | all
    suffix     = request.args.get('suffix', CONFIG.get('export_suffix', '/announce'))

    ranking = db.get_ranking(period, 9999, min_uptime)

    lines = []
    with db.lock:
        trackers_snap = {k: dict(v) for k, v in db.trackers.items()}

    for item in ranking:
        domain   = item['domain']
        td       = trackers_snap.get(domain, {})
        protocol = td.get('protocol', 'tcp')   # tcp / https / udp
        port     = td.get('port', 80)
        ips      = td.get('ips', [])

        # 协议过滤
        is_udp = (protocol == 'udp')
        if proto == 'tcp' and is_udp: continue
        if proto == 'udp' and not is_udp: continue

        # IP版本过滤（检查该域名下是否有符合版本的 IP）
        if ip_ver != 'all':
            has_ver = any(ip.get('version') == ip_ver for ip in ips if not ip.get('removed'))
            if not has_ver: continue

        # 构造 URL
        if protocol == 'https':
            scheme = 'https'
        elif protocol == 'udp':
            scheme = 'udp'
        else:
            scheme = 'http'

        url = f"{scheme}://{domain}:{port}{suffix}"
        lines.append(url)

    text = '\n'.join(lines)
    response = make_response(text)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename="trackers-{period}.txt"'
    return response


# 是否信任反向代理的 X-Forwarded-For 头（直接暴露到公网时务必关闭，否则可伪造IP）
# 仅在本机有反向代理（nginx/caddy 等）时设为 True
_TRUST_PROXY_HEADER = False

def _client_ip():
    """获取客户端IP。默认只信任 remote_addr，不信任 X-Forwarded-For（防伪造）。
    仅在 _TRUST_PROXY_HEADER=True 且有反向代理时才读取该头。"""
    if _TRUST_PROXY_HEADER:
        fwd = request.headers.get('X-Forwarded-For', '')
        if fwd:
            # 取最后一个可信跳（防止 XFF 链伪造）
            return fwd.split(',')[-1].strip()
    return request.remote_addr

@app.route('/api/nav', methods=['POST'])
def api_nav():
    """前端切换页面时调用，让控制台显示导航记录"""
    data = request.json or {}
    tab  = data.get('tab', '?')
    tab_names = {
        'dashboard': '仪表盘', 'trackers': 'Tracker列表',
        'ranking': '可用率排行', 'logs': '日志', 'config': '配置'
    }
    if tab in tab_names:
        g.access_note = f"nav [{tab_names[tab]}]"
    return jsonify({'ok': True})

@app.route('/api/logs')
def api_logs():
    limit = min(request.args.get('limit', 300, type=int), 5000)
    return jsonify(db.get_logs(limit))

@app.route('/api/logs/clear', methods=['POST'])
@_require_role('admin')
def api_clear_logs():
    db.clear_logs()
    g.access_note = "clear logs"
    return jsonify({'success':True})

@app.route('/api/logs/export')
def api_export_logs():
    """下载 error.log（gzip 压缩）。不存在时返回 404。
    注意：不设 Content-Encoding，浏览器原样保存，7z/WinRAR 可直接解压。
    """
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    _candidate = os.path.realpath(os.path.join(_BASE_DIR, 'error.log'))
    if not (_candidate.startswith(_BASE_DIR + os.sep) or _candidate == os.path.join(_BASE_DIR, 'error.log')):
        return jsonify({'error': '路径非法'}), 400
    if not os.path.exists(_candidate):
        return jsonify({'error': 'error.log 不存在（日志存盘可能未开启）'}), 404

    with open(_candidate, 'rb') as f:
        raw = f.read()
    body = _gzip.compress(raw, compresslevel=6)
    from flask import Response
    return Response(body, status=200, headers={
        'Content-Disposition': 'attachment; filename=error.log.gz',
        'Content-Type':        'application/gzip',
        'Content-Length':      str(len(body)),
    })

@app.route('/api/history/clear', methods=['POST'])
@_require_role('admin')
def api_clear_history():
    """清空 JSON 文件中的历史可用率缓存，内存统计不受影响，重启后生效。"""
    try:
        if os.path.exists(CONFIG['data_file']):
            with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
                data = json.load(f)
            for entry in data.values():
                entry.pop('history_24h', None)
                entry.pop('history_7d',  None)
                entry.pop('history_30d', None)
            with open(CONFIG['data_file'], 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        cprint('[history/clear] JSON缓存已清空，重启后统计将从零开始', 'info')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history/status', methods=['GET'])
@_require_role('admin', 'operator', 'viewer')
def api_history_status():
    """检查 JSON 文件中是否存在历史缓存数据"""
    try:
        if not os.path.exists(CONFIG['data_file']):
            return jsonify({'has_cache': False})
        with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
            data = json.load(f)
        def _has_data(v):
            if not v: return False
            if isinstance(v, dict): return v.get('total', 0) > 0
            if isinstance(v, list): return len(v) > 0
            return False
        has_cache = any(
            _has_data(entry.get('history_24h')) or
            _has_data(entry.get('history_7d'))  or
            _has_data(entry.get('history_30d'))
            for entry in data.values()
        )
        return jsonify({'has_cache': has_cache})
    except Exception as e:
        return jsonify({'has_cache': False, 'error': str(e)})

@app.route('/api/config', methods=['GET','POST'])
def api_config():
    # POST 修改配置：仅 admin
    if request.method == 'POST':
        role = session.get('role')
        if role != 'admin':
            return jsonify({'error': '权限不足'}), 403
        data = request.json or {}
        keys = ['check_interval','timeout','retry_mode','retry_interval',
                'monitor_workers','export_suffix','show_removed_ips',
                'log_to_disk','log_level','console_log_level','http_proxy','udp_proxy','proxy_enabled',
                'dns_mode','dns_custom','max_log_entries','page_refresh_ms',
                'tracker_stat_period','rank_stat_period','cache_history','tab_switch_refresh']

        # 字段的人可读标签
        labels = {
            'check_interval':      '监控间隔',
            'timeout':             '连接超时',
            'retry_mode':          '重试模式',
            'retry_interval':      '重试间隔',
            'monitor_workers':     '并发检测数',
            'export_suffix':       '导出后缀',
            'log_to_disk':         '日志存盘',
            'log_level':           '日志级别',
            'console_log_level':   '日志级别',
            'http_proxy':          'HTTP代理',
            'udp_proxy':           'UDP代理',
            'proxy_enabled':       '代理开关',
            'dns_mode':            'DNS模式',
            'dns_custom':          '自定义DNS',
            'max_log_entries':     '最大日志条数',
            'page_refresh_ms':     '页面刷新间隔',
            'tracker_stat_period': '监控统计周期',
            'rank_stat_period':    '排行统计周期',
            'cache_history':       '缓存统计可用率',
            'tab_switch_refresh':  '切换时刷新',
        }
        suffixes = {
            'check_interval': 's', 'timeout': 's', 'retry_interval': 's',
            'page_refresh_ms': 'ms',
        }
        bool_fmt = {True: '开', False: '关'}

        changes = []
        for k in keys:
            if k not in data: continue
            old_val = CONFIG.get(k)
            new_val = data[k]
            if k == 'console_log_level':
                k = 'log_level'
                old_val = CONFIG.get('log_level', CONFIG.get('console_log_level'))
            if old_val == new_val: continue
            CONFIG[k] = new_val
            label  = labels.get(k, k)
            suffix = suffixes.get(k, '')
            if isinstance(new_val, bool):
                val_str = bool_fmt.get(new_val, str(new_val))
            else:
                val_str = f"{new_val}{suffix}"
            changes.append(f"{label}={val_str}")

        persist_config(CONFIG)

        proxy_changed_keys = {'udp_proxy', 'proxy_enabled', 'timeout'}
        if any(k in data for k in proxy_changed_keys):
            _socks5_pool.invalidate()
            cprint('[SOCKS5Pool] 代理配置变更，连接池已重置', 'debug')

        if changes:
            msg = f"配置已更新: {' | '.join(changes)}"
            g.access_note = msg

        return jsonify({'success':True,'config':{k:CONFIG[k] for k in keys if k != 'console_log_level'}})

    # GET 读取配置：未登录只返回前端行为控制必要字段（不含账户/代理等敏感信息）
    # 已登录用户额外返回运维相关字段（仍不含账户信息）
    public_keys = ['page_refresh_ms', 'tab_switch_refresh', 'tracker_stat_period', 'rank_stat_period', 'show_removed_ips']
    if not session.get('role'):
        return jsonify({k: CONFIG.get(k) for k in public_keys})
    # 已登录用户返回更多展示字段，但不含账户信息（users/密钥）
    all_keys = ['check_interval','timeout','retry_mode','retry_interval',
                'log_to_disk','log_level','http_proxy','udp_proxy','proxy_enabled',
                'dns_mode','dns_custom','max_log_entries','page_refresh_ms',
                'tracker_stat_period','rank_stat_period','cache_history','tab_switch_refresh',
                'show_removed_ips','monitor_workers','export_suffix']
    return jsonify({k: CONFIG.get(k) for k in all_keys})

@app.route('/api/users', methods=['GET'])
@_require_role('admin')
def api_users_get():
    """返回用户列表（不含密码哈希）"""
    users = [{'username': u['username'], 'role': u['role']} for u in CONFIG.get('users', [])]
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@_require_role('admin')
def api_users_save():
    """批量保存用户配置，支持新增/修改/删除"""
    data = request.json or {}
    new_users = data.get('users', [])
    result = []
    existing = {u['username']: u for u in CONFIG.get('users', [])}
    for u in new_users:
        uname = (u.get('username','') or '').strip()
        role  = u.get('role','viewer')
        import re as _re
        # 用户名只允许字母数字下划线连字符，1-32字符
        if not uname or not _re.match(r'^[a-zA-Z0-9_-]{1,32}$', uname):
            continue
        if role not in ('admin','operator','viewer'):
            continue
        pw_plain = (u.get('password','') or '').strip()
        if pw_plain:
            if len(pw_plain) < 4:
                continue  # 密码太短，拒绝保存
            pw_hash, pw_salt = _hash_pw(pw_plain)
            result.append({'username': uname, 'role': role, 'password': pw_hash, 'salt': pw_salt})
        elif uname in existing:
            # 保留旧密码哈希 + 盐（包含旧版兼容格式）
            old_u = existing[uname]
            entry = {'username': uname, 'role': role, 'password': old_u['password']}
            if 'salt' in old_u:
                entry['salt'] = old_u['salt']
            result.append(entry)
        else:
            continue  # 新用户必须设密码
    CONFIG['users'] = result
    persist_config(CONFIG)
    g.access_note = f"users updated ({len(result)} users)"
    return jsonify({'success': True, 'count': len(result)})

# ==================== 主程序 ====================
if __name__ == '__main__':
    db.load()
    db.add_log("网络监控服务启动", 'info')

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    _check_now.set()   # 启动后立即触发第一轮检测，不等待 check_interval

    probe_t = threading.Thread(target=_probe_loop, daemon=True)
    probe_t.start()

    print(f"\n{'='*58}")
    print(f"  网络监控 - Network Monitor")
    print(f"{'='*58}")
    print(f"  访问地址       : http://localhost:{CONFIG['port']}  (IPv4+IPv6 双栈)")
    print(f"  监控间隔       : {CONFIG['check_interval']}秒")
    print(f"  超时时间       : {CONFIG['timeout']}秒")
    dns_desc = {'system':'系统DNS','dnspython':'dnspython','custom':f"自定义({CONFIG.get('dns_custom','8.8.8.8')})"}.get(CONFIG.get('dns_mode','system'),'系统DNS')
    print(f"  DNS解析模式    : {dns_desc}")
    print(f"  日志最大条目   : {CONFIG.get('max_log_entries',2000)}条")
    print(f"  重试模式       : {CONFIG['retry_mode']}")
    print(f"  日志级别       : {CONFIG.get('log_level', 'info')}")
    print(f"  磁盘日志       : {'开启' if CONFIG['log_to_disk'] else '关闭'}")
    if CONFIG['proxy_enabled']:
        http_p = CONFIG.get('http_proxy','').strip()
        udp_p  = CONFIG.get('udp_proxy','').strip()
        print(f"  代理           : 启用")
        print(f"    HTTP/TCP代理 : {http_p if http_p else '(未设置)'}")
        print(f"    UDP代理      : {udp_p  if udp_p  else '(未设置)'}")
    else:
        print(f"  代理           : 关闭")
    users_info = CONFIG.get('users', [])
    print(f"  用户账户       : {len(users_info)} 个 ({', '.join(u['username']+'('+u['role']+')' for u in users_info)})")
    print(f"{'='*58}")
    print(f"  权限说明:")
    print(f"    admin    - 全部权限（配置+用户管理，重试不限速）")
    print(f"    operator - 增删tracker，重试限速500ms")
    print(f"    viewer   - 只读，重试限速1000ms")
    print(f"{'='*58}\n")

    try:
        from waitress import serve
        print("  使用 waitress 生产服务器\n")
        # waitress 通过多个 listen 参数同时监听 IPv4 和 IPv6
        port = CONFIG['port']
        serve(app,
              listen=f'0.0.0.0:{port} [::]:{port}',
              threads=8,
              ident='')  # 禁止 waitress 注入 Server 响应头
    except ImportError:
        print("  提示: pip install waitress 可消除开发警告\n")
        # Flask 开发服务器：在支持 IPv6 的系统上 '::' 通常同时接受 IPv4（双栈）
        # 若系统不支持，退回 0.0.0.0
        import socket
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.close()
            app.run(host='::', port=CONFIG['port'], debug=False)
        except OSError:
            app.run(host='0.0.0.0', port=CONFIG['port'], debug=False)