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
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, make_response, session, g, Response, redirect, send_from_directory
from flask_cors import CORS
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests as req_lib
from typing import Any, Dict, Optional, Tuple, List
from werkzeug.exceptions import HTTPException

# ==================== 配置持久化 ====================
CONFIG_FILE  = 'config.json'
DEFAULT_CONFIG = {
    'listen_port': 443,                # 新增，默认端口
    'listen_ipv4': 'global',           # 新增，默认 IPv4 监听模式
    'listen_ipv4_custom': '',          # 新增，默认自定义 IPv4 地址为空
    'listen_ipv6': 'global',           # 新增，默认 IPv6 监听模式
    'listen_ipv6_custom': '',          # 新增，默认自定义 IPv6 地址为空
    'http_proxy_enabled': False,       # 新增，HTTP 代理独立开关
    'udp_proxy_enabled': False,        # 新增，UDP 代理独立开关
    'check_interval': 30,
    'timeout': 5,
    'retry_mode': 'polling',           # 'polling' | 固定秒数(int)
    'retry_interval': 5,               # 当 retry_mode != 'polling' 时使用
    'monitor_workers': 120,            # 并发检测线程数（可配置，建议 30~200）
    'stagger_batch_proxy': 5,          # 代理模式：每批发包数
    'stagger_batch_direct': 5,         # 直连模式：每批发包数
    'stagger_delay_proxy': 150,        # 代理模式：批间延迟 ms
    'stagger_delay_direct': 100,       # 直连模式：批间延迟 ms
    'log_to_disk': False,
    'log_level': 'info',               # none | info | error | debug
    'log_file': 'error.log',
    'data_file': 'data.json',
    'max_history': 2880,               # history_24h 上限：24h × 3600s ÷ 30s间隔 = 2880点
    'http_proxy': '',
    'udp_proxy': '',
    'dns_mode': 'system',              # system | dnspython | custom
    'dns_custom': '8.8.8.8',           # 自定义DNS时使用，支持多个用逗号分隔
    'dns_use_tcp': False,              # 自定义/dnspython 模式下强制使用 TCP 53（国内UDP丢包时开启）
    'max_log_entries': 1000,           # 日志最大条目数（兼容旧版，以下三项优先）
    'max_log_info': 1000,              # Info 级日志最大条目数
    'max_log_success': 1000,           # Success 级日志最大条目数
    'max_log_error': 1000,             # Error 级日志最大条目数
    'page_refresh_ms': 30000,          # 前端页面自动刷新间隔(ms)，0=禁用
    'cache_history': True,             # 是否缓存历史可用率到JSON（重启不丢失）
    'dashboard_stat_period': '24h',    # 仪表盘可用率统计周期：24h | 7d | 30d（排行TOP10+快速搜索）
    'tracker_stat_period': '24h',      # 监控列表可用率统计周期：24h | 7d | 30d
    'tab_switch_refresh': True,        # 切换仪表盘/监控列表时是否刷新数据
    'export_suffix': '/announce',      # 导出 tracker 列表时追加的路径后缀
    'show_removed_ips': True,          # 是否显示已移除的历史IP（前端控制）
    'default_layout_width': '1700',    # 默认页面视野宽度（px字符串，对应50%~100%）
    'allow_private_ips': False,        # 是否允许添加内网IP，默认禁止（SSRF防护）
    'min_password_length': 8,          # 用户修改密码最小长度
    'refresh_geo_on_restart': True,    # 重启时自动更新 IP 归属地
    # ── 安全/限流内存清理 ──
    'cleanup_interval': 3600,          # 限流内存清理间隔（秒）。各内存字典说明：
                                       #   _rate_limit_store : 每IP的请求时间戳列表，用于通用限流（rate_limit装饰器）
                                       #   _rate_limit_warned: 每IP最后一次限流警告时间，避免日志刷屏
                                       #   _login_fail       : 每IP的登录失败次数+锁定到期时间，防暴力破解
                                       #   _retry_throttle   : 每用户最后一次重试操作时间，限制重试频率
                                       #   _query_rate       : 每IP的公开查询接口请求时间戳，独立限流
                                       # 建议值：1800~7200（秒）。设太小会频繁清理，失去防护效果；
                                       # 设太大内存会缓慢增长（每个唯一IP约100字节）。
    # ── CF/反向代理 IP 信任 ──
    'trust_cf_ip': False,              # 是否信任 CF-Connecting-IP / X-Forwarded-For 获取真实客户端IP
                                       # 通过 Cloudflare 访问时设为 True，Flask 直接暴露公网时保持 False
                                       # 注意：设为 True 前必须确认请求确实来自CF（否则可伪造IP绕过限流）
                                       # 本地内网/http测试时设为 False 即可，不影响功能
    'users': [
        {"username": "admin",    "password": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", "role": "admin"},
        {"username": "operator", "password": "06e55b633481f7bb072957eabcf110c972e86691c3cfedabe088024bffe42f23", "role": "operator"},
        {"username": "viewer",   "password": "d35ca5051b82ffc326a3b0b6574a9a3161dee16b9478a199ee39cd803ce5b799",  "role": "viewer"},
    ],
}
POLLING_SEQUENCE = [5, 15, 30, 60]

def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            for k in ['check_interval','timeout','retry_mode','retry_interval',
                      'monitor_workers','stagger_batch_proxy','stagger_batch_direct','stagger_delay_proxy','stagger_delay_direct',
                      'log_to_disk','log_level','console_log_level',
                      'http_proxy','udp_proxy','http_proxy_enabled', 'udp_proxy_enabled',
                      'listen_port', 'listen_ipv4', 'listen_ipv4_custom', 'listen_ipv6', 'listen_ipv6_custom',
                      'dns_mode','dns_custom','dns_use_tcp','max_log_entries','max_log_info','max_log_success','max_log_error','page_refresh_ms',
                      'dashboard_stat_period','tracker_stat_period','cache_history','tab_switch_refresh','export_suffix',
                      'show_removed_ips','default_layout_width','allow_private_ips','min_password_length','users',
                      'cleanup_interval','trust_cf_ip']:
                if k in saved:
                    cfg[k] = saved[k]
            # 向后兼容：旧配置文件用 rank_stat_period，迁移到 dashboard_stat_period
            if 'dashboard_stat_period' not in saved and 'rank_stat_period' in saved:
                cfg['dashboard_stat_period'] = saved['rank_stat_period']
            # 向后兼容：旧配置文件用 console_log_level，迁移到 log_level
            if 'log_level' not in cfg and 'console_log_level' in cfg:
                cfg['log_level'] = cfg['console_log_level']
    except Exception as e:
        cprint(f"配置加载失败: {e}", 'error')
    return cfg

def persist_config(cfg):
    try:
        savable = {k: cfg[k] for k in ['check_interval','timeout','retry_mode','retry_interval',
                                        'monitor_workers','stagger_batch_proxy','stagger_batch_direct','stagger_delay_proxy','stagger_delay_direct',
                                        'log_to_disk','log_level',
                                        'http_proxy','udp_proxy','http_proxy_enabled', 'udp_proxy_enabled',
                                        'listen_port', 'listen_ipv4', 'listen_ipv4_custom', 'listen_ipv6', 'listen_ipv6_custom',
                                        'dns_mode','dns_custom','dns_use_tcp','max_log_entries','max_log_info','max_log_success','max_log_error','page_refresh_ms',
                                        'dashboard_stat_period','tracker_stat_period','cache_history',
                                        'tab_switch_refresh','export_suffix','show_removed_ips','default_layout_width',
                                        'allow_private_ips','min_password_length','users',
                                        'cleanup_interval','trust_cf_ip']
                   if k in cfg}
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(savable, f, indent=2, ensure_ascii=False)
    except Exception as e:
        cprint(f"配置保存失败: {e}", 'error')

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
app.config['SESSION_COOKIE_SECURE']   = True   # CF 代理 HTTPS，必须带 Secure 标志
_https_enabled = os.environ.get('HTTPS_ENABLED', '0').strip() == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024    # 请求体上限 1MB，防 DoS

def _is_https_request():
    """判断当前请求是否来自 HTTPS（兼容 CF/Nginx 反代）"""
    if _https_enabled:
        return True
    # Cloudflare: CF-Visitor: {"scheme":"https"}
    cf_visitor = request.headers.get('CF-Visitor', '')
    if '"https"' in cf_visitor:
        return True
    # 标准反代头
    if request.headers.get('X-Forwarded-Proto', '').lower() == 'https':
        return True
    # Nginx proxy_pass 常用
    if request.headers.get('X-Scheme', '').lower() == 'https':
        return True
    return False

# 关闭 werkzeug 自带的 request log，我们自己处理
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ==================== 全局异常处理器 ====================
@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    # HTTP 异常（如404）继续由 Flask 处理
    if isinstance(e, HTTPException):
        return e
    # 收集请求信息
    ip = _client_ip()
    username = session.get('username', '?')
    path = request.path
    method = request.method
    data = {}
    if request.is_json:
        try:
            data = request.get_json(silent=True) or {}
        except:
            pass
    log_msg = (f"Unhandled exception - IP: {ip}, User: {username}, "
               f"{method} {path}, Data: {data}, Error: {repr(e)}")
    app.logger.error(log_msg, exc_info=True)
    cprint(log_msg, 'error')
    return jsonify({'success': False, 'error': '服务器内部错误，请稍后重试'}), 500

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
    """旧版 SHA256 无盐哈希，仅用于向后兼容迁移判断（只读验证，不写入新密码）。
    新密码统一使用 _hash_pw()（PBKDF2+盐）存储，此函数不会被用于存储任何新密码。
    安全扫描误报：此处 SHA256 仅作旧格式识别，不符合"存储新密码"场景，可忽略。
    """
    return hashlib.sha256(pw.encode()).hexdigest()  # nosec B324

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

# ==================== CSRF 防护 ====================
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            token = request.headers.get('X-CSRFToken')
            if not token or token != session.get('csrf_token'):
                return jsonify({'error': 'CSRF token invalid or missing'}), 403
        return f(*args, **kwargs)
    return decorated_function

# 提供一个 API 获取 CSRF token（可选）
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf_token()
    return jsonify({'csrf_token': token})

# ==================== 限流工具 ====================
# 更精细的限流：使用内存存储，每个 IP 每分钟限制请求数
_rate_limit_store = {}        # {ip: [timestamp, ...]} 请求时间戳列表
_rate_limit_lock = threading.Lock()
_rate_limit_warned = {}       # {ip: last_warn_time} 限流警告去重（避免日志刷屏）
_rate_limit_warned_lock = threading.Lock()

def rate_limit(limit: int = 60, window: int = 60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = _client_ip()
            now = time.time()
            with _rate_limit_lock:
                records = _rate_limit_store.get(ip, [])
                # 清理过期记录
                records = [t for t in records if now - t < window]
                if len(records) >= limit:
                    # 检查是否已打印警告
                    with _rate_limit_warned_lock:
                        last_warn = _rate_limit_warned.get(ip, 0)
                        if now - last_warn >= window:  # 超过窗口期或从未警告
                            _rate_limit_warned[ip] = now
                            cprint(f"IP {ip} 请求超过限流 ({limit}/{window}s)，已拒绝", 'info')
                    return jsonify({'error': '请求过于频繁，请稍后再试'}), 429
                records.append(now)
                _rate_limit_store[ip] = records
            return f(*args, **kwargs)
        return wrapper
    return decorator

# 重试限流已存在，这里用于其他 API

# ==================== 控制台输出工具 ====================
LEVEL_ORDER = {'none': 0, 'info': 1, 'error': 2, 'debug': 3}
# 完全静默的路径（前端内部轮询/导航，不是真实用户请求）
_log_write_lock = threading.Lock()   # 新增：定义锁
_NOISY_PATHS = {'/api/nav'}
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
                except Exception as e:
                    cprint(f"写入 access.log 失败: {e}", 'error')

def _write_access_log(line: str):
    """把一行 nginx 格式日志写入 access.log（仅 log_to_disk=True 时）。加锁防截断。"""
    if CONFIG.get('log_to_disk'):
        with _log_write_lock:
            try:
                with open(_ACCESS_LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
            except Exception as e:
                cprint(f"写入 access.log 失败: {e}", 'error')

def access_log(msg: str):
    """业务操作日志（登录/登出/添加/删除/重试/配置变更等）。
    控制台沿用带前缀的内部格式；写盘统一交给 after_request 的 nginx 行处理。
    这里只负责打印到控制台，不再自己写 access.log。
    """
    cprint(msg, 'info')


# ==================== 代理工具 ====================
def make_proxy_dict():
    """构建 requests 代理字典"""
    if not CONFIG.get('http_proxy_enabled'):
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

# ==================== 缓存工具 ====================
class LRUCache:
    """LRU缓存实现，限制缓存大小"""
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.cache = {}
        self.order = []
        self.lock = threading.RLock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                # 移动到最前面（最近使用）
                self.order.remove(key)
                self.order.insert(0, key)
                return self.cache[key]
            return None
    
    def put(self, key, value):
        with self.lock:
            if key in self.cache:
                # 移动到最前面（最近使用）
                self.order.remove(key)
                self.order.insert(0, key)
                self.cache[key] = value
            else:
                # 检查容量
                if len(self.cache) >= self.capacity:
                    # 移除最久未使用的
                    oldest = self.order.pop()
                    del self.cache[oldest]
                # 添加新项
                self.order.insert(0, key)
                self.cache[key] = value
    
    def clear(self):
        with self.lock:
            self.cache.clear()
            self.order.clear()

# ==================== 数据库 ====================
_geo_cache_lock = threading.RLock()
class TrackerDB:
    def __init__(self):
        self.lock  = threading.RLock()
        self.trackers = {}
        self.logs  = []
        self.stats = {'total': 0, 'alive': 0, 'ipv4': 0, 'ipv6': 0}
        # 可用率缓存
        self.uptime_cache = LRUCache(1000)  # 限制缓存大小
        self.cache_lock = threading.RLock()
        self.cache_ttl = 30  # 秒
        # 异步保存线程池（单线程）
        self._save_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="db_save")
        self._save_pending = False

    def _get_uptime_cached(self, domain, period):
        """从缓存获取域名可用率，如果缓存有效则返回，否则 None"""
        entry = self.uptime_cache.get((domain, period))
        if entry and time.time() - entry['time'] < self.cache_ttl:
            return entry['value']
        return None

    def _set_uptime_cache(self, domain, period, value):
        self.uptime_cache.put((domain, period), {'value': value, 'time': time.time()})

    def _clear_uptime_cache(self, domain=None):
        if domain:
            # 由于LRU缓存不支持按前缀删除，这里我们遍历所有键并删除匹配的
            # 注意：这会遍历整个缓存，对于大缓存可能效率不高
            # 但考虑到缓存大小限制为1000，这是可以接受的
            keys_to_remove = []
            with self.cache_lock:
                # 注意：这里需要访问LRUCache的内部数据结构，这不是最佳实践
                # 但为了保持兼容性，暂时这样实现
                for key in list(self.uptime_cache.cache.keys()):
                    if isinstance(key, tuple) and len(key) == 2 and key[0] == domain:
                        keys_to_remove.append(key)
                for key in keys_to_remove:
                    if key in self.uptime_cache.cache:
                        del self.uptime_cache.cache[key]
                        if key in self.uptime_cache.order:
                            self.uptime_cache.order.remove(key)
        else:
            self.uptime_cache.clear()

    # ---------- tracker 管理 ----------
    def add_tracker(self, domain, port, protocol, ip_list=None):
        with self.lock:
            if domain not in self.trackers:
                self.trackers[domain] = {
                    'domain': domain, 'port': port, 'protocol': protocol,
                    'ips': [],
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
            self._save_async()  # 改为异步保存

    def update_status(self, domain, ip, status, latency, check_time=None):
        with self.lock:
            if domain in self.trackers:
                for info in self.trackers[domain]['ips']:
                    if info['ip'] == ip:
                        info['status']     = status
                        info['latency']    = latency
                        info['last_check'] = check_time or datetime.now().isoformat()  # 优先使用传入的时间
                        break
                self._push_history(domain, ip, status)
                self._recalc()
                self._clear_uptime_cache(domain)
                self._save_async()  # 异步保存

    def _push_history(self, domain, ip, status):
        """把探测结果写入 hdb（时间戳历史库）。
        跳过 removed IP，避免污染统计。"""
        t = self.trackers[domain]
        for info in t['ips']:
            if info['ip'] == ip:
                if info.get('removed', False):
                    return
                break
        else:
            return
        # 写入 hdb，domain 作为父级，IP 归属关系自包含在 history.json
        hdb.push_ip(domain, ip, status)

    def _recalc(self):
        total = alive = ipv4 = ipv6 = 0
        alive_v4 = alive_v6 = 0
        offline = 0        # 总离线IP数
        offline_v4 = 0     # IPv4离线数
        offline_v6 = 0     # IPv6离线数
        unknown = 0        # 总未知IP数
        unknown_v4 = 0     # IPv4未知数
        unknown_v6 = 0     # IPv6未知数
        paused_count = 0   # 已暂停的监控数量（域名级或IP级）
        tcp_total = tcp_alive = tcp_offline = tcp_unknown = 0
        udp_total = udp_alive = udp_offline = udp_unknown = 0
        # 延迟统计（只统计在线且latency>0的IP）
        lats_all = []; lats_v4 = []; lats_v6 = []; lats_tcp = []; lats_udp = []
        for d in self.trackers.values():
            proto = d.get('protocol', 'tcp')
            is_udp = (proto == 'udp')
            domain_paused = d.get('paused', False)
            for ip in d['ips']:
                if ip.get('removed'): continue
                ip_paused = domain_paused or ip.get('paused', False)
                if ip_paused:
                    paused_count += 1
                    continue   # 已暂停不计入在线/离线统计
                total += 1
                is6 = ':' in ip['ip']
                if is6:
                    ipv6 += 1
                else:
                    ipv4 += 1
                online = ip['status'] == 'online'
                offline_ip = ip['status'] == 'offline'
                if online:
                    alive += 1
                    if is6:
                        alive_v6 += 1
                    else:
                        alive_v4 += 1
                    # 收集延迟（只有在线且latency>0）
                    lat = ip.get('latency', -1)
                    if lat is not None and lat > 0:
                        lats_all.append(lat)
                        if is6: lats_v6.append(lat)
                        else:   lats_v4.append(lat)
                        if is_udp: lats_udp.append(lat)
                        else:      lats_tcp.append(lat)
                elif offline_ip:
                    offline += 1           # 累计离线IP
                    if is6:
                        offline_v6 += 1
                    else:
                        offline_v4 += 1
                else:
                    unknown += 1           # 未知状态
                    if is6:
                        unknown_v6 += 1
                    else:
                        unknown_v4 += 1
                if is_udp:
                    udp_total += 1
                    if online:
                        udp_alive += 1
                    elif offline_ip:
                        udp_offline += 1
                    else:
                        udp_unknown += 1
                else:
                    tcp_total += 1
                    if online:
                        tcp_alive += 1
                    elif offline_ip:
                        tcp_offline += 1
                    else:
                        tcp_unknown += 1
        def _avg(lst): return round(sum(lst)/len(lst)) if lst else -1
        self.stats = {
            'total': total, 'alive': alive, 'offline': offline, 'unknown': unknown,
            'ipv4': ipv4, 'ipv6': ipv6,
            'alive_v4': alive_v4, 'alive_v6': alive_v6,
            'offline_v4': offline_v4, 'offline_v6': offline_v6,
            'unknown_v4': unknown_v4, 'unknown_v6': unknown_v6,
            'tcp_total': tcp_total, 'tcp_alive': tcp_alive, 'tcp_offline': tcp_offline, 'tcp_unknown': tcp_unknown,
            'udp_total': udp_total, 'udp_alive': udp_alive, 'udp_offline': udp_offline, 'udp_unknown': udp_unknown,
            'paused_count': paused_count,
            'avg_latency':     _avg(lats_all),
            'avg_latency_v4':  _avg(lats_v4),
            'avg_latency_v6':  _avg(lats_v6),
            'avg_latency_tcp': _avg(lats_tcp),
            'avg_latency_udp': _avg(lats_udp),
        }

    def get_trackers(self):
        """返回 tracker 字典，使用快照减少锁持有时间 IP/域名的可用率统计全部从 hdb 按时间窗口计算。"""
        with self.lock:
            # 浅拷贝 trackers 结构
            trackers_copy = {}
            for domain, t in self.trackers.items():
                t_copy = dict(t)
                t_copy['ips'] = t['ips'][:]  # 复制列表
                trackers_copy[domain] = t_copy
        # 锁外填充可用率
        result = {}
        for domain, t_copy in trackers_copy.items():
            ips_copy = []
            for ip_obj in t_copy['ips']:
                ip_copy = {k: v for k, v in ip_obj.items()
                           if k not in ('history_24h','history_7d','history_30d')}
                if 'added_time' not in ip_copy:
                    ip_copy['added_time'] = t_copy.get('added_time')
                ip = ip_obj.get('ip', '')
                # IP 级三个周期可用率
                for pk, secs in HISTORY_WINDOWS.items():
                    ip_copy[f'uptime_{pk}'] = hdb.get_ip_uptime(domain, ip, secs)
                # ip_uptime 用当前配置周期
                period = CONFIG.get('tracker_stat_period', '24h')
                ip_copy['ip_uptime'] = ip_copy.get(f'uptime_{period}')
                # IP 级末尾连续失败次数（近24h）
                recent = hdb.get_ip_recent(domain, ip, 86400)
                ip_consec = 0
                for v in reversed(recent):
                    if v == 0: ip_consec += 1
                    else: break
                ip_copy['consec_fail'] = ip_consec
                ips_copy.append(ip_copy)
            t_copy['ips'] = ips_copy
            # 域名级：hdb 内该域名下所有IP（含历史已移除）汇总，但排除已暂停IP
            # 已暂停IP不参与域名可用率计算，实时生效
            domain_paused = t_copy.get('paused', False)
            paused_ip_set = set()
            if not domain_paused:
                for ip_obj in t_copy['ips']:
                    if ip_obj.get('paused') and not ip_obj.get('removed'):
                        paused_ip_set.add(ip_obj.get('ip', ''))
            for pk, secs in HISTORY_WINDOWS.items():
                cache_key = (domain, pk)
                cached = self._get_uptime_cached(domain, pk)
                if cached is not None:
                    t_copy[f'uptime_{pk}'] = cached
                    continue
                if CONFIG.get('cache_history', True):
                    s = hdb.get_domain_summary(domain, secs, excluded_ips=paused_ip_set if paused_ip_set else None)
                    uptime_val = round(s['ok'] / s['total'] * 100, 1) if s['total'] > 0 else None
                    t_copy[f'uptime_{pk}'] = uptime_val
                    t_copy[f'ok_{pk}']     = s['ok']
                    t_copy[f'total_{pk}']  = s['total']
                    t_copy[f'fail_{pk}']   = s['fail']
                    self._set_uptime_cache(domain, pk, uptime_val)
                else:
                    t_copy[f'uptime_{pk}'] = None
                    t_copy[f'ok_{pk}']     = None
                    t_copy[f'total_{pk}']  = None
                    t_copy[f'fail_{pk}']   = None
            for k in ('history_24h', 'history_7d', 'history_30d'):
                t_copy.pop(k, None)
            result[domain] = t_copy
        return result

    def get_stats(self):
        with self.lock: return dict(self.stats)

    def get_ranking(self, period='24h', limit=200, min_uptime=0.0):
        secs = HISTORY_WINDOWS.get(period, 86400)
        out = []
        with self.lock:
            for domain, d in self.trackers.items():
                if d.get('paused'):
                    continue
                active_ips = [ip for ip in d['ips'] if not ip.get('removed') and not ip.get('paused')]
                if not active_ips: continue
                # 已暂停IP不参与域名可用率计算
                paused_ip_set = {ip.get('ip','') for ip in d['ips']
                                 if ip.get('paused') and not ip.get('removed')}
                s      = hdb.get_domain_summary(domain, secs, excluded_ips=paused_ip_set if paused_ip_set else None)
                uptime = round(s['ok'] / s['total'] * 100, 2) if s['total'] > 0 else None
                if uptime is None and min_uptime > 0: continue
                if uptime is not None and uptime < min_uptime: continue
                online_count  = sum(1 for ip in active_ips if ip.get('status') == 'online')
                # 故障IP数：仅计活跃（非暂停）且offline的IP
                offline_count = sum(1 for ip in active_ips if ip.get('status') == 'offline')
                versions = list({ip.get('version','ipv4') for ip in active_ips})
                out.append({'domain': domain, 'port': d.get('port',80),
                            'protocol': d.get('protocol','tcp'),
                            'uptime': uptime,
                            'ip_count': len(active_ips),
                            'online_count': online_count,
                            'offline_count': offline_count,
                            'has_v4': 'ipv4' in versions,
                            'has_v6': 'ipv6' in versions,
                            'all_paused': all(ip.get('paused') for ip in active_ips) if active_ips else False})
        out.sort(key=lambda x: (-(x['uptime'] if x['uptime'] is not None else -1), -x['online_count'], x['domain']))
        return out[:limit]

    # ---------- 日志 ----------
    def add_log(self, message, level='info'):
        entry = {'time': datetime.now().isoformat(), 'level': level, 'message': message}
        # 按级别选对应最大条目数（info/success/error 独立，其余fallback到max_log_entries）
        _level_key = {'info': 'max_log_info', 'success': 'max_log_success', 'error': 'max_log_error'}
        max_key = _level_key.get(level, 'max_log_entries')
        with self.lock:
            self.logs.append(entry)
            # 全局总条目裁剪（保持向后兼容：按各级别独立上限裁剪）
            max_e = CONFIG.get(max_key, CONFIG.get('max_log_entries', 1000))
            # 只裁剪同级别的日志，其他级别不受影响
            level_logs_idx = [i for i, e in enumerate(self.logs) if e['level'] == level]
            while len(level_logs_idx) > max_e:
                self.logs.pop(level_logs_idx[0])
                level_logs_idx = [i for i, e in enumerate(self.logs) if e['level'] == level]
            # 磁盘日志只写 error 级别，避免成功结果和轮检摘要塞满日志文件
            if CONFIG.get('log_to_disk') and level == 'error':
                try:
                    with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
                        f.write(f"[{entry['time']}][{level.upper()}] {message}\n")
                except Exception as e:
                    cprint(f"写入 error.log 失败: {e}", 'error')

    def get_logs(self, limit=1000, level=None):
        with self.lock:
            if level and level != 'all':
                filtered = [e for e in self.logs if e['level'] == level]
                return list(filtered[-limit:])
            return list(self.logs[-limit:])

    def clear_logs(self, level=None):
        with self.lock:
            if level and level != 'all':
                self.logs = [e for e in self.logs if e['level'] != level]
            else:
                self.logs = []

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
            show_removed = CONFIG.get('show_removed_ips', True)
            changed = False
            # 从后往前遍历现有 IP
            for i in range(len(td['ips'])-1, -1, -1):
                ip_obj = td['ips'][i]
                ip = ip_obj['ip']
                if ip in new_ips:
                    # IP 仍然存在：若有 removed 标记则清除
                    if ip_obj.pop('removed', None) is not None:
                        changed = True
                else:
                    # IP 消失
                    if show_removed:
                        if not ip_obj.get('removed'):
                            ip_obj['removed'] = True
                            changed = True
                    else:
                        td['ips'].pop(i)
                        changed = True
            # 添加新 IP
            for ip_info in new_ip_list:
                if ip_info['ip'] not in existing:
                    ip_info.update({
                        'status': 'unknown',
                        'latency': -1,
                        'last_check': None,
                        'added_time': datetime.now().isoformat()
                    })
                    td['ips'].append(ip_info)
                    changed = True
            if changed:
                self._recalc()
                self._clear_uptime_cache(domain)
                self._save_async()

    # 异步保存：将保存任务提交到线程池
    def _save_async(self):
        if self._save_pending:
            return   # 已有保存任务在排队，跳过本次
        self._save_pending = True
        def _save_worker():
            try:
                self._save()
            except Exception as e:
                cprint(f"异步保存失败: {e}", 'error')
            finally:
                self._save_pending = False
        self._save_executor.submit(_save_worker)

    def _save(self):
        try:
            data = {}
            with self.lock:
                for d, t in self.trackers.items():
                    ips_to_save = []
                    for ip_obj in t['ips']:
                        ip_entry = {k: v for k, v in ip_obj.items()
                                    if k not in ('history_24h','history_7d','history_30d')}
                        # 如果 cache_history 为 True，才写入历史摘要
                        if CONFIG.get('cache_history', True):
                            # IP级摘要（供人工查看，不用于重启恢复）
                            ip = ip_obj.get('ip', '')
                            for pk, secs in HISTORY_WINDOWS.items():
                                ip_entry[f'history_{pk}'] = hdb.get_ip_summary(d, ip, secs)
                        ips_to_save.append(ip_entry)
                    entry = {'domain':d,'port':t.get('port',80),
                             'protocol':t.get('protocol','tcp'),
                             'ips':ips_to_save,'added_time':t['added_time'],
                             'paused':t.get('paused',False)}
                    if CONFIG.get('cache_history', True):
                        # 域名级摘要：排除已暂停IP（与前端算法一致，供人工查看）
                        paused_set = {ip.get('ip','') for ip in t['ips']
                                      if ip.get('paused') and not ip.get('removed') and not t.get('paused')}
                        for pk, secs in HISTORY_WINDOWS.items():
                            s = hdb.get_domain_summary(d, secs, excluded_ips=paused_set if paused_set else None)
                            entry[f'history_{pk}'] = {'total': s['total'], 'ok': s['ok'], 'fail': s['fail']}
                    data[d] = entry
            with open(CONFIG['data_file'], 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            if CONFIG.get('cache_history', True):
                hdb.save()
        except Exception as e:
            cprint(f"保存 data.json 失败: {e}", 'error')

    def load(self):
        try:
            if not os.path.exists(CONFIG['data_file']): return False
            with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
                data = json.load(f)
            with self.lock:
                for d, t in data.items():
                    all_ips    = t.get('ips', [])
                    clean_ips  = [ip for ip in all_ips if not ip.get('removed', False)]
                    removed_cnt = len(all_ips) - len(clean_ips)
                    if removed_cnt:
                        cprint(f"[load] {d}: 跳过探测 {removed_cnt} 个已移除IP（历史数据保留在 history.json）", 'debug')
                    for ip_obj in clean_ips:
                        for k in ('history_24h','history_7d','history_30d'):
                            ip_obj.pop(k, None)
                    self.trackers[d] = {
                        'domain':d,'port':t.get('port',80),
                        'protocol':t.get('protocol','tcp'),'ips':clean_ips,
                        'added_time':t.get('added_time',datetime.now().isoformat()),
                        'dns_error': t.get('dns_error', False),
                        'paused': t.get('paused', False)
                    }
                self._recalc()
            # 预热 geo 缓存
            warmed = 0
            for td in self.trackers.values():
                for ip_obj in td.get('ips', []):
                    ip  = ip_obj.get('ip', '')
                    geo = ip_obj.get('country')
                    if ip and geo and geo.get('country_code','XX') != 'XX' and _geo_cache.get(ip) is None:
                        _geo_cache.put(ip, geo)
                        warmed += 1
            if warmed:
                cprint(f"[geo] 预热归属地缓存 {warmed} 条", 'info')
            return True
        except Exception as e:
            cprint(f"加载 data.json 失败: {e}", 'error')
            return False

    def _cleanup_hdb_on_startup(self):
        """重启后只做 GC，不清除任何 IP key。
        history.json 自包含 domain->IP 归属，已移除IP的历史保留用于域名统计。"""
        hdb._gc()
        cprint("[hdb] 启动GC完成", 'debug')

db = TrackerDB()

# ==================== 历史数据库（时间戳方案）====================
# history.json 格式：域名为父级，IP为子级，归属关系自包含
# {
#   "example.com": {
#     "ip:1.2.3.4": [[ts, 0/1], ...],
#     "ip:5.6.7.8": [[ts, 0/1], ...]
#   }
# }
# 每条记录 [unix_timestamp(int), result(0或1)]
# GC：只保留30天内数据，每小时清理一次
# 域名级可用率 = 该域名下所有IP（含历史已移除）的 ok/total 汇总
# 重启后直接从 history.json 读取 domain->IP 归属，不依赖 data.json

HISTORY_FILE = 'history.json'
HISTORY_WINDOWS = {
    '24h': 86400,
    '7d':  7 * 86400,
    '30d': 30 * 86400,
}

class HistoryDB:
    def __init__(self):
        self.lock     = threading.RLock()
        self._data    = {}
        self._last_gc = 0

    def _key_ip(self, ip): return f'ip:{ip}'

    def push_ip(self, domain, ip, result):
        """写入一条探测结果到对应域名下的IP key"""
        v   = 1 if result in (True, 'online') else 0
        now = int(time.time())
        with self.lock:
            dom = self._data.setdefault(domain, {})
            dom.setdefault(self._key_ip(ip), []).append([now, v])
        if now - self._last_gc > 3600:
            self._gc()

    def get_ip_summary(self, domain, ip, window_secs):
        """返回指定域名下指定IP在窗口内的 {total, ok, fail}"""
        cutoff = int(time.time()) - window_secs
        with self.lock:
            pts = self._data.get(domain, {}).get(self._key_ip(ip), [])
            window = [v for ts, v in pts if ts >= cutoff]
        ok = sum(window)
        return {'total': len(window), 'ok': ok, 'fail': len(window) - ok}

    def get_ip_uptime(self, domain, ip, window_secs):
        """返回指定域名下指定IP在窗口内的可用率（0~100）或 None"""
        s = self.get_ip_summary(domain, ip, window_secs)
        return round(s['ok'] / s['total'] * 100, 1) if s['total'] > 0 else None

    def get_domain_summary(self, domain, window_secs, excluded_ips=None):
        """域名级汇总：该域名下所有历史IP（含已移除）的 ok/total 之和。
        excluded_ips: set of ip strings to exclude（已暂停IP，实时排除）"""
        cutoff = int(time.time()) - window_secs
        excl_keys = {self._key_ip(ip) for ip in excluded_ips} if excluded_ips else set()
        with self.lock:
            ip_map = self._data.get(domain, {})
            total_ok = total_cnt = 0
            for ik, pts in ip_map.items():
                if ik in excl_keys:
                    continue
                for ts, v in pts:
                    if ts >= cutoff:
                        total_ok  += v
                        total_cnt += 1
        return {'total': total_cnt, 'ok': total_ok, 'fail': total_cnt - total_ok}

    def get_ip_recent(self, domain, ip, window_secs):
        """返回窗口内的原始 [v, ...] 列表（用于连续失败计算）"""
        cutoff = int(time.time()) - window_secs
        with self.lock:
            pts = self._data.get(domain, {}).get(self._key_ip(ip), [])
            return [v for ts, v in pts if ts >= cutoff]

    def remove_domain(self, domain):
        """手动删除域名时调用，清除该域名所有历史数据"""
        with self.lock:
            self._data.pop(domain, None)

    def _gc(self):
        """清理30天外的数据"""
        cutoff = int(time.time()) - 30 * 86400
        with self.lock:
            for domain in list(self._data.keys()):
                ip_map = self._data[domain]
                for ik in list(ip_map.keys()):
                    ip_map[ik] = [[ts, v] for ts, v in ip_map[ik] if ts >= cutoff]
                    if not ip_map[ik]:
                        del ip_map[ik]
                if not ip_map:
                    del self._data[domain]
            self._last_gc = int(time.time())

    # 无效IP集合：CF安全DNS可能将tracker解析为这些地址，需自动过滤
    _INVALID_IPS = {'[::]', '::', '0.0.0.0', '127.0.0.1', '::1'}

    @staticmethod
    def _is_invalid_ip(ip_str):
        """判断是否为无效IP（NXDOMAIN类DNS劫持结果）"""
        ip = ip_str.lower().strip()
        return ip in HistoryDB._INVALID_IPS

    def save(self):
        """持久化到 history.json（原子写入：先写临时文件再替换，防止写入中断导致数据损坏）"""
        tmp_file = HISTORY_FILE + '.tmp'
        try:
            with self.lock:
                data_copy = {
                    domain: {ik: list(pts) for ik, pts in ip_map.items()}
                    for domain, ip_map in self._data.items()
                }
            # 第一步：写入临时文件（即使此时崩溃，原文件也不受影响）
            with open(tmp_file, 'w', encoding='utf-8') as f:
                # 每个IP条目单独一行，便于手动编辑和区分
                f.write('{\n')
                domains = list(data_copy.items())
                for d_idx, (domain, ip_map) in enumerate(domains):
                    f.write(f'  {json.dumps(domain, ensure_ascii=False)}: {{\n')
                    ip_items = list(ip_map.items())
                    for i_idx, (ik, pts) in enumerate(ip_items):
                        pts_str = json.dumps(pts, separators=(',', ':'))
                        comma = ',' if i_idx < len(ip_items) - 1 else ''
                        f.write(f'    {json.dumps(ik)}: {pts_str}{comma}\n')
                    domain_comma = ',' if d_idx < len(domains) - 1 else ''
                    f.write(f'  }}{domain_comma}\n')
                f.write('}\n')
            # 第二步：原子替换（os.replace 在同一文件系统下是原子操作）
            os.replace(tmp_file, HISTORY_FILE)
        except Exception as e:
            cprint(f"[HistoryDB] 保存失败: {e}", 'error')
            # 清理可能残留的临时文件
            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except Exception:
                pass

    def load(self):
        """从 history.json 恢复，GC过期数据，自动过滤无效IP（如[::]、127.0.0.1）"""
        try:
            if not os.path.exists(HISTORY_FILE):
                return
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            cutoff = int(time.time()) - 30 * 86400
            loaded_domains = loaded_ips = skipped_ips = 0
            with self.lock:
                for domain, ip_map in raw.items():
                    if not isinstance(ip_map, dict):
                        continue  # 跳过旧格式残留（扁平key格式）
                    cleaned_map = {}
                    for ik, pts in ip_map.items():
                        if not isinstance(pts, list):
                            continue
                        # 自动过滤CF安全DNS解析出的无效IP（[::]、127.0.0.1等）
                        raw_ip = ik[3:] if ik.startswith('ip:') else ik
                        if self._is_invalid_ip(raw_ip):
                            cprint(f"[HistoryDB] 跳过无效IP: {ik} (域名: {domain})", 'debug')
                            skipped_ips += 1
                            continue
                        cleaned = [[int(ts), int(v)] for ts, v in pts if ts >= cutoff]
                        if cleaned:
                            cleaned_map[ik] = cleaned
                            loaded_ips += 1
                    if cleaned_map:
                        self._data[domain] = cleaned_map
                        loaded_domains += 1
            if skipped_ips:
                cprint(f"[HistoryDB] 已自动过滤 {skipped_ips} 个无效IP记录（[::]、127.0.0.1等）", 'info')
            cprint(f"[HistoryDB] 加载完成：{loaded_domains} 个域名，{loaded_ips} 个IP key", 'info')
        except Exception as e:
            cprint(f"[HistoryDB] 加载失败: {e}", 'error')

hdb = HistoryDB()

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
        self.created_at  = time.time()
        self.last_used   = time.time()

        # 共享 UDP socket（固定源端口）
        self._udp        = socket.socket(af, socket.SOCK_DGRAM)
        try:
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        bind_addr = '::' if af == socket.AF_INET6 else ''
        self._udp.bind((bind_addr, 0))   # 必须监听所有接口，以确保能收到响应
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
        # 更新最后使用时间
        self.last_used = time.time()
        
        # 验证数据包大小
        if len(packet) > 1024 * 64:  # 64KB 限制
            raise OSError("数据包过大")
        
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
                # 验证响应包大小
                if len(data) > 1024 * 64:  # 64KB 限制
                    raise OSError("响应包过大")
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
    _SESSION_TIMEOUT = 3600  # 会话超时时间（秒）

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
        等待超时抛 _ProxyConnectError（不计入代理失败计数）。
        """
        # 快路径：session 有效且未超时直接返回
        with self._lock:
            if (self._session and self._session.valid
                    and self._proxy == proxy_url
                    and self._timeout == timeout
                    and (time.time() - self._session.last_used) < self._SESSION_TIMEOUT):
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
            # 验证代理地址
            if not validate_proxy_url(proxy_url):
                raise _ProxyConnectError("代理地址格式无效")
            
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
        self._udp_sock.bind((bind_addr, 0))   # 必须监听所有接口，确保能收到响应

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
# GEO缓存：key=IP, value=geo dict。使用LRU缓存，限制大小
_GEO_CACHE_CAPACITY = 10000  # 缓存容量
_geo_cache = LRUCache(_GEO_CACHE_CAPACITY)
_geo_cache_lock = threading.RLock()

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

def is_private_ip(ip: str) -> bool:
    """判断是否为私有/保留地址"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified
    except ValueError:
        return False

def get_geo(ip: str) -> dict:
    # 先查缓存，命中直接返回，不发网络请求
    cached = _geo_cache.get(ip)
    if cached and cached.get('country_code','XX') != 'XX':
        return cached   # 只用成功的缓存；XX 表示之前失败，允许重试
    result = {'country':'Unknown','country_code':'XX','isp':'Unknown'}
    # SSRF防护：仅对公网IP发起查询，私有/回环地址直接返回Unknown
    if not _is_safe_public_ip(ip):
        _geo_cache.put(ip, result)
        return result
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
                _geo_cache.put(ip, result)
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
    use_tcp = CONFIG.get('dns_use_tcp', False)
    for rtype, ver in [('A', 'ipv4'), ('AAAA', 'ipv6')]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout  = CONFIG['timeout']
            resolver.lifetime = CONFIG['timeout']
            for rdata in resolver.resolve(domain, rtype, tcp=use_tcp):
                ip = str(rdata)
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass  # 无该类型记录，正常
        except Exception as e:
            db.add_log(f"[dnspython] DNS {rtype} {domain}: {type(e).__name__}: {e}", 'debug')
    return ips

def _parse_dns_servers():
    """解析 dns_custom 配置字符串，返回 [(ip, use_tcp), ...] 列表。
    支持格式：
      8.8.8.8          → UDP/TCP 由全局 dns_use_tcp 决定
      tcp://8.8.8.8    → 强制 TCP 53

    兜底逻辑说明：
      CONFIG.get('dns_custom', '8.8.8.8') —— 配置文件里压根没有 dns_custom 键时的硬编码默认值，
        正常情况下配置页面已经写入该键，这里只是防止空键导致后续代码崩溃。
      if not raw_list: raw_list = ['8.8.8.8'] —— 用户把字段留空/全填逗号时的二次兜底，
        同样只是保证列表非空，不会在实际使用中被触发到。
      两处 8.8.8.8 都不是业务逻辑，而是"最后一道防崩溃"，无实际配置含义。
    """
    servers_raw = CONFIG.get('dns_custom', '8.8.8.8').strip()
    use_tcp_global = CONFIG.get('dns_use_tcp', False)
    raw_list = [s.strip() for s in servers_raw.replace('，', ',').split(',') if s.strip()]
    if not raw_list:
        # 用户填了空字符串或全是逗号，兜底用 Google DNS，避免列表为空导致后续崩溃
        raw_list = ['8.8.8.8']
    servers = []
    for s in raw_list:
        if s.lower().startswith('tcp://'):
            servers.append((s[6:].strip(), True))
        else:
            servers.append((s, use_tcp_global))
    return servers

def _query_single_server(domain: str, rtype: str, srv_ip: str, use_tcp: bool, timeout: float):
    """向单台 DNS 服务器查询。
    返回值：
      [ip, ...]  —— 查询成功，有记录
      []         —— 域名不存在（NXDOMAIN / NoAnswer），确定性结果
      None       —— 超时 / 网络错误，此服务器本次失败
    """
    proto = 'TCP' if use_tcp else 'UDP'
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [srv_ip]
        resolver.timeout  = timeout
        resolver.lifetime = timeout
        return [str(r) for r in resolver.resolve(domain, rtype, tcp=use_tcp)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        # 域名确实不存在，属于正常的"无结果"，不记录为错误
        return []
    except Exception as e:
        # 超时 / 连接失败 / 协议错误 —— error 级别，控制台和 Web 日志都能看到
        db.add_log(
            f"[custom DNS] {srv_ip}({proto}) 查询 {rtype} {domain} 失败: {type(e).__name__}: {e}",
            'error'
        )
        cprint(
            f"[custom DNS] {srv_ip}({proto}) 查询 {rtype} {domain} 失败: {type(e).__name__}: {e}",
            'error'
        )
        return None  # 告知调用方此服务器本次失败，继续尝试其他服务器

# ── DNS 轮询状态（全局，所有 domain 共用，线程安全） ─────────────────────
# 记录"当前轮到哪台服务器"的游标，原子递增取模实现 Round-Robin。
# 各 domain 的每次查询都从同一个游标出发，天然分散请求到不同服务器，
# 不会像 Racing 那样同时向所有服务器发包，大幅减少对运营商 TCP 53 的并发冲击。
_dns_rr_index  = 0
_dns_rr_lock   = threading.Lock()

def _dns_rr_next(count: int) -> int:
    """返回本次查询的起始服务器下标（Round-Robin），线程安全。"""
    global _dns_rr_index
    with _dns_rr_lock:
        idx = _dns_rr_index % count
        _dns_rr_index = (_dns_rr_index + 1) % count
        return idx

def _resolve_custom(domain: str):
    """模式3: 自定义DNS服务器 —— 轮询负载均衡 + 顺序故障转移。

    策略说明：
      1. 每次查询从 Round-Robin 游标选出"本轮首选"服务器，只向它发一次请求。
      2. 若首选服务器超时/失败，依次尝试列表中的其余服务器（故障转移）。
      3. 遇到 NXDOMAIN/NoAnswer 视为"域名不存在的确定答案"，直接停止不再尝试。
      4. 全部服务器均失败时返回空列表，由上层 resolve() 处理日志和 dns_error 标记。

    相比 Racing 模式的优势：
      - 每次只向 1 台服务器发包，不会因并发请求触发运营商对 TCP 53 的限速/丢包。
      - Round-Robin 让请求均匀分散到各服务器，单台压力低，国内/国外混用时效果好。
      - 某台挂掉后自动切换，不影响整体可用性。
    """
    servers = _parse_dns_servers()
    timeout = float(CONFIG.get('timeout', 5))
    count   = len(servers)
    ips     = []
    seen    = set()

    for rtype, ver in [('A', 'ipv4'), ('AAAA', 'ipv6')]:
        start = _dns_rr_next(count)          # Round-Robin 起始下标
        result_ips = None

        for i in range(count):
            srv_ip, use_tcp = servers[(start + i) % count]
            res = _query_single_server(domain, rtype, srv_ip, use_tcp, timeout)

            if res is None:
                # 此服务器超时/网络错误，日志已在 _query_single_server 里记录
                # 继续尝试下一台（故障转移）
                continue

            if res:
                # 查询成功，有 IP 记录
                result_ips = res
                break

            # res == []：NXDOMAIN / NoAnswer —— 域名不存在，确定性结果，无需再问其他服务器
            result_ips = []
            break

        if result_ips:
            for ip in result_ips:
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})

    return ips

# 已记录过DNS失败的域名集合（应用生命周期内只报一次，避免控制台/web日志刷屏）
# 重启应用后集合清空，会重新提醒一次，方便感知配置变更后的效果。
_dns_fail_logged: set = set()
_dns_fail_lock = threading.Lock()

def _dns_fail_once(domain: str) -> bool:
    """返回 True 表示首次失败，应记录日志；False 表示已记录过，静默跳过。"""
    with _dns_fail_lock:
        if domain in _dns_fail_logged:
            return False
        _dns_fail_logged.add(domain)
        return True

def _dns_fail_clear(domain: str):
    """DNS 解析恢复时清除静默标记，下次失败重新提醒。"""
    with _dns_fail_lock:
        _dns_fail_logged.discard(domain)

def resolve(domain: str):
    """根据 CONFIG['dns_mode'] 选择 DNS 解析策略"""
    mode = CONFIG.get('dns_mode', 'system')
    try:
        if mode == 'dnspython':
            ips = _resolve_dnspython(domain)
        elif mode == 'custom':
            ips = _resolve_custom(domain)
        else:
            ips = _resolve_system(domain)
    except Exception as e:
        if _dns_fail_once(domain):
            cprint(f"DNS解析异常 {domain}: {e}", 'error')
            db.add_log(f"DNS解析异常 {domain}: {e}", 'error')
        return []
    if not ips:
        if _dns_fail_once(domain):
            db.add_log(f"DNS解析失败 {domain} [模式:{mode}]: 无结果", 'error')
            cprint(f"DNS解析失败 {domain} [模式:{mode}]", 'error')
    else:
        # 解析成功，清除静默标记（下次再失败时重新提醒）
        _dns_fail_clear(domain)
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
    use_proxy = (CONFIG.get('http_proxy_enabled') and
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


def validate_proxy_url(proxy_url: str) -> bool:
    """验证代理地址格式是否合法"""
    if not proxy_url:
        return True  # 空代理地址视为合法（未启用）
    
    # 支持的代理协议
    valid_schemes = ['http', 'https', 'socks5', 'socks4']
    
    # 解析代理地址
    try:
        # 提取协议
        scheme = None
        for s in valid_schemes:
            if proxy_url.lower().startswith(f'{s}://'):
                scheme = s
                break
        
        if not scheme:
            return False
        
        # 提取主机和端口
        addr = proxy_url[len(f'{scheme}://'):]
        
        # 验证IPv6格式
        if '[' in addr and ']' in addr:
            m = re.match(r'^\[([0-9a-fA-F:]+)\]:(\d+)$', addr)
            if m:
                # 验证IPv6地址
                try:
                    socket.inet_pton(socket.AF_INET6, m.group(1))
                    # 验证端口
                    port = int(m.group(2))
                    return 1 <= port <= 65535
                except:
                    return False
        else:
            # 验证IPv4或域名格式
            m = re.match(r'^([^:]+):(\d+)$', addr)
            if m:
                host = m.group(1)
                port = int(m.group(2))
                
                # 验证端口
                if not (1 <= port <= 65535):
                    return False
                
                # 验证主机（IPv4或域名）
                try:
                    # 尝试解析为IPv4
                    socket.inet_pton(socket.AF_INET, host)
                    return True
                except:
                    # 尝试解析为域名
                    try:
                        socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                        return True
                    except:
                        return False
        return False
    except:
        return False

def validate_config(config: dict) -> list:
    """验证配置参数的合法性，返回错误列表"""
    errors = []
    
    # 验证端口
    if 'listen_port' in config:
        port = config['listen_port']
        if not isinstance(port, int) or port < 1 or port > 65535:
            errors.append('监听端口必须是1-65535之间的整数')
    
    # 验证线程数
    if 'monitor_workers' in config:
        workers = config['monitor_workers']
        if not isinstance(workers, int) or workers < 1 or workers > 1000:
            errors.append('并发检测线程数必须是1-1000之间的整数')
    
    # 验证代理地址
    if 'http_proxy' in config:
        if config.get('http_proxy_enabled') and config['http_proxy']:
            if not validate_proxy_url(config['http_proxy']):
                errors.append('HTTP代理地址格式无效')
    
    if 'udp_proxy' in config:
        if config.get('udp_proxy_enabled') and config['udp_proxy']:
            if not validate_proxy_url(config['udp_proxy']):
                errors.append('UDP代理地址格式无效')
    
    # 验证密码长度
    if 'min_password_length' in config:
        min_len = config['min_password_length']
        if not isinstance(min_len, int) or min_len < 6 or min_len > 128:
            errors.append('密码最小长度必须是6-128之间的整数')
    
    return errors

def parse_url(url: str):
    """解析 tracker URL，支持 IPv4/IPv6/域名，支持方括号 IPv6 格式"""
    url = url.strip()
    
    # 验证URL长度
    if len(url) > 1000:
        return None, None, None
    
    # 纯 IPv4:port  例: 1.2.3.4:6969
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$', url)
    if m:
        ip = m.group(1)
        port = int(m.group(2))
        # 验证IPv4地址
        try:
            socket.inet_pton(socket.AF_INET, ip)
            # 验证端口
            if 1 <= port <= 65535:
                return 'tcp', ip, port
        except:
            pass
    
    # 纯 [IPv6]:port  例: [2001:db8::1]:6969
    m = re.match(r'^\[([0-9a-fA-F:]+)\]:(\d+)$', url)
    if m:
        ip = m.group(1)
        port = int(m.group(2))
        # 验证IPv6地址
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            # 验证端口
            if 1 <= port <= 65535:
                return 'tcp', ip, port
        except:
            pass
    
    # scheme://[IPv6]:port/path  例: http://[2c0f:f4c0::108]:80/announce
    m = re.match(r'^(udp|http|https)://\[([0-9a-fA-F:]+)\](?::(\d+))?(/.*)?$', url, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        host = m.group(2)
        port = int(m.group(3)) if m.group(3) else (443 if scheme == 'https' else 80)
        # 验证IPv6地址
        try:
            socket.inet_pton(socket.AF_INET6, host)
            # 验证端口
            if 1 <= port <= 65535:
                return scheme, host, port
        except:
            pass
    
    # scheme://hostname:port/path
    m = re.match(r'^(udp|http|https)://([^:/\s\[\]]+)(?::(\d+))?(?:/.*)?$', url, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        host = m.group(2)
        port = int(m.group(3)) if m.group(3) else (443 if scheme == 'https' else 80)
        # 验证端口
        if 1 <= port <= 65535:
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
    """封装 SOCKS5 UDP 头并发往 relay，支持 IPv4/IPv6 目标，添加安全检查"""
    try:
        # 验证目标地址
        dst_host, dst_port = dst
        if is_private_ip(dst_host) and not CONFIG.get('allow_private_ips'):
            raise OSError("禁止访问内网地址")
        
        # 验证端口
        if not (1 <= dst_port <= 65535):
            raise OSError("无效的端口号")
        
        # 验证数据包大小
        if len(data) > 1024 * 64:  # 64KB 限制
            raise OSError("数据包过大")
        
        # 封装SOCKS5 UDP头
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
                if len(hb) > 255:
                    raise OSError("域名过长")
                hdr = (b'\x00\x00\x00\x03' + bytes([len(hb)]) + hb
                       + struct.pack('!H', dst_port))
        
        # 发送数据
        udp_sock.sendto(hdr + data, relay_addr)
    except Exception as e:
        raise OSError(f"SOCKS5发送失败: {e}")


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
    udp_proxy = CONFIG.get('udp_proxy', '').strip() if CONFIG.get('udp_proxy_enabled') else ''
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
                return False, -1, f"{_PROXY_UNAVAIL_PREFIX}代理通信失败: {err_str}"

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
        s.bind(bind_addr)   # 必须监听所有接口，确保能收到响应
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

def check_ip(domain, ip_info, retry=True, update_db=True):
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
    if update_db:
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
            # 无结果时日志已在 resolve() 内通过 _dns_fail_once 去重，此处不重复打印
            pass
    except Exception as e:
        db.update_ips(domain, [], dns_error=True)
        # 异常日志同样由 resolve() 内去重处理，此处静默
        pass

# ==================== 网络探针 ====================
# 双重网络健康判断：
#   方案A（探针）：后台定期 TCP 连接 8.8.8.8:53，维护 _probe_ok 状态
#   方案B（失败率）：monitor_loop 每轮统计，≥90% 失败视为本地网络异常
# 两种方案任一触发，即认定本地网络异常，跳过本轮历史写入
_probe_ok   = True    # 探针当前状态（True=可达，False=不可达）
_probe_lock = threading.Lock()
_net_bad = False   # 网络故障标志，由 monitor_loop 每轮更新
_probe_details = {}  # 每个探针IP的最后探测结果 {ip: True/False}

def _probe_loop():
    """后台探针线程：多目标探测，任一可达即视为网络正常，全部不可达才告警。"""
    global _probe_ok, _probe_details
    _warned = False
    # 多个探针目标：任一可达即认为网络正常（避免单点误判）
    PROBE_TARGETS = [
        ('8.8.8.8',   53),   # Google DNS
        ('1.1.1.1',   53),   # Cloudflare DNS
        ('114.114.114.114', 53),  # 国内DNS（服务器在国内也能探到）
    ]
    PROBE_TIMEOUT = 3
    while True:
        probe_interval = CONFIG.get('check_interval', 30)
        reachable = False
        hit_target = ''
        details = {}
        for host, port in PROBE_TARGETS:
            try:
                s = socket.create_connection((host, port), timeout=PROBE_TIMEOUT)
                s.close()
                details[host] = True
                reachable = True
                if not hit_target:
                    hit_target = f"{host}:{port}"
            except Exception:
                details[host] = False
        with _probe_lock:
            prev = _probe_ok
            _probe_ok = reachable
            _probe_details = details
        if not reachable and not _warned:
            targets_str = ', '.join(f"{h}:{p}" for h,p in PROBE_TARGETS)
            msg = f"[探针] 全部目标({targets_str})均不可达，本地网络可能异常"
            db.add_log(msg, 'error')
            cprint(msg, 'error')
            _warned = True
        elif reachable and _warned:
            msg = f"[探针] 网络已恢复，{hit_target} 可达"
            db.add_log(msg, 'info')
            cprint(msg, 'info')
            _warned = False
        time.sleep(probe_interval)

# 立即检测触发器：启动时或添加 tracker 后置位，monitor_loop 检测到后立即执行（不等待 check_interval）
_check_now = threading.Event()

def _check_one_and_record(domain, ip_info, temp_results, round_ok, round_fail, round_lock, temp_lock):
    ip = ip_info['ip']
    with db.lock:
        td       = db.trackers.get(domain, {})
        port     = td.get('port', 80)
        protocol = td.get('protocol', 'tcp')
    proto_s = protocol.upper()
    try:
        # 调用 check_ip 但不更新数据库
        status, lat, err = check_ip(domain, ip_info, retry=True, update_db=False)
        lat_s = f"{lat}ms" if lat >= 0 else "N/A"
        if status == 'skipped':
            cprint(f"⏭ {proto_s}://{domain}:{port} ({ip}) 跳过 | {err}", 'debug')
            return
        # 记录检测完成的时间戳
        check_time = datetime.now().isoformat()
        # 存储结果（增加 check_time）
        with temp_lock:
            temp_results[(domain, ip)] = (status, lat, err, protocol, port, check_time)
        # 更新计数（用于失败率判断）
        if status == 'online':
            with round_lock: round_ok[0] += 1
        else:
            with round_lock: round_fail[0] += 1
        # 立即打印控制台日志，但不写入 db.logs
        if status == 'online':
            msg = f"✓ {proto_s}://{domain}:{port} ({ip}) {lat_s}"
            cprint(msg, 'success')
        else:
            reason = f" | {err}" if err else ""
            msg = f"✗ {proto_s}://{domain}:{port} ({ip}) 离线{reason}"
            cprint(msg, 'error')
    except Exception as e:
        msg = f"检查异常 {domain}:{port} ({ip}): {type(e).__name__}: {e}"
        cprint(msg, 'error')
        with round_lock: round_fail[0] += 1

def _write_healthy_results(temp_results):
    for (domain, ip), (status, lat, err, protocol, port, check_time) in temp_results.items():
        # 更新状态和历史，传入 check_time
        db.update_status(domain, ip, status, lat, check_time)
        # 添加日志
        proto_s = protocol.upper()
        lat_s = f"{lat}ms" if lat >= 0 else "N/A"
        if status == 'online':
            msg = f"✓ {proto_s}://{domain}:{port} ({ip}) {lat_s}"
            db.add_log(msg, 'success')
        else:
            reason = f" | {err}" if err else ""
            msg = f"✗ {proto_s}://{domain}:{port} ({ip}) 离线{reason}"
            db.add_log(msg, 'error')
        # 归属地补查（与原有逻辑相同）
        need_geo = False
        with db.lock:
            for ip_obj in db.trackers.get(domain, {}).get('ips', []):
                if ip_obj.get('ip') == ip:
                    need_geo = ip_obj.get('country', {}).get('country_code', 'XX') == 'XX'
                    break
        if need_geo:
            new_geo = get_geo(ip)
            if new_geo.get('country_code', 'XX') != 'XX':
                with db.lock:
                    for ip_obj in db.trackers.get(domain, {}).get('ips', []):
                        if ip_obj.get('ip') == ip:
                            ip_obj['country'] = new_geo
                            break

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
            # ── 第二步：并行检测所有 IP（暂不更新数据库） ───────────────
            snapshot = db.get_trackers()
            tasks = []
            for domain, data in snapshot.items():
                if data.get('paused'):        # 整个域名暂停，跳过
                    continue
                for ip_info in data.get('ips', []):
                    if not ip_info.get('removed') and not ip_info.get('paused'):
                        tasks.append((domain, ip_info))
            # 存储本轮结果的字典：{(domain, ip): (status, lat, err, protocol, port)}
            temp_results = {}
            temp_lock = threading.Lock()
            # 用计数器收集本轮检测结果，检测完后判断网络健康度
            round_ok  = [0]
            round_fail = [0]
            round_lock = threading.Lock()
            # ── 发包错峰：分批提交避免瞬间高并发冲击本地网络/代理 ──────────
            use_proxy_stagger = bool(CONFIG.get('udp_proxy_enabled') and CONFIG.get('udp_proxy','').strip())
            if use_proxy_stagger:
                STAGGER_BATCH = int(CONFIG.get('stagger_batch_proxy', 5))
                STAGGER_DELAY = int(CONFIG.get('stagger_delay_proxy', 150)) / 1000.0
            else:
                STAGGER_BATCH = int(CONFIG.get('stagger_batch_direct', 5))
                STAGGER_DELAY = int(CONFIG.get('stagger_delay_direct', 100)) / 1000.0
            with ThreadPoolExecutor(max_workers=max(8, CONFIG.get('monitor_workers', 120))) as chk_pool:
                futures = {}
                if len(tasks) > STAGGER_BATCH:
                    for i in range(0, len(tasks), STAGGER_BATCH):
                        batch = tasks[i:i + STAGGER_BATCH]
                        for d, ipi in batch:
                            f = chk_pool.submit(_check_one_and_record, d, ipi, temp_results,
                                                round_ok, round_fail, round_lock, temp_lock)
                            futures[f] = (d, ipi['ip'])
                        if i + STAGGER_BATCH < len(tasks):
                            time.sleep(STAGGER_DELAY)
                else:
                    futures = {chk_pool.submit(_check_one_and_record, d, ipi, temp_results,
                                               round_ok, round_fail, round_lock, temp_lock): (d, ipi['ip'])
                               for d, ipi in tasks}
                for f in as_completed(futures):
                    try: f.result()
                    except Exception as e:
                        d, ip = futures[f]
                        cprint(f"检测线程异常 {d} ({ip}): {e}", 'error')
            # ── 第三步：网络健康判断（探针 + 失败率双重保障）────────────
            total_checked = round_ok[0] + round_fail[0]
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
                fail_rate = round_fail[0] / total_checked
                if fail_rate >= 0.90:
                    net_ok = False
                    net_reason = f'失败率{fail_rate*100:.0f}%({round_fail[0]}/{total_checked})'
            if not net_ok:
                if not _net_warn_printed:
                    warn_msg = (f"[网络异常] 疑似本地网络故障（{net_reason}），"
                                f"本轮历史数据不计入统计")
                    db.add_log(warn_msg, 'error')
                    cprint(warn_msg, 'error')
                    _net_warn_printed = True
                with _probe_lock:
                    _net_bad = True
                # 本轮结果直接丢弃，不更新数据库
            else:
                if _net_warn_printed:
                    recover_msg = "[网络恢复] 探针与检测均正常，恢复历史数据统计"
                    db.add_log(recover_msg, 'info')
                    cprint(recover_msg, 'info')
                    _net_warn_printed = False
                with _probe_lock:
                    _net_bad = False
                if temp_results:   # 只有有实际检测结果才写入
                    _write_healthy_results(temp_results)
                    if CONFIG.get('cache_history', True):
                        db._save_async()
                # 保存数据（仅当 cache_history 开启）
                if CONFIG.get('cache_history', True):
                    db._save_async()  # 改为异步保存
            s = db.get_stats()
            summary = (f"轮检完成 | "
                       f"总:{s['total']} [v4:{s['ipv4']} v6:{s['ipv6']}] | "
                       f"在线:{s['alive']} [v4:{s['alive_v4']} v6:{s['alive_v6']}]"
                       + (" | ⚠ 网络异常轮次，历史跳过" if not net_ok else ""))
            db.add_log(summary, 'info')
        except Exception as e:
            msg = f"监控线程错误: {type(e).__name__}: {e}"
            db.add_log(msg, 'error')
            cprint(msg, 'error')
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
    # CSP：只允许同源资源，内联脚本/样式因项目需要允许（unsafe-inline）
    # 不加 upgrade-insecure-requests，避免内网http环境下把http资源强制升级导致加载失败
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self'"
    )
    # HSTS：仅在 HTTPS 模式下添加，内网 http 环境不加（避免浏览器强制跳转https导致无法访问）
    if _https_enabled:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Server 头不暴露服务器特征，直接移除
    response.headers.remove('Server')
    path   = request.path
    method = request.method
    # ── API whoami响应禁止缓存（防止 CF/CDN 缓存认证状态等动态内容）──
    if path.startswith('/api/auth/whoami'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
    # ── 调试模式判断（控制 304 是否静默） ──
    is_debug_mode = CONFIG.get('log_level') == 'debug' or getattr(app, 'debug', False)
    # ── 静态资源（/static/）缓存策略 ──
    # 路径安全：Flask send_from_directory 内部用 werkzeug.security.safe_join，
    # 已防止路径穿越（CWE-22），无需额外处理。
    # Cache-Control: public, max-age=31536000, immutable
    #   浏览器 + CF 均缓存1年，源站下线期间静态资源照常加载。
    #   更新文件时在 CF 控制台手动清除缓存（Purge Cache）即可。
    # 调试模式下 304 会正常 输出到控制台 + 写入 access.log
    # 200 正常记录：首次加载/CF回源时可见。
    if path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        if response.status_code == 304 and not is_debug_mode:
            return response  # 非调试模式下 304静默
        # 200 继续往下，正常记录日志
    # ── JSON API gzip 压缩（浏览器支持时，响应 >1KB 才压缩）──
    # 文件下载（Content-Disposition）跳过，避免对已压缩内容二次压缩
    # 重要：含 Set-Cookie 的响应（登录等）跳过 gzip，防止 set_data() 破坏 session cookie
    ct = response.content_type or ''
    has_set_cookie = bool(response.headers.get('Set-Cookie'))
    if ('application/json' in ct or 'text/plain' in ct) \
            and not response.headers.get('Content-Disposition') \
            and not has_set_cookie:
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
    # 保留此逻辑，因为这些请求每秒几十次，完全无调试价值
    # 静默路径（前端内部轮询/导航）：不打印日志
    if path.split('?')[0].rstrip('/') in _NOISY_PATHS:
        return response
    # whoami 去重日志：正常200每IP每分钟只打印一次，429/异常状态始终打印
    if path == '/api/auth/whoami':
        real_ip = request.headers.get('CF-Connecting-IP') or request.headers.get('X-Real-IP') or request.remote_addr
        now_t = time.time()
        _wkey = f'whoami:{real_ip}'
        with _rate_limit_warned_lock:
            last_t = _rate_limit_warned.get(_wkey, 0)
            is_anomaly = response.status_code != 200
            if is_anomaly or (now_t - last_t >= 60):
                _rate_limit_warned[_wkey] = now_t
                # 打印日志（异常完整记录，正常只记一条去重摘要）
                pass  # 继续走下方统一日志逻辑
            else:
                return response  # 正常请求1分钟内静默
    # HTML 页面的 304（ETag命中/CF回源验证）静默：非调试模式下隐藏:0字节请求（不刷控制台、不写 access.log）
    # 只有调试模式才放行，让正常日志流程输出
    _HTML_PATHS = {'/', '/home', '/stats', '/ranking', '/logs', '/config'}
    if (path.rstrip('/') or '/') in _HTML_PATHS and response.status_code == 304 and not is_debug_mode:
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

    # ===== 为 GET 页面请求设置 CSRF cookie =====
    if request.method == 'GET' and not request.path.startswith('/api/'):
        token = generate_csrf_token()
        response.set_cookie('csrf_token', token, httponly=False, samesite='Lax', secure=app.config['SESSION_COOKIE_SECURE'])

    return response

# ==================== HTML 路由 ====================
def find_html():
    base = os.path.dirname(os.path.abspath(__file__))
    for p in [os.path.join(base,'templates','index.html'), os.path.join(base,'index.html')]:
        if os.path.exists(p): return p
    return None

# language/ 已移入 static/language/，由 Flask 内置静态路由处理，无需自定义路由
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
    etag = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    _html_cache.update({'mtime': mtime, 'raw': raw, 'gz': gz, 'etag': etag})
    return _html_cache

def _serve_html():
    p = find_html()
    if not p:
        return "index.html not found.", 404
    cache = _load_html(p)
    etag  = f'"{cache["etag"]}"'
    # 无论客户端是否发了 Cache-Control: no-cache（即 F5 刷新），
    # 只要 If-None-Match 匹配就返回 304，让浏览器用本地缓存。
    # RFC 7234 §5.2：服务端可以忽略 no-cache 指令并返回 304，
    # 这是服务端主动优化，不违反规范。
    if request.headers.get('If-None-Match') == etag:
        resp = make_response('', 304)
        resp.headers['ETag']          = etag
        resp.headers['Cache-Control'] = 'no-cache'
        resp.headers['Vary']          = 'Accept-Encoding, Cookie'
        resp.headers['Content-Length'] = '0'
        return resp
    accept_gz = 'gzip' in request.headers.get('Accept-Encoding', '')
    body      = cache['gz'] if accept_gz else cache['raw']
    resp = make_response(body, 200)
    resp.headers['Content-Type']  = 'text/html; charset=utf-8'
    resp.headers['ETag']          = etag
    # 浏览器：max-age=0+must-revalidate → 每次向 CF 验证 ETag（304=0字节，极快）
    # CF：s-maxage=3600 → 边缘缓存1小时，ETag变（html更新）时重新回源
    # Vary: Cookie → 登录/未登录用不同缓存版本（避免把登录页缓存给未登录用户）
    resp.headers['Cache-Control'] = 'public, max-age=0, must-revalidate, s-maxage=3600'
    resp.headers['Vary']          = 'Accept-Encoding, Cookie'
    if accept_gz:
        resp.headers['Content-Encoding'] = 'gzip'
    return resp

@app.route('/')
def index():
    if request.query_string:
        return redirect('/home', code=301)
    return _serve_html()

@app.route('/home')
@app.route('/stats')
@app.route('/ranking')
@app.route('/logs')
@app.route('/config')
def spa_routes():
    # 带 query string 的请求一律重定向到干净路径，防止被刷流量
    # 安全修复：使用白名单校验路径，避免 Open Redirect（用户可控 request.path 可被构造为恶意路径）
    if request.query_string:
        _SPA_PATH_WHITELIST = {'/home', '/stats', '/ranking', '/logs', '/config'}
        safe_path = request.path if request.path in _SPA_PATH_WHITELIST else '/'
        return redirect(safe_path, code=301)
    return _serve_html()

# ── 公开 Tracker 导出 API ──
@app.route('/trackers')
@app.route('/tracker.txt')
def api_trackers_compat():
    """Legacy-compatible shortcuts — directly serves /api/tracker, no redirect."""
    return api_trackers_export()

@app.route('/api/tracker')
def api_trackers_export():
    """Public tracker list — plain text, one URL per line.

    GET /api/tracker
    /trackers and /tracker.txt redirect here automatically (legacy-compatible).

    Query params (all optional):
      day    = 24h | 7d | 30d        (default: 24h)   uptime stats period
      uptime = 0 | 50 | 80 | 90 | 100 (default: 0)   minimum uptime % (0 = no filter)
      net    = all | tcp | udp       (default: all)   protocol filter
      ip     = all | ipv4 | ipv6    (default: all)   IP version filter
      url    = any string            (default: /announce) URL suffix per entry

    Examples:
      curl http://host/api/tracker
      curl "http://host/api/tracker?day=7d&uptime=90"
      curl "http://host/api/tracker?day=30d&uptime=90&net=tcp&ip=ipv4"
      curl "http://host/api/tracker?day=30d&uptime=90&ip=ipv6"
      curl "http://host/api/tracker?uptime=90&net=udp&ip=ipv4&url=/announce"
    """
    period     = request.args.get('day', '24h')
    if period not in ('24h','7d','30d'): period = '24h'
    min_uptime = request.args.get('uptime', 0, type=float)
    proto      = request.args.get('net', 'all').lower()
    ip_ver     = request.args.get('ip', 'all').lower()
    suffix_raw = request.args.get('url', None)
    if suffix_raw is None:
        suffix = CONFIG.get('export_suffix', '/announce')
    else:
        # 允许传 "announce" 自动补斜杠，或传 "" 表示无后缀
        suffix = ('/' + suffix_raw.lstrip('/')) if suffix_raw else ''
    ranking = db.get_ranking(period, 9999, min_uptime)
    with db.lock:
        trackers_snap = {k: dict(v) for k, v in db.trackers.items()}
    lines = []
    for item in ranking:
        domain   = item['domain']
        td       = trackers_snap.get(domain, {})
        protocol = td.get('protocol', 'tcp')
        port     = td.get('port', 80)
        ips      = td.get('ips', [])
        if proto != 'all':
            is_udp = (protocol == 'udp')
            if proto == 'udp' and not is_udp: continue
            if proto == 'tcp' and is_udp: continue
        online_ips = [ip for ip in ips if not ip.get('removed') and ip.get('status') == 'online']
        if ip_ver != 'all':
            online_ips = [ip for ip in online_ips if ip.get('version','ipv4') == ip_ver]
        if not online_ips: continue
        scheme = 'udp' if protocol == 'udp' else ('https' if protocol == 'https' else 'http')
        url = f"{scheme}://{domain}:{port}{suffix}"
        lines.append(url)
        lines.append('')  # 每个域名后空一行
    while lines and lines[-1] == '':
        lines.pop()
    text = '\n'.join(lines)
    resp = Response(text, mimetype='text/plain')
    resp.headers['Cache-Control'] = 'public, max-age=60'
    return resp

# ==================== API ====================
_login_fail = {}           # {client_ip: [fail_count, locked_until, notified]}
_login_fail_lock = threading.Lock()

def _login_check_and_record(client, success):
    """记录登录失败/成功，失败达到阈值后锁定IP一段时间。"""
    MAX_FAIL  = 10        # 最大失败次数
    LOCK_TIME = 15 * 60   # 锁定时长（秒）
    with _login_fail_lock:
        if success:
            _login_fail.pop(client, None)
            return
        rec = _login_fail.get(client, [0, 0, False])
        rec[0] += 1
        if rec[0] >= MAX_FAIL and not rec[2]:
            rec[1] = time.time() + LOCK_TIME
            rec[2] = True
            msg = f'[auth] IP {client} 登录失败 {rec[0]} 次，锁定 {LOCK_TIME//60} 分钟'
            cprint(msg, 'error')
            try: db.add_log(msg, 'error')
            except Exception: pass
        _login_fail[client] = rec

# 重试操作节流：按用户session记录上次操作时间
_retry_throttle = {}       # {username: last_check_time}
_retry_throttle_lock = threading.Lock()

def _check_retry_throttle(min_interval_ms):
    """检查当前用户是否在冷却期内，返回True=允许，False=拒绝。"""
    username = session.get('username') or _client_ip()
    now = time.time()
    min_interval = min_interval_ms / 1000.0
    with _retry_throttle_lock:
        last = _retry_throttle.get(username, 0)
        if now - last < min_interval:
            return False
        _retry_throttle[username] = now
        return True

def _memory_cleanup_loop():
    """后台定期清理限流/登录失败等内存字典中的过期条目，防止长时间运行内存缓慢增长。
    清理间隔由 config['cleanup_interval'] 控制，默认3600秒（1小时）。
    各字典清理策略：
      _rate_limit_store  : 删除所有时间戳列表为空的IP条目（时间戳已在每次请求时滚动清理）
      _rate_limit_warned : 删除上次警告时间超过2倍cleanup_interval的IP
      _login_fail        : 删除锁定已到期 且 失败次数已重置 的IP条目
      _retry_throttle    : 删除上次操作时间超过1小时的用户
      _query_rate        : 删除所有时间戳列表为空的IP条目
    """
    while True:
        interval = CONFIG.get('cleanup_interval', 3600)
        time.sleep(interval)
        now = time.time()
        cleaned = {}

        # 清理 _rate_limit_store：删除空列表条目
        with _rate_limit_lock:
            before = len(_rate_limit_store)
            expired = [ip for ip, ts in _rate_limit_store.items() if not ts]
            for ip in expired:
                del _rate_limit_store[ip]
            cleaned['rate_limit_store'] = before - len(_rate_limit_store)

        # 清理 _rate_limit_warned：超过2倍间隔未再触发的IP
        with _rate_limit_warned_lock:
            before = len(_rate_limit_warned)
            expired = [ip for ip, t in _rate_limit_warned.items() if now - t > interval * 2]
            for ip in expired:
                del _rate_limit_warned[ip]
            cleaned['rate_limit_warned'] = before - len(_rate_limit_warned)

        # 清理 _login_fail：锁定已到期的条目
        with _login_fail_lock:
            before = len(_login_fail)
            expired = [ip for ip, rec in _login_fail.items()
                       if rec[1] < now and now - rec[1] > interval]
            for ip in expired:
                del _login_fail[ip]
            cleaned['login_fail'] = before - len(_login_fail)

        # 清理 _retry_throttle：超过1小时未操作的用户
        with _retry_throttle_lock:
            before = len(_retry_throttle)
            expired = [u for u, t in _retry_throttle.items() if now - t > 3600]
            for u in expired:
                del _retry_throttle[u]
            cleaned['retry_throttle'] = before - len(_retry_throttle)

        # 清理 _query_rate：删除空列表条目
        with _query_rate_lock:
            before = len(_query_rate)
            expired = [ip for ip, ts in _query_rate.items() if not ts]
            for ip in expired:
                del _query_rate[ip]
            cleaned['query_rate'] = before - len(_query_rate)

        total = sum(cleaned.values())
        if total > 0:
            cprint(f"[cleanup] 限流内存清理完成，共清除 {total} 条过期记录: {cleaned}", 'info')
# ── 认证 ──
@app.route('/api/auth/login', methods=['POST'])
@rate_limit(limit=10, window=60)  # 登录限流
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
    # 生成 CSRF token
    token = generate_csrf_token()
    resp = jsonify({'success': True, 'username': username, 'role': user['role'], 'csrf_token': token})
    resp.set_cookie('csrf_token', token, httponly=False, samesite='Lax', secure=app.config['SESSION_COOKIE_SECURE'])
    g.access_note = f"login [{username}] role={user['role']}"
    return resp

@app.route('/api/auth/logout', methods=['POST'])
@csrf_protect
def api_logout():
    username = session.get('username','?')
    session.clear()
    g.access_note = f"logout [{username}]"
    return jsonify({'success': True})

@app.route('/api/auth/change-password', methods=['POST'])
@csrf_protect
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
    min_len = CONFIG.get('min_password_length', 8)
    if len(new_pw) < min_len:
        return jsonify({'error': f'新密码长度不能少于{min_len}位'}), 400
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
@rate_limit(limit=30, window=60)   # 每IP每分钟最多30次，防刷
def api_whoami():
    role = session.get('role')
    resp = jsonify({'logged_in': bool(role), 'role': role, 'username': session.get('username') if role else None})
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    return resp

# ── 统计 ──
@app.route('/api/count')
def api_stats():
    s = db.get_stats()
    with _probe_lock:
        probe_ok = _probe_ok
        net_bad = _net_bad
    s['net_probe_ok'] = probe_ok
    s['net_healthy']  = probe_ok and not net_bad
    s['probe_details'] = _probe_details
    today = datetime.now().strftime('%Y-%m-%d')
    logs = db.get_logs(limit=5000)
    s['today_alerts'] = sum(
        1 for l in logs
        if l.get('level') == 'error'
        and l.get('time', '').startswith(today)
        and ('离线' in l.get('message', '') or 'offline' in l.get('message', '').lower())
    )
    return jsonify(s)

@app.route('/api/datas')
def api_trackers():
    return jsonify(db.get_trackers())

# ── tracker 管理 ──
# 在文件顶部添加脱敏函数（例如紧跟在 _client_ip 定义之后）
def _anonymize_ip(ip: str) -> str:
    parts = ip.split('.')
    if len(parts) == 4:
        # IPv4: 1.2.3.4 -> 1.*.*.4
        return f"{parts[0]}.*.*.{parts[3]}"
    segs = ip.split(':')
    if len(segs) >= 3:
        # IPv6: 保留前两组和最后一组，中间用 **** 代替
        return f"{segs[0]}:{segs[1]}:****:{segs[-1]}"
    return ip  # fallback

def _validate_ip(ip: str) -> bool:
    """检查 IP 是否允许添加（根据配置）"""
    if CONFIG.get('allow_private_ips'):
        return True
    return not is_private_ip(ip)

def _validate_domain_ips(ips: list) -> Tuple[bool, Optional[str]]:
    """检查解析出的 IP 列表是否允许添加"""
    if CONFIG.get('allow_private_ips'):
        return True, None
    for info in ips:
        ip = info['ip']
        if is_private_ip(ip):
            return False, f"包含内网地址: {ip}"
    return True, None

@app.route('/api/tracker/add', methods=['POST'])
@_require_role('admin', 'operator')
@csrf_protect
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
            if not _validate_ip(host):
                errors.append(f"禁止添加内网IP: {host}"); continue
            geo  = get_geo(host)
            ver  = 'ipv6' if ':' in host else 'ipv4'
            ips  = [{'ip':host,'version':ver,'country':geo}]
        else:
            ips = resolve(host)
            if not ips:
                errors.append(f"DNS解析失败: {host}"); continue
            valid, msg = _validate_domain_ips(ips)
            if not valid:
                errors.append(f"{host} {msg}"); continue
        db.add_tracker(host, port, protocol, ips)
        # 获取原始 IP 并脱敏
        raw_ip = _client_ip()
        masked_ip = _anonymize_ip(raw_ip)
        op_user = session.get('username', '?')
        msg = f"添加 {protocol.upper()}://{host}:{port} 解析{len(ips)}个IP"
        db.add_log(f"{masked_ip} [{op_user}] {msg}", 'info')   # 脱敏后写入日志
        g.access_note = f"add {protocol.upper()}://{host}:{port} ({len(ips)} IPs) by {raw_ip} [{op_user}]"
        def bg(d=host):
            with db.lock:
                # 后台检测保持不变
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
@csrf_protect
def api_delete():
    domain = (request.json or {}).get('domain','').strip()
    with db.lock:
        if domain in db.trackers:
            # 清除该域名在 hdb 中的所有历史（含活跃IP和已移除IP，因为是域名级父节点）
            hdb.remove_domain(domain)
            del db.trackers[domain]
            db._recalc()
            db._clear_uptime_cache(domain)
            db._save_async()
            raw_ip = _client_ip()
            masked_ip = _anonymize_ip(raw_ip)
            op_user = session.get('username', '?')
            msg = f"删除 {domain}"
            db.add_log(f"{masked_ip} [{op_user}] {msg}", 'info')   # 脱敏后写入日志
            g.access_note = f"delete {domain} by {raw_ip} [{op_user}]"
            return jsonify({'success':True})
    return jsonify({'error':'不存在'}), 404

@app.route('/api/tracker/pause', methods=['POST'])
@_require_role('admin', 'operator')
@csrf_protect
def api_pause():
    """暂停/恢复监控。支持：整个域名、域名下单个IP、全部域名。
    body: { action: 'pause'|'resume', domain?: str, ip?: str, all?: bool }
    """
    data   = request.json or {}
    action = data.get('action', 'pause')
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
        db._save_async()  # 异步保存
    label = '暂停' if paused else '恢复'
    target = 'ALL' if all_ else (f"{domain}/{ip}" if ip else domain)
    # 操作者信息
    raw_ip   = _client_ip()
    op_user  = session.get('username', '?')
    # IPv4: 1.*.*.256（保留第1段和最后1段，中间打星）
    # IPv6: 保留前2组和最后一组，中间打星
    parts = raw_ip.split('.')
    if len(parts) == 4:
        masked_ip = f"{parts[0]}.*.*.{parts[3]}"
    else:
        segs = raw_ip.split(':')
        if len(segs) >= 3:
            masked_ip = f"{segs[0]}:{segs[1]}:****:{segs[-1]}"
        else:
            masked_ip = raw_ip
    # 控制台/access.log 用完整 IP；Web 日志用脱敏 IP
    console_str = f"{raw_ip} [{op_user}] 监控{label}: {target}"
    web_str     = f"{masked_ip} [{op_user}] 监控{label}: {target}"
    g.access_note = f"{label} {target} by {raw_ip} [{op_user}]"
    print(f"[PAUSE] {console_str}")          # 控制台完整 IP
    db.add_log(web_str, 'info')              # Web 界面脱敏 IP
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
            cprint(f"{ts} [INFO] {res_msg}", 'info', raw=True)
        else:
            reason = f" | {err}" if err and status=='offline' else ""
            res_msg = f"重试结果: {protocol.upper()}://{domain}:{port} ({ipi['ip']}) → {status} {lat_s}{reason}"
            cprint(f"{ts} [INFO] {res_msg}", 'info', raw=True)
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
    with db.lock:
        trackers_snap = {k: dict(v) for k, v in db.trackers.items()}
    lines = []
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
        lines.append('')  # 每个域名后空一行
    while lines and lines[-1] == '':
        lines.pop()
    text = '\n'.join(lines)
    response = make_response(text)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename="trackers-{period}.txt"'
    # 防止浏览器 MIME 嗅探将 text/plain 误解析为 HTML（防御 XSS）
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# CF/反向代理 IP 信任：读取 config，运行时可热更新，无需重启
# 关于 CF 是否能被伪造：
#   直接访问源站时：攻击者可伪造 CF-Connecting-IP / X-Forwarded-For → 设 False
#   流量经过 CF 时：CF 会覆盖 CF-Connecting-IP 为真实客户端IP，且源站只收到来自
#   CF CIDR 的连接，所以此时信任 CF-Connecting-IP 是安全的 → 设 True
#   本地内网/http测试：remote_addr 就是真实IP，设 False 完全够用

def _client_ip():
    """获取客户端真实IP。
    trust_cf_ip=True：优先读 CF-Connecting-IP（CF会覆盖，不可伪造），
                      其次读 X-Forwarded-For 最右侧可信跳。
    trust_cf_ip=False（默认/内网）：直接用 remote_addr，不信任任何代理头。
    """
    if CONFIG.get('trust_cf_ip', False):
        # CF 专用头，CF 会强制覆盖此值为真实客户端IP
        cf_ip = request.headers.get('CF-Connecting-IP', '').strip()
        if cf_ip:
            return cf_ip
        # 无CF头时降级：取 XFF 链最后一个（最靠近服务器的可信跳）
        fwd = request.headers.get('X-Forwarded-For', '')
        if fwd:
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

# ── /api/query 对外查询接口 ──────────────────────────────────────────────────
# 速率限制：同IP每分钟最多66次
import threading as _threading
_query_rate: dict = {}
_query_rate_lock = _threading.Lock()

def _query_rate_limit(ip_key: str, limit: int = 66, window: int = 60) -> bool:
    import time as _time
    now = _time.time()
    with _query_rate_lock:
        ts = _query_rate.get(ip_key, [])
        ts = [t for t in ts if now - t < window]
        if len(ts) >= limit:
            _query_rate[ip_key] = ts
            return False
        ts.append(now)
        _query_rate[ip_key] = ts
        return True

@app.route('/api/query')
def api_query():
    """
    对外开放的单域名/IP查询接口。
    参数:
        ?host=<域名或IP>
        &list=status,uptime,delay,location,checked  (可选，默认 status,uptime,delay,checked)
        &type=json|txt  (可选；只带host时默认txt，带list时默认json，显式指定优先)
    域名查询时，JSON 中 ips 字段自动包含所有激活IP（非暂停、非移除）的详情；
    txt 格式每行一个IP：ip  status  uptime  delay  [location]  [checked]
    速率限制: 同IP每分钟66次
    """
    client_ip = _client_ip()
    if not _query_rate_limit(client_ip):
        type_arg = request.args.get('type', '').lower()
        if type_arg == 'json':
            return jsonify({'error': 'Rate limit exceeded. Max 66/min per IP.', 'code': 429}), 429
        from flask import Response as _R
        return _R('Rate limit exceeded (max 66/min per IP)\n', status=429, mimetype='text/plain')
    host = request.args.get('host', '').strip()
    if not host:
        return jsonify({'error': 'Missing required parameter: host',
                        'usage': '/api/query?host=example.com',
                        'optional': 'list=status,uptime,delay,location,checked  type=json|txt'}), 400
    list_raw  = request.args.get('list', '').lower()
    type_raw  = request.args.get('type', '').lower()
    has_extra = bool(list_raw or type_raw)
    # 字段集合（ips 不作为独立字段，域名查询时自动附带）
    VALID = {'status', 'uptime', 'delay', 'location', 'checked'}
    if list_raw:
        fields = {f.strip() for f in list_raw.split(',') if f.strip()} & VALID
        if not fields: fields = {'status', 'uptime', 'delay', 'checked'}
    else:
        fields = {'status', 'uptime', 'delay', 'checked'}
    fields.add('status')
    # 格式：仅带host→txt；有list/type时→json；显式type优先
    if   type_raw == 'txt':  fmt = 'txt'
    elif type_raw == 'json': fmt = 'json'
    elif not has_extra:      fmt = 'txt'
    else:                    fmt = 'json'
    # 查找匹配的 tracker
    matched_ip = None; matched_tr = None; is_domain = False
    with db.lock:
        all_tr = dict(db.trackers)
    # 优先精确匹配域名
    if host in all_tr:
        matched_tr = all_tr[host]
        is_domain  = True
        # 选代表IP（优先online且未暂停，否则第一个非removed非paused）
        active = [ip for ip in matched_tr.get('ips', []) if not ip.get('removed') and not ip.get('paused')]
        if not active:
            active = [ip for ip in matched_tr.get('ips', []) if not ip.get('removed')]
        online = [ip for ip in active if ip.get('status') == 'online']
        matched_ip = online[0] if online else (active[0] if active else None)
    else:
        # 按IP地址匹配
        for _dom, _tr in all_tr.items():
            for _ip in _tr.get('ips', []):
                if _ip.get('ip') == host and not _ip.get('removed'):
                    matched_tr = _tr; matched_ip = _ip; break
            if matched_tr: break
    if not matched_tr:
        if fmt == 'txt':
            from flask import Response as _R
            return _R(f'{host}  Not Found\n', status=404, mimetype='text/plain')
        return jsonify({'error': f'Host not found: {host}', 'host': host}), 404
    # 构建域名级状态
    period = CONFIG.get('tracker_stat_period', '24h')
    secs   = HISTORY_WINDOWS.get(period, 86400)
    is_paused  = matched_tr.get('paused') or (matched_ip and matched_ip.get('paused'))
    raw_status = matched_ip.get('status', 'unknown') if matched_ip else 'unknown'
    if is_paused:       status_val = 'Paused'
    elif raw_status == 'online':  status_val = 'Online'
    elif raw_status == 'offline': status_val = 'Offline'
    else:                         status_val = 'Unknown'
    result = {'host': host}
    if 'status' in fields:
        result['status'] = status_val
    if 'uptime' in fields:
        if is_domain:
            tr_paused  = matched_tr.get('paused', False)
            paused_set = set() if tr_paused else {
                ip.get('ip','') for ip in matched_tr.get('ips', [])
                if ip.get('paused') and not ip.get('removed')
            }
            s = hdb.get_domain_summary(host, secs, excluded_ips=paused_set if paused_set else None)
        else:
            domain_key = next((d for d, t in all_tr.items() if any(i.get('ip') == host for i in t.get('ips', []))), '')
            s = hdb.get_ip_summary(domain_key, host, secs)
        uptime = round(s['ok'] / s['total'] * 100, 1) if s['total'] > 0 else None
        result['uptime'] = f'{uptime}%' if uptime is not None else None
    if 'delay' in fields:
        lat = matched_ip.get('latency', -1) if matched_ip else -1
        result['delay'] = f'{lat}ms' if isinstance(lat, (int, float)) and lat >= 0 else None
    if 'location' in fields:
        co    = (matched_ip.get('country') or {}) if matched_ip else {}
        parts = [p for p in [co.get('country'), co.get('isp')] if p]
        result['location'] = ' · '.join(parts) if parts else None
    if 'checked' in fields:
        result['checked'] = (matched_ip.get('last_check') or None) if matched_ip else None

    # ── 域名查询：附带所有激活IP的详情 ──────────────────────────
    if is_domain:
        ip_rows = []
        for ipi in matched_tr.get('ips', []):
            if ipi.get('removed') or ipi.get('paused'):
                continue
            s_ip  = hdb.get_ip_summary(host, ipi.get('ip', ''), secs)
            up_ip = round(s_ip['ok'] / s_ip['total'] * 100, 1) if s_ip['total'] > 0 else None
            lat_i = ipi.get('latency', -1)
            row   = {
                'ip':      ipi.get('ip'),
                'version': ipi.get('version', 'ipv4'),
                'status':  ipi.get('status', 'unknown'),
                'latency': lat_i,
                'uptime':  up_ip,
            }
            if 'location' in fields:
                co_i  = ipi.get('country') or {}
                pts   = [p for p in [co_i.get('country'), co_i.get('isp')] if p]
                row['location'] = ' · '.join(pts) if pts else None
            if 'checked' in fields:
                row['checked'] = ipi.get('last_check') or None
            ip_rows.append(row)
        result['ips'] = ip_rows

    # ── 输出 ──────────────────────────────────────────────────────
    if fmt == 'txt':
        from flask import Response as _R
        lines = []
        if is_domain:
            # 第一行：域名汇总
            col_order = ['status', 'uptime', 'delay', 'location', 'checked']
            summary_parts = [host] + [str(result[k]) if result.get(k) is not None else '-'
                                      for k in col_order if k in result]
            lines.append('  '.join(summary_parts))
            # 后续行：每个激活IP一行
            for row in result.get('ips', []):
                ip_parts = [row['ip'],
                            row.get('status', 'unknown'),
                            (f"{row['uptime']}%" if row.get('uptime') is not None else '-'),
                            (f"{row['latency']}ms" if isinstance(row.get('latency'), (int, float)) and row['latency'] >= 0 else '-')]
                if 'location' in fields:
                    ip_parts.append(row.get('location') or '-')
                if 'checked' in fields:
                    ip_parts.append(str(row.get('checked')) if row.get('checked') else '-')
                lines.append('  '.join(ip_parts))
        else:
            col_order = ['status', 'uptime', 'delay', 'location', 'checked']
            parts = [host] + [str(result[k]) if result.get(k) is not None else '-'
                              for k in col_order if k in result]
            lines.append('  '.join(parts))
        return _R('\n'.join(lines) + '\n', mimetype='text/plain',
                  headers={'Cache-Control': 'no-store'})
    return jsonify(result)

# ── 日志 ──
@app.route('/api/logs')
def api_logs():
    limit = min(request.args.get('limit', 300, type=int), 5000)
    level = request.args.get('level', 'all').lower()  # all | info | success | error
    if level not in ('all', 'info', 'success', 'error'): level = 'all'
    return jsonify(db.get_logs(limit, level=level))

@app.route('/api/logs/clear', methods=['POST'])
@_require_role('admin')
@csrf_protect
def api_clear_logs():
    level = request.json.get('level', 'all') if request.json else 'all'
    if level not in ('all', 'info', 'success', 'error'): level = 'all'
    db.clear_logs(level=level)
    g.access_note = f"clear logs level={level}"
    return jsonify({'success':True})

@app.route('/api/logs/export')
def api_export_logs():
    """下载 error.log（gzip 压缩）。不存在时返回 404。
    注意：不设 Content-Encoding，浏览器原样保存，7z/WinRAR 可直接解压。
    """
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    _candidate = os.path.realpath(os.path.join(_BASE_DIR, 'error.log'))
    # 检查是否在 _BASE_DIR 下，防止路径遍历
    if not os.path.abspath(_candidate).startswith(os.path.abspath(_BASE_DIR) + os.sep) and _candidate != os.path.join(_BASE_DIR, 'error.log'):
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

# ── 历史管理 ──
@app.route('/api/history/clear', methods=['POST'])
@_require_role('admin')
@csrf_protect
def api_clear_history():
    """清空 hdb 内存历史和 history.json，重启后统计从零开始。"""
    try:
        with hdb.lock:
            hdb._data.clear()
        if os.path.exists(HISTORY_FILE):
            os.remove(HISTORY_FILE)
        db._clear_uptime_cache()
        db._save_async()   # 顺带刷新 data.json 里的摘要（会变为全0）
        cprint('[history/clear] history.json 及内存历史已清空', 'info')
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error('[history/clear] 清空历史失败: %s', e, exc_info=True)
        return jsonify({'success': False, 'error': '操作失败，请查看服务端日志'}), 500

@app.route('/api/ips/clear-removed', methods=['POST'])
@_require_role('admin')  # 仅限 admin
@csrf_protect
def api_clear_removed_ips():
    """清空所有标记为 removed 的历史IP（内存中删除，并保存到 data.json）"""
    try:
        with db.lock:
            cleared = 0
            for domain, td in db.trackers.items():
                for i in range(len(td['ips'])-1, -1, -1):
                    if td['ips'][i].get('removed'):
                        td['ips'].pop(i)
                        cleared += 1
            db._recalc()
            db._clear_uptime_cache()
            db._save_async()
        cprint(f'[api] 清空历史IP: 已删除 {cleared} 个IP', 'info')
        return jsonify({'success': True, 'cleared': cleared})
    except Exception as e:
        app.logger.error(f"清空历史IP失败: {e}")
        return jsonify({'error': '清空失败'}), 500

@app.route('/api/history/status', methods=['GET'])
@_require_role('admin', 'operator', 'viewer')
def api_history_status():
    """检查是否存在历史数据（hdb 内存或 history.json）"""
    try:
        with hdb.lock:
            has_cache = bool(hdb._data)
        if not has_cache:
            has_cache = os.path.exists(HISTORY_FILE)
        return jsonify({'has_cache': has_cache})
    except Exception as e:
        app.logger.error('[history/status] 查询失败: %s', e, exc_info=True)
        return jsonify({'has_cache': False, 'error': '查询失败，请查看服务端日志'})

# ── 配置 ──
@app.route('/api/config', methods=['GET','POST'])
def api_config():
    # POST 修改配置：仅 admin
    if request.method == 'POST':
        role = session.get('role')
        if role != 'admin':
            return jsonify({'error': '权限不足'}), 403
        if not request.headers.get('X-CSRFToken') or request.headers.get('X-CSRFToken') != session.get('csrf_token'):
            return jsonify({'error': 'CSRF token invalid'}), 403
        data = request.json or {}
        
        # 验证配置参数
        errors = validate_config(data)
        if errors:
            return jsonify({'error': '配置参数无效', 'details': errors}), 400
        keys = ['check_interval','timeout','retry_mode','retry_interval',
                'monitor_workers','stagger_batch_proxy','stagger_batch_direct','stagger_delay_proxy','stagger_delay_direct',
                'log_to_disk','log_level','console_log_level','http_proxy','udp_proxy','http_proxy_enabled', 'udp_proxy_enabled',
                'listen_port', 'listen_ipv4', 'listen_ipv4_custom', 'listen_ipv6', 'listen_ipv6_custom',
                'dns_mode','dns_custom','dns_use_tcp','max_log_entries','max_log_info','max_log_success','max_log_error','page_refresh_ms',
                'dashboard_stat_period','tracker_stat_period','cache_history','tab_switch_refresh',
                'export_suffix','show_removed_ips','default_layout_width','allow_private_ips','min_password_length','users',
                'cleanup_interval','trust_cf_ip']
        labels = {
            'check_interval':        '监控间隔',
            'timeout':               '连接超时',
            'retry_mode':            '重试模式',
            'retry_interval':        '重试间隔',
            'monitor_workers':       '并发检测数',
            'stagger_batch_proxy':   '代理每批发包数',
            'stagger_batch_direct':  '直连每批发包数',
            'stagger_delay_proxy':   '代理批间延迟',
            'stagger_delay_direct':  '直连批间延迟',
            'log_to_disk':           '日志存盘',
            'log_level':             '日志级别',
            'console_log_level':     '控制台日志级别',
            'http_proxy':            'HTTP代理',
            'udp_proxy':             'UDP代理',
            'http_proxy_enabled':    'HTTP代理开关',
            'udp_proxy_enabled':     'UDP代理开关',
            'listen_port':           '监听端口',
            'listen_ipv4':           'ipv4监听',
            'listen_ipv4_custom':    '自定义ipv4监听',
            'listen_ipv6':           'ipv6监听',
            'listen_ipv6_custom':    '自定义ipv6监听',
            'dns_mode':              'DNS模式',
            'dns_custom':            '自定义DNS',
            'dns_use_tcp':           'DNS强制TCP',
            'max_log_entries':       '最大日志条数',
            'max_log_info':          'Info日志最大条数',
            'max_log_success':       'Success日志最大条数',
            'max_log_error':         'Error日志最大条数',
            'page_refresh_ms':       '页面刷新间隔',
            'dashboard_stat_period': '仪表盘统计周期',
            'tracker_stat_period':   '监控列表统计周期',
            'cache_history':         '缓存统计可用率',
            'tab_switch_refresh':    '切换时刷新',
            'export_suffix':         '导出后缀',
            'show_removed_ips':      '显示历史IP',
            'default_layout_width':  '默认页面视野宽度',
            'allow_private_ips':     '允许内网IP',
            'min_password_length':   '最小密码长度',
            'users':                 '用户账户',
            'cleanup_interval':      '限流内存清理间隔',
            'trust_cf_ip':           'CF/代理IP信任',
        }
        suffixes = {
            'check_interval': 's', 'timeout': 's', 'retry_interval': 's',
            'page_refresh_ms': 'ms', 'stagger_delay_proxy': 'ms', 'stagger_delay_direct': 'ms',
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
        # 如果代理相关配置变化，重置 SOCKS5 连接池
        proxy_changed_keys = {'udp_proxy', 'timeout', 'udp_proxy_enabled', 'http_proxy_enabled'}
        if any(k in data for k in proxy_changed_keys):
            _socks5_pool.invalidate()
            cprint('[SOCKS5Pool] 代理配置变更，连接池已重置', 'debug')
        if changes:
            msg = f"配置已更新: {' | '.join(changes)}"
            g.access_note = msg
        return jsonify({'success':True,'config':{k:CONFIG[k] for k in keys if k != 'console_log_level'}})
    # GET 读取配置：未登录只返回前端行为控制必要字段（不含账户/代理等敏感信息）
    # 已登录用户额外返回运维相关字段（仍不含账户信息）
    public_keys = ['page_refresh_ms', 'tab_switch_refresh', 'dashboard_stat_period', 'tracker_stat_period', 'show_removed_ips', 'default_layout_width', 'allow_private_ips', 'min_password_length']
    if not session.get('role'):
        return jsonify({k: CONFIG.get(k) for k in public_keys})
    all_keys = ['check_interval','timeout','retry_mode','retry_interval',
                'log_to_disk','log_level','http_proxy','udp_proxy','http_proxy_enabled','udp_proxy_enabled',
                'dns_mode','dns_custom','dns_use_tcp','max_log_entries','max_log_info','max_log_success','max_log_error','page_refresh_ms',
                'dashboard_stat_period','tracker_stat_period','cache_history','tab_switch_refresh',
                'show_removed_ips','monitor_workers','stagger_batch_proxy','stagger_batch_direct','stagger_delay_proxy','stagger_delay_direct','export_suffix','default_layout_width',
                'allow_private_ips','min_password_length','cleanup_interval','trust_cf_ip']
    return jsonify({k: CONFIG.get(k) for k in all_keys})

@app.route('/api/users', methods=['GET'])
@_require_role('admin')
def api_users_get():
    """返回用户列表（不含密码哈希）"""
    users = [{'username': u['username'], 'role': u['role']} for u in CONFIG.get('users', [])]
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@_require_role('admin')
@csrf_protect
def api_users_save():
    """批量保存用户配置，支持新增/修改/删除。管理员设置初始密码无最小长度限制。"""
    data = request.json or {}
    new_users = data.get('users', [])
    result = []
    errors = []
    existing = {u['username']: u for u in CONFIG.get('users', [])}
    import re as _re
    for u in new_users:
        uname = (u.get('username','') or '').strip()
        role  = u.get('role','viewer')
        if not uname or not _re.match(r'^[a-zA-Z0-9_-]{1,32}$', uname):
            errors.append(f'用户名 "{uname}" 不合法（只允许字母数字下划线连字符，1-32字符）')
            continue
        if role not in ('admin','operator','viewer'):
            errors.append(f'用户 "{uname}" 角色不合法')
            continue
        pw_plain = (u.get('password','') or '').strip()
        if pw_plain:
            # 管理员在后台设置密码无最小长度限制，只限最大长度
            if len(pw_plain) > 256:
                errors.append(f'用户 "{uname}" 密码过长（最多256位）')
                continue
            pw_hash, pw_salt = _hash_pw(pw_plain)
            result.append({'username': uname, 'role': role, 'password': pw_hash, 'salt': pw_salt})
        elif uname in existing:
            # 密码为空：保留旧密码哈希+盐
            old_u = existing[uname]
            entry = {'username': uname, 'role': role, 'password': old_u['password']}
            if 'salt' in old_u:
                entry['salt'] = old_u['salt']
            result.append(entry)
        else:
            errors.append(f'新用户 "{uname}" 必须设置密码')
            continue
    if errors:
        return jsonify({'success': False, 'errors': errors}), 400
    # 确保至少保留一个 admin
    if not any(u.get('role') == 'admin' for u in result):
        return jsonify({'success': False, 'errors': ['至少需要保留一个 admin 账户']}), 400
    CONFIG['users'] = result
    persist_config(CONFIG)
    g.access_note = f"users updated ({len(result)} users)"
    return jsonify({'success': True, 'count': len(result)})

# ==================== 主程序 ====================
if __name__ == '__main__':
    db.load()
    hdb.load()
    db._cleanup_hdb_on_startup()   # 清理已移除IP和domain级的hdb key
    db.add_log("网络监控服务启动", 'info')

    def _get_geo_force(ip: str) -> dict:
        """强制查询 IP 归属地，跳过缓存，并更新缓存（用于批量刷新）"""
        # 先查缓存（仅用于防止短时间内重复查询，此处可忽略）
        # 直接发起网络请求
        result = {'country':'Unknown', 'country_code':'XX', 'isp':'Unknown'}
        # SSRF防护：仅对公网IP发起查询
        if not _is_safe_public_ip(ip):
            with _geo_cache_lock:
                _geo_cache[ip] = result
            return result
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
            # 更新缓存（无论成功与否，避免反复查询无法访问的IP）
            with _geo_cache_lock:
                _geo_cache[ip] = result
        except Exception:
            pass
        return result
    
    # ==================== 启动后 geo 更新线程 ====================
    def _geo_update_loop():
        """后台更新 IP 归属地信息（根据配置执行不同策略）"""
        time.sleep(10)   # 等待服务完全启动
        refresh_all = CONFIG.get('refresh_geo_on_restart', True)
        # 用于记录连续失败的 IP，避免无限重试（仅本次启动有效）
        fail_count = {}
        MAX_FAIL = 3   # 连续失败超过此次数则跳过

        with db.lock:
            # 收集需要处理的 IP
            targets = []
            for domain, td in db.trackers.items():
                for ip_obj in td.get('ips', []):
                    ip = ip_obj.get('ip', '')
                    if not ip:
                        continue
                    if refresh_all:
                        # 全部刷新：所有IP都加入
                        targets.append((domain, ip_obj))
                    else:
                        # 仅修复未知归属地
                        c = ip_obj.get('country', {})
                        if isinstance(c, dict) and c.get('country_code', 'XX') == 'XX':
                            targets.append((domain, ip_obj))
        
        if not targets:
            cprint("[geo] 没有需要更新归属地的 IP", 'info')
            return
        
        mode = "全部刷新" if refresh_all else "修复未知"
        cprint(f"[geo] 开始{mode}，共 {len(targets)} 个 IP（间隔 0.8 秒，避免触发限流）", 'info')

        updated_count = 0
        for domain, ip_obj in targets:
            ip = ip_obj.get('ip', '')
            if not ip:
                continue
            new_geo = get_geo(ip)
            # 如果该 IP 已连续失败超过 MAX_FAIL 次，则跳过本次更新
            if fail_count.get(ip, 0) >= MAX_FAIL:
                cprint(f"[geo] 跳过 {ip}（已连续失败 {MAX_FAIL} 次）", 'debug')
                continue
            
            # 强制查询最新归属地（绕过缓存）
            new_geo = _get_geo_force(ip)

            # 判断是否成功获取到有效数据（country_code != 'XX'）
            if new_geo.get('country_code', 'XX') != 'XX':
                # 成功：重置失败计数
                fail_count.pop(ip, None)
                # 获取当前数据库中的旧值
                old_geo = ip_obj.get('country', {})
                old_cc = old_geo.get('country_code', 'XX')
                new_cc = new_geo.get('country_code', 'XX')
                # 如果不同，才更新
                if old_cc != new_cc or old_geo.get('isp') != new_geo.get('isp'):
                    with db.lock:
                        # 重新定位该 IP（防止列表在遍历过程中发生变化）
                        for td in db.trackers.values():
                            for obj in td.get('ips', []):
                                if obj.get('ip') == ip:
                                    obj['country'] = new_geo
                                    updated_count += 1
                                    break
                    if updated_count % 10 == 0:
                        db._save_async() # 每更新 10 个 IP 异步保存一次
                    cprint(f"[geo] 更新 {ip}: {old_cc} -> {new_cc}", 'debug')
            else:
                # 查询失败：增加失败计数
                fail_count[ip] = fail_count.get(ip, 0) + 1
                cprint(f"[geo] 查询失败 {ip}（失败 {fail_count[ip]}/{MAX_FAIL}）", 'debug')
            time.sleep(0.8)   # 避免触发 ip-api 限流
        
        if updated_count:
            db._save_async()
            cprint(f"[geo] 归属地更新完成，共更新 {updated_count} 个 IP", 'info')
        else:
            cprint("[geo] 没有 IP 的归属地发生更新", 'info')

    geo_repair_t = threading.Thread(target=_geo_update_loop, daemon=True)
    geo_repair_t.start()

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    _check_now.set()   # 启动后立即触发第一轮检测，不等待 check_interval

    probe_t = threading.Thread(target=_probe_loop, daemon=True)
    probe_t.start()

    cleanup_t = threading.Thread(target=_memory_cleanup_loop, daemon=True)
    cleanup_t.start()

    # 显示启动信息（略，但需要更新端口显示）
    port = CONFIG['listen_port']  # 使用新的端口配置
    ipv4_mode = CONFIG.get('listen_ipv4', 'global')
    ipv6_mode = CONFIG.get('listen_ipv6', 'global')
    ipv4_custom = CONFIG.get('listen_ipv4_custom', '')
    ipv6_custom = CONFIG.get('listen_ipv6_custom', '')

    print(f"\n{'='*58}")
    print(f"  网络监控 - Network Monitor")
    print(f"{'='*58}")
    print(f"  IPv4监听模式   : {ipv4_mode}" + (f" ({ipv4_custom})" if ipv4_mode == 'custom' and ipv4_custom else ""))
    print(f"  IPv6监听模式   : {ipv6_mode}" + (f" ({ipv6_custom})" if ipv6_mode == 'custom' and ipv6_custom else ""))
    print(f"  访问地址       : http://localhost:{port}  (IPv4+IPv6 双栈)")
    print(f"  监控间隔       : {CONFIG['check_interval']}秒")
    print(f"  超时时间       : {CONFIG['timeout']}秒")
    dns_desc = {'system':'系统DNS','dnspython':'dnspython','custom':f"自定义({CONFIG.get('dns_custom','8.8.8.8')})"}.get(CONFIG.get('dns_mode','system'),'系统DNS')
    if CONFIG.get('dns_use_tcp') and CONFIG.get('dns_mode') != 'system':
        dns_desc += ' [TCP]'
    print(f"  DNS解析模式    : {dns_desc}")
    print(f"  日志最大条目   : Info={CONFIG.get('max_log_info',1000)} / Success={CONFIG.get('max_log_success',1000)} / Error={CONFIG.get('max_log_error',1000)}条")
    print(f"  重试模式       : {CONFIG['retry_mode']}")
    print(f"  日志级别       : {CONFIG.get('log_level', 'info')}")
    print(f"  磁盘日志       : {'开启' if CONFIG['log_to_disk'] else '关闭'}")
    if CONFIG['http_proxy_enabled']:
        http_p = CONFIG.get('http_proxy','').strip()
        print(f"  HTTP代理       : 启用")
        print(f"  HTTP/TCP代理   : {http_p if http_p else '(未设置)'}")
    else:
        print(f"  HTTP代理       : 关闭")
    if CONFIG['udp_proxy_enabled']:
        udp_p  = CONFIG.get('udp_proxy','').strip()
        print(f"  UDP代理        : 启用")
        print(f"  UDP代理        : {udp_p  if udp_p  else '(未设置)'}")
    else:
        print(f"  UDP代理        : 关闭")
    print(f"  允许内网IP     : {'是' if CONFIG.get('allow_private_ips') else '否'}")
    print(f"  最小密码长度   : {CONFIG.get('min_password_length', 8)}")
    users_info = CONFIG.get('users', [])
    admin_count = sum(1 for u in users_info if u.get('role') == 'admin')
    operator_count = sum(1 for u in users_info if u.get('role') == 'operator')
    viewer_count = sum(1 for u in users_info if u.get('role') == 'viewer')
    print(f"  用户账户       : {len(users_info)} 个 (admin: {admin_count}, operator: {operator_count}, viewer: {viewer_count})")
    # print(f"  用户账户       : {len(users_info)} 个 ({', '.join(u['username']+'('+u['role']+')' for u in users_info)})") # 控制台 暴露用户名 不可取
    print(f"{'='*58}")
    print(f"  权限说明:")
    print(f"    admin    - 全部权限（配置+用户管理，重试不限速）")
    print(f"    operator - 增删tracker，重试限速500ms")
    print(f"    viewer   - 只读，重试限速1000ms")
    print(f"{'='*58}\n")

    def generate_self_signed_cert(cert_file, key_file):
        """生成自签名证书"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            
            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # 生成证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Network Monitor"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                # 证书有效期1年
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # 保存证书和私钥
            with open(cert_file, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            cprint(f"自签名证书生成成功: {cert_file}, {key_file}", 'info')
        except ImportError:
            cprint("缺少cryptography库，无法生成自签名证书", 'error')
        except Exception as e:
            cprint(f"生成自签名证书失败: {e}", 'error')
    
    # 读取HTTPS配置
    https_enabled = os.environ.get('HTTPS_ENABLED', '0').strip() == '1'
    cert_file = os.environ.get('HTTPS_CERT', 'cert.pem')
    key_file = os.environ.get('HTTPS_KEY', 'key.pem')
    
    try:
        from waitress import serve
        print("  使用 waitress 生产服务器\n")
        
        if https_enabled:
            # 检查证书文件是否存在
            if not (os.path.exists(cert_file) and os.path.exists(key_file)):
                cprint("HTTPS启用但证书文件不存在，将使用自签名证书", 'info')
                # 生成自签名证书
                generate_self_signed_cert(cert_file, key_file)
            
            # 构建HTTPS监听地址列表
            listen_addrs = []
            # IPv4 地址处理
            if ipv4_mode == 'global':
                listen_addrs.append(f'https://0.0.0.0:{port}')
            elif ipv4_mode == 'local':
                listen_addrs.append(f'https://127.0.0.1:{port}')
            elif ipv4_mode == 'custom':
                if ipv4_custom:
                    listen_addrs.append(f'https://{ipv4_custom}:{port}')
                else:
                    print("警告: IPv4 自定义地址为空，将不监听 IPv4")
            # IPv6 地址处理
            if ipv6_mode == 'global':
                listen_addrs.append(f'https://[::]:{port}')
            elif ipv6_mode == 'local':
                listen_addrs.append(f'https://[::1]:{port}')
            elif ipv6_mode == 'custom':
                if ipv6_custom:
                    # 如果自定义 IPv6 地址不含方括号，添加方括号
                    if ':' in ipv6_custom and not ipv6_custom.startswith('['):
                        ipv6_custom = f'[{ipv6_custom}]'
                    listen_addrs.append(f'https://{ipv6_custom}:{port}')
                else:
                    print("警告: IPv6 自定义地址为空，将不监听 IPv6")
            
            if not listen_addrs:
                print("错误：至少需要监听一个地址", file=sys.stderr)
                sys.exit(1)
            
            cprint(f"HTTPS服务器启动在 {listen_addrs[0]}", 'info')
            serve(app, listen=listen_addrs, threads=8, ident='', certfile=cert_file, keyfile=key_file)
        else:
            # 构建HTTP监听地址列表
            listen_addrs = []
            # IPv4 地址处理
            if ipv4_mode == 'global':
                listen_addrs.append(f'0.0.0.0:{port}')
            elif ipv4_mode == 'local':
                listen_addrs.append(f'127.0.0.1:{port}')
            elif ipv4_mode == 'custom':
                if ipv4_custom:
                    listen_addrs.append(f'{ipv4_custom}:{port}')
                else:
                    print("警告: IPv4 自定义地址为空，将不监听 IPv4")
            # IPv6 地址处理
            if ipv6_mode == 'global':
                listen_addrs.append(f'[::]:{port}')
            elif ipv6_mode == 'local':
                listen_addrs.append(f'[::1]:{port}')
            elif ipv6_mode == 'custom':
                if ipv6_custom:
                    # 如果自定义 IPv6 地址不含方括号，添加方括号
                    if ':' in ipv6_custom and not ipv6_custom.startswith('['):
                        ipv6_custom = f'[{ipv6_custom}]'
                    listen_addrs.append(f'{ipv6_custom}:{port}')
                else:
                    print("警告: IPv6 自定义地址为空，将不监听 IPv6")
            
            if not listen_addrs:
                print("错误：至少需要监听一个地址", file=sys.stderr)
                sys.exit(1)
            
            cprint(f"HTTP服务器启动在 http://localhost:{port}", 'info')
            serve(app, listen=listen_addrs, threads=8, ident='')
    except ImportError:
        print("  警告: waitress 未安装，将使用 Flask 开发服务器（不推荐用于生产）")
        print("  建议执行: pip install waitress")
        try:
            ans = input("是否继续使用开发服务器？(y/N): ").strip().lower()
            if ans != 'y':
                print("已取消启动。")
                sys.exit(0)
        except EOFError:
            pass
        # 使用 Flask 内置服务器（仅用于开发，不支持同时监听多地址）
        # 这里简化：如果同时监听了多个地址，使用第一个 IPv4 地址；如果只监听 IPv6 则使用 IPv6
        import socket
        host = None
        # 构建监听地址列表（与waitress相同）
        listen_addrs = []
        # IPv4 地址处理
        if ipv4_mode == 'global':
            listen_addrs.append(f'0.0.0.0:{port}')
        elif ipv4_mode == 'local':
            listen_addrs.append(f'127.0.0.1:{port}')
        elif ipv4_mode == 'custom':
            if ipv4_custom:
                listen_addrs.append(f'{ipv4_custom}:{port}')
            else:
                print("警告: IPv4 自定义地址为空，将不监听 IPv4")
        # IPv6 地址处理
        if ipv6_mode == 'global':
            listen_addrs.append(f'[::]:{port}')
        elif ipv6_mode == 'local':
            listen_addrs.append(f'[::1]:{port}')
        elif ipv6_mode == 'custom':
            if ipv6_custom:
                # 如果自定义 IPv6 地址不含方括号，添加方括号
                if ':' in ipv6_custom and not ipv6_custom.startswith('['):
                    ipv6_custom = f'[{ipv6_custom}]'
                listen_addrs.append(f'{ipv6_custom}:{port}')
            else:
                print("警告: IPv6 自定义地址为空，将不监听 IPv6")
        
        if listen_addrs:
            first = listen_addrs[0]
            if '[' in first:
                host = first.split('[')[1].split(']')[0]
            else:
                host = first.split(':')[0]
        else:
            host = '127.0.0.1'
        print(f"  启动 Flask 开发服务器在 {host}:{port}")
        app.run(host=host, port=port, debug=False)