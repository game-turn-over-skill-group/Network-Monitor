# -*- coding: utf-8 -*-
"""
网络监控 - Network Monitor
Windows部署: pip install Flask flask-cors dnspython requests waitress && python app.py
"""

import queue
import os
import json
import numpy as np
import time
import socket
import struct
import logging
import threading
import random
import select
import subprocess
import re
import platform
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, make_response, session, g, Response, redirect, send_from_directory
from flask_cors import CORS
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests as req_lib
from typing import Any, Dict, Optional, Tuple, List
from werkzeug.exceptions import HTTPException

# ==================== 配置持久化 ====================
CONFIG_FILE  = 'config.json'
# ─────────────────────────────────────────────────────────────
# 配置维护说明：
# 1. 新增配置项：只需在此处添加 DEFAULT_CONFIG 键值对
# 2. 加载/保存/API：自动从 DEFAULT_CONFIG 读取，无需手动添加
# 3. labels/suffixes：用于日志显示，如需中文名称请同步更新 api_config() 中的 labels 和 suffixes
#    （不影响配置功能，仅日志显示英文键名）
# ─────────────────────────────────────────────────────────────
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
    'log_to_disk': False,              # 日志存盘（access.log、error.log）
    'console_log_level': 'info',       # none | info | error | debug
    'console_error_log': False,        # 控制台 error 日志输出开关（默认关闭）
    'debug_save_trace': False,         # 调试：输出异步保存耗时/队列状态（仅 debug 级别打印）
    'log_file': 'error.log',
    'data_file': 'data.json',
    'max_history': 2880,               # history_24h 上限：24h × 3600s ÷ 30s间隔 = 2880点
    'http_proxy': '',
    'udp_proxy': '',
    'dns_mode': 'system',              # system | dnspython | custom
    'dns_custom': '8.8.8.8',           # 自定义DNS时使用，支持多个用逗号分隔
    'dns_use_tcp': False,              # 自定义/dnspython 模式下强制使用 TCP 53（国内UDP丢包时开启）
    'dns_timeout': 0,                  # DNS 单次查询超时（秒）。0=与 timeout 相同；可设为 2~4 加快多 DNS 故障转移
    'dns_skip_domains': [],            # 跳过DNS查询的域名名单（一行一个域名，固定IP或无IP域名，跳过所有A/AAAA查询节约流量）
    'dns_lb_enabled': True,            # DNS服务器负载均衡/权重排序开关（默认关闭）；关闭时始终按配置顺序顺序尝试
    'dns_refresh_interval': 120,       # DNS 刷新间隔（秒），默认 2 分钟
    'max_log_entries': 50000,          # 日志最大条目数（兼容旧版，以下三项优先）
    'max_log_info': 25000,             # Info 级日志最大条目数
    'max_log_success': 20000,          # Success 级日志最大条目数
    'max_log_error': 2000,             # Error 级日志最大条目数
    'page_refresh_ms': 30000,          # 前端页面自动刷新间隔(ms)，0=禁用
    'save_interval': 120,              # 日志存盘 (history.json.append) 定时保存间隔（秒），默认120秒
    'cache_history': True,             # 缓存统计可用率：是否缓存历史可用率到 history.json（重启不丢失）
    'dashboard_stat_period': '24h',    # 仪表盘可用率统计周期：24h | 7d | 30d（排行TOP10+快速搜索）
    'tracker_stat_period': '7d',       # 监控列表可用率统计周期：24h | 7d | 30d
    'tab_switch_refresh': True,        # 切换仪表盘/监控列表时是否刷新数据
    'uptime_algorithm': 'legacy',      # 可用率统计算法：legacy（含历史所有IP）| current（仅当前活跃IP）
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
    # ── 网络探针与故障检测 ──
    'probe_throttle_enabled': False,   # 探测节流开关：重启后避免30秒内重复探测（默认：False）
    'probe_fail_threshold': 30,        # 本轮失败率达到多少%触发网络异常（默认30%）
    'probe_timeout': 5.0,              # 探针超时（秒），支持小数如 0.5s
    'probe_interval': 1,               # 探测周期（秒），默认1秒
    'probe_mode': 'icmp',              # 探测模式：icmp（ICMP ping）| tcp（TCP DNS探测）
    'probe_fine_check_enabled': True,  # 精细探针检查开关：开启后任何一个探针超时即等待恢复（拥堵避让算法）
    'probe_ipv4_targets': [            # IPv4 探针目标列表（任一可达即认为 IPv4 正常）
        '8.8.8.8',                     # Google Public DNS
        '1.1.1.1',                     # Cloudflare DNS
        '223.6.6.6',                   # 国内 阿里 DNS
    ],
    'probe_ipv6_targets': [            # IPv6 探针目标列表（任一可达即认为 IPv6 正常，留空则禁用）
        '2001:4860:4860::8888',        # Google IPv6 DNS
        '2606:4700:4700::1111',        # Cloudflare IPv6 DNS
        '2400:3200:baba::1',           # 阿里巴巴 IPv6 DNS（替换失效的 240c::6666 CNNIC）
    ],
    # ── 连续失败自动暂停 ──
    'auto_pause_enabled': True,        # 是否开启连续失败自动暂停
    'auto_pause_threshold': 30,        # 连续失败多少次后自动暂停该IP
    'auto_pause_persist': False,       # 是否在重启后保持自动暂停状态（默认关闭，避免误暂停后无人处理）
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
            # 自动从 DEFAULT_CONFIG 获取所有配置键，避免重复定义
            for k in DEFAULT_CONFIG.keys():
                if k in saved:
                    cfg[k] = saved[k]
            # 向后兼容：旧配置文件用 rank_stat_period，迁移到 dashboard_stat_period
            if 'dashboard_stat_period' not in saved and 'rank_stat_period' in saved:
                cfg['dashboard_stat_period'] = saved['rank_stat_period']
            # 向后兼容：旧配置文件用 log_level，迁移到 console_log_level
            if 'log_level' in saved and 'console_log_level' not in saved:
                cfg['console_log_level'] = saved['log_level']
    except Exception as e:
        cprint(f"配置加载失败: {e}", 'error')
    return cfg

def persist_config(cfg):
    try:
        # 自动从 DEFAULT_CONFIG 获取所有配置键，避免重复定义
        savable = {k: cfg[k] for k in DEFAULT_CONFIG.keys() if k in cfg}
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

def rate_limit(limit: int = 120, window: int = 60):
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
    """根据 log_level 和 console_error_log 配置决定是否打印到控制台。加锁保证多线程下不截断。
    raw=True：原样输出（nginx access log 格式，不加前缀）
    raw=False：加 YYYY/M/D HH:MM:SS [LEVEL] 前缀；info级别同步写入 access.log
    """
    cl = CONFIG.get('console_log_level', 'info')
    if cl == 'none':
        return
    if level == 'success':
        return
    # console_error_log 优先级最高：关闭时不显示任何 error 日志，其他级别正常显示
    if level == 'error' and not CONFIG.get('console_error_log', False):
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
        # 活跃IP集合：存储 (domain, ip) 元组，仅包含非暂停、非移除的IP
        self._active_ips = set()
        # IP快速查找表：{(domain, ip): ip_obj}，O(1)查找
        self._ip_map = {}
        # 可用率缓存
        self.uptime_cache = LRUCache(1000)  # 限制缓存大小
        self.ip_stats_cache = LRUCache(5000)  # IP级统计缓存
        self.cache_lock = threading.RLock()
        self.cache_ttl = 30  # 秒
        # 异步保存线程池（单线程）
        self._save_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="db_save")
        self._save_pending = False
        self._save_requested = False
        self._save_state_lock = threading.RLock()
        self._dirty_trackers = set()  # 标记需要保存的tracker域名
        self._last_save_time = 0  # 上次保存时间（用于节流）

    def _save_trace_enabled(self):
        return CONFIG.get('debug_save_trace', False) and CONFIG.get('console_log_level') == 'debug'

    def _get_uptime_cached(self, domain, period):
        """从缓存获取域名可用率，如果缓存有效则返回，否则 None"""
        entry = self.uptime_cache.get((domain, period))
        if entry and time.time() - entry['time'] < self.cache_ttl:
            return entry['value']
        return None

    def _set_uptime_cache(self, domain, period, value):
        self.uptime_cache.put((domain, period), {'value': value, 'time': time.time()})

    def _get_ip_stats_cached(self, domain, ip):
        """从缓存获取IP级统计（可用率+连续失败次数）"""
        entry = self.ip_stats_cache.get((domain, ip))
        if entry and time.time() - entry['time'] < self.cache_ttl:
            return entry['value']
        return None

    def _set_ip_stats_cache(self, domain, ip, stats):
        self.ip_stats_cache.put((domain, ip), {'value': stats, 'time': time.time()})

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
                # 清除该域名下所有IP的统计缓存
                ip_keys_to_remove = []
                for key in list(self.ip_stats_cache.cache.keys()):
                    if isinstance(key, tuple) and len(key) == 2 and key[0] == domain:
                        ip_keys_to_remove.append(key)
                for key in ip_keys_to_remove:
                    if key in self.ip_stats_cache.cache:
                        del self.ip_stats_cache.cache[key]
                        if key in self.ip_stats_cache.order:
                            self.ip_stats_cache.order.remove(key)
        else:
            self.uptime_cache.clear()
            self.ip_stats_cache.clear()

    # ---------- tracker 管理 ----------
    def add_tracker(self, domain, port, protocol, ip_list=None):
        with self.lock:
            if domain not in self.trackers:
                self.trackers[domain] = {
                    'domain': domain, 'port': port, 'protocol': protocol,
                    'ips': [],
                    'added_time': datetime.now().isoformat(),
                    'dns_error': False,
                    'dns_skip': False,
                    'paused': False  # 确保新添加的 tracker 有 paused 字段
                }
            else:
                # 已有条目：只更新 port/protocol，不覆盖 domain 字段（用户可能手动改成IP）
                self.trackers[domain]['port']     = port
                self.trackers[domain]['protocol'] = protocol
            if ip_list:
                existing = {x['ip'] for x in self.trackers[domain]['ips']}
                for info in ip_list:
                    if info['ip'] not in existing:
                        info.update({'status': 'unknown', 'latency': -1, 'last_check': None,
                                     'added_time': datetime.now().isoformat()})
                        self.trackers[domain]['ips'].append(info)
                        self._active_ips.add((domain, info['ip']))
                        self._ip_map[(domain, info['ip'])] = info
            # 标记该tracker有变化
            self._dirty_trackers.add(domain)
            # 延迟保存，不立即调用 _save_async()，由定时保存统一处理
            # 立刻 异步保存 data.json
            self._save_async()

    def update_status(self, domain, ip, status, latency, check_time=None, write_history=True):
        with self.lock:
            if domain in self.trackers:
                ip_obj = self._ip_map.get((domain, ip))
                if ip_obj:
                    ip_obj['status'] = status
                    ip_obj['latency'] = latency
                    ip_obj['last_check'] = check_time or datetime.now().isoformat()
                    # 同时保存数值时间戳，避免后续转换
                    try:
                        dt = datetime.fromisoformat(ip_obj['last_check'])
                        ip_obj['last_check_ts'] = dt.timestamp()
                    except Exception:
                        ip_obj['last_check_ts'] = time.time()
                    # 非暂停、非移除的IP才加入活跃集
                    if not ip_obj.get('paused') and not ip_obj.get('removed'):
                        self._active_ips.add((domain, ip))
                    else:
                        self._active_ips.discard((domain, ip))
                if write_history:
                    self._push_history(domain, ip, status)
                self._recalc()
                self._clear_uptime_cache(domain)
                # 标记tracker脏，由定时保存线程在（自定义）比如：120秒后 统一更新 data.json
                # 这样既能保证data.json最终会更新，又不会导致高频I/O
                # 如果你看到的100多KB/s 是正常的 是由data.json大小决定的
                # 如果你拿掉下面的标记 那么 启动程序时 或 自定义save_interval存盘间隔 就不会触发 更新状态 更新data.json文件了 就只有启动时上一次 加载history.json的数据了
                self._dirty_trackers.add(domain)

    def _push_history(self, domain, ip, status):
        """把探测结果写入 hdb（时间戳历史库）。
        跳过 removed IP，避免污染统计。"""
        ip_obj = self._ip_map.get((domain, ip))
        if ip_obj is None:
            return
        if ip_obj.get('removed', False):
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
        # 新增：按协议和IP版本统计
        tcp_v4_total = tcp_v4_alive = tcp_v4_offline = tcp_v4_unknown = 0
        tcp_v6_total = tcp_v6_alive = tcp_v6_offline = tcp_v6_unknown = 0
        udp_v4_total = udp_v4_alive = udp_v4_offline = udp_v4_unknown = 0
        udp_v6_total = udp_v6_alive = udp_v6_offline = udp_v6_unknown = 0
        # 延迟统计（只统计在线且latency>0的IP）
        lats_all = []; lats_v4_tcp = []; lats_v4_udp = []; lats_v6_tcp = []; lats_v6_udp = []
        lats_tcp = []; lats_udp = []
        
        # 先统计已暂停的数量（需要遍历全部IP）
        for d in self.trackers.values():
            domain_paused = d.get('paused', False)
            if domain_paused:
                # 域名级暂停：统计所有非移除IP
                for ip in d['ips']:
                    if not ip.get('removed'):
                        paused_count += 1
            else:
                # IP级暂停：统计已暂停的IP
                for ip in d['ips']:
                    if ip.get('paused') and not ip.get('removed'):
                        paused_count += 1
        
        # 遍历活跃IP集合统计其他指标（只处理活跃IP）
        for domain, ip_str in self._active_ips:
            # 使用 _ip_map 快速查找，O(1) 复杂度
            ip_obj = self._ip_map.get((domain, ip_str))
            if not ip_obj:
                continue
            
            td = self.trackers.get(domain)
            if not td:
                continue
            
            # 跳过暂停的IP（包括域名级暂停和IP级暂停）
            if ip_obj.get('paused') or td.get('paused'):
                continue
            
            proto = td.get('protocol', 'tcp')
            is_udp = (proto == 'udp')
            
            total += 1
            is6 = ':' in ip_str
            if is6:
                ipv6 += 1
            else:
                ipv4 += 1
            online = ip_obj['status'] == 'online'
            offline_ip = ip_obj['status'] == 'offline'
            if online:
                alive += 1
                if is6:
                    alive_v6 += 1
                else:
                    alive_v4 += 1
                # 收集延迟（只有在线且latency>0）
                lat = ip_obj.get('latency', -1)
                if lat is not None and lat > 0:
                    lats_all.append(lat)
                    if is_udp:
                        lats_udp.append(lat)
                        if is6:
                            lats_v6_udp.append(lat)
                        else:
                            lats_v4_udp.append(lat)
                    else:
                        lats_tcp.append(lat)
                        if is6:
                            lats_v6_tcp.append(lat)
                        else:
                            lats_v4_tcp.append(lat)
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
            
            # 新增：按协议和IP版本统计
            if is_udp:
                udp_total += 1
                if online:
                    udp_alive += 1
                elif offline_ip:
                    udp_offline += 1
                else:
                    udp_unknown += 1
                
                # UDPv4统计
                if not is6:
                    udp_v4_total += 1
                    if online:
                        udp_v4_alive += 1
                    elif offline_ip:
                        udp_v4_offline += 1
                    else:
                        udp_v4_unknown += 1
                # UDPv6统计
                else:
                    udp_v6_total += 1
                    if online:
                        udp_v6_alive += 1
                    elif offline_ip:
                        udp_v6_offline += 1
                    else:
                        udp_v6_unknown += 1
            else:
                tcp_total += 1
                if online:
                    tcp_alive += 1
                elif offline_ip:
                    tcp_offline += 1
                else:
                    tcp_unknown += 1
                
                # TCPv4统计
                if not is6:
                    tcp_v4_total += 1
                    if online:
                        tcp_v4_alive += 1
                    elif offline_ip:
                        tcp_v4_offline += 1
                    else:
                        tcp_v4_unknown += 1
                # TCPv6统计
                else:
                    tcp_v6_total += 1
                    if online:
                        tcp_v6_alive += 1
                    elif offline_ip:
                        tcp_v6_offline += 1
                    else:
                        tcp_v6_unknown += 1
                        
        # ALL统计（求和）
        all_total = tcp_v4_total + tcp_v6_total + udp_v4_total + udp_v6_total
        all_alive = tcp_v4_alive + tcp_v6_alive + udp_v4_alive + udp_v6_alive
        all_offline = tcp_v4_offline + tcp_v6_offline + udp_v4_offline + udp_v6_offline
        all_unknown = tcp_v4_unknown + tcp_v6_unknown + udp_v4_unknown + udp_v6_unknown
        
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
            'avg_latency':       _avg(lats_all),
            'avg_latency_v4_tcp': _avg(lats_v4_tcp),
            'avg_latency_v4_udp': _avg(lats_v4_udp),
            'avg_latency_v6_tcp': _avg(lats_v6_tcp),
            'avg_latency_v6_udp': _avg(lats_v6_udp),
            'avg_latency_tcp':   _avg(lats_tcp),
            'avg_latency_udp':   _avg(lats_udp),
            # 新增字段
            'tcp_v4_total': tcp_v4_total, 'tcp_v4_alive': tcp_v4_alive, 'tcp_v4_offline': tcp_v4_offline, 'tcp_v4_unknown': tcp_v4_unknown,
            'tcp_v6_total': tcp_v6_total, 'tcp_v6_alive': tcp_v6_alive, 'tcp_v6_offline': tcp_v6_offline, 'tcp_v6_unknown': tcp_v6_unknown,
            'udp_v4_total': udp_v4_total, 'udp_v4_alive': udp_v4_alive, 'udp_v4_offline': udp_v4_offline, 'udp_v4_unknown': udp_v4_unknown,
            'udp_v6_total': udp_v6_total, 'udp_v6_alive': udp_v6_alive, 'udp_v6_offline': udp_v6_offline, 'udp_v6_unknown': udp_v6_unknown,
            'all_total': all_total, 'all_alive': all_alive, 'all_offline': all_offline, 'all_unknown': all_unknown,
            'tcp_v4_latency': _avg(lats_v4_tcp),
            'tcp_v6_latency': _avg(lats_v6_tcp),
            'udp_v4_latency': _avg(lats_v4_udp),
            'udp_v6_latency': _avg(lats_v6_udp),
            'all_latency': _avg(lats_all),
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
            # 批量获取该域名下所有IP的统计数据
            ip_stats_map = self._get_domain_ip_stats(domain)
            
            ips_copy = []
            for ip_obj in t_copy['ips']:
                ip_copy = {k: v for k, v in ip_obj.items()
                           if k not in ('history_24h','history_7d','history_30d')}
                # 确保 auto_paused 字段被保留
                if 'auto_paused' in ip_obj:
                    ip_copy['auto_paused'] = ip_obj['auto_paused']
                if 'added_time' not in ip_copy:
                    ip_copy['added_time'] = t_copy.get('added_time')
                ip = ip_obj.get('ip', '')
                # 从缓存获取IP级统计
                ip_stats = ip_stats_map.get(ip, {})
                # IP 级三个周期可用率
                for pk in HISTORY_WINDOWS.keys():
                    ip_copy[f'uptime_{pk}'] = ip_stats.get(f'uptime_{pk}')
                # ip_uptime 用当前配置周期
                period = CONFIG.get('tracker_stat_period', '24h')
                ip_copy['ip_uptime'] = ip_copy.get(f'uptime_{period}')
                # IP 级末尾连续失败次数（近24h）
                ip_copy['consec_fail'] = ip_stats.get('consec_fail', 0)
                ips_copy.append(ip_copy)
            t_copy['ips'] = ips_copy
            # 域名级：hdb 内该域名下所有IP（含历史已移除）汇总，但排除已暂停IP
            # 已暂停IP不参与域名可用率计算，实时生效
            domain_paused = t_copy.get('paused', False)
            paused_ip_set = set()
            active_ip_set = set()
            if not domain_paused:
                for ip_obj in t_copy['ips']:
                    if ip_obj.get('paused') and not ip_obj.get('removed'):
                        paused_ip_set.add(ip_obj.get('ip', ''))
                    elif not ip_obj.get('removed'):
                        active_ip_set.add(ip_obj.get('ip', ''))
            for pk, secs in HISTORY_WINDOWS.items():
                cache_key = (domain, pk)
                cached = self._get_uptime_cached(domain, pk)
                if cached is not None:
                    t_copy[f'uptime_{pk}'] = cached
                    continue
                if CONFIG.get('cache_history', True):
                    use_legacy = CONFIG.get('uptime_algorithm', 'legacy') == 'legacy'
                    if use_legacy:
                        s = hdb.get_domain_summary(domain, secs,
                                                   excluded_ips=paused_ip_set if paused_ip_set else None)
                    else:
                        s = hdb.get_domain_summary(domain, secs,
                                                   excluded_ips=paused_ip_set if paused_ip_set else None,
                                                   included_ips=active_ip_set if active_ip_set else None)
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

    def _get_domain_ip_stats(self, domain):
        """批量获取域名下所有IP的统计数据，减少重复遍历"""
        ip_stats_map = {}
        
        # 获取该域名下所有IP（包括已移除的）
        all_ips = []
        with self.lock:
            td = self.trackers.get(domain)
            if td:
                for ip_obj in td.get('ips', []):
                    all_ips.append(ip_obj.get('ip', ''))
        
        for ip in all_ips:
            if not ip:
                continue
            
            # 尝试从缓存获取
            cached_stats = self._get_ip_stats_cached(domain, ip)
            if cached_stats is not None:
                ip_stats_map[ip] = cached_stats
                continue
            
            # 计算IP级统计
            stats = {}
            
            # 三个周期的可用率
            for pk, secs in HISTORY_WINDOWS.items():
                uptime = hdb.get_ip_uptime(domain, ip, secs)
                stats[f'uptime_{pk}'] = uptime
            
            # 连续失败次数（近24h）
            recent = hdb.get_ip_recent(domain, ip, 86400)
            consec_fail = 0
            for v in reversed(recent):
                if v == 0:
                    consec_fail += 1
                else:
                    break
            stats['consec_fail'] = consec_fail
            
            # 缓存结果
            self._set_ip_stats_cache(domain, ip, stats)
            ip_stats_map[ip] = stats
        
        return ip_stats_map

    def get_stats(self):
        with self.lock: return dict(self.stats)

    def get_ranking(self, period='24h', limit=200, min_uptime=0.0):
        secs = HISTORY_WINDOWS.get(period, 86400)
        out = []
        with self.lock:
            for name, tr in self.trackers.items():
                if tr.get('paused'):
                    continue
                # 一次遍历完成所有统计，避免多次遍历
                active_ips = []
                active_ip_set = set()
                paused_ip_set = set()
                online_count = 0
                offline_count = 0
                versions = set()
                for ip_obj in tr.get('ips', []):
                    ip = ip_obj.get('ip', '')
                    if ip_obj.get('removed'):
                        continue
                    if ip_obj.get('paused'):
                        paused_ip_set.add(ip)
                    else:
                        active_ips.append(ip_obj)
                        active_ip_set.add(ip)
                        status = ip_obj.get('status')
                        if status == 'online':
                            online_count += 1
                        elif status == 'offline':
                            offline_count += 1
                        versions.add(ip_obj.get('version', 'ipv4'))
                if not active_ips:
                    continue
                use_legacy = CONFIG.get('uptime_algorithm', 'legacy') == 'legacy'
                if use_legacy:
                    s = hdb.get_domain_summary(name, secs,
                                               excluded_ips=paused_ip_set if paused_ip_set else None)
                else:
                    s = hdb.get_domain_summary(name, secs,
                                               excluded_ips=paused_ip_set if paused_ip_set else None,
                                               included_ips=active_ip_set if active_ip_set else None)
                uptime = round(s['ok'] / s['total'] * 100, 2) if s['total'] > 0 else None
                if uptime is None and min_uptime > 0:
                    continue
                if uptime is not None and uptime < min_uptime:
                    continue
                domain = tr.get('domain', name)
                out.append({'name': name, 'domain': domain, 'port': tr.get('port', 80),
                            'protocol': tr.get('protocol', 'tcp'),
                            'uptime': uptime,
                            'ip_count': len(active_ips),
                            'online_count': online_count,
                            'offline_count': offline_count,
                            'has_v4': 'ipv4' in versions,
                            'has_v6': 'ipv6' in versions,
                            'all_paused': False})
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
            # 优化：从列表开头查找并删除，避免每次重新计算索引
            if len(self.logs) > max_e:
                # 统计当前级别日志数量
                level_count = sum(1 for e in self.logs if e['level'] == level)
                if level_count > max_e:
                    # 需要删除的数量
                    to_remove = level_count - max_e
                    remove_idx = 0
                    while to_remove > 0 and remove_idx < len(self.logs):
                        if self.logs[remove_idx]['level'] == level:
                            self.logs.pop(remove_idx)
                            to_remove -= 1
                        else:
                            remove_idx += 1
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
    def update_ips(self, domain, new_ip_list, dns_error=False, dns_skip=False):
        """每轮解析后更新 IP 列表：
        - 合并新IP（保留历史状态）
        - 标记消失的旧IP为 removed（不立即删除，保留检测到下次重启）
        - 记录 DNS 错误状态
        - 记录 DNS 跳过状态
        """
        with self.lock:
            if domain not in self.trackers:
                return
            td = self.trackers[domain]
            td['dns_error'] = dns_error
            td['dns_skip'] = dns_skip
            if dns_error or (not new_ip_list and not dns_skip):
                # DNS 失败：保留旧 IP 继续检测，仅标记错误
                return
            if dns_skip:
                # DNS 跳过：不发起查询，保留现有 IP 继续检测
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
                    # IP 仍然存在：若有 removed=True 标记则清除（保留 removed=False 的锁定标记）
                    if ip_obj.get('removed') is True:
                        ip_obj.pop('removed', None)
                        self._active_ips.add((domain, ip))
                        self._ip_map[(domain, ip)] = ip_obj
                        changed = True
                else:
                    # IP 消失
                    # 如果有 lock 标记，则跳过移除处理（IP被锁定）
                    if ip_obj.get('lock'):
                        # 确保被锁定的 IP 始终在活跃列表中，继续被探测
                        key = (domain, ip)
                        self._active_ips.add(key)
                        self._ip_map[key] = ip_obj
                        continue
                    key = (domain, ip)
                    if key in self._active_ips:
                        self._active_ips.discard(key)
                    self._ip_map.pop(key, None)
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
                    self._active_ips.add((domain, ip_info['ip']))
                    self._ip_map[(domain, ip_info['ip'])] = ip_info
                    changed = True
            if changed:
                self._recalc()
                self._clear_uptime_cache(domain)
                # 标记该tracker有配置变化（DNS更新导致IP变化）
                self._dirty_trackers.add(domain)
                # 立刻 异步保存 data.json
                self._save_async()

    # 异步保存：将保存任务提交到线程池
    def _save_async(self):
        """异步保存（线程安全，合并高频请求，带节流）"""
        with self._save_state_lock:
            # 节流：两次保存之间至少间隔1秒，避免高频写入
            now = time.time()
            if now - self._last_save_time < 1.0:
                # 如果已有任务在执行，标记需要再保存一次
                if self._save_pending:
                    self._save_requested = True
                return
            
            if self._save_pending:
                # 已有保存任务在执行/排队：只标记“还需要再保存一次”
                # 避免高频更新时丢失最后一次落盘请求。
                self._save_requested = True
                if self._save_trace_enabled():
                    cprint("[save] queue=busy pending=1 requested=1 -> merge", 'debug')
                return
            self._save_pending = True
            self._save_requested = False
            self._last_save_time = now  # 记录保存开始时间
            if self._save_trace_enabled():
                cprint("[save] queue=idle pending=1 requested=0 -> submit worker", 'debug')
        def _save_worker():
            while True:
                t0 = time.perf_counter()
                try:
                    self._save()
                except Exception as e:
                    cprint(f"异步保存失败: {e}", 'error')
                finally:
                    cost_ms = int((time.perf_counter() - t0) * 1000)
                    with self._save_state_lock:
                        # 期间若有新请求，立刻再保存一轮；否则退出并清空 pending。
                        if self._save_requested:
                            if self._save_trace_enabled():
                                cprint(f"[save] worker cost={cost_ms}ms pending=1 requested=1 -> continue", 'debug')
                            self._save_requested = False
                            continue
                        self._save_pending = False
                        if self._save_trace_enabled():
                            cprint(f"[save] worker cost={cost_ms}ms pending=0 requested=0 -> done", 'debug')
                        break
        self._save_executor.submit(_save_worker)

    def _save(self):
        """保存 data.json（tracker配置）"""
        try:
            with self.lock:
                # 如果没有配置变化，直接跳过
                if len(self._dirty_trackers) == 0:
                    return
                
                # ── 第一步：持锁期间只做纯内存拷贝（微秒级），不阻塞 API ────────
                # 判断是否需要增量保存
                total_trackers = len(self.trackers)
                dirty_count = len(self._dirty_trackers)
                
                if dirty_count > 0 and dirty_count < total_trackers * 0.5:
                    # 增量保存：只处理变化的tracker
                    snapshot = []
                    for d in self._dirty_trackers:
                        if d in self.trackers:
                            t = self.trackers[d]
                            ips_snap = []
                            for ip_obj in t['ips']:
                                ip_entry = {k: v for k, v in ip_obj.items()
                                            if k not in ('history_24h','history_7d','history_30d')}
                                ips_snap.append(ip_entry)
                            paused_set = ({ip_obj.get('ip','') for ip_obj in t['ips']
                                           if ip_obj.get('paused') and not ip_obj.get('removed')}
                                          if not t.get('paused') else set())
                            snapshot.append((d, t.get('domain', d), t.get('port', 80),
                                             t.get('protocol', 'tcp'), t['added_time'],
                                             t.get('paused', False), ips_snap, paused_set))
                    
                    # 读取现有文件内容
                    if os.path.exists(CONFIG['data_file']):
                        with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
                            try:
                                data = json.load(f)
                            except:
                                data = {}
                    else:
                        data = {}
                    # 处理删除场景：dirty 但已不在 self.trackers 中的域名，需从 data.json 移除
                    for d in self._dirty_trackers:
                        if d not in self.trackers:
                            data.pop(d, None)
                else:
                    # 全量保存
                    snapshot = []
                    for d, t in self.trackers.items():
                        ips_snap = []
                        for ip_obj in t['ips']:
                            ip_entry = {k: v for k, v in ip_obj.items()
                                        if k not in ('history_24h','history_7d','history_30d')}
                            ips_snap.append(ip_entry)
                        paused_set = ({ip_obj.get('ip','') for ip_obj in t['ips']
                                       if ip_obj.get('paused') and not ip_obj.get('removed')}
                                      if not t.get('paused') else set())
                        snapshot.append((d, t.get('domain', d), t.get('port', 80),
                                         t.get('protocol', 'tcp'), t['added_time'],
                                         t.get('paused', False), ips_snap, paused_set))
                    data = {}
                
                # 清空脏标记
                self._dirty_trackers.clear()

            # ── 第二步：锁外做慢操作（读 hdb 历史、写文件），不阻塞任何 API ─
            do_history = CONFIG.get('cache_history', True)
            for d, domain, port, protocol, added_time, paused, ips_snap, paused_set in snapshot:
                ips_to_save = []
                active_ips_for_hdb = set()
                for ip_entry in ips_snap:
                    if do_history:
                        ip = ip_entry.get('ip', '')
                        for pk, secs in HISTORY_WINDOWS.items():
                            ip_entry[f'history_{pk}'] = hdb.get_ip_summary(d, ip, secs)
                    ips_to_save.append(ip_entry)
                    # 收集活跃IP（未移除且未暂停）
                    if not ip_entry.get('removed') and not ip_entry.get('paused'):
                        active_ips_for_hdb.add(ip_entry.get('ip', ''))
                entry = {'domain': domain, 'port': port, 'protocol': protocol,
                         'ips': ips_to_save, 'added_time': added_time, 'paused': paused}
                if do_history:
                    for pk, secs in HISTORY_WINDOWS.items():
                        s = hdb.get_domain_summary(d, secs,
                                                   excluded_ips=paused_set if paused_set else None,
                                                   included_ips=active_ips_for_hdb if active_ips_for_hdb else None)
                        entry[f'history_{pk}'] = {'total': s['total'], 'ok': s['ok'], 'fail': s['fail']}
                data[d] = entry

            with open(CONFIG['data_file'], 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            # hdb.save() 只由定时保存线程处理，不在此处调用
            # 避免每次配置变化都触发历史数据保存
            #if do_history:
            #    hdb.save()
        except Exception as e:
            cprint(f"保存 data.json 失败: {e}", 'error')

    def load(self):
        try:
            if not os.path.exists(CONFIG['data_file']): return False
            with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
                data = json.load(f)
            with self.lock:
                self._active_ips.clear()
                self._ip_map.clear()
                total_removed = 0
                modified_trackers = set()  # 跟踪被修改的 tracker
                for d, t in data.items():
                    all_ips    = t.get('ips', [])
                    # 启动时删除 IP：
                    # - removed: true 且不是自动暂停的 → 删除
                    # - removed: true 且是自动暂停的 → 保留
                    # - 其他情况 → 保留
                    clean_ips = []
                    for ip in all_ips:
                        is_removed = ip.get('removed')
                        is_auto_paused = ip.get('auto_paused')
                        if is_removed and not is_auto_paused:
                            continue
                        # 旧版本兼容：删除 paused=false 和 removed=false 字段
                        if ip.get('paused') == False:
                            ip.pop('paused', None)
                        if ip.get('removed') == False:
                            ip.pop('removed', None)
                        clean_ips.append(ip)
                    removed_cnt = len(all_ips) - len(clean_ips)
                    if removed_cnt:
                        total_removed += removed_cnt
                        modified_trackers.add(d)  # 标记该 tracker 被修改
                        cprint(f"[load] {d}: 清理 {removed_cnt} 个已移除IP", 'debug')
                    for ip_obj in clean_ips:
                        # 清理 IP 级别的历史摘要字段（这些字段应该从 history.json 中实时计算）
                        for k in ('history_24h','history_7d','history_30d'):
                            ip_obj.pop(k, None)
                        # ===== 新增：为旧数据补充 last_check_ts =====
                        if 'last_check' in ip_obj and 'last_check_ts' not in ip_obj:
                            try:
                                dt = datetime.fromisoformat(ip_obj['last_check'])
                                ip_obj['last_check_ts'] = dt.timestamp()
                            except Exception:
                                ip_obj['last_check_ts'] = 0
                    # 只保留非removed的IP，同时清理域名级别的历史摘要字段
                    tracker_data = {
                        'domain':t.get('domain',d),'port':t.get('port',80),
                        'protocol':t.get('protocol','tcp'),'ips':clean_ips,
                        'added_time':t.get('added_time',datetime.now().isoformat()),
                        'dns_error': t.get('dns_error', False),
                        'dns_skip': t.get('dns_skip', False),
                        # 注意：history_24h, history_7d, history_30d 从 t 中排除，由 get_trackers() 实时计算
                    }
                    # 精简模式：有 paused 字段=真，无=假；旧版本兼容删除 paused=false
                    if t.get('paused') is True:
                        tracker_data['paused'] = True
                    elif t.get('paused') == False:
                        pass  # 不添加 paused=false 字段
                    # 初始化活跃IP集合和IP快速查找表（只添加非paused的IP）
                    domain_paused = t.get('paused')
                    for ip_obj in clean_ips:
                        ip = ip_obj.get('ip')
                        # 非暂停IP 或 被锁定的IP（锁定IP不受暂停影响）
                        if ip and ((not ip_obj.get('paused') and not domain_paused) or ip_obj.get('lock')):
                            self._active_ips.add((d, ip))
                            self._ip_map[(d, ip)] = ip_obj
                    self.trackers[d] = tracker_data
                    # 重启时自动恢复自动暂停的IP（auto_pause_persist关闭时）
                    # 注意：只有当域名也未被暂停时才恢复IP
                    if not CONFIG.get('auto_pause_persist', False):
                        domain_paused = t.get('paused')
                        if not domain_paused:
                            for ip_obj in clean_ips:
                                ip = ip_obj.get('ip')
                                if ip and ip_obj.get('paused') and ip_obj.get('auto_paused'):
                                    ip_obj.pop('paused', None)
                                    ip_obj.pop('auto_paused', None)
                                    if not ip_obj.get('lock'):
                                        self._active_ips.add((d, ip))
                                        self._ip_map[(d, ip)] = ip_obj
                                    modified_trackers.add(d)
                                    log_msg = f"[load] {d}({ip}) 自动暂停已恢复，开始检测"
                                    cprint(log_msg, 'info')
                                    self.add_log(log_msg, 'info')
                self._recalc()
            # 预热 geo 缓存（保持不变）
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
            # 标记数据已同步，避免启动时全量保存
            self._dirty_trackers.clear()
            # 返回被修改的 tracker 列表和移除数量，由主程序在 hdb 加载完成后 再统一保存 data.json
            return (True, modified_trackers, total_removed)
        except Exception as e:
            cprint(f"加载 data.json 失败: {e}", 'error')
            return False

    def _cleanup_hdb_on_startup(self):
        """重启后只做 GC，不清除任何 IP key。
        history.json 自包含 domain->IP 归属，已移除IP的历史保留用于域名统计。"""
        hdb._gc()
        cprint("[hdb] 启动GC完成", 'debug')
        # （无需同步=受限于存盘间隔）：从 hdb 更新 last_check_ts（hdb 包含最新的探测记录）
        # self._sync_last_check_from_hdb()

    def _sync_last_check_from_hdb(self):
        """从 history DB 同步每个IP的最新探测时间戳到 data.json 的 last_check_ts"""
        updated = 0
        try:
            # 先检查 hdb 是否已加载
            if not hdb._numpy_loaded:
                msg = f"[sync] hdb 尚未加载完成，跳过同步"
                cprint(msg, 'debug')
                db.add_log(msg, 'debug')
                return
            
            msg = f"[sync] 开始同步 last_check_ts，trackers 数量: {len(self.trackers)}"
            cprint(msg, 'debug')
            db.add_log(msg, 'debug')
            
            # 使用独立的锁访问 hdb
            with hdb.lock:
                # 先收集需要更新的数据，避免在迭代时修改
                to_update = []
                for domain, tracker in self.trackers.items():
                    ips = tracker.get('ips', [])
                    for ip_obj in ips:
                        ip = ip_obj.get('ip')
                        if not ip:
                            continue
                        ip_key = hdb._key_ip(ip)
                        # 检查 hdb 中是否有该数据
                        if domain in hdb._numpy_data:
                            domain_data = hdb._numpy_data[domain]
                            if ip_key in domain_data:
                                ts_arr = domain_data[ip_key].get('ts')
                                if ts_arr is not None and len(ts_arr) > 0:
                                    latest_ts = int(ts_arr[-1])
                                    current_ts = int(ip_obj.get('last_check_ts', 0))
                                    if latest_ts > current_ts:
                                        to_update.append((domain, ip, latest_ts))
            
            # 在独立的块中更新数据
            if to_update:
                with self.lock:
                    for domain, ip, latest_ts in to_update:
                        # 更新 tracker 中的 IP 对象
                        tracker = self.trackers.get(domain)
                        if tracker:
                            for ip_obj in tracker.get('ips', []):
                                if ip_obj.get('ip') == ip:
                                    ip_obj['last_check_ts'] = latest_ts
                                    # 更新 _ip_map
                                    if (domain, ip) in self._ip_map:
                                        self._ip_map[(domain, ip)]['last_check_ts'] = latest_ts
                                    updated += 1
                                    break
            
            if updated > 0:
                msg = f"[sync] 从 hdb 同步 {updated} 个 IP 的 last_check_ts"
                cprint(msg, 'debug')
                db.add_log(msg, 'debug')
            else:
                msg = f"[sync] 没有需要同步的 IP last_check_ts"
                cprint(msg, 'debug')
                db.add_log(msg, 'debug')
                
        except Exception as e:
            import traceback
            msg = f"[sync] 同步 last_check_ts 失败: {e}"
            cprint(msg, 'error')
            db.add_log(msg, 'error')
            msg = f"[sync] 详细错误: {traceback.format_exc()}"
            cprint(msg, 'error')
            db.add_log(msg, 'error')

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
HISTORY_NUMPY_FILE = 'history.npz'
HISTORY_WINDOWS = {
    '24h': 86400,
    '7d':  7 * 86400,
    '30d': 30 * 86400,
}

class HistoryDB:
    def __init__(self):
        self.lock         = threading.RLock()
        self._data        = {}
        self._numpy_data  = {}
        self._last_gc     = 0
        self._dirty_domains = set()
        self._save_timer   = None
        self._pending_records = []
        self._last_flush   = 0
        self._numpy_loaded = False

    def _key_ip(self, ip): return f'ip:{ip}'

    def _ensure_numpy(self, domain, ip_key):
        if domain not in self._numpy_data:
            self._numpy_data[domain] = {}
        if ip_key not in self._numpy_data[domain]:
            self._numpy_data[domain][ip_key] = {'ts': np.array([], dtype=np.int32), 'v': np.array([], dtype=np.int8)}

    def push_ip(self, domain, ip, result):
        """写入一条探测结果到对应域名下的IP key（先缓存，批量写入）"""
        v   = 1 if result in (True, 'online') else 0
        now = int(time.time())
        ip_key = self._key_ip(ip)
        with self.lock:
            dom = self._data.setdefault(domain, {})
            dom.setdefault(ip_key, []).append([now, v])
            self._dirty_domains.add(domain)
            self._pending_records.append((domain, ip_key, now, v))
            if self._numpy_loaded:
                self._ensure_numpy(domain, ip_key)
                self._numpy_data[domain][ip_key]['ts'] = np.append(self._numpy_data[domain][ip_key]['ts'], now)
                self._numpy_data[domain][ip_key]['v'] = np.append(self._numpy_data[domain][ip_key]['v'], v)
        if now - self._last_gc > 3600:
            self._gc()

    def get_ip_summary(self, domain, ip, window_secs):
        """返回指定域名下指定IP在窗口内的 {total, ok, fail}"""
        cutoff = int(time.time()) - window_secs
        ip_key = self._key_ip(ip)
        with self.lock:
            if self._numpy_loaded and domain in self._numpy_data and ip_key in self._numpy_data[domain]:
                ts_arr = self._numpy_data[domain][ip_key]['ts']
                v_arr = self._numpy_data[domain][ip_key]['v']
                if len(ts_arr) == 0:
                    return {'total': 0, 'ok': 0, 'fail': 0}
                mask = ts_arr >= cutoff
                window_v = v_arr[mask]
                ok = int(window_v.sum())
                total = len(window_v)
                return {'total': total, 'ok': ok, 'fail': total - ok}
            pts = self._data.get(domain, {}).get(ip_key, [])
            window = [v for ts, v in pts if ts >= cutoff]
        ok = sum(window)
        return {'total': len(window), 'ok': ok, 'fail': len(window) - ok}

    def get_ip_uptime(self, domain, ip, window_secs):
        """返回指定域名下指定IP在窗口内的可用率（0~100）或 None"""
        s = self.get_ip_summary(domain, ip, window_secs)
        return round(s['ok'] / s['total'] * 100, 1) if s['total'] > 0 else None

    def get_domain_summary(self, domain, window_secs, excluded_ips=None, included_ips=None):
        """域名级汇总：该域名下所有历史IP（含已移除）的 ok/total 之和。"""
        cutoff = int(time.time()) - window_secs
        excl_keys = {self._key_ip(ip) for ip in excluded_ips} if excluded_ips else set()
        incl_keys = {self._key_ip(ip) for ip in included_ips} if included_ips else None
        with self.lock:
            if self._numpy_loaded and domain in self._numpy_data:
                ip_map = self._numpy_data[domain]
                total_ok = total_cnt = 0
                for ik, data in ip_map.items():
                    if ik in excl_keys:
                        continue
                    if incl_keys and ik not in incl_keys:
                        continue
                    ts_arr = data['ts']
                    v_arr = data['v']
                    if len(ts_arr) == 0:
                        continue
                    mask = ts_arr >= cutoff
                    total_ok += int(v_arr[mask].sum())
                    total_cnt += int(mask.sum())
                return {'total': total_cnt, 'ok': total_ok, 'fail': total_cnt - total_ok}
            ip_map = self._data.get(domain, {})
            total_ok = total_cnt = 0
            for ik, pts in ip_map.items():
                if ik in excl_keys:
                    continue
                if incl_keys and ik not in incl_keys:
                    continue
                for ts, v in pts:
                    if ts >= cutoff:
                        total_ok  += v
                        total_cnt += 1
        return {'total': total_cnt, 'ok': total_ok, 'fail': total_cnt - total_ok}

    def get_ip_recent(self, domain, ip, window_secs):
        """返回窗口内的原始 [v, ...] 列表（用于连续失败计算）"""
        cutoff = int(time.time()) - window_secs
        ip_key = self._key_ip(ip)
        with self.lock:
            if self._numpy_loaded and domain in self._numpy_data and ip_key in self._numpy_data[domain]:
                ts_arr = self._numpy_data[domain][ip_key]['ts']
                v_arr = self._numpy_data[domain][ip_key]['v']
                if len(ts_arr) == 0:
                    return []
                mask = ts_arr >= cutoff
                return v_arr[mask].tolist()
            pts = self._data.get(domain, {}).get(ip_key, [])
            return [v for ts, v in pts if ts >= cutoff]

    def remove_domain(self, domain):
        """手动删除域名时调用，清除该域名所有历史数据"""
        with self.lock:
            self._data.pop(domain, None)
            self._numpy_data.pop(domain, None)
            self._dirty_domains.add(domain)

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
            if self._numpy_loaded:
                for domain in list(self._numpy_data.keys()):
                    ip_map = self._numpy_data[domain]
                    for ik in list(ip_map.keys()):
                        ts_arr = ip_map[ik]['ts']
                        v_arr = ip_map[ik]['v']
                        if len(ts_arr) == 0:
                            del ip_map[ik]
                            continue
                        mask = ts_arr >= cutoff
                        if mask.all():
                            continue
                        ip_map[ik]['ts'] = ts_arr[mask]
                        ip_map[ik]['v'] = v_arr[mask]
                    if not ip_map:
                        del self._numpy_data[domain]
            self._last_gc = int(time.time())

    # 无效IP集合：CF安全DNS可能将tracker解析为这些地址，需自动过滤
    _INVALID_IPS = {'[::]', '::', '0.0.0.0', '127.0.0.1', '::1'}

    @staticmethod
    def _is_invalid_ip(ip_str):
        """判断是否为无效IP（NXDOMAIN类DNS劫持结果）"""
        ip = ip_str.lower().strip()
        return ip in HistoryDB._INVALID_IPS

    def save(self, force_full=False):
        """运行时：追加到 history.json.append，同时更新 NumPy 数组并保存 NumPy 文件"""
        try:
            with self.lock:
                if not self._pending_records:
                    return

                with open(HISTORY_FILE + '.append', 'a', encoding='utf-8') as f:
                    for domain, ik, ts, v in self._pending_records:
                        record = json.dumps({
                            'd': domain,
                            'i': ik,
                            't': ts,
                            'v': v
                        }, separators=(',', ':'))
                        f.write(record + '\n')
                    f.flush()
                    os.fsync(f.fileno())

                self._pending_records = []
                self._dirty_domains.clear()

        except Exception as e:
            cprint(f"[HistoryDB] 保存失败: {e}", 'error')

    def _save_numpy(self):
        """保存 NumPy 文件（二进制高效格式）"""
        try:
            if not self._numpy_loaded:
                return
            with self.lock:
                np.savez_compressed(
                    HISTORY_NUMPY_FILE,
                    data=self._numpy_data
                )
        except Exception as e:
            cprint(f"[HistoryDB] NumPy保存失败: {e}", 'error')

    def _merge_append_file_to_numpy(self, append_file):
        """将 append 文件合并到 NumPy 数组"""
        try:
            if not os.path.exists(append_file):
                return 0
            records = []
            with open(append_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        records.append(rec)
                    except:
                        continue
            if not records:
                return 0
            for rec in records:
                domain = rec.get('d')
                ik = rec.get('i')
                ts = rec.get('t')
                v = rec.get('v')
                if not domain or not ik:
                    continue
                self._ensure_numpy(domain, ik)
                existing_ts = self._numpy_data[domain][ik]['ts']
                if len(existing_ts) > 0 and ts in existing_ts:
                    continue
                self._numpy_data[domain][ik]['ts'] = np.append(self._numpy_data[domain][ik]['ts'], ts)
                self._numpy_data[domain][ik]['v'] = np.append(self._numpy_data[domain][ik]['v'], v)
            return len(records)
        except Exception as e:
            cprint(f"[HistoryDB] NumPy合并append失败: {e}", 'error')
            return 0

    def _merge_append_file(self):
        """合并追加文件到主 history.json（定期执行，减少文件碎片）"""
        append_file = HISTORY_FILE + '.append'
        if not os.path.exists(append_file):
            return
        
        try:
            # 读取追加文件的所有记录
            with open(append_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        domain = rec.get('d')
                        ik = rec.get('i')
                        ts = rec.get('t')
                        v = rec.get('v')
                        if domain and ik:
                            dom = self._data.setdefault(domain, {})
                            dom.setdefault(ik, []).append([ts, v])
                    except:
                        continue
            
            # 全量写入主文件
            tmp_file = HISTORY_FILE + '.tmp'
            with open(tmp_file, 'w', encoding='utf-8') as f:
                f.write('{\n')
                domains = list(self._data.items())
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
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, HISTORY_FILE)
            
            # 删除追加文件
            os.remove(append_file)
            cprint(f"[HistoryDB] 合并完成，已清理追加文件", 'info')
        except Exception as e:
            cprint(f"[HistoryDB] 合并失败: {e}", 'error')

    def load(self):
        """启动时：加载 NumPy 文件，合并 history.json.append，生成 history.npz"""
        try:
            cutoff = int(time.time()) - 30 * 86400
            append_file = HISTORY_FILE + '.append'

            if os.path.exists(HISTORY_NUMPY_FILE):
                cprint(f"[HistoryDB] 发现 history.npz，开始加载...", 'info')
                try:
                    with self.lock:
                        loaded = np.load(HISTORY_NUMPY_FILE, allow_pickle=True)
                        self._numpy_data = loaded['data'].item()
                        self._numpy_loaded = True
                    cprint(f"[HistoryDB] NumPy文件加载成功", 'info')
                    if os.path.exists(append_file):
                        cprint(f"[HistoryDB] 发现append文件，开始合并到NumPy...", 'info')
                        count = self._merge_append_file_to_numpy(append_file)
                        cprint(f"[HistoryDB] NumPy合并append完成: {count} 条", 'info')
                        self._save_numpy()
                        os.remove(append_file)
                        cprint(f"[HistoryDB] 已清理append文件", 'info')
                except Exception as e:
                    cprint(f"[HistoryDB] NumPy加载失败，回退到JSON模式: {e}", 'error')
                    self._load_json_fallback(cutoff)
            else:
                cprint(f"[HistoryDB] 未发现 history.npz，使用JSON模式加载...", 'info')
                self._load_json_fallback(cutoff)
                cprint(f"[HistoryDB] JSON加载完成，转换为NumPy格式...", 'info')
                self._convert_json_to_numpy()
                self._save_numpy()
                cprint(f"[HistoryDB] NumPy转换并保存完成", 'info')

            with self.lock:
                total_domains = len(self._numpy_data)
                total_ips = sum(len(ip_map) for ip_map in self._numpy_data.values())
            cprint(f"[HistoryDB] 初始化完成：{total_domains} 个域名，{total_ips} 个IP key", 'info')

        except Exception as e:
            cprint(f"[HistoryDB] 加载失败: {e}", 'error')

    def _load_json_fallback(self, cutoff):
        """回退到 JSON 格式加载（兼容无 NumPy 文件时）"""
        loaded_domains = loaded_ips = skipped_ips = 0
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            with self.lock:
                for domain, ip_map in raw.items():
                    if not isinstance(ip_map, dict):
                        continue
                    cleaned_map = {}
                    for ik, pts in ip_map.items():
                        if not isinstance(pts, list):
                            continue
                        raw_ip = ik[3:] if ik.startswith('ip:') else ik
                        if self._is_invalid_ip(raw_ip):
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
            cprint(f"[HistoryDB] 已自动过滤 {skipped_ips} 个无效IP记录", 'info')
        cprint(f"[HistoryDB] JSON加载完成：{loaded_domains} 个域名，{loaded_ips} 个IP key", 'info')
        self._dirty_domains.clear()

    def _convert_json_to_numpy(self):
        """将 JSON 格式数据转换为 NumPy 格式"""
        with self.lock:
            for domain, ip_map in self._data.items():
                for ik, pts in ip_map.items():
                    if not pts:
                        continue
                    self._ensure_numpy(domain, ik)
                    ts_arr = np.array([p[0] for p in pts], dtype=np.int32)
                    v_arr = np.array([p[1] for p in pts], dtype=np.int8)
                    self._numpy_data[domain][ik]['ts'] = ts_arr
                    self._numpy_data[domain][ik]['v'] = v_arr
            self._numpy_loaded = True

    def export_to_json(self, json_file):
        """导出 NumPy 数据到 JSON 文件（用于备份或查看）"""
        try:
            with self.lock:
                data = {}
                for domain, ip_map in self._numpy_data.items():
                    data[domain] = {}
                    for ik, d in ip_map.items():
                        ts_arr = d['ts']
                        v_arr = d['v']
                        pts = [[int(ts), int(v)] for ts, v in zip(ts_arr, v_arr)]
                        data[domain][ik] = pts
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, separators=(',', ':'))
            cprint(f"[HistoryDB] 导出JSON完成: {json_file}", 'info')
        except Exception as e:
            cprint(f"[HistoryDB] 导出JSON失败: {e}", 'error')

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

# ── ip-api.com 持久 HTTP Session ─────────────────────────────────────
# requests.Session 内部维护 urllib3 连接池，同一主机的请求复用 TCP 连接，
# 避免每次 get_geo 都触发 TCP 握手/挥手，减少 TIME_WAIT 和 SYN_SENT。
_geo_http_session: Optional[req_lib.Session] = None
_geo_http_session_lock = threading.Lock()

def _get_geo_session() -> req_lib.Session:
    """返回全局复用的 geo HTTP Session（含代理），不存在时懒建。"""
    global _geo_http_session
    with _geo_http_session_lock:
        if _geo_http_session is None:
            s = req_lib.Session()
            proxies = make_proxy_dict()
            if proxies:
                s.proxies.update(proxies)
            s.headers.update({'Connection': 'keep-alive'})
            # pool_connections=1：只连接 ip-api.com 这一个主机，1 个连接池够用。
            # pool_maxsize=4：允许最多 4 条并发连接（监控线程 + geo更新线程可能同时调用）。
            # 不用 with response 后连接会被正确归还而非丢弃，不会再有 "pool is full" 警告。
            adapter = req_lib.adapters.HTTPAdapter(
                pool_connections=1,
                pool_maxsize=4,
                max_retries=0,
            )
            s.mount('http://',  adapter)
            s.mount('https://', adapter)
            _geo_http_session = s
        return _geo_http_session

def _reset_geo_session():
    """代理配置变更后调用，重建 Session 以使新代理生效。"""
    global _geo_http_session
    with _geo_http_session_lock:
        old = _geo_http_session
        _geo_http_session = None
    if old:
        try: old.close()
        except: pass

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
        import urllib.parse
        safe_ip = urllib.parse.quote(ip, safe=':.[]')
        s = _get_geo_session()
        # 不用 with，直接赋值：
        # stream=False 时 urllib3 读完响应体后会自动把连接归还连接池（keep-alive复用）。
        # 用 with response 反而会在 __exit__ 时调 r.close()，
        # 导致连接被标记为废弃而不是归还，触发 "Connection pool is full" 警告。
        r = s.get(
            f"http://ip-api.com/json/{safe_ip}?fields=country,countryCode,isp",
            timeout=5, stream=False
        )
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
        # 否定缓存命中：该记录类型已确认不存在，直接跳过
        if _dns_neg_is_blocked(domain, rtype):
            continue
        try:
            resolver = dns.resolver.Resolver()
            _dto = _dns_query_timeout()
            resolver.timeout  = _dto
            resolver.lifetime = _dto
            for rdata in resolver.resolve(domain, rtype, tcp=use_tcp):
                ip = str(rdata)
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # 确定性无记录：累加连续计数，达阈值进 CD
            hit = _dns_neg_record_all_empty(domain, rtype)
            if hit:
                msg = (f"[dnspython] {domain} {rtype} 连续 {hit} 轮无结果，"
                       f"进入否定缓存 CD {_DNS_NEG_TTL//3600}h")
                cprint(msg, 'debug')
                db.add_log(msg, 'debug')
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

def _dns_query_timeout() -> float:
    """DNS 查询使用的超时（秒），可与探测 timeout 分离以加快多服务器故障转移。"""
    raw = CONFIG.get('dns_timeout')
    base = float(CONFIG.get('timeout', 5))
    try:
        if raw is None or float(raw) <= 0:
            return max(0.5, base)
        return max(0.5, min(float(raw), 60.0))
    except (TypeError, ValueError):
        return max(0.5, base)

# 自定义 DNS：按服务器记录近期失败，冷却期内降低优先级（仍会尝试，排在队尾）。
# dnspython 单次 resolve 通常每次新建 TCP，不在这里做连接池；缩短超时 + 避开慢服更实际。
_dns_srv_stats: Dict[Tuple[str, bool], Dict[str, float]] = {}
_dns_srv_stats_lock = threading.Lock()

def _dns_note_srv_result(srv_ip: str, use_tcp: bool, ok: bool):
    """ok=True：查询成功或 NXDOMAIN/NoAnswer（服务器可达）；ok=False：超时/网络错误。"""
    k = (srv_ip, use_tcp)
    now = time.time()
    with _dns_srv_stats_lock:
        st = dict(_dns_srv_stats.get(k, {'fail_s': 0, 'cool_until': 0.0}))
        if ok:
            st['fail_s'] = 0
            st['cool_until'] = 0.0
        else:
            fs = int(st.get('fail_s', 0)) + 1
            st['fail_s'] = float(fs)
            delay = min(120.0, 15.0 * (2 ** min(fs - 1, 3)))
            st['cool_until'] = now + delay
        _dns_srv_stats[k] = st

def _dns_custom_try_order(servers: List[Tuple[str, bool]]) -> List[int]:
    """返回本轮尝试顺序（服务器下标）。

    dns_lb_enabled=True（负载均衡开启）：按健康度排序 + Round-Robin 旋转，
        非冷却、失败少者优先；相同优先级内用 RR 旋转，分散负载。
    dns_lb_enabled=False（默认关闭）：始终按配置顺序（0,1,2,...）顺序尝试，
        不做任何重排，避免并发查询同时打到同一台 DNS 导致被限流。
    """
    count = len(servers)
    if count <= 0:
        return []

    # 负载均衡关闭时：固定按配置顺序，不做 RR 旋转，不做健康度排序
    if not CONFIG.get('dns_lb_enabled', False):
        return list(range(count))

    # 负载均衡开启时：健康度排序 + Round-Robin
    now = time.time()
    with _dns_srv_stats_lock:
        def sort_key(i: int):
            srv_ip, use_tcp = servers[i]
            st = _dns_srv_stats.get((srv_ip, use_tcp), {'fail_s': 0, 'cool_until': 0.0})
            cooling = now < float(st.get('cool_until', 0))
            fail_s = int(st.get('fail_s', 0))
            return (1 if cooling else 0, fail_s, i)

        indices = sorted(range(count), key=sort_key)
    start = _dns_rr_next(len(indices))
    return [indices[(start + j) % len(indices)] for j in range(len(indices))]


# ==================== TCP DNS 长连接池 ====================
import select as _select_mod

class _TcpDnsConn:
    """
    单条 TCP DNS 持久长连接。
    ─ 建立后不主动关闭，等对端发 FIN 才关闭（或探测到断连时重建）。
    ─ 兼容 Windows 10 / Linux：
        · Windows：用 SIO_KEEPALIVE_VALS ioctl 设置 keepalive 参数
                   用 select() 替代 MSG_PEEK+setblocking 做存活探测
                   （Windows 上 setblocking(False)+recv 会抛 WinError 10035，
                    被误判为断连；select 更可靠）
        · Linux：TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT
    ─ 线程安全：持有自己的锁，同一连接的查询串行执行（防 TCP 流混淆）。
    """
    # Windows SIO_KEEPALIVE_VALS：一次 ioctl 设置 keepalive 开关+空闲时间+间隔
    _SIO_KEEPALIVE_VALS = 0x98000004  # == socket.SIO_KEEPALIVE_VALS（Python 3.6+有）

    def __init__(self, srv_ip: str, port: int = 53):
        self.srv_ip = srv_ip
        self.port   = port
        self._sock  = None
        self._lock  = threading.Lock()

    # ── 建立/重建 socket ────────────────────────────────────────────────
    def _make_sock(self, timeout: float) -> socket.socket:
        af   = socket.AF_INET6 if ':' in self.srv_ip else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if hasattr(socket, 'TCP_KEEPIDLE'):
            # Linux
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL,  5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,    3)
        else:
            # Windows：SIO_KEEPALIVE_VALS ioctl
            # 格式：onoff(4B) + keepalivetime(ms,4B) + keepaliveinterval(ms,4B)
            try:
                import struct as _st
                keepalive_vals = _st.pack('lll', 1, 10000, 5000)  # on, 10s空闲, 5s间隔
                sock.ioctl(socket.SIO_KEEPALIVE_VALS, keepalive_vals)
            except (AttributeError, OSError):
                pass  # 旧版 Python / 特殊环境，跳过，SO_KEEPALIVE 已设

        sock.connect((self.srv_ip, self.port))
        return sock

    # ── 存活探测（Windows/Linux 兼容） ─────────────────────────────────
    def _check_alive(self) -> bool:
        """
        用 select() 探测连接状态，不消耗数据，Windows/Linux 均兼容。
        逻辑：
          · select 的 readable 集合中出现 self._sock ──说明有数据或对端关闭了连接。
            再 recv(1, MSG_PEEK) 验证：空串 = 对端 FIN；非空 = 有未读数据（理论上不应有）。
          · select 超时（0 秒）返回空 ──说明连接空闲，正常存活。
          · 任何异常 ──认为连接不可用。
        """
        if self._sock is None:
            return False
        try:
            rd, _, ex = _select_mod.select([self._sock], [], [self._sock], 0)
            if ex:
                return False  # 异常状态
            if rd:
                # 有可读事件：peek 1 字节确认是否是 FIN
                try:
                    data = self._sock.recv(1, socket.MSG_PEEK)
                    return len(data) > 0  # b'' = FIN
                except OSError:
                    return False
            return True  # select 超时 = 空闲，连接正常
        except OSError:
            return False

    # ── 发包 / 收包 ─────────────────────────────────────────────────────
    @staticmethod
    def _send_recv(sock: socket.socket, req: dns.message.Message) -> dns.message.Message:
        wire = req.to_wire()
        sock.sendall(struct.pack('!H', len(wire)) + wire)
        raw_len  = _TcpDnsConn._recv_exact(sock, 2)
        resp_len = struct.unpack('!H', raw_len)[0]
        raw_resp = _TcpDnsConn._recv_exact(sock, resp_len)
        return dns.message.from_wire(raw_resp)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError('TCP DNS：对端关闭连接')
            buf += chunk
        return buf

    # ── 公开查询接口 ────────────────────────────────────────────────────
    def query(self, domain: str, rtype: str, timeout: float) -> dns.message.Message:
        """
        发送 DNS 查询，返回响应。
        · 查询前检测连接存活；断了则重建（最多重建1次）。
        · 连接对象一直持有 socket，不主动关闭。
        """
        rdtype = dns.rdatatype.from_text(rtype)
        req    = dns.message.make_query(domain, rdtype)

        with self._lock:
            for attempt in range(2):
                # step1: 确保连接存活
                if not self._check_alive():
                    if self._sock:
                        try: self._sock.close()
                        except: pass
                        self._sock = None
                    # 建连失败直接抛给调用方
                    self._sock = self._make_sock(timeout)

                # step2: 发包收包
                try:
                    self._sock.settimeout(timeout)
                    return _TcpDnsConn._send_recv(self._sock, req)
                except OSError:
                    # IO 错误：本次连接失效，清理后 attempt=1 时重连再试
                    try: self._sock.close()
                    except: pass
                    self._sock = None
                    if attempt == 1:
                        raise
                except socket.timeout:
                    # 超时：连接本身可能还好，直接上抛让调用方记录失败
                    raise

    def close(self):
        with self._lock:
            if self._sock:
                try: self._sock.close()
                except: pass
                self._sock = None


class _TcpDnsPool:
    """
    按 srv_ip 维护一个 _TcpDnsConn 实例（每 DNS 服务器一条持久连接）。
    线程安全：池的增删加锁，查询由连接对象自己的锁串行化。
    """
    def __init__(self):
        self._conns: Dict[str, _TcpDnsConn] = {}
        self._lock  = threading.Lock()

    def get(self, srv_ip: str) -> _TcpDnsConn:
        with self._lock:
            if srv_ip not in self._conns:
                self._conns[srv_ip] = _TcpDnsConn(srv_ip)
            return self._conns[srv_ip]

    def invalidate(self, srv_ip: str):
        """连接彻底不可用时清理，下次 get 重建。"""
        with self._lock:
            conn = self._conns.pop(srv_ip, None)
        if conn:
            conn.close()


# 全局 TCP DNS 连接池单例
_tcp_dns_pool = _TcpDnsPool()


def _query_single_server(domain: str, rtype: str, srv_ip: str, use_tcp: bool):
    """向单台 DNS 服务器查询。
    TCP 模式：使用全局长连接池，不在每次查询时新建/断开连接。
    UDP 模式：走原有 dnspython resolver（短连接，UDP 无连接开销）。

    返回值：
      [ip, ...]  —— 查询成功，有记录
      []         —— 域名不存在（NXDOMAIN / NoAnswer），确定性结果
      None       —— 超时 / 网络错误，此服务器本次失败
    """
    proto   = 'TCP' if use_tcp else 'UDP'
    timeout = _dns_query_timeout()

    # ── 网络探针检查：根据DNS服务器IP类型检查对应探针状态 ───────────────
    skip, reason = _should_skip_dns_for_server(srv_ip)
    if skip:
        # 探针异常时跳过此DNS服务器查询，返回特殊哨兵值表示探针跳过
        # 与 None（超时/错误）和 []（无结果）区分
        return _DNS_PROBE_SKIP

    def _log_noresult():
        now = time.time()
        key = (domain, rtype)
        with _dns_noresult_lock:
            last = _dns_noresult_logged.get(key, 0)
            if now - last > 86400:
                _dns_noresult_logged[key] = now
                msg = f"[custom DNS] {srv_ip}({proto}) 查询 {rtype} {domain} 失败: 无结果"
                db.add_log(msg, 'debug')
                cprint(msg, 'debug')

    def _log_error(e):
        msg = f"[custom DNS] {srv_ip}({proto}) 查询 {rtype} {domain} 失败: {type(e).__name__}: {e}"
        db.add_log(msg, 'debug')
        cprint(msg, 'debug')

    # ── TCP 长连接路径 ──────────────────────────────────────────────────
    if use_tcp:
        try:
            conn = _tcp_dns_pool.get(srv_ip)
            resp = conn.query(domain, rtype, timeout)

            # 解析响应
            rdata_type = dns.rdatatype.from_text(rtype)
            results = []
            for rrset in resp.answer:
                if rrset.rdtype == rdata_type:
                    for r in rrset:
                        results.append(r.address)

            if resp.rcode() == dns.rcode.NXDOMAIN or (not results and resp.rcode() == dns.rcode.NOERROR):
                # NXDOMAIN 或确实无此记录类型
                _log_noresult()
                return []

            return results if results else []

        except OSError as e:
            # 连接/网络错误：清理连接，告知调用方此服务器失败
            _tcp_dns_pool.invalidate(srv_ip)
            _log_error(e)
            return None
        except dns.exception.Timeout as e:
            # 超时：不清理连接（连接可能仍可用，只是这次慢），记录并返回 None
            _log_error(e)
            return None
        except Exception as e:
            _log_error(e)
            return None

    # ── UDP 路径（原有逻辑不变）────────────────────────────────────────
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [srv_ip]
        resolver.timeout  = timeout
        resolver.lifetime = timeout
        return [str(r) for r in resolver.resolve(domain, rtype, tcp=False)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        _log_noresult()
        return []
    except Exception as e:
        _log_error(e)
        return None

# 探针跳过标记（特殊哨兵值，用于区分探针跳过时的DNS查询结果）
_DNS_PROBE_SKIP = object()

# ── DNS 轮询状态（全局，所有 domain 共用，线程安全） ─────────────────────
# 记录"当前轮到哪台服务器"的游标，原子递增取模实现 Round-Robin。
# 各 domain 的每次查询都从同一个游标出发，天然分散请求到不同服务器，
# 不会像 Racing 那样同时向所有服务器发包，大幅减少对运营商 TCP 53 的并发冲击。
_dns_rr_index  = 0
_dns_rr_lock   = threading.Lock()

def _dns_rr_next(count: int) -> int:
    """返回 RR 旋转偏移（0..count-1），线程安全。

    自定义 DNS：用在「已排好优先级的下标列表」上，决定本轮从列表里哪一位开始试，
    不是「一个域名只绑一台 DNS」；单次查询仍按顺序逐台试直到成功或确定无记录。
    """
    global _dns_rr_index
    with _dns_rr_lock:
        idx = _dns_rr_index % count
        _dns_rr_index = (_dns_rr_index + 1) % count
        return idx

def _resolve_custom(domain: str):
    """模式3: 自定义DNS服务器 —— 健康度排序 + Round-Robin + 顺序故障转移.

    返回: (ips_list, probe_skipped)
      - ips_list: 解析到的IP列表
      - probe_skipped: True 表示所有DNS服务器都因探针跳过未查询

    策略说明：
      1. 按近期超时次数做短冷却：经常超时的服务器排在队尾（仍会尝试，避免全员冷却时饿死）。
      2. 在优先序列上再做 Round-Robin 旋转，分散负载。
      3. 依次为每台服务器单独查询；超时/错误则换下一台。
      4. 遇到 NXDOMAIN/NoAnswer 视为确定答案，直接停止，不再问其他服务器。
      5. 全部失败时返回空列表，由上层 resolve() 处理日志和 dns_error 标记.

    说明：dnspython 单次查询多为「一问一连」，自建 TCP 连接池成本高；
    实践中更有效的是 dns_timeout（可短于探测 timeout）+ 避开近期超时服务器.

    轮询语义（易混点）：
      - 不是「一个域名永远只用一台 DNS」：每次查 A / AAAA 各自会按 try_order 顺序试，第一台失败立刻试下一台。
      - 「轮询」指：全进程共享 RR，让不同次 resolve() 的首选 DNS 在列表里错位，分散压力。
      - 不是「多个域名凑够错误才换 DNS」：单次查询内即会故障转移；健康度是每台 DNS 的全局统计，不按域名凑次数。
    """
    servers = _parse_dns_servers()
    count   = len(servers)
    ips     = []
    seen    = set()
    all_probe_skipped = True  # 是否所有记录类型都被探针跳过

    for rtype, ver in [('A', 'ipv4'), ('AAAA', 'ipv6')]:
        # 否定缓存命中：该记录类型已确认不存在，直接跳过，不向 DNS 发包
        if _dns_neg_is_blocked(domain, rtype):
            continue

        try_order = _dns_custom_try_order(servers)
        result_ips = None
        had_timeout  = False   # 本轮是否有任何一台 DNS 超时
        empty_count  = 0       # 本轮返回无结果的 DNS 台数
        queried      = 0       # 本轮实际发包的 DNS 台数

        for i in range(count):
            idx = try_order[i]
            srv_ip, use_tcp = servers[idx]
            res = _query_single_server(domain, rtype, srv_ip, use_tcp)
            
            # 探针跳过：未实际查询，不记录统计，直接跳过此服务器
            if res is _DNS_PROBE_SKIP:
                continue
            
            queried += 1
            all_probe_skipped = False  # 至少有一次实际查询

            if res is None:
                # 超时/网络错误：不算无结果，标记 had_timeout
                _dns_note_srv_result(srv_ip, use_tcp, False)
                had_timeout = True
                continue

            _dns_note_srv_result(srv_ip, use_tcp, True)
            if res:
                # 拿到真实 IP：重置无结果计数，结束本记录类型查询
                result_ips = res
                _dns_neg_record_has_result(domain, rtype)
                break

            # res == []：此台 DNS 确认无记录，继续问下一台（收集全部意见）
            empty_count += 1

        if result_ips is None and not had_timeout and empty_count == queried and queried > 0:
            # 本轮所有 DNS 均返回无结果（无超时、无成功）——累加计数
            hit = _dns_neg_record_all_empty(domain, rtype)
            if hit:
                msg = (f"[custom DNS] {domain} {rtype} 连续 {hit} 轮全部无结果，"
                       f"进入否定缓存 CD {_DNS_NEG_TTL//3600}h")
                cprint(msg, 'debug')
                db.add_log(msg, 'debug')
            result_ips = []
        elif result_ips is None and had_timeout:
            # 有超时：重置连续无结果计数，本轮结果不确定
            _dns_neg_record_timeout(domain, rtype)
            result_ips = []
        elif result_ips is None and queried == 0:
            # 所有服务器都被探针跳过：不记录错误，跳过此记录类型
            continue
        
        if result_ips:
            for ip in result_ips:
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'ip': ip, 'version': ver, 'country': get_geo(ip)})

    return ips, all_probe_skipped

# 已记录过DNS失败的域名集合（应用生命周期内只报一次，避免控制台/web日志刷屏）
# 重启应用后集合清空，会重新提醒一次，方便感知配置变更后的效果。
_dns_fail_logged: set = set()
_dns_fail_lock = threading.Lock()

# 已记录过DNS“无结果”的域名+记录类型集合（应用生命周期内只报一次，避免刷屏）
_dns_noresult_logged = {}          # {(domain, rtype): last_time}
_dns_noresult_lock = threading.Lock()

# ── DNS 否定缓存（negative cache） ──────────────────────────────────────────
# 触发条件（两者同时满足）：
#   1. 本轮所有 DNS 服务器对该记录类型都返回"无结果"（没有任何一台超时或返回 IP）
#   2. 满足条件1的情况已连续出现 _DNS_NEG_THRESHOLD 次
# 进入 CD 后缓存 _DNS_NEG_TTL 秒，期间跳过查询；重启后计数和缓存均清空。
# 超时（None）不计入无结果次数——网络抖动不等于记录不存在。
_DNS_NEG_TTL       = 24 * 3600   # CD 时长：24 小时
_DNS_NEG_THRESHOLD = 5           # 连续全部无结果多少次才进 CD
_dns_neg_cache: dict = {}        # {(domain, rtype): expire_timestamp}  —— CD 中的条目
_dns_neg_miss:  dict = {}        # {(domain, rtype): consecutive_count} —— 连续全无结果计数
_dns_neg_lock   = threading.Lock()

def _dns_neg_is_blocked(domain: str, rtype: str) -> bool:
    """返回 True 表示该记录类型正处于 CD 中，本次应跳过查询直接返回空。"""
    key = (domain, rtype)
    with _dns_neg_lock:
        exp = _dns_neg_cache.get(key)
        if exp is None:
            return False
        if time.time() < exp:
            return True
        del _dns_neg_cache[key]   # CD 已过期，清除；计数器保留，让下一轮重新积累
        return False

def _dns_neg_record_all_empty(domain: str, rtype: str):
    """本轮所有 DNS 均返回无结果时调用。
    累加连续计数；达到阈值时写入 CD，并记录一条 debug 日志。
    """
    key = (domain, rtype)
    with _dns_neg_lock:
        count = _dns_neg_miss.get(key, 0) + 1
        _dns_neg_miss[key] = count
        if count >= _DNS_NEG_THRESHOLD:
            _dns_neg_cache[key] = time.time() + _DNS_NEG_TTL
            return count  # 返回计数供日志使用
    return 0  # 未达阈值，不进 CD

def _dns_neg_record_has_result(domain: str, rtype: str):
    """本轮查到了真实 IP 时调用：重置计数、清除 CD。"""
    key = (domain, rtype)
    with _dns_neg_lock:
        _dns_neg_miss.pop(key, None)
        _dns_neg_cache.pop(key, None)

def _dns_neg_record_timeout(domain: str, rtype: str):
    """本轮至少有一台 DNS 超时时调用：重置连续无结果计数（超时≠无结果）。"""
    key = (domain, rtype)
    with _dns_neg_lock:
        _dns_neg_miss.pop(key, None)

def _dns_neg_clear(domain: str):
    """解析恢复时清除该域名所有否定状态（A + AAAA 的计数和 CD）。"""
    with _dns_neg_lock:
        for rtype in ('A', 'AAAA'):
            _dns_neg_cache.pop((domain, rtype), None)
            _dns_neg_miss.pop((domain, rtype), None)

def _dns_fail_once(domain: str) -> bool:
    """返回 True 表示首次失败，应记录日志；False 表示已记录过，静默跳过。"""
    with _dns_fail_lock:
        if domain in _dns_fail_logged:
            return False
        _dns_fail_logged.add(domain)
        return True

def _dns_fail_clear(domain: str):
    """DNS 解析恢复时清除静默标记，下次失败重新提醒。
    注意：否定缓存由 resolve() 按记录类型精确清除，此处不做全清以避免误清。"""
    with _dns_fail_lock:
        _dns_fail_logged.discard(domain)

def _is_dns_skip(domain: str) -> bool:
    """检查域名是否在跳过DNS查询名单中"""
    skip_list = CONFIG.get('dns_skip_domains', [])
    if not skip_list:
        return False
    domain_lower = domain.lower()
    for skip_domain in skip_list:
        if skip_domain and skip_domain.lower() == domain_lower:
            return True
    return False

def resolve(domain: str):
    """根据 CONFIG['dns_mode'] 选择 DNS 解析策略
    返回: (ips_list, dns_skip_flag)
      - ips_list: 解析到的IP列表
      - dns_skip_flag: 'list'=域名在跳过名单中；'probe'=因探针异常跳过；False=正常查询
    """
    # 检查是否在跳过DNS查询名单中
    if _is_dns_skip(domain):
        return ([], 'list')

    mode = CONFIG.get('dns_mode', 'system')
    probe_skipped = False  # 是否因探针跳过未实际查询
    try:
        if mode == 'dnspython':
            ips = _resolve_dnspython(domain)
        elif mode == 'custom':
            ips, probe_skipped = _resolve_custom(domain)
        else:
            ips = _resolve_system(domain)
    except Exception as e:
        if _dns_fail_once(domain):
            cprint(f"DNS解析异常 {domain}: {e}", 'error')
            db.add_log(f"DNS解析异常 {domain}: {e}", 'error')
        return ([], False)
    
    # 探针跳过：不触发DNS错误，保留旧缓存
    if probe_skipped:
        return ([], 'probe')
    
    if ips:
        # 解析成功：按实际返回的记录类型精确清除否定缓存（计数 + CD）
        # 只清"本次真的查到了结果"的类型，避免把另一类型的否定缓存也误清掉
        got_versions = {ip_info['version'] for ip_info in ips}
        if 'ipv4' in got_versions:
            _dns_neg_record_has_result(domain, 'A')
        if 'ipv6' in got_versions:
            _dns_neg_record_has_result(domain, 'AAAA')
        _dns_fail_clear(domain)
    if not ips:
        # custom 模式下：无结果/超时都会在 _query_single_server 内按「具体 DNS + 记录类型」记录；
        # 这里避免再输出一条通用的「无结果」重复日志。
        if mode != 'custom' and _dns_fail_once(domain):
            db.add_log(f"DNS解析失败 {domain} [模式:{mode}]: 无结果", 'error')
            cprint(f"DNS解析失败 {domain} [模式:{mode}]", 'error')
    else:
        # 解析成功，清除静默标记（下次再失败时重新提醒）
        _dns_fail_clear(domain)
    return (ips, False)


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
    
    # 验证探测周期
    if 'probe_interval' in config:
        interval = config['probe_interval']
        if not isinstance(interval, (int, float)) or interval < 0.1 or interval > 60:
            errors.append('探测周期必须是0.1-60之间的数字')
    
    # 验证探测模式
    if 'probe_mode' in config:
        mode = config['probe_mode']
        if mode not in ['icmp', 'tcp']:
            errors.append('探测模式必须是 icmp 或 tcp')
    
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

    if 'dns_timeout' in config:
        try:
            dto = float(config['dns_timeout'])
            if dto < 0 or dto > 60:
                errors.append('DNS查询超时必须在0-60秒之间（0表示与连接超时相同）')
        except (TypeError, ValueError):
            errors.append('DNS查询超时必须是数字')
    
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
    # 注意：不使用 connect()+send()+recv()，而是使用 sendto()+recvfrom()
    # 原因：connect() 在 Windows 上对 UDP 是异步绑定，ICMP Port Unreachable
    #       (WinError 10054) 有时在 send() 阶段就抛出，有时在 recv() 阶段，
    #       行为不稳定。改用 sendto()+recvfrom() 与 udping.py 保持一致：
    #       sendto() 必定成功，ICMP 错误统一在 recvfrom() 中以 OSError/
    #       WinError 10054 抛出，IPv4/IPv6 均可靠检测到端口未开放。
    s = None
    try:
        infos = socket.getaddrinfo(ip, port, type=socket.SOCK_DGRAM)
        if not infos:
            return False, -1, "地址解析失败"
        fam, _, _, _, sockaddr = infos[0]

        s = socket.socket(fam, socket.SOCK_DGRAM)
        # Windows：确保 ICMP Port Unreachable 能在 recvfrom 中以 WSAECONNRESET/WinError 10054 抛出，
        # 否则某些环境会表现为“只超时”，无法区分端口未开放与丢包。
        try:
            if hasattr(socket, 'SIO_UDP_CONNRESET'):
                s.ioctl(socket.SIO_UDP_CONNRESET, 1)
        except Exception:
            pass
        # 加大接收缓冲区，高并发时防止内核丢包
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError: pass

        # 显式 bind：固定本地端口，高并发时防止端口被OS回收或复用
        bind_addr = ('::', 0) if fam == socket.AF_INET6 else ('', 0)
        s.bind(bind_addr)   # 必须监听所有接口，确保能收到响应

        # 用单调时钟做截止时间，避免系统时钟跳变导致剩余时间计算偏差
        t = time.perf_counter()
        s.sendto(packet, sockaddr)  # 不 connect，直接 sendto

        # 接收并校验 transaction_id
        # recvfrom 会在此处触发 ICMP Port Unreachable → OSError/WinError 10054
        deadline = t + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise socket.timeout()
            s.settimeout(max(remaining, 0.05))
            data, addr = s.recvfrom(4096)
            # 直连场景下应尽量只接受目标回包；避免接收到其他 tid/端口的残留包导致误判。
            if addr[0] != sockaddr[0]:
                continue
            # 只用 transaction_id 过滤旧包
            if len(data) >= 8 and data[4:8] != tid:
                continue
            break

        lat = int((time.perf_counter() - t) * 1000)
        if len(data) >= 16 and struct.unpack('!L', data[:4])[0] == 0:
            return True, lat, None
        return False, -1, "无效响应"

    except socket.timeout:
        return False, -1, f"超时(>{timeout}s)"
    except ConnectionRefusedError:
        # Linux/Mac: ICMP Port Unreachable → ConnectionRefusedError
        return False, -1, "端口未开放"
    except OSError as e:
        # Windows: ICMP Port Unreachable → WinError 10054
        if getattr(e, 'winerror', None) == 10054 or getattr(e, 'errno', None) == 10054 or 'forcibly closed' in str(e).lower():
            return False, -1, "端口未开放"
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        return False, -1, f"{type(e).__name__}: {e}"
    finally:
        # 无论任何路径退出都确保 socket 关闭，彻底回收端口
        if s:
            try: s.close()
            except: pass


# ==================== 网络探针：原生 ICMP Ping ====================
# 从 icmp_ping.py 移植，使用非阻塞IO + select，避免 SO_RCVTIMEO 问题

_PROBE_PAYLOAD_SIZE = 1

def _probe_checksum(data):
    """计算 ICMP 校验和"""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def _create_icmp4(ident, seq):
    """创建 IPv4 ICMP Echo 请求包"""
    header = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    payload = b'\x00' * _PROBE_PAYLOAD_SIZE
    cksum = _probe_checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, cksum, ident, seq)
    return header + payload

def _create_icmp6(ident, seq):
    """创建 IPv6 ICMP Echo 请求包"""
    header = struct.pack('!BBHHH', 128, 0, 0, ident, seq)
    return header + b'\x00' * _PROBE_PAYLOAD_SIZE

def _probe_resolve(target):
    """解析目标地址，返回 (family, dest)"""
    info = socket.getaddrinfo(target, 0)
    return info[0][0], info[0][4]

def icmp_ping(host: str, timeout: float = 3, payload: bytes = b'\x00') -> tuple:
    """
    原生 ICMP Ping 探测（兼容 IPv4/IPv6）
    返回 (成功: bool, 延迟毫秒: int, 错误信息: str)
    
    参数:
        host    : 目标域名或 IP 地址
        timeout : 超时时间（秒）
        payload : 保留参数，兼容原有调用
    
    返回:
        (True, 延迟ms, None)   : 成功收到回包
        (False, -1, 错误描述)  : 失败（超时、不可达等）
    
    说明:
        使用原生 socket 实现，非阻塞IO + select，支持 Windows/Linux/macOS
        需要管理员权限才能创建原始 socket
    """
    try:
        family, dest = _probe_resolve(host)
    except Exception as e:
        return False, -1, f"DNS解析失败: {e}"
    
    ident = random.randint(0, 0xFFFF)
    seq = 0
    
    try:
        if family == socket.AF_INET:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        sock.setblocking(False)
    except PermissionError:
        return False, -1, "需要管理员权限（ICMP原始socket）"
    except Exception as e:
        return False, -1, f"创建socket失败: {e}"
    
    try:
        # 发送 ICMP 请求
        if family == socket.AF_INET:
            packet = _create_icmp4(ident, seq)
        else:
            packet = _create_icmp6(ident, seq)
        
        try:
            sock.sendto(packet, dest)
            send_time = time.time()
        except OSError as e:
            return False, -1, f"发送失败: {e}"
        
        # 接收响应
        rtt = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select.select([sock], [], [], remaining)
                if not ready:
                    break
                data, addr = sock.recvfrom(1024)
                recv_time = time.time()
                
                # 校验响应
                if family == socket.AF_INET:
                    if len(data) < 28:
                        continue
                    icmp = data[20:28]
                    itype, _, _, rid, rseq = struct.unpack('!BBHHH', icmp)
                    if itype == 0 and rid == ident and rseq == seq:
                        rtt = (recv_time - send_time) * 1000
                        break
                else:
                    if len(data) < 8:
                        continue
                    itype, _, _, rid, rseq = struct.unpack('!BBHHH', data[:8])
                    if itype == 129 and rid == ident and rseq == seq:
                        rtt = (recv_time - send_time) * 1000
                        break
            except Exception:
                pass
        
        if rtt is not None:
            return True, rtt, None
        else:
            return False, -1, f"超时 (>{timeout}s)"
    finally:
        sock.close()


# ==================== 网络探针：TCP 长连接探测 ====================
# 从 tcping_long.py 移植，维持 TCP 连接，发送最小 DNS 查询测量 RTT

def _build_dns_query():
    """构建最小 DNS 查询报文（根域 NS 查询）"""
    # Header: ID=0x0001, Standard query, RD=1
    header = struct.pack('!HHHHHH', 0x0001, 0x0100, 1, 0, 0, 0)
    # Question: 根域编码为 0x00，查询类型 NS (2)，类 IN (1)
    question = b'\x00' + struct.pack('!HH', 2, 1)
    return header + question

_PROBE_DNS_QUERY = _build_dns_query()

def _tcp_probe_connect(target, port=53, timeout=5):
    """创建 TCP 连接到目标端口，返回 socket 或 None"""
    try:
        addrs = socket.getaddrinfo(target, port, proto=socket.IPPROTO_TCP)
        for fam, stype, proto, _, addr in addrs:
            sock = socket.socket(fam, stype, proto)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.settimeout(timeout)
            sock.connect(addr)
            sock.setblocking(False)
            return sock
    except Exception:
        pass
    return None

def _tcp_probe_recv_exact(sock, n, timeout=1.0):
    """从非阻塞 socket 精确接收 n 字节，超时返回 None"""
    data = b''
    deadline = time.time() + timeout
    while len(data) < n:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        try:
            ready = select.select([sock], [], [], remaining)
            if not ready[0]:
                return None
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        except (socket.error, ConnectionResetError, BrokenPipeError):
            return None
    return data

def _tcp_probe_once(sock, timeout=1.0):
    """发送 DNS 查询并接收响应，返回 RTT(毫秒) 或 None
    
    参数:
        sock: TCP socket（非阻塞模式）
        timeout: 接收响应超时时间（秒），默认1.0秒
    """
    try:
        # TCP DNS：2字节长度 + 报文
        msg = struct.pack('!H', len(_PROBE_DNS_QUERY)) + _PROBE_DNS_QUERY
        sock.sendall(msg)
        send_time = time.time()

        # 先读 2 字节长度
        len_data = _tcp_probe_recv_exact(sock, 2, timeout)
        if len_data is None:
            return None
        pkt_len = struct.unpack('!H', len_data)[0]
        if pkt_len < 12:  # DNS 头部至少 12 字节
            return None
        # 读取剩余报文
        pkt = _tcp_probe_recv_exact(sock, pkt_len, timeout)
        if pkt is None:
            return None
        rtt = (time.time() - send_time) * 1000
        return rtt
    except Exception:
        return None

def tcp_probe(host, port=53, timeout=5, probe_timeout=1.0):
    """
    TCP 长连接探测（通过 DNS 查询测量 RTT）
    返回 (成功: bool, 延迟毫秒: int, 错误信息: str, socket或None)
    
    参数:
        host         : 目标地址（支持带端口格式如 "8.8.8.8:53"）
        port         : 默认端口（如果 host 不含端口）
        timeout      : 连接超时时间（秒）
        probe_timeout: 接收响应超时时间（秒）
    
    返回:
        (True, 延迟ms, None, sock)    : 成功
        (False, -1, 错误描述, None)   : 失败
    """
    # 解析目标地址中的端口
    target_host = host
    target_port = port
    if ':' in host and not host.startswith('['):
        # 格式: ip:port
        parts = host.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            target_host = parts[0]
            target_port = int(parts[1])
    
    sock = _tcp_probe_connect(target_host, target_port, timeout)
    if sock is None:
        return False, -1, "连接失败", None
    
    # 使用 probe_timeout 作为接收响应超时
    rtt = _tcp_probe_once(sock, probe_timeout)
    if rtt is not None:
        return True, rtt, None, sock
    else:
        try:
            sock.close()
        except:
            pass
        return False, -1, "超时", None


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
    retry_mode = CONFIG.get('retry_mode')
    if retry_mode == 'disabled':
        raise ValueError('Retry is disabled')
    if retry_mode == 'polling':
        return next_retry_wait(domain)
    return int(CONFIG.get('retry_interval', 5))

# ==================== 监控逻辑 ====================
# 代理不可用时的哨兵错误前缀，check_ip/_check_one 识别后跳过状态更新
_PROXY_UNAVAIL_PREFIX = 'PROXY_UNAVAIL:'

def _is_proxy_unavail(err: str) -> bool:
    return bool(err and err.startswith(_PROXY_UNAVAIL_PREFIX))

def check_ip(domain, ip_info, retry=True, update_db=True):
    ip   = ip_info['ip']
    # 设置手动探测标记，5秒内跳过节流检查
    _manual_check_pending[(domain, ip)] = time.time()
    try:
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
            try:
                wait = get_retry_wait(domain)
                cprint(f"首次失败 {domain}:{port} ({ip}) 等待{wait}s重试 | {err}", 'debug')
                time.sleep(wait)
                ok, lat, err = fn(ip, port)
                # 重试后再次判断
                if not ok and _is_proxy_unavail(err):
                    return 'skipped', lat, err
            except ValueError:
                # 重试已禁用，直接返回失败状态
                pass
        status = 'online' if ok else 'offline'
        if update_db:
            db.update_status(domain, ip, status, lat)
        return status, lat, err
    finally:
        # 清理手动探测标记（可选，节流逻辑会自动处理过期标记）
        _manual_check_pending.pop((domain, ip), None)

def _resolve_and_update(name, domain, port, protocol):
    """每轮检测前重新解析 DNS，更新 IP 列表（合并新IP，标记消失IP，DNS失败保留旧缓存）
    name:   data.json 外层key（备注），用于数据库索引
    domain: data['domain'] 字段，实际连接地址（可以是域名，也可以是IP）
    """
    is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain)) or (':' in domain and '.' not in domain)
    if is_ip:
        return  # IP 直连模式，无需 DNS 解析
    
    # 网络探针检查：探针异常时跳过DNS查询，避免产生无效DNS请求
    # 注意：自定义DNS模式在 _query_single_server 层面按DNS服务器IP类型精细检查
    # 系统DNS/dnspython模式无法区分DNS服务器类型，使用全局检查
    dns_mode = CONFIG.get('dns_mode', 'system')
    if dns_mode != 'custom':
        skip_dns, dns_reason = _should_skip_dns_query()
        if skip_dns:
            return
    
    try:
        new_ips, dns_skip = resolve(domain)
        
        # DNS跳过名单：更新数据库标记跳过状态
        if dns_skip == 'list':
            cprint(f"DNS跳过 {name} ({domain}): 在跳过名单中", 'debug')
            db.update_ips(name, [], dns_error=False, dns_skip=True)
            return
        
        # 探针跳过：不更新数据库（保留旧缓存和跳过状态）
        if dns_skip == 'probe':
            return
        
        db.update_ips(name, new_ips, dns_error=(not new_ips and not dns_skip), dns_skip=False)
        if new_ips:
            cprint(f"DNS刷新 {name} ({domain}): {len(new_ips)}个IP", 'debug')
        else:
            # 无结果时日志已在 resolve() 内通过 _dns_fail_once 去重，此处不重复打印
            pass
    except Exception as e:
        db.update_ips(name, [], dns_error=True)
        # 异常日志同样由 resolve() 内去重处理，此处静默
        pass

# ==================== 网络探针 ====================
# 双重网络健康判断：
#   方案A（探针）：后台定期探测，维护 _probe_ok_v4/_probe_ok_v6 状态
#   方案B（失败率）：检查 check_interval 秒内的失败率
# 两种方案任一触发，即认定本地网络异常，跳过本次历史写入
_probe_ok_v4 = None   # IPv4 探针状态（None=未配置，True/False=有结果）
_probe_ok_v6 = None   # IPv6 探针状态（None=未配置，True/False=有结果）
_probe_lock  = threading.Lock()
_net_bad     = False  # 网络故障标志（全局失败率超阈值）
_net_bad_lock = threading.Lock()
_probe_details = {}   # 每个探针IP的最后探测结果 {ip: {'ok': bool, 'latency': int_or_-1, 'version': 'ipv4'/'ipv6'}}
_probe_has_timeout_v4 = False  # IPv4探针是否有任何一个超时（精细检测）
_probe_has_timeout_v6 = False  # IPv6探针是否有任何一个超时（精细检测）

# 实时健康缓存（每次探测前检查，TTL 秒内不重复扫描）
_health_cache = {
    'last_update': 0,
    'net_bad': False,
    'fail_rate': 0.0  # 初始值是0.0（0%）
}
_health_cache_lock = threading.Lock()
HEALTH_CACHE_TTL = 1   # 缓存有效期 1 秒，可调

# 连续失败计数：{(domain, ip): int}
_consec_fail_count = {}
_consec_fail_lock  = threading.Lock()

# 归属地查询线程池（异步执行，避免阻塞探测线程）
_geo_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="geo")

def _check_icmp_permission():
    """启动时检查 ICMP 权限，若不可用则记录一次错误但不影响主流程"""
    try:
        ok, _ = icmp_ping('1.1.1.1', timeout=5)
        if not ok:
            cprint("[ICMP] 权限检查失败：无法发送 ICMP 包，网络健康检测将不可用。", 'info')
        else:
            cprint("[ICMP] 权限检查通过，ICMP 探针正常工作。", 'info')
    except Exception:
        pass

# TCP 探针连接缓存：{cache_key: (socket, last_use_time)}
_probe_tcp_sockets = {}
_probe_tcp_lock = threading.Lock()

def _probe_one_icmp(host, timeout=3):
    """ICMP 模式探测单个目标"""
    return icmp_ping(host, timeout=timeout, payload=b'\x00')

def _probe_one_tcp(host, port=53, timeout=5):
    """TCP 模式探测单个目标（维持长连接，失败自动重连）"""
    # 解析目标地址中的端口
    target_host = host
    target_port = port
    
    # IPv6地址处理：
    # - 带端口的IPv6格式：[2001:4860:4860::8888]:53
    # - 不带端口的IPv6格式：2001:4860:4860::8888（不应解析端口）
    if host.startswith('['):
        # IPv6 带方括号格式
        end_bracket = host.rfind(']')
        if end_bracket > 0 and end_bracket < len(host) - 1 and host[end_bracket+1] == ':':
            # 有端口：[addr]:port
            try:
                target_port = int(host[end_bracket+2:])
                target_host = host[1:end_bracket]
            except:
                target_host = host[1:end_bracket]
        else:
            # 无端口：[addr]
            target_host = host[1:end_bracket]
    elif ':' in host and not host.count(':') > 1:
        # 仅IPv4可能带端口且冒号数量为1（IPv6地址有多个冒号）
        parts = host.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            target_host = parts[0]
            target_port = int(parts[1])
    # 纯IPv6地址（不带方括号）：不解析端口，直接使用
    
    cache_key = f"{target_host}:{target_port}"
    
    with _probe_tcp_lock:
        sock = _probe_tcp_sockets.get(cache_key)
    
    if sock:
        # 使用已有连接
        rtt = _tcp_probe_once(sock, timeout)  # 传递超时参数
        if rtt is not None:
            return True, rtt, None
        # 连接失败，关闭并重新建立
        try:
            sock.close()
        except:
            pass
        with _probe_tcp_lock:
            if _probe_tcp_sockets.get(cache_key) == sock:
                del _probe_tcp_sockets[cache_key]
        sock = None
    
    # 建立新连接
    sock = _tcp_probe_connect(target_host, target_port, timeout)
    if sock is None:
        return False, -1, "连接失败"
    
    # 使用传入的超时参数（探针接收响应超时）
    rtt = _tcp_probe_once(sock, timeout)
    if rtt is not None:
        with _probe_tcp_lock:
            _probe_tcp_sockets[cache_key] = sock
        return True, rtt, None
    else:
        try:
            sock.close()
        except:
            pass
        return False, -1, "超时"

def _probe_one(host, port=53, timeout=5, mode='icmp'):
    """
    探测单个目标
    返回 (可达: bool, 延迟ms: int, 错误信息: str)
    
    参数:
        host   : 目标地址（支持带端口格式如 "8.8.8.8:53"）
        port   : 默认端口（ICMP模式忽略，TCP模式使用）
        timeout: 超时时间（秒）
        mode   : 探测模式 'icmp' 或 'tcp'
    """
    if mode == 'tcp':
        return _probe_one_tcp(host, port, timeout)
    else:
        return _probe_one_icmp(host, timeout)

def _parse_target(target):
    """解析目标地址，返回 (host, port)，不含端口时默认使用53"""
    # IPv6带方括号格式：[2001:4860::8888]:53 或 [2001:4860::8888]
    if target.startswith('['):
        end_bracket = target.rfind(']')
        if end_bracket > 0 and end_bracket < len(target) - 1 and target[end_bracket+1] == ':':
            # 有端口：[addr]:port
            try:
                return target[1:end_bracket], int(target[end_bracket+2:])
            except:
                return target[1:end_bracket], 53
        else:
            # 无端口：[addr]
            return target[1:end_bracket], 53
    # IPv4带端口格式：8.8.8.8:53（只有一个冒号）
    elif ':' in target and target.count(':') == 1:
        parts = target.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
    # 纯地址（IPv4或IPv6）：不解析端口
    return target, 53

def _probe_loop():
    """后台探针线程：IPv4/IPv6 分组探测，分别维护可达状态和延迟。
    - IPv4 探针：从 CONFIG['probe_ipv4_targets'] 读取（默认 8.8.8.8/1.1.1.1/223.6.6.6）
    - IPv6 探针：从 CONFIG['probe_ipv6_targets'] 读取，可为空列表（禁用IPv6探测）
    - 超时：从 CONFIG['probe_timeout'] 读取（默认 5s）
    - 周期：从 CONFIG['probe_interval'] 读取（默认 1s）
    - 模式：从 CONFIG['probe_mode'] 读取（icmp 或 tcp）
    - 每组中任一可达即认为该栈正常
    - _probe_ok_v4 = IPv4 可达（用于判断是否丢弃IPv4探测的历史写入）
    - _probe_ok_v6 = IPv6 可达 / None（未配置）
    """
    global _probe_ok_v4, _probe_ok_v6, _probe_details, _probe_has_timeout_v4, _probe_has_timeout_v6
    _warned_v4 = False
    _warned_v6 = False
    _warned_fine_v4 = False  # 精细探针检查告警去重（IPv4）
    _warned_fine_v6 = False  # 精细探针检查告警去重（IPv6）
    while True:
        # 从配置读取参数
        PROBE_INTERVAL = float(CONFIG.get('probe_interval', 1))
        PROBE_TIMEOUT  = float(CONFIG.get('probe_timeout', 5.0))  # 支持小数超时
        PROBE_MODE     = CONFIG.get('probe_mode', 'icmp')

        # 每轮从 CONFIG 动态读取目标列表，支持运行时热更新
        ipv4_target_list = CONFIG.get('probe_ipv4_targets', ['8.8.8.8', '1.1.1.1', '223.6.6.6'])
        ipv6_target_list = CONFIG.get('probe_ipv6_targets', [])
        
        # 解析目标列表，提取端口
        IPV4_TARGETS = []
        for target in ipv4_target_list:
            host, port = _parse_target(target)
            IPV4_TARGETS.append((host, port, 'ipv4'))
        
        IPV6_TARGETS = []
        for target in ipv6_target_list:
            host, port = _parse_target(target)
            IPV6_TARGETS.append((host, port, 'ipv6'))

        details = {}

        # ── IPv4 探测（并行执行）───────────────────────────────────────────
        v4_reachable = None  # None=未配置
        v4_hit = ''
        v4_has_timeout = False  # 是否有任何一个IPv4探针超时
        if IPV4_TARGETS:
            v4_reachable = False
            with ThreadPoolExecutor(max_workers=len(IPV4_TARGETS)) as executor:
                futures = {executor.submit(_probe_one, host, port, PROBE_TIMEOUT, PROBE_MODE): (host, port, ver)
                          for host, port, ver in IPV4_TARGETS}
                for future in as_completed(futures):
                    host, port, ver = futures[future]
                    try:
                        ok, lat, err = future.result()
                    except Exception as e:
                        ok, lat, err = False, -1, str(e)
                    details[host] = {'ok': ok, 'latency': lat, 'version': ver, 'error': err}
                    if ok and not v4_reachable:
                        v4_reachable = True
                        v4_hit = f"{host}:{port}"
                    if not ok:
                        v4_has_timeout = True

        # ── IPv6 探测（并行执行）─────────────────────────────────────────────
        v6_reachable = None  # None=未配置
        v6_hit = ''
        v6_errors = []
        v6_has_timeout = False  # 是否有任何一个IPv6探针超时
        if IPV6_TARGETS:
            v6_reachable = False
            with ThreadPoolExecutor(max_workers=len(IPV6_TARGETS)) as executor:
                futures = {executor.submit(_probe_one, host, port, PROBE_TIMEOUT, PROBE_MODE): (host, port, ver)
                          for host, port, ver in IPV6_TARGETS}
                for future in as_completed(futures):
                    host, port, ver = futures[future]
                    try:
                        ok, lat, err = future.result()
                    except Exception as e:
                        ok, lat, err = False, -1, str(e)
                    details[host] = {'ok': ok, 'latency': lat, 'version': ver, 'error': err}
                    if ok and not v6_reachable:
                        v6_reachable = True
                        v6_hit = f"{host}:{port}"
                    elif not ok and err:
                        v6_errors.append(f"{host}: {err}")
                    if not ok:
                        v6_has_timeout = True

        with _probe_lock:
            _probe_ok_v4 = v4_reachable
            _probe_ok_v6 = v6_reachable
            _probe_details = details
            _probe_has_timeout_v4 = v4_has_timeout
            _probe_has_timeout_v6 = v6_has_timeout

        # ── IPv4 告警 ──────────────────────────────────────────────────
        v4_targets_str = ', '.join(f"{h}:{p}" for h,p,_ in IPV4_TARGETS) if IPV4_TARGETS else '(无)'
        if not v4_reachable and not _warned_v4:
            msg = f"[探针] IPv4全部目标({v4_targets_str})均不可达，IPv4网络可能异常"
            db.add_log(msg, 'info')
            cprint(msg, 'info')
            _warned_v4 = True
            _warned_fine_v4 = True  # 全部不可达时也标记精细告警已触发
        elif v4_reachable and _warned_v4:
            msg = f"[探针] IPv4网络已恢复，{v4_hit} 可达"
            db.add_log(msg, 'info')
            cprint(msg, 'info')
            _warned_v4 = False
            _warned_fine_v4 = False  # 恢复时清除精细告警标记

        # ── IPv6 告警（附带具体错误原因）──────────────────────────────────
        if v6_reachable is not None:
            v6_targets_str = ', '.join(f"{h}:{p}" for h,p,_ in IPV6_TARGETS)
            if not v6_reachable and not _warned_v6:
                error_detail = '; '.join(v6_errors) if v6_errors else '所有目标均无响应'
                msg = f"[探针] IPv6全部目标({v6_targets_str})均不可达: {error_detail}"
                db.add_log(msg, 'info')
                cprint(msg, 'info')
                _warned_v6 = True
                _warned_fine_v6 = True  # 全部不可达时也标记精细告警已触发
            elif v6_reachable and _warned_v6:
                msg = f"[探针] IPv6网络已恢复，{v6_hit} 可达"
                db.add_log(msg, 'info')
                cprint(msg, 'info')
                _warned_v6 = False
                _warned_fine_v6 = False  # 恢复时清除精细告警标记

        # ── 精细探针检查告警（仅开启精细检查时）──────────────────────────────
        # 条件：至少1个成功（避免与全部不可达告警重复）、但存在超时
        # 注意：日志已备注，如有需要可取消备注
        probe_fine_check = CONFIG.get('probe_fine_check_enabled', False)
        if probe_fine_check:
            # IPv4 精细告警
            if IPV4_TARGETS and v4_reachable and v4_has_timeout and not _warned_fine_v4:
                # 找出超时的探针
                v4_timeout_ips = [h for h, d in details.items() if d.get('version') == 'ipv4' and not d.get('ok')]
                v4_timeout_str = ', '.join(v4_timeout_ips) if v4_timeout_ips else ''
                # msg = f"[精细探针] IPv4部分探针({v4_timeout_str})超时，暂停探测等待恢复"
                # db.add_log(msg, 'info')
                # cprint(msg, 'info')
                _warned_fine_v4 = True
            elif IPV4_TARGETS and not v4_has_timeout and _warned_fine_v4:
                # msg = f"[精细探针] IPv4所有探针已恢复，继续探测"
                # db.add_log(msg, 'info')
                # cprint(msg, 'info')
                _warned_fine_v4 = False

            # IPv6 精细告警
            if IPV6_TARGETS and v6_reachable and v6_has_timeout and not _warned_fine_v6:
                v6_timeout_ips = [h for h, d in details.items() if d.get('version') == 'ipv6' and not d.get('ok')]
                v6_timeout_str = ', '.join(v6_timeout_ips) if v6_timeout_ips else ''
                # msg = f"[精细探针] IPv6部分探针({v6_timeout_str})超时，暂停探测等待恢复"
                # db.add_log(msg, 'info')
                # cprint(msg, 'info')
                _warned_fine_v6 = True
            elif IPV6_TARGETS and not v6_has_timeout and _warned_fine_v6:
                # msg = f"[精细探针] IPv6所有探针已恢复，继续探测"
                # db.add_log(msg, 'info')
                # cprint(msg, 'info')
                _warned_fine_v6 = False

        time.sleep(PROBE_INTERVAL)


def _update_health_status():
    """实时评估整体网络健康状态，更新 _net_bad 和缓存。每次探测前调用，开销极小（TTL 内直接返回）。"""
    now = time.time()
    with _health_cache_lock:
        # 缓存未过期，直接返回缓存的故障状态
        if now - _health_cache['last_update'] < HEALTH_CACHE_TTL:
            return _health_cache['net_bad']

        # 重新计算失败率
        threshold = CONFIG.get('probe_fail_threshold', 30) / 100.0
        max_age_sec = CONFIG.get('check_interval', 30)  # 只统计最近30秒内探测过的IP

        total = 0
        fail = 0
        with db.lock:
            # 直接使用 db._ip_map 快速查找活跃IP，O(1) 复杂度
            for domain, ip in db._active_ips:
                ip_obj = db._ip_map.get((domain, ip))
                if not ip_obj:
                    continue
                # 二次确认：如果 IP 被暂停或移除（理论上不应出现在活跃集中），跳过
                if ip_obj.get('removed') or ip_obj.get('paused'):
                    continue
                # 优先使用数值时间戳 last_check_ts，避免重复转换
                last_ts = ip_obj.get('last_check_ts')
                if last_ts is None:
                    last_str = ip_obj.get('last_check')
                    if last_str:
                        try:
                            last_ts = datetime.fromisoformat(last_str).timestamp()
                            ip_obj['last_check_ts'] = last_ts
                        except (ValueError, TypeError):
                            continue
                    else:
                        continue
                # 只统计最近30秒内探测过的IP（防止才启动的时候上一次的故障被重复统计）
                if now - last_ts > max_age_sec:
                    continue
                total += 1
                if ip_obj.get('status') == 'offline':
                    fail += 1

        net_bad = False
        fail_rate = None
        if total >= 5:
            fail_rate = fail / total
            net_bad = (fail_rate >= threshold)
            _health_cache['fail_rate'] = fail_rate
            # 状态变化时打印日志
            if net_bad != _health_cache.get('net_bad', False):
                if net_bad:
                    cprint(f"[实时健康] 网络故障触发：失败率 {fail_rate*100:.1f}% ≥ {threshold*100:.0f}%", 'info')
                    db.add_log(f"[实时健康] 网络故障触发：失败率 {fail_rate*100:.1f}% ≥ {threshold*100:.0f}%", 'info')
                else:
                    cprint(f"[实时健康] 网络恢复：失败率降至 {fail_rate*100:.1f}% < {threshold*100:.0f}%", 'info')
                    db.add_log(f"[实时健康] 网络恢复：失败率降至 {fail_rate*100:.1f}% < {threshold*100:.0f}%", 'info')
        else:
            # 样本不足时，保持之前的 net_bad 状态（不清除）
            net_bad = _health_cache.get('net_bad', False)
            fail_rate = _health_cache.get('fail_rate')

        _health_cache['net_bad'] = net_bad
        _health_cache['fail_rate'] = fail_rate
        _health_cache['last_update'] = now

        # 同时更新全局 _net_bad（供其他地方使用）
        with _net_bad_lock:
            global _net_bad
            _net_bad = net_bad

        return net_bad

# 立即检测触发器（兼容旧接口，独立线程模式下不再使用，保留以避免其他代码引用报错）
_check_now = threading.Event()

# ==================== 独立线程监控架构 ====================
# 每个 (domain, ip) 和每个 domain（DNS刷新）都有独立线程，各自睡眠 check_interval 秒。
# 启动时对所有 tracker 的线程加随机偏移（stagger），错峰探测和DNS查询，
# 避免一次性大量并发触发运营商风控。
#
# 全局线程注册表：{key: threading.Thread}
#   key = ('ip', domain, ip)   —— IP探测线程
#   key = ('dns', domain)      —— DNS刷新线程
_tracker_threads: Dict[tuple, threading.Thread] = {}
_tracker_threads_lock = threading.Lock()
# 停止信号：每个线程的停止事件
_tracker_stop_events: Dict[tuple, threading.Event] = {}
# 并发探测限制（信号量 + 计数器）
_probe_semaphore: threading.Semaphore = None
_probe_active_count: int = 0
_probe_active_lock: threading.Lock = threading.Lock()
_stats_thread_info: dict = {'active_probes': 0, 'max_probes': 120}
_manual_check_pending: dict = {}  # 手动探测标记：{(domain, ip): timestamp}，5秒内跳过节流

def _ip_ver(ip_str: str) -> str:
    """返回 IP 地址族字符串：'ipv6' 或 'ipv4'。解析失败默认视为 ipv4。"""
    import ipaddress as _ipa
    try:
        return 'ipv6' if isinstance(_ipa.ip_address(ip_str), _ipa.IPv6Address) else 'ipv4'
    except Exception:
        return 'ipv4'

def _wrap_ipv6(host: str) -> str:
    """将 IPv6 地址包装为 [addr] 格式，IPv4/hostname 原样返回。
    用于拼接 tracker URL 时确保 IPv6 地址被 [] 包裹。
    """
    if not host:
        return host
    # 已经包装过的直接返回
    if host.startswith('[') and host.endswith(']'):
        return host
    # 包含冒号 → IPv6 地址
    if ':' in host:
        return f'[{host}]'
    return host

def _get_probe_net_status(ip_str: str):
    """返回 (skip_probe: bool, skip_history: bool, reason: str)
    - skip_probe: True = 完全跳过探测（不发包），False = 继续探测
    - skip_history: True = 跳过写入历史，False = 正常写入
    """
    ver = _ip_ver(ip_str)
    
    # 1. 探针状态检查 - 区分 IPv4/IPv6，探针异常或未就绪时完全跳过探测
    with _probe_lock:
        probe_v4_ok = _probe_ok_v4
        probe_v6_ok = _probe_ok_v6
        probe_v4_timeout = _probe_has_timeout_v4
        probe_v6_timeout = _probe_has_timeout_v6
    
    # IPv4 探针未就绪或异常 → 跳过 IPv4 IP 的探测和写入
    if ver == 'ipv4' and probe_v4_ok is not True:  # None 或 False 都跳过
        return True, True, 'IPv4探针不可达'
    # IPv6 探针未就绪或异常 → 跳过 IPv6 IP 的探测和写入
    if ver == 'ipv6' and probe_v6_ok is not True:  # None 或 False 都跳过
        return True, True, 'IPv6探针不可达'
    
    # 2. 精细探针检查（拥堵避让）- 任何一个探针超时即等待恢复
    # 探测IPv4时检查所有IPv4探针，探测IPv6时检查所有IPv6探针
    probe_fine_check = CONFIG.get('probe_fine_check_enabled', False)
    if probe_fine_check:
        if ver == 'ipv4' and probe_v4_timeout:
            return True, True, 'IPv4探针存在超时，等待恢复'
        if ver == 'ipv6' and probe_v6_timeout:
            return True, True, 'IPv6探针存在超时，等待恢复'
    
    # 3. 实时整体健康检查（基于失败率）- 只跳过写入，不跳过探测
    if _update_health_status():
        return False, True, '全局网络故障（失败率超阈值）'
    
    # 正常情况
    return False, False, ''

def _should_skip_dns_query():
    """检查是否应该跳过DNS查询（网络探针故障时避让）
    返回 (skip: bool, reason: str)
    - skip: True = 跳过DNS查询，False = 继续查询
    - reason: 跳过原因描述
    
    适用于系统DNS和dnspython模式（无法区分DNS服务器IP类型），
    自定义DNS模式使用 _should_skip_dns_for_server 进行更精细的检查。
    """
    with _probe_lock:
        probe_v4_ok = _probe_ok_v4
        probe_v6_ok = _probe_ok_v6
        probe_v4_timeout = _probe_has_timeout_v4
        probe_v6_timeout = _probe_has_timeout_v6
    
    # 从配置读取探针目标列表，判断是否配置了对应协议的探针
    ipv4_targets = CONFIG.get('probe_ipv4_targets', ['8.8.8.8', '1.1.1.1', '223.6.6.6'])
    ipv6_targets = CONFIG.get('probe_ipv6_targets', [])
    has_ipv4_probe = bool(ipv4_targets) and any(t.strip() for t in ipv4_targets)
    has_ipv6_probe = bool(ipv6_targets) and any(t.strip() for t in ipv6_targets)
    
    # 1. 基础检查：IPv4和IPv6探针全部异常时跳过
    v4_all_bad = probe_v4_ok is False
    v6_all_bad = probe_v6_ok is False
    
    # 如果配置了IPv4探针且全部失败
    if has_ipv4_probe and v4_all_bad:
        return True, 'IPv4探针全部不可达'
    # 如果配置了IPv6探针且全部失败
    if has_ipv6_probe and v6_all_bad:
        return True, 'IPv6探针全部不可达'
    
    # 2. 精细探针检查（拥堵避让）- 任何一个探针超时即跳过
    # 注意：系统DNS/dnspython模式无法区分，所以只要任意一方有超时就全部跳过
    probe_fine_check = CONFIG.get('probe_fine_check_enabled', False)
    if probe_fine_check:
        if has_ipv4_probe and probe_v4_timeout:
            return True, 'IPv4探针存在超时，等待恢复'
        if has_ipv6_probe and probe_v6_timeout:
            return True, 'IPv6探针存在超时，等待恢复'
    
    # 3. 实时整体健康检查（基于失败率）
    if _update_health_status():
        return True, '全局网络故障（失败率超阈值）'
    
    return False, ''

def _should_skip_dns_for_server(srv_ip: str):
    """检查向特定DNS服务器发起查询时是否应该跳过
    根据DNS服务器的IP类型（IPv4/IPv6）检查对应的探针状态
    
    srv_ip: DNS服务器IP地址
    
    返回 (skip: bool, reason: str)
    - skip: True = 跳过此DNS服务器查询，False = 继续查询
    - reason: 跳过原因描述
    """
    import ipaddress as _ipa
    try:
        ip_obj = _ipa.ip_address(srv_ip)
        is_ipv6 = isinstance(ip_obj, _ipa.IPv6Address)
    except Exception:
        # 解析失败，默认为IPv4
        is_ipv6 = False
    
    ver = 'ipv6' if is_ipv6 else 'ipv4'
    
    with _probe_lock:
        probe_v4_ok = _probe_ok_v4
        probe_v6_ok = _probe_ok_v6
        probe_v4_timeout = _probe_has_timeout_v4
        probe_v6_timeout = _probe_has_timeout_v6
    
    # 从配置读取探针目标列表，判断是否配置了对应协议的探针
    ipv4_targets = CONFIG.get('probe_ipv4_targets', ['8.8.8.8', '1.1.1.1', '223.6.6.6'])
    ipv6_targets = CONFIG.get('probe_ipv6_targets', [])
    has_ipv4_probe = bool(ipv4_targets) and any(t.strip() for t in ipv4_targets)
    has_ipv6_probe = bool(ipv6_targets) and any(t.strip() for t in ipv6_targets)
    
    # IPv4 DNS服务器 → 检查IPv4探针
    if not is_ipv6:
        if has_ipv4_probe and probe_v4_ok is False:
            return True, 'IPv4探针全部不可达'
        
        probe_fine_check = CONFIG.get('probe_fine_check_enabled', False)
        if probe_fine_check and has_ipv4_probe and probe_v4_timeout:
            return True, 'IPv4探针存在超时，等待恢复'
    
    # IPv6 DNS服务器 → 检查IPv6探针
    else:
        if has_ipv6_probe and probe_v6_ok is False:
            return True, 'IPv6探针全部不可达'
        
        probe_fine_check = CONFIG.get('probe_fine_check_enabled', False)
        if probe_fine_check and has_ipv6_probe and probe_v6_timeout:
            return True, 'IPv6探针存在超时，等待恢复'
    
    # 实时整体健康检查（基于失败率）- 任何网络故障都跳过
    if _update_health_status():
        return True, '全局网络故障（失败率超阈值）'
    
    return False, ''

def _ip_monitor_thread(domain: str, ip: str, stop_event: threading.Event,
                       initial_delay: float = 0.0):
    """每个IP独立监控线程。
    - 启动时先睡 initial_delay 秒（错峰）。
    - 探测成功：等待 check_interval 秒后再次探测。
    - 探测失败：根据连续失败次数递增等待 5/15/30/60 秒（循环），不再额外立即重试。
    - 探测前检查网络状态（探针），网络异常时跳过本次探测，不写历史，不计入失败计数。
    - DNS查询由对应 domain 的 DNS 线程负责，IP线程只做探测。
    """
    # 首次启动错峰延迟
    if initial_delay > 0:
        stop_event.wait(timeout=initial_delay)
        if stop_event.is_set():
            return

    _warned_net = False   # 网络异常去重标记

    # 使用全局 POLLING_SEQUENCE
    # POLLING_SEQUENCE = [5, 15, 30, 60]

    while not stop_event.is_set():
        try:
            # 检查该 IP 是否被暂停或移除（持锁时间尽量短）
            should_skip = False
            skip_reason = ''
            with db.lock:
                td = db.trackers.get(domain, {})
                if not td:
                    return  # tracker 已删除，退出线程
                # 使用 _ip_map 快速查找，O(1) 复杂度
                ip_obj = db._ip_map.get((domain, ip))
                if ip_obj is None or ip_obj.get('removed') is True:
                    return  # IP 已移除，退出线程（removed=False 的 IP 被锁定，继续探测）
                if ip_obj.get('paused') or td.get('paused'):
                    should_skip = True
                    skip_reason = 'paused'
                else:
                    port     = td.get('port', 80)
                    protocol = td.get('protocol', 'tcp')

            if should_skip:
                # 暂停状态：等待正常间隔后继续
                next_wait = CONFIG.get('check_interval', 30)
                stop_event.wait(timeout=next_wait)
                continue

            # ── 检查上次探测时间，避免重启后立即重复探测 ──────────────────
            # 只有开启探测节流时才执行
            if CONFIG.get('probe_throttle_enabled', False):
                # 清理过期的手动探测标记（>5秒）
                now = time.time()
                expired_keys = [k for k, ts in _manual_check_pending.items() if now - ts > 5]
                for k in expired_keys:
                    _manual_check_pending.pop(k, None)
                
                # 检查是否是手动探测（5秒内跳过节流）
                manual_key = (domain, ip)
                if manual_key in _manual_check_pending:
                    # 手动探测刚完成，跳过节流
                    _manual_check_pending.pop(manual_key, None)
                else:
                    check_interval = CONFIG.get('check_interval', 30)
                    last_ts = None
                    last_status = None
                    try:
                        # 使用非阻塞方式获取上次探测时间和状态
                        if (domain, ip) in db._ip_map:
                            ip_info = db._ip_map[(domain, ip)]
                            last_ts = ip_info.get('last_check_ts')
                            last_status = ip_info.get('status')
                    except Exception:
                        pass
                    
                    if last_ts:
                        elapsed = time.time() - last_ts
                        # 如果上次状态是正常的（online），才进行节流
                        # 如果上次状态是异常的（offline），应该立即探测判断是否恢复
                        # 只有当 elapsed < check_interval 时才需要等待
                        if elapsed < check_interval and last_status == 'online':
                            # 距离上次正常探测太近，等待剩余时间
                            wait_time = check_interval - elapsed
                            # 只有当等待时间 > 0.1 秒时才等待，避免微小等待
                            if wait_time > 0.1:
                                cprint(f"[探测节流] {domain}({ip}) 上次正常探测仅 {elapsed:.1f}s，等待 {wait_time:.1f}s", 'debug')
                                db.add_log(f"[探测节流] {domain}({ip}) 上次正常探测仅 {elapsed:.1f}s，等待 {wait_time:.1f}s", 'debug')
                                stop_event.wait(timeout=wait_time)
                                continue

            # ── 探测前检查网络状态（探针异常时跳过探测，失败率超阈值时跳过写入）───────
            skip_probe, skip_history, net_reason = _get_probe_net_status(ip)
            
            # 探针异常 → 完全跳过探测（不发包）
            if skip_probe:
                if not _warned_net:
                    cprint(f"[网络异常] {domain}({ip}) {net_reason}，跳过本次探测", 'debug')
                    _warned_net = True
                # 持续异常：跳过探测，等待后继续
                # 使用 probe_interval 快速重试检查，避免长时间等待
                next_wait = CONFIG.get('probe_interval', 1)
                stop_event.wait(timeout=next_wait)
                continue
            elif _warned_net:
                # 恢复正常
                cprint(f"[网络恢复] {domain}({ip}) 网络已恢复正常", 'debug')
                _warned_net = False

            # ── 实际探测（不再做立即重试）────────────────────────
            fn = udp_ping if protocol == 'udp' else tcp_ping
            # 使用信号量限制并发探测数
            with _probe_semaphore:
                # 更新活跃探测计数
                with _probe_active_lock:
                    _stats_thread_info['active_probes'] += 1
                try:
                    ok, lat, err = fn(ip, port)
                finally:
                    with _probe_active_lock:
                        _stats_thread_info['active_probes'] -= 1

            # 代理不可用 → 跳过，保留上次状态，不计入失败计数
            if not ok and _is_proxy_unavail(err):
                next_wait = CONFIG.get('check_interval', 30)
                stop_event.wait(timeout=next_wait)
                continue

            status = 'online' if ok else 'offline'

            # ── 再次检查探针（探测期间可能网络已故障） ──────────
            skip_probe2, skip_history2, net_reason2 = _get_probe_net_status(ip)

            # ── 连续失败计数 & 自动暂停 & 动态轮询等待 ──────────
            key = (domain, ip)
            auto_pause_enabled = CONFIG.get('auto_pause_enabled', True)
            auto_pause_threshold = CONFIG.get('auto_pause_threshold', 30)

            # 处理成功/失败状态，更新失败计数并计算下次等待时间
            if status == 'online':
                # 成功：清除失败计数，下次等待正常间隔
                with _consec_fail_lock:
                    if key in _consec_fail_count:
                        old = _consec_fail_count[key]
                        _consec_fail_count.pop(key, None)
                        cprint(f"[重置失败计数] {domain}({ip}) 从 {old} 重置为 0", 'debug')
                next_wait = CONFIG.get('check_interval', 30)
            else:
                # 失败（且不是代理不可用/网络探针异常）：累加失败计数
                with _consec_fail_lock:
                    cur = _consec_fail_count.get(key, 0) + 1
                    _consec_fail_count[key] = cur
                cprint(f"[失败计数] {domain}({ip}) 当前连续失败: {cur}", 'debug')

                # 自动暂停检查（仅在未跳过写入时）
                if auto_pause_enabled and cur >= auto_pause_threshold and not skip_history2:
                    auto_pause_persist = CONFIG.get('auto_pause_persist', False)
                    with db.lock:
                        ip_obj2 = db._ip_map.get((domain, ip))
                        if ip_obj2:
                            ip_obj2['paused'] = True
                            ip_obj2['auto_paused'] = True  # 标记为自动暂停
                            db._active_ips.discard((domain, ip))
                            db._ip_map.pop((domain, ip), None)
                            # 只有当 auto_pause_persist 开启时才保存暂停状态到磁盘
                            if auto_pause_persist:
                                db._dirty_trackers.add(domain)  # 标记需要保存
                    pause_msg = (f"[自动暂停] {protocol.upper()}://{_wrap_ipv6(domain)}:{port} ({ip}) "
                                 f"累计失败 {cur} 次，已自动暂停监控"
                                 f"{'（重启后保持暂停）' if auto_pause_persist else '（重启后恢复）'}")
                    db.add_log(pause_msg, 'info')
                    cprint(pause_msg, 'info')
                    with _consec_fail_lock:
                        _consec_fail_count[key] = 0
                    # 如果配置了持久化，立即保存
                    if auto_pause_persist:
                        db._save_async()
                    next_wait = CONFIG.get('check_interval', 30)
                else:
                    # 根据重试模式计算下次等待时间
                    retry_mode = CONFIG.get('retry_mode')
                    if retry_mode == 'disabled':
                        # 重试已禁用，使用默认检查间隔
                        next_wait = CONFIG.get('check_interval', 30)
                    elif retry_mode == 'polling':
                        # 轮询模式：根据连续失败次数计算轮询等待时间（循环使用 5/15/30/60）
                        idx = (cur - 1) % len(POLLING_SEQUENCE)
                        next_wait = POLLING_SEQUENCE[idx]
                    else:
                        # 固定间隔模式
                        next_wait = float(CONFIG.get('retry_interval', 5.0))  # 支持小数
                    cprint(f"[下次等待] {domain}({ip}) 失败次数 {cur}，等待 {next_wait} 秒", 'debug')

            # 防御：确保等待时间至少为 1 秒，避免疯狂循环
            if next_wait <= 0:
                next_wait = 5
                cprint(f"[警告] next_wait 异常 ({next_wait})，强制设为 5 秒", 'error')

            check_time = datetime.now().isoformat()

            # ── 写历史（探针正常且失败率未超阈值才写）───────────────────────────
            if not skip_history2:
                db.update_status(domain, ip, status, lat, check_time, write_history=True)
                # 日志
                lat_s = f"{lat}ms" if lat >= 0 else "N/A"
                proto_s = protocol.upper()
                if status == 'online':
                    db.add_log(f"✓ {proto_s}://{_wrap_ipv6(domain)}:{port} ({ip}) {lat_s}", 'success')
                    cprint(f"✓ {proto_s}://{_wrap_ipv6(domain)}:{port} ({ip}) {lat_s}", 'success')
                else:
                    reason = f" | {err}" if err else ""
                    db.add_log(f"✗ {proto_s}://{_wrap_ipv6(domain)}:{port} ({ip}) 离线{reason}", 'error')
                    cprint(f"✗ {proto_s}://{_wrap_ipv6(domain)}:{port} ({ip}) 离线{reason}", 'error')
                # 归属地补查（异步执行，不阻塞探测线程）
                need_geo = False
                with db.lock:
                    ip_obj3 = db._ip_map.get((domain, ip))
                    if ip_obj3:
                        need_geo = ip_obj3.get('country', {}).get('country_code', 'XX') == 'XX'
                if need_geo:
                    # 异步执行归属地查询，避免阻塞探测线程
                    def _async_geo_update(domain, ip):
                        try:
                            new_geo = get_geo(ip)
                            if new_geo.get('country_code', 'XX') != 'XX':
                                with db.lock:
                                    ip_obj3 = db._ip_map.get((domain, ip))
                                    if ip_obj3:
                                        ip_obj3['country'] = new_geo
                        except Exception:
                            pass
                    _geo_executor.submit(_async_geo_update, domain, ip)
            else:
                # 网络故障，只更新状态不写历史
                db.update_status(domain, ip, status, lat, check_time, write_history=False)
                cprint(f"[跳过历史] {domain}({ip}) 探测完成但探针不可达({net_reason2})，历史不计入", 'debug')

        except Exception as e:
            cprint(f"[IP线程异常] {domain}({ip}): {type(e).__name__}: {e}", 'error')
            import traceback as _tb
            cprint(f"[IP线程异常] 调用栈:\n{_tb.format_exc()}", 'error')
            next_wait = CONFIG.get('check_interval', 30)
        except BaseException as e:
            cprint(f"[IP线程致命] {domain}({ip}): {type(e).__name__}: {e}", 'error')
            import traceback as _tb
            cprint(f"[IP线程致命] 调用栈:\n{_tb.format_exc()}", 'error')
            raise

        # 按照计算出的等待时间进入下一次循环
        stop_event.wait(timeout=next_wait)


def _dns_refresh_thread(name: str, domain: str, port: int, protocol: str,
                        stop_event: threading.Event, initial_delay: float = 0.0):
    """每个域名独立DNS刷新线程。
    - 启动时先睡 initial_delay 秒（错峰），之后每隔 check_interval 秒刷新一次 DNS。
    - 刷新后若出现新IP，自动启动对应的IP监控线程。
    - IP直连模式（domain是IP）则跳过，不做DNS查询。
    """
    is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain)) or (':' in domain and '.' not in domain)
    if is_ip:
        return  # IP 直连无需 DNS 线程

    if initial_delay > 0:
        stop_event.wait(timeout=initial_delay)
        if stop_event.is_set():
            return

    # 读取独立 DNS 刷新间隔
    dns_interval = CONFIG.get('dns_refresh_interval', CONFIG.get('check_interval', 30))

    while not stop_event.is_set():
        try:
            paused = False
            with db.lock:
                if name not in db.trackers:
                    break  # tracker 已删除
                paused = db.trackers[name].get('paused', False)

            if paused:
                stop_event.wait(timeout=dns_interval)
                continue

            # 网络探针检查：探针异常时跳过DNS查询，避免产生无效DNS请求
            # 注意：自定义DNS模式在 _query_single_server 层面按DNS服务器IP类型精细检查
            # 系统DNS/dnspython模式无法区分DNS服务器类型，使用全局检查
            dns_mode = CONFIG.get('dns_mode', 'system')
            if dns_mode != 'custom':
                skip_dns, dns_reason = _should_skip_dns_query()
                if skip_dns:
                    # 等待 probe_interval 后重试检查，与IP探测保持一致的响应速度
                    next_wait = CONFIG.get('probe_interval', 1)
                    stop_event.wait(timeout=next_wait)
                    continue

            new_ips, dns_skip = resolve(domain)
            
            # DNS跳过名单：按正常周期等待，不需要频繁重试
            if dns_skip == 'list':
                cprint(f"DNS跳过 {name} ({domain}): 在跳过名单中", 'debug')
                # 更新数据库标记跳过状态
                db.update_ips(name, [], dns_error=False, dns_skip=True)
                stop_event.wait(timeout=dns_interval)
                continue
            
            # 探针跳过：快速重试检查，避免长时间等待
            if dns_skip == 'probe':
                cprint(f"DNS跳过 {name} ({domain}): 探针异常，等待恢复", 'debug')
                # 不更新数据库（保留旧缓存和跳过状态）
                next_wait = CONFIG.get('probe_interval', 1)
                stop_event.wait(timeout=next_wait)
                continue
            
            db.update_ips(name, new_ips, dns_error=(not new_ips and not dns_skip), dns_skip=False)
            if new_ips:
                cprint(f"DNS刷新 {name} ({domain}): {len(new_ips)}个IP", 'debug')
                # 对新出现的IP自动启动独立监控线程
                _ensure_ip_threads(name)
        except Exception as e:
            try:
                db.update_ips(name, [], dns_error=True)
            except Exception:
                pass
            cprint(f"[DNS线程异常] {name}: {type(e).__name__}: {e}", 'debug')

        stop_event.wait(timeout=dns_interval)


def _ensure_ip_threads(name: str):
    """确保 tracker name 下所有活跃IP都有对应的监控线程，新增IP自动启动线程。"""
    with db.lock:
        td = db.trackers.get(name, {})
        if not td:
            return
        active_ips = [
            ip_obj.copy() for ip_obj in td.get('ips', [])
            if not ip_obj.get('removed') and not ip_obj.get('paused')
        ]

    for ip_obj in active_ips:
        ip = ip_obj.get('ip', '')
        if not ip:
            continue
        key = ('ip', name, ip)
        with _tracker_threads_lock:
            t = _tracker_threads.get(key)
            if t and t.is_alive():
                continue  # 线程已存在且活跃
            # 启动新线程（无错峰延迟，因为是新加入的IP）
            stop_ev = threading.Event()
            _tracker_stop_events[key] = stop_ev
            t = threading.Thread(
                target=_ip_monitor_thread,
                args=(name, ip, stop_ev, 0.0),
                daemon=True,
                name=f"mon-{name[:20]}-{ip}"
            )
            _tracker_threads[key] = t
            t.start()
            cprint(f"[线程启动] IP监控: {name}({ip})", 'debug')


def _stop_tracker_threads(name: str, ip: str = None):
    """停止指定 tracker（或其某个IP）的监控线程。
    ip=None 表示停止该 tracker 下所有线程（含DNS刷新线程）。
    """
    with _tracker_threads_lock:
        keys_to_stop = []
        for key in list(_tracker_threads.keys()):
            if ip is None:
                if key[1] == name:
                    keys_to_stop.append(key)
            else:
                if key == ('ip', name, ip):
                    keys_to_stop.append(key)

        for key in keys_to_stop:
            ev = _tracker_stop_events.get(key)
            if ev:
                ev.set()
            _tracker_threads.pop(key, None)
            _tracker_stop_events.pop(key, None)
            cprint(f"[线程停止] {key}", 'debug')


def _start_all_tracker_threads(max_workers: int = 120):
    """启动时为所有已加载的 tracker 创建线程，带随机错峰延迟。
    目标：把 N 个 tracker 的首次探测和DNS查询均匀分散到 check_interval 秒内，
    避免启动时一次性大量并发。
    """
    check_interval = CONFIG.get('check_interval', 30)
    with db.lock:
        all_trackers = {k: v for k, v in db.trackers.items()}

    domain_count = len(all_trackers)
    if domain_count == 0:
        cprint(f"[并发限制] 最大并发探测线程数: {max_workers}", 'info')
        return

    # 为每个域名分配一个固定偏移槽，错峰启动
    # 均匀分布在 [0, check_interval) 秒内
    domain_list = list(all_trackers.keys())
    random.shuffle(domain_list)  # 随机打乱避免每次启动顺序一样

    for idx, name in enumerate(domain_list):
        td = all_trackers[name]
        domain   = td.get('domain', name)
        port     = td.get('port', 80)
        protocol = td.get('protocol', 'tcp')

        dns_interval = CONFIG.get('dns_refresh_interval', CONFIG.get('check_interval', 30))
        # DNS 线程的错峰延迟使用 dns_interval，让 DNS 查询均匀散布在 dns_interval 秒内
        dns_initial_delay = (idx / max(domain_count, 1)) * dns_interval
        # 均匀错峰：每个域名的启动延迟在 [0, check_interval) 内均匀分布
        initial_delay = (idx / max(domain_count, 1)) * check_interval

        # 启动 DNS 刷新线程（域名有效时）
        is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain)) or (':' in domain and '.' not in domain)
        if not is_ip:
            dns_key = ('dns', name)
            with _tracker_threads_lock:
                if dns_key not in _tracker_threads or not _tracker_threads[dns_key].is_alive():
                    stop_ev = threading.Event()
                    _tracker_stop_events[dns_key] = stop_ev
                    t = threading.Thread(
                        target=_dns_refresh_thread,
                        args=(name, domain, port, protocol, stop_ev, dns_initial_delay),
                        daemon=True,
                        name=f"dns-{name[:30]}"
                    )
                    _tracker_threads[dns_key] = t
                    t.start()

        # 启动所有IP的独立监控线程
        active_ips = [
            ip_obj for ip_obj in td.get('ips', [])
            if not ip_obj.get('removed')
        ]
        ip_count = len(active_ips)
        for ip_idx, ip_obj in enumerate(active_ips):
            ip = ip_obj.get('ip', '')
            if not ip:
                continue
            key = ('ip', name, ip)
            with _tracker_threads_lock:
                if key in _tracker_threads and _tracker_threads[key].is_alive():
                    continue
                # IP内部再细分错峰：同一域名下多IP均匀分布在该域名的时间槽内
                if ip_count > 1:
                    slot = check_interval / domain_count
                    ip_delay = initial_delay + (ip_idx / ip_count) * slot
                else:
                    ip_delay = initial_delay

                stop_ev = threading.Event()
                _tracker_stop_events[key] = stop_ev
                t = threading.Thread(
                    target=_ip_monitor_thread,
                    args=(name, ip, stop_ev, ip_delay),
                    daemon=True,
                    name=f"mon-{name[:20]}-{ip}"
                )
                _tracker_threads[key] = t
                t.start()

    cprint(f"[并发限制] 最大并发探测线程数: {max_workers}", 'info')
    cprint(f"[监控启动] 共 {domain_count} 个tracker，已启动独立线程，"
           f"错峰分布在 {check_interval}s 内", 'info')


# 旧的 monitor_loop 保留为存根（启动脚本引用），实际功能已迁移到独立线程
# 这里只做线程清理/健康检查（死线程重启）
def _periodic_save_loop():
    """定时保存线程：每120秒将数据持久化到磁盘。
    - history.json.append: 只追加探测历史（不合并，合并在启动时进行）
    - data.json: 只在配置变化时保存（添加/删除/暂停/恢复）
    彻底消除因频繁写磁盘导致的高 I/O 问题。
    """
    while True:
        save_interval = CONFIG.get('save_interval', 120)
        time.sleep(save_interval)          # 保存到硬盘的间隔（可配置）
        try:
            if CONFIG.get('cache_history', True):
                # 只追加到 .append 文件（合并在启动时进行）
                hdb.save()
                # 如果有配置变化，保存 data.json
                if len(db._dirty_trackers) > 0:
                    db._save_async()
        except Exception as e:
            cprint(f"[定时保存] 异常: {e}", 'error')


def monitor_loop():
    """监控管理线程：定期检查死线程并重启，启动所有独立监控线程，不再做轮询探测。"""
    global _probe_semaphore
    db.add_log("监控服务启动（独立线程模式）", 'info')
    cprint("监控服务启动（独立线程模式）", 'info')
    # 初始化并发探测信号量
    max_workers = CONFIG.get('monitor_workers', 120)
    _probe_semaphore = threading.Semaphore(max_workers)
    _stats_thread_info['max_probes'] = max_workers
    # 传递给启动函数，让日志输出顺序更合理
    _start_all_tracker_threads(max_workers)
    _check_now.set()

    # 启动定时保存线程（60秒一次，替代每次探测后立即保存）
    save_t = threading.Thread(target=_periodic_save_loop, daemon=True, name="periodic-save")
    save_t.start()

    while True:
        try:
            # 每分钟检查一次死线程并重启
            time.sleep(60)
            _restart_dead_threads()
        except Exception as e:
            cprint(f"监控管理线程错误: {type(e).__name__}: {e}", 'error')


def _restart_dead_threads():
    """检查并重启死掉的监控线程（线程崩溃后自动恢复）。"""
    dead = []
    with _tracker_threads_lock:
        for key, t in _tracker_threads.items():
            if not t.is_alive():
                dead.append(key)

    if not dead:
        return

    cprint(f"[线程恢复] 发现 {len(dead)} 个死线程，正在重启...", 'debug')
    for key in dead:
        kind = key[0]
        name = key[1]
        with db.lock:
            td = db.trackers.get(name)
            if not td:
                with _tracker_threads_lock:
                    _tracker_threads.pop(key, None)
                    _tracker_stop_events.pop(key, None)
                continue

        if kind == 'ip':
            ip = key[2]
            with _tracker_threads_lock:
                stop_ev = threading.Event()
                _tracker_stop_events[key] = stop_ev
                t = threading.Thread(
                    target=_ip_monitor_thread,
                    args=(name, ip, stop_ev, 0.0),
                    daemon=True,
                    name=f"mon-{name[:20]}-{ip}"
                )
                _tracker_threads[key] = t
                t.start()
            cprint(f"[线程恢复] IP监控线程重启: {name}({ip})", 'debug')
        elif kind == 'dns':
            with db.lock:
                td = db.trackers.get(name, {})
                domain   = td.get('domain', name)
                port     = td.get('port', 80)
                protocol = td.get('protocol', 'tcp')
            with _tracker_threads_lock:
                stop_ev = threading.Event()
                _tracker_stop_events[key] = stop_ev
                t = threading.Thread(
                    target=_dns_refresh_thread,
                    args=(name, domain, port, protocol, stop_ev, 0.0),
                    daemon=True,
                    name=f"dns-{name[:30]}"
                )
                _tracker_threads[key] = t
                t.start()
            cprint(f"[线程恢复] DNS刷新线程重启: {name}", 'debug')

# ==================== 请求日志中间件 ====================
# 批量请求去重：记录最近一次页面请求的时间戳，短时间内的 API 批量请求只打印一行摘要
_last_page_request = {'time': 0, 'remote': '', 'logged': False}
_page_req_lock = threading.Lock()

@app.before_request
def log_request():
    """记录初始化批量加载提示（仅在页面首次加载时）"""
    g.req_start = datetime.now()  # 记录请求接收时间，供 after_request 使用
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
    is_debug_mode = CONFIG.get('console_log_level') == 'debug' or getattr(app, 'debug', False)
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
    now_str   = getattr(g, 'req_start', datetime.now()).strftime('%d/%b/%Y:%H:%M:%S +0800')
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

    # 重试结果延迟打印：在 nginx 日志之后输出，保证顺序：操作信息→nginx日志→重试结果
    for _log_msg in getattr(g, 'deferred_retry_logs', []):
        cprint(_log_msg, 'info', raw=True)

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
      net    = all | tcp | udp | http | https  (default: all)   protocol filter
      ip     = all | ipv4 | ipv6    (default: all)   IP version filter
      url    = any string            (default: /announce) URL suffix per entry
      name   = any string            (default: empty) 对于IP地址域名额外附加名称版URL

    Examples:
      curl http://host/api/tracker
      curl "http://host/api/tracker?day=7d&uptime=90"
      curl "http://host/api/tracker?day=30d&uptime=90&net=tcp&ip=ipv4"
      curl "http://host/api/tracker?day=30d&uptime=90&ip=ipv6"
      curl "http://host/api/tracker?uptime=90&net=udp&ip=ipv4&url=/announce"
      curl "http://host/api/tracker?name=1"  # IP域名tracker同时导出名称版
    """
    period     = request.args.get('day', '24h')
    if period not in ('24h','7d','30d'): period = '24h'
    min_uptime = request.args.get('uptime', 0, type=float)
    proto      = request.args.get('net', 'all').lower()
    ip_ver     = request.args.get('ip', 'all').lower()
    name_param = 'name' in request.args  # &name 存在即生效，无需赋值
    suffix_raw = request.args.get('url', None)
    if suffix_raw is None:
        suffix = CONFIG.get('export_suffix', '/announce')
    else:
        # 允许传 "announce" 自动补斜杠，或传 "" 表示无后缀
        suffix = ('/' + suffix_raw.lstrip('/')) if suffix_raw else ''
    ranking = db.get_ranking(period, 9999, min_uptime)
    lines = []
    with db.lock:
        for item in ranking:
            name     = item['name']    # 外层key(备注)，用于查 trackers
            domain   = item['domain']  # 实际连接地址，用于拼 URL
            td       = db.trackers.get(name, {})
            protocol = td.get('protocol', 'tcp')
            port     = td.get('port', 80)
            # 直接过滤在线IP，避免创建完整列表
            has_online = False
            if ip_ver == 'all':
                # 不需要版本过滤时，只要有一个在线IP即可
                for ip_obj in td.get('ips', []):
                    if not ip_obj.get('removed') and not ip_obj.get('paused') and ip_obj.get('status') == 'online':
                        has_online = True
                        break
            else:
                # 需要版本过滤
                for ip_obj in td.get('ips', []):
                    if not ip_obj.get('removed') and not ip_obj.get('paused') and ip_obj.get('status') == 'online' and ip_obj.get('version', 'ipv4') == ip_ver:
                        has_online = True
                        break
            if not has_online:
                continue
            if proto != 'all':
                is_udp   = (protocol == 'udp')
                is_https = (protocol == 'https')
                is_http  = not is_udp and not is_https
                if proto == 'udp'   and not is_udp:            continue
                if proto == 'tcp'   and is_udp:                continue  # TCP含HTTP+HTTPS
                if proto == 'https' and not is_https:          continue
                if proto == 'http'  and (is_udp or is_https):  continue
            scheme = 'udp' if protocol == 'udp' else ('https' if protocol == 'https' else 'http')
            url = f"{scheme}://{_wrap_ipv6(domain)}:{port}{suffix}"
            lines.append(url)
            # &name: 当domain为纯IP时，额外附加名称版URL
            if name_param and name != domain:
                is_ip = ':' in domain or bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
                if is_ip:
                    name_url = f"|{scheme}://{name}:{port}{suffix}"
                    lines.append(name_url)
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
        try:
            interval = CONFIG.get('cleanup_interval', 3600)
            time.sleep(interval)
            now = time.time()
            cleaned = {}

            # 清理 _rate_limit_store：删除空列表条目
            with _rate_limit_lock:
                before = len(_rate_limit_store)
                expired = [ip for ip, ts in list(_rate_limit_store.items()) if not ts]
                for ip in expired:
                    _rate_limit_store.pop(ip, None)
                cleaned['rate_limit_store'] = before - len(_rate_limit_store)

            # 清理 _rate_limit_warned：超过2倍间隔未再触发的IP
            with _rate_limit_warned_lock:
                before = len(_rate_limit_warned)
                expired = [ip for ip, t in list(_rate_limit_warned.items()) if now - t > interval * 2]
                for ip in expired:
                    _rate_limit_warned.pop(ip, None)
                cleaned['rate_limit_warned'] = before - len(_rate_limit_warned)

            # 清理 _login_fail：锁定已到期的条目
            with _login_fail_lock:
                before = len(_login_fail)
                expired = [ip for ip, rec in list(_login_fail.items())
                           if rec[1] < now and now - rec[1] > interval]
                for ip in expired:
                    _login_fail.pop(ip, None)
                cleaned['login_fail'] = before - len(_login_fail)

            # 清理 _retry_throttle：超过1小时未操作的用户
            with _retry_throttle_lock:
                before = len(_retry_throttle)
                expired = [u for u, t in list(_retry_throttle.items()) if now - t > 3600]
                for u in expired:
                    _retry_throttle.pop(u, None)
                cleaned['retry_throttle'] = before - len(_retry_throttle)

            # 清理 _query_rate：删除空列表条目
            with _query_rate_lock:
                before = len(_query_rate)
                expired = [ip for ip, ts in list(_query_rate.items()) if not ts]
                for ip in expired:
                    _query_rate.pop(ip, None)
                cleaned['query_rate'] = before - len(_query_rate)

            total = sum(cleaned.values())
            if total > 0:
                cprint(f"[cleanup] 限流内存清理完成，共清除 {total} 条过期记录: {cleaned}", 'info')
        except Exception as e:
            # 兜底保护：清理线程异常不应影响主监控流程
            cprint(f"[cleanup] 清理线程异常: {e}", 'error')
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
        net_bad     = _net_bad
        probe_v4_ok = _probe_ok_v4
        probe_v6_ok = _probe_ok_v6
    s['net_probe_v4_ok'] = probe_v4_ok   # None=未配置, True/False=有结果
    s['net_probe_v6_ok'] = probe_v6_ok   # None=未配置, True/False=有结果
    s['net_healthy']     = not net_bad   # True=全局网络正常（失败率未超阈值）
    s['probe_details']   = _probe_details  # {ip: {ok, latency, version}}
    # 从缓存获取失败率
    with _health_cache_lock:
        s['net_fail_rate'] = _health_cache.get('fail_rate')
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
            ips, dns_skip = resolve(host)
            if dns_skip:
                errors.append(f"域名 {host} 在DNS跳过名单中，无法添加"); continue
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
        msg = f"添加 {protocol.upper()}://{_wrap_ipv6(host)}:{port} 解析{len(ips)}个IP"
        db.add_log(f"{masked_ip} [{op_user}] {msg}", 'info')   # 脱敏后写入日志
        g.access_note = f"add {protocol.upper()}://{_wrap_ipv6(host)}:{port} ({len(ips)} IPs) by {raw_ip} [{op_user}]"
        # 为新增 tracker 启动独立监控线程（含DNS刷新和所有IP的探测线程）
        def _start_new_tracker(name=host, domain=host, prt=port, proto=protocol):
            time.sleep(0.3)  # 短暂延迟，等 add_tracker 落库完成
            is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain)) or (':' in domain and '.' not in domain)
            if not is_ip:
                dns_key = ('dns', name)
                with _tracker_threads_lock:
                    stop_ev = threading.Event()
                    _tracker_stop_events[dns_key] = stop_ev
                    t = threading.Thread(
                        target=_dns_refresh_thread,
                        args=(name, domain, prt, proto, stop_ev, 0.0),
                        daemon=True, name=f"dns-{name[:30]}"
                    )
                    _tracker_threads[dns_key] = t
                    t.start()
            _ensure_ip_threads(name)
        threading.Thread(target=_start_new_tracker, daemon=True).start()
        results.append({'domain':host,'port':port,'protocol':protocol,'ip_count':len(ips)})
    if not results and errors:
        return jsonify({'error':'; '.join(errors)}), 400
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
            db._dirty_trackers.add(domain)  # 标记需要保存（删除场景：_save 据此从 data.json 移除该域名）
            db._save_async()
            raw_ip = _client_ip()
            masked_ip = _anonymize_ip(raw_ip)
            op_user = session.get('username', '?')
            msg = f"删除 {domain}"
            db.add_log(f"{masked_ip} [{op_user}] {msg}", 'info')   # 脱敏后写入日志
            g.access_note = f"delete {domain} by {raw_ip} [{op_user}]"
            # 停止该tracker的所有监控线程
            _stop_tracker_threads(domain)
            return jsonify({'success':True})
    return jsonify({'error':'不存在'}), 404

@app.route('/api/tracker/pause', methods=['POST'])
@_require_role('admin', 'operator')
@csrf_protect
def api_pause():
    """暂停/恢复监控。支持：整个域名、域名下单个IP、全部域名。
    精简模式：有字段=真（暂停），无字段=假（正常）
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
                if paused:
                    td['paused'] = True
                else:
                    td.pop('paused', None)
                for ip_obj in td.get('ips', []):
                    if paused:
                        ip_obj['paused'] = True
                    else:
                        ip_obj.pop('paused', None)
                    key = (d, ip_obj.get('ip'))
                    if paused:
                        db._active_ips.discard(key)
                        db._ip_map.pop(key, None)
                    else:
                        if not ip_obj.get('removed'):
                            db._active_ips.add(key)
                            db._ip_map[key] = ip_obj
                db._dirty_trackers.add(d)  # 标记需要保存
                changed.append(d)
        elif domain and ip:
            # 单个 IP
            td = db.trackers.get(domain)
            if not td:
                return jsonify({'error': '域名不存在'}), 404
            # 先从 _ip_map 查找（快速路径）
            ip_obj = db._ip_map.get((domain, ip))
            if not ip_obj:
                # 如果 _ip_map 中找不到（可能已暂停），遍历查找
                for ip_obj2 in td.get('ips', []):
                    if ip_obj2.get('ip') == ip:
                        ip_obj = ip_obj2
                        break
            if ip_obj:
                # （用于重启时区分暂停和自动暂停）
                if paused:
                    ip_obj['paused'] = True
                else:
                    ip_obj.pop('paused', None)
                    ip_obj.pop('auto_paused', None)  # 恢复时删除标记
                key = (domain, ip)
                if paused:
                    db._active_ips.discard(key)
                else:
                    if not ip_obj.get('removed'):
                        db._active_ips.add(key)
                        db._ip_map[key] = ip_obj
                db._dirty_trackers.add(domain)  # 标记需要保存
                changed.append(f"{domain}/{ip}")
        elif domain:
            # 整个域名
            td = db.trackers.get(domain)
            if not td:
                return jsonify({'error': '域名不存在'}), 404
            if paused:
                td['paused'] = True
            else:
                td.pop('paused', None)
            for ip_obj in td.get('ips', []):
                if paused:
                    ip_obj['paused'] = True
                else:
                    ip_obj.pop('paused', None)
                key = (domain, ip_obj.get('ip'))
                if paused:
                    db._active_ips.discard(key)
                    db._ip_map.pop(key, None)
                else:
                    if not ip_obj.get('removed'):
                        db._active_ips.add(key)
                        db._ip_map[key] = ip_obj
            db._dirty_trackers.add(domain)  # 标记需要保存
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

@app.route('/api/tracker/lock', methods=['POST'])
@_require_role('admin')
@csrf_protect
def api_lock():
    data = request.json or {}
    domain = (data.get('domain', '') or '').strip()
    ip = (data.get('ip', '') or '').strip()
    lock = data.get('lock', True)
    with db.lock:
        td = db.trackers.get(domain)
        if not td:
            return jsonify({'error': '域名不存在'}), 404
        ip_obj = None
        for ip_obj2 in td.get('ips', []):
            if ip_obj2.get('ip') == ip:
                ip_obj = ip_obj2
                break
        if not ip_obj:
            return jsonify({'error': 'IP不存在'}), 404
        
        if lock:
            # 锁定：删除 removed 标记，添加 lock 标记，paused 状态保持不变
            ip_obj.pop('removed', None)
            ip_obj['lock'] = True
            # 如果不是域名暂停，则添加到活跃IP
            if not td.get('paused'):
                key = (domain, ip)
                db._active_ips.add(key)
                db._ip_map[key] = ip_obj
        else:
            # 解锁：删除 lock 标记
            ip_obj.pop('lock', None)
            # 移除活跃IP（让DNS刷新来控制）
            key = (domain, ip)
            db._active_ips.discard(key)
            db._ip_map.pop(key, None)
        
        db._dirty_trackers.add(domain)
        db._save_async()
    
    label = '锁定' if lock else '解锁'
    target = f"{domain}/{ip}"
    raw_ip   = _client_ip()
    op_user  = session.get('username', '?')
    parts = raw_ip.split('.')
    if len(parts) == 4:
        masked_ip = f"{parts[0]}.*.*.{parts[3]}"
    else:
        segs = raw_ip.split(':')
        if len(segs) >= 3:
            masked_ip = f"{segs[0]}:{segs[1]}:****:{segs[-1]}"
        else:
            masked_ip = raw_ip
    console_str = f"{raw_ip} [{op_user}] {label}: {target}"
    web_str     = f"{masked_ip} [{op_user}] {label}: {target}"
    g.access_note = f"{label} {target} by {raw_ip} [{op_user}]"
    print(f"[LOCK] {console_str}")
    db.add_log(web_str, 'info')
    return jsonify({'success': True, 'lock': lock})

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
    # 操作者信息
    raw_ip   = _client_ip()
    op_user  = session.get('username', '?')
    parts = raw_ip.split('.')
    if len(parts) == 4:
        masked_ip = f"{parts[0]}.*.*.{parts[3]}"
    else:
        segs = raw_ip.split(':')
        if len(segs) >= 3:
            masked_ip = f"{segs[0]}:{segs[1]}:****:{segs[-1]}"
        else:
            masked_ip = raw_ip
    target = f"{domain}/{target_ip}" if target_ip else domain
    # Web 日志：重试操作记录（脱敏IP），在重试结果之前
    web_str = f"{masked_ip} [{op_user}] 重试: {target}"
    db.add_log(web_str, 'info')
    with db.lock:
        if domain not in db.trackers:
            return jsonify({'error':'不存在'}), 404
        port     = db.trackers[domain].get('port', 80)
        protocol = db.trackers[domain].get('protocol','tcp')
        ips_snap = list(db.trackers[domain]['ips'])
    results = []
    # 重试结果延迟到 after_request（nginx日志之后）打印，保证顺序：操作信息→nginx日志→重试结果
    g.deferred_retry_logs = []
    for ipi in ips_snap:
        # 已暂停的IP固定跳过；已移除但未锁定的IP也跳过（锁定的IP必须重试）
        if ipi.get('paused'): continue
        if ipi.get('removed') and not ipi.get('lock'): continue
        if target_ip and ipi['ip'] != target_ip: continue
        status, lat, err = check_ip(domain, ipi, retry=False)
        lat_s = f"{lat}ms" if lat>=0 else "N/A"
        now = datetime.now()
        ts = f"{now.year}/{now.month}/{now.day} {now.strftime('%H:%M:%S')}"
        if status == 'skipped':
            reason_clean = err.replace(_PROXY_UNAVAIL_PREFIX, '') if err else ''
            res_msg = f"重试结果: {protocol.upper()}://{_wrap_ipv6(domain)}:{port} ({ipi['ip']}) → 跳过(代理不可用) | {reason_clean}"
        else:
            reason = f" | {err}" if err and status=='offline' else ""
            res_msg = f"重试结果: {protocol.upper()}://{_wrap_ipv6(domain)}:{port} ({ipi['ip']}) → {status} {lat_s}{reason}"
        g.deferred_retry_logs.append(f"{ts} [INFO] {res_msg}")
        db.add_log(res_msg, 'info')
        results.append({'ip':ipi['ip'],'status':status,'latency':lat,'error':err})
    g.access_note = f"重试 {target} by {raw_ip} [{op_user}]"
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
      name      = any string       (默认空) 对于IP地址域名额外附加名称版URL
    """
    period     = request.args.get('period', '24h')
    if period not in ('24h','7d','30d'): period = '24h'
    min_uptime = request.args.get('min_uptime', 0, type=float)
    proto      = request.args.get('proto', 'all').lower()      # tcp | udp | all
    ip_ver     = request.args.get('ip_ver', 'all').lower()     # ipv4 | ipv6 | all
    name_param = 'name' in request.args  # &name 存在即生效，无需赋值
    suffix     = request.args.get('suffix', CONFIG.get('export_suffix', '/announce'))
    ranking = db.get_ranking(period, 9999, min_uptime)
    with db.lock:
        trackers_snap = {k: dict(v) for k, v in db.trackers.items()}
    lines = []
    for item in ranking:
        name     = item['name']    # 外层key(备注)，用于查 trackers
        domain   = item['domain']  # 实际连接地址，用于拼 URL
        td       = trackers_snap.get(name, {})
        protocol = td.get('protocol', 'tcp')
        port     = td.get('port', 80)
        ips      = td.get('ips', [])
        # 协议过滤
        is_udp   = (protocol == 'udp')
        is_https = (protocol == 'https')
        is_http  = not is_udp and not is_https
        if proto == 'tcp'   and is_udp:                continue  # TCP含HTTP+HTTPS
        if proto == 'udp'   and not is_udp:            continue
        if proto == 'https' and not is_https:          continue
        if proto == 'http'  and (is_udp or is_https):  continue
        # IP版本过滤（检查该域名下是否有符合版本的非暂停IP）
        if ip_ver != 'all':
            has_ver = any(ip.get('version') == ip_ver for ip in ips if not ip.get('removed') and not ip.get('paused'))
            if not has_ver: continue
        # 构造 URL
        if protocol == 'https':
            scheme = 'https'
        elif protocol == 'udp':
            scheme = 'udp'
        else:
            scheme = 'http'
        url = f"{scheme}://{_wrap_ipv6(domain)}:{port}{suffix}"
        lines.append(url)
        # &name: 当domain为纯IP时，额外附加名称版URL
        if name_param and name != domain:
            is_ip = ':' in domain or bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
            if is_ip:
                name_url = f"|{scheme}://{name}:{port}{suffix}"
                lines.append(name_url)
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
    # 优先精确匹配：外层key(备注)或 domain 字段(实际地址)均可匹配
    matched_key = None
    if host in all_tr:
        matched_key = host
    else:
        # 尝试通过 tr['domain'] 字段匹配（实际连接地址）
        for _k, _tr in all_tr.items():
            if _tr.get('domain', '') == host:
                matched_key = _k
                break
    if matched_key is not None:
        matched_tr = all_tr[matched_key]
        host = matched_key  # 统一用key作为标识
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
            active_ip_set = {
                ip.get('ip','') for ip in matched_tr.get('ips', [])
                if not ip.get('paused') and not ip.get('removed')
            }
            s = hdb.get_domain_summary(host, secs, 
                                       excluded_ips=paused_set if paused_set else None,
                                       included_ips=active_ip_set if active_ip_set else None)
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
            #if ipi.get('removed') or ipi.get('paused'): #过滤 已暂停的域名
            if ipi.get('removed'):
                continue
            s_ip  = hdb.get_ip_summary(host, ipi.get('ip', ''), secs)
            up_ip = round(s_ip['ok'] / s_ip['total'] * 100, 1) if s_ip['total'] > 0 else None
            lat_i = ipi.get('latency', -1)
            # IP状态：暂停优先于原始状态
            ip_status = 'Paused' if ipi.get('paused') else ipi.get('status', 'unknown')
            row   = {
                'ip':      ipi.get('ip'),
                'version': ipi.get('version', 'ipv4'),
                'status':  ip_status,
                'latency': lat_i,
                'uptime':  up_ip,
                'paused':  ipi.get('paused', False),
                'auto_paused': ipi.get('auto_paused', False),
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
    req_limit = request.args.get('limit', 300, type=int)
    level = request.args.get('level', 'all').lower()
    if level not in ('all', 'info', 'success', 'error'):
        level = 'all'

    # 从 CONFIG 读取该级别的内存上限
    if level == 'all':
        max_limit = max(
            CONFIG.get('max_log_info', 1000),
            CONFIG.get('max_log_success', 1000),
            CONFIG.get('max_log_error', 1000)
        )
    elif level == 'info':
        max_limit = CONFIG.get('max_log_info', 1000)
    elif level == 'success':
        max_limit = CONFIG.get('max_log_success', 1000)
    elif level == 'error':
        max_limit = CONFIG.get('max_log_error', 1000)
    else:
        max_limit = 1000

    ABS_MAX = 100000  # 绝对上限，10万条日志
    limit = min(req_limit, max_limit, ABS_MAX)    # 取最小值，最终 limit 不超过配置上限
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

@app.route('/api/stats/threads', methods=['GET'])
@_require_role('admin', 'operator', 'viewer')
def api_stats_threads():
    """返回当前探测线程统计信息"""
    try:
        with _probe_active_lock:
            active = _stats_thread_info['active_probes']
        max_probes = _stats_thread_info['max_probes']
        with db.lock:
            total_active_ips = len(db._active_ips)
        return jsonify({
            'active_probes': active,
            'max_probes': max_probes,
            'total_active_ips': total_active_ips,
            'available_slots': max(0, max_probes - active)
        })
    except Exception as e:
        app.logger.error('[stats/threads] 查询失败: %s', e, exc_info=True)
        return jsonify({'error': '查询失败'}), 500

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
                domain_changed = False
                for i in range(len(td['ips'])-1, -1, -1):
                    if td['ips'][i].get('removed'):
                        td['ips'].pop(i)
                        cleared += 1
                        domain_changed = True
                if domain_changed:
                    db._dirty_trackers.add(domain)  # 标记需要保存
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
        # 自动从 DEFAULT_CONFIG 获取所有配置键，避免重复定义
        keys = list(DEFAULT_CONFIG.keys())
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
            'dns_skip_domains':      'DNS跳过域名名单',
            'log_to_disk':           '日志存盘',
            'log_level':             '日志级别',
            'console_log_level':     '控制台日志级别',
            'debug_save_trace':      '保存调试日志',
            'save_interval':         '存盘间隔',
            'console_error_log':     '控制台Error日志',
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
            'dns_timeout':           'DNS查询超时',
            'dns_lb_enabled':        'DNS负载均衡',
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
            'probe_fail_threshold':  '网络故障失败率阈值',
            'probe_ipv6_targets':    'IPv6探针目标',
            'probe_timeout':         '探针超时',
            'probe_ipv4_targets':    'IPv4探针目标',
            'probe_interval':        '探测周期',
            'probe_mode':            '探测模式',
            'probe_fine_check_enabled': '精细探针检查',
            'auto_pause_enabled':    '自动暂停开关',
            'auto_pause_threshold':  '自动暂停累计失败次数',
            'auto_pause_persist':    '重启保持自动暂停',
        }
        suffixes = {
            'check_interval': 's', 'timeout': 's', 'retry_interval': 's', 'dns_timeout': 's',
            'page_refresh_ms': 'ms', 'stagger_delay_proxy': 'ms', 'stagger_delay_direct': 'ms',
            'save_interval': 's', 'probe_interval': 's',
        }
        bool_fmt = {True: '开', False: '关'}
        changes = []
        for k in keys:
            if k not in data: continue
            old_val = CONFIG.get(k)
            new_val = data[k]
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
        if any(k in data and data[k] != CONFIG.get(k) for k in proxy_changed_keys):
            _socks5_pool.invalidate()
            cprint('[SOCKS5Pool] 代理配置变更，连接池已重置', 'debug')
        # 如果并发检测数变化，更新信号量
        if 'monitor_workers' in data and data['monitor_workers'] != CONFIG.get('monitor_workers'):
            global _probe_semaphore
            max_workers = data['monitor_workers']
            _probe_semaphore = threading.Semaphore(max_workers)
            _stats_thread_info['max_probes'] = max_workers
            cprint(f'[并发限制] 最大并发探测线程数更新为: {max_workers}', 'info')
        if changes:
            msg = f"配置已更新: {' | '.join(changes)}"
            g.access_note = msg
        result = {k: CONFIG[k] for k in keys}
        return jsonify({'success':True,'config':result})
    # GET 读取配置：未登录只返回前端行为控制必要字段（不含账户/代理等敏感信息）
    # 已登录用户额外返回运维相关字段（仍不含账户信息）
    public_keys = ['page_refresh_ms', 'tab_switch_refresh', 'uptime_algorithm', 'dashboard_stat_period', 'tracker_stat_period', 'show_removed_ips', 'default_layout_width', 'allow_private_ips', 'min_password_length']
    if not session.get('role'):
        return jsonify({k: CONFIG.get(k) for k in public_keys})
    # 自动从 DEFAULT_CONFIG 获取所有配置键，避免重复定义
    all_keys = list(DEFAULT_CONFIG.keys())
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
    # 加载 data.json，获取被修改的 tracker 列表和移除数量
    load_result = db.load()
    modified_trackers = set()
    total_removed = 0
    if isinstance(load_result, tuple):
        success, modified_trackers, total_removed = load_result
    else:
        success = load_result
    # 加载 history.json（必须在 data.json 之后，因为需要 tracker 列表）
    hdb.load()
    db._cleanup_hdb_on_startup()   # 清理已移除IP和domain级的hdb key
    # 在 hdb 加载完成后，保存修改过的 tracker（此时 hdb 已就绪，可以正确计算历史统计）
    if modified_trackers:
        if total_removed > 0:
            msg = f"[load] 共清理 {total_removed} 个已移除IP，恢复 {len(modified_trackers)} 个自动暂停IP，保存 data.json"
        else:
            msg = f"[load] 恢复 {len(modified_trackers)} 个自动暂停IP，保存 data.json"
        cprint(msg, 'info')
        for d in modified_trackers:
            db._dirty_trackers.add(d)  # 标记需要保存
        db._save_async()
    db.add_log("网络监控服务启动", 'info')

    def _get_geo_force(ip: str) -> dict:
        """强制查询 IP 归属地，跳过缓存，并更新缓存（用于批量刷新）"""
        result = {'country':'Unknown', 'country_code':'XX', 'isp':'Unknown'}
        # SSRF防护：仅对公网IP发起查询
        if not _is_safe_public_ip(ip):
            with _geo_cache_lock:
                _geo_cache.put(ip, result)
            return result
        try:
            import urllib.parse
            safe_ip = urllib.parse.quote(ip, safe=':.[]')
            s = _get_geo_session()
            # 不用 with：stream=False 时 urllib3 读完响应体后自动归还连接到池子。
            # with response 的 __exit__ 会调 r.close() 使连接被丢弃而非复用。
            r = s.get(
                f"http://ip-api.com/json/{safe_ip}?fields=country,countryCode,isp",
                timeout=5, stream=False
            )
            if r.status_code == 200:
                d = r.json()
                if d.get('countryCode') and d['countryCode'] != 'XX':
                    result = {'country': d.get('country','Unknown'),
                    'country_code': d.get('countryCode','XX'),
                    'isp': d.get('isp','Unknown')}
            # 更新缓存（无论成功与否，避免反复查询无法访问的IP）
            with _geo_cache_lock:
                _geo_cache.put(ip, result)
        except Exception:
            pass
        return result
    
    # ==================== 启动后 geo 更新线程 ====================
    def _geo_update_loop():
        """后台更新 IP 归属地信息（根据配置执行不同策略）"""
        try:
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

            # IP 去重：同一 IP 可能出现在多个 tracker 下，只查一次网络，
            # 查完后统一更新所有引用它的 tracker。
            seen_ips: set = set()
            deduped = []
            for domain, ip_obj in targets:
                ip = ip_obj.get('ip', '')
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    deduped.append((domain, ip_obj))
            targets = deduped

            cprint(f"[geo] 开始{mode}，共 {len(targets)} 个唯一 IP（间隔 0.8 秒，避免触发限流）", 'info')

            updated_count = 0
            for domain, ip_obj in targets:
                ip = ip_obj.get('ip', '')
                if not ip:
                    continue
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
                    old_cc = old_geo.get('country_code', 'XX') if isinstance(old_geo, dict) else 'XX'
                    new_cc = new_geo.get('country_code', 'XX')
                    # 如果不同，才更新所有引用该 IP 的 tracker
                    if old_cc != new_cc or (isinstance(old_geo, dict) and old_geo.get('isp') != new_geo.get('isp')):
                        with db.lock:
                            for td in db.trackers.values():
                                for obj in td.get('ips', []):
                                    if obj.get('ip') == ip:
                                        obj['country'] = new_geo
                                        updated_count += 1
                                        break
                        if updated_count % 10 == 0:
                            db._save_async()
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
        except Exception as e:
            cprint(f"[geo] 归属地更新线程异常退出: {e}", 'error')

    geo_repair_t = threading.Thread(target=_geo_update_loop, daemon=True)
    geo_repair_t.start()

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    # 注：monitor_loop 内部会调用 _start_all_tracker_threads()，无需手动触发

    # 启动时检查 ICMP 权限
    _check_icmp_permission()

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
    print(f"  日志级别       : {CONFIG.get('console_log_level', 'info')}")
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

        import errno as _errno
        import traceback as _tb
        from waitress import trigger as _waitress_trigger
        _orig_trigger_close = _waitress_trigger.trigger.close
        _trigger_close_stack = [None]
        def _patched_trigger_close(self):
            if not getattr(self, '_closed', False):
                import io as _io
                buf = _io.StringIO()
                _tb.print_stack(file=buf)
                _trigger_close_stack[0] = buf.getvalue()
                cprint(f"[诊断] trigger.close() 被调用，调用栈:\n{buf.getvalue()}", 'error')
            _orig_trigger_close(self)
        _waitress_trigger.trigger.close = _patched_trigger_close

        _orig_physical_pull = _waitress_trigger.trigger._physical_pull
        def _patched_physical_pull(self):
            try:
                _orig_physical_pull(self)
            except OSError as e:
                if getattr(e, 'winerror', None) in (_errno.WSAENOTSOCK,):
                    cprint(f"[诊断] trigger._physical_pull 触发 WSAENOTSOCK，_closed={getattr(self, '_closed', '?')}", 'error')
                    if _trigger_close_stack[0]:
                        cprint(f"[诊断] 上次 trigger.close 调用栈:\n{_trigger_close_stack[0]}", 'error')
                else:
                    raise
        _waitress_trigger.trigger._physical_pull = _patched_physical_pull
        
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