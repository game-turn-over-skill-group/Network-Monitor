# -*- coding: utf-8 -*-
"""
网络监控 - Network Monitor
Windows部署: pip install -r requirements.txt && python app.py
"""

import os
import sys
import json
import time
import socket
import struct
import threading
import random
import re
import traceback
from datetime import datetime
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import dns.resolver
import requests

# ==================== 配置文件持久化 ====================
CONFIG_FILE = 'network_monitor_config.json'

DEFAULT_CONFIG = {
    'port': 8443,
    'check_interval': 30,
    'timeout': 5,
    'retry_interval': 5,
    'log_to_disk': False,
    'log_file': 'network_monitor.log',
    'data_file': 'network_monitor_data.json',
    'max_history': 288,
    'http_proxy': '',
    'udp_proxy': '',
    'proxy_enabled': False,
}

def load_config():
    config = dict(DEFAULT_CONFIG)
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            for key in ['check_interval', 'timeout', 'retry_interval', 'log_to_disk',
                        'http_proxy', 'udp_proxy', 'proxy_enabled']:
                if key in saved:
                    config[key] = saved[key]
    except:
        pass
    return config

def save_config_to_disk(config):
    try:
        savable = {k: config[k] for k in ['check_interval', 'timeout', 'retry_interval',
                                            'log_to_disk', 'http_proxy', 'udp_proxy', 'proxy_enabled']}
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(savable, f, indent=2, ensure_ascii=False)
    except:
        pass

CONFIG = load_config()

app = Flask(__name__, static_folder='static')
CORS(app)

def get_proxy_session():
    if not CONFIG['proxy_enabled']:
        return None
    http_proxy = CONFIG.get('http_proxy', '')
    session = requests.Session()
    if http_proxy:
        session.proxies = {'http': http_proxy, 'https': http_proxy}
    return session

# ==================== 内存数据库 ====================
class TrackerDatabase:
    def __init__(self):
        self.lock = threading.RLock()
        self.trackers = {}
        self.logs = []
        self.stats = {'total': 0, 'alive': 0, 'ipv4': 0, 'ipv6': 0}
        self.last_update = None

    def add_tracker(self, domain, port, protocol, ip_list=None):
        with self.lock:
            if domain not in self.trackers:
                self.trackers[domain] = {
                    'domain': domain,
                    'port': port,
                    'protocol': protocol,
                    'ips': [],
                    'history_24h': [],
                    'history_7d': [],
                    'history_30d': [],
                    'added_time': datetime.now().isoformat()
                }
            else:
                self.trackers[domain]['port'] = port
                self.trackers[domain]['protocol'] = protocol

            if ip_list:
                existing_ips = {ip['ip'] for ip in self.trackers[domain]['ips']}
                for ip_info in ip_list:
                    if ip_info['ip'] not in existing_ips:
                        ip_info['status'] = 'unknown'
                        ip_info['latency'] = -1
                        ip_info['last_check'] = None
                        self.trackers[domain]['ips'].append(ip_info)

            self.stats['total'] = len(self.trackers)
            self._save_to_disk()

    def update_tracker_status(self, domain, ip, status, latency):
        with self.lock:
            if domain in self.trackers:
                for ip_info in self.trackers[domain]['ips']:
                    if ip_info['ip'] == ip:
                        ip_info['status'] = status
                        ip_info['latency'] = latency
                        ip_info['last_check'] = datetime.now().isoformat()
                        break
                self._update_history(domain, status)
                self._recalculate_stats()

    def _update_history(self, domain, status):
        tracker = self.trackers[domain]
        status_int = 1 if status == 'online' else 0
        tracker['history_24h'].append(status_int)
        if len(tracker['history_24h']) > CONFIG['max_history']:
            tracker['history_24h'].pop(0)
        tracker['history_7d'].append(status_int)
        if len(tracker['history_7d']) > 2016:
            tracker['history_7d'].pop(0)
        tracker['history_30d'].append(status_int)
        if len(tracker['history_30d']) > 8640:
            tracker['history_30d'].pop(0)

    def _recalculate_stats(self):
        total = alive = ipv4 = ipv6 = 0
        for domain, data in self.trackers.items():
            for ip_info in data['ips']:
                total += 1
                if ip_info['status'] == 'online':
                    alive += 1
                if ':' in ip_info['ip']:
                    ipv6 += 1
                else:
                    ipv4 += 1
        self.stats = {'total': total, 'alive': alive, 'ipv4': ipv4, 'ipv6': ipv6}
        self.last_update = datetime.now()

    def get_trackers(self):
        with self.lock:
            return dict(self.trackers)

    def get_stats(self):
        with self.lock:
            return dict(self.stats)

    def get_ranking(self, period='24h', limit=200, only_100=True):
        ranking = []
        with self.lock:
            for domain, data in self.trackers.items():
                if period == '24h':
                    history = data['history_24h']
                elif period == '7d':
                    history = data['history_7d']
                else:
                    history = data['history_30d']

                if not history:
                    uptime = 0.0
                else:
                    uptime = sum(history) / len(history) * 100

                if only_100 and uptime < 100.0:
                    continue

                ranking.append({
                    'domain': domain,
                    'port': data.get('port', 80),
                    'protocol': data.get('protocol', 'tcp'),
                    'uptime': round(uptime, 2),
                    'ip_count': len(data['ips']),
                    'period': period
                })

        ranking.sort(key=lambda x: (-x['uptime'], x['domain']))
        return ranking[:limit]

    def add_log(self, message, level='info'):
        log_entry = {
            'time': datetime.now().isoformat(),
            'level': level,
            'message': message
        }
        with self.lock:
            self.logs.append(log_entry)
            if len(self.logs) > 2000:
                self.logs.pop(0)
            if CONFIG['log_to_disk']:
                try:
                    with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
                        f.write(f"[{log_entry['time']}] [{level.upper()}] {message}\n")
                except:
                    pass

    def get_logs(self, limit=200):
        with self.lock:
            return list(self.logs[-limit:])

    def clear_logs(self):
        with self.lock:
            self.logs = []

    def _save_to_disk(self):
        try:
            data = {}
            with self.lock:
                for domain, tracker in self.trackers.items():
                    data[domain] = {
                        'domain': domain,
                        'port': tracker.get('port', 80),
                        'protocol': tracker.get('protocol', 'tcp'),
                        'ips': tracker['ips'],
                        'added_time': tracker['added_time']
                    }
            with open(CONFIG['data_file'], 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except:
            pass

    def load_from_disk(self):
        try:
            if os.path.exists(CONFIG['data_file']):
                with open(CONFIG['data_file'], 'r', encoding='utf-8') as f:
                    data = json.load(f)
                with self.lock:
                    for domain, tracker in data.items():
                        self.trackers[domain] = {
                            'domain': domain,
                            'port': tracker.get('port', 80),
                            'protocol': tracker.get('protocol', 'tcp'),
                            'ips': tracker['ips'],
                            'history_24h': [],
                            'history_7d': [],
                            'history_30d': [],
                            'added_time': tracker.get('added_time', datetime.now().isoformat())
                        }
                    self._recalculate_stats()
                return True
        except:
            pass
        return False

db = TrackerDatabase()

# ==================== 网络工具 ====================

def resolve_domain(domain):
    ips = []
    errors = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = CONFIG['timeout']
        resolver.lifetime = CONFIG['timeout']
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            geo = get_geo_info(ip)
            ips.append({'ip': ip, 'version': 'ipv4', 'country': geo})
    except Exception as e:
        errors.append(f"IPv4: {type(e).__name__}: {e}")

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = CONFIG['timeout']
        resolver.lifetime = CONFIG['timeout']
        answers = resolver.resolve(domain, 'AAAA')
        for rdata in answers:
            ip = str(rdata)
            geo = get_geo_info(ip)
            ips.append({'ip': ip, 'version': 'ipv6', 'country': geo})
    except Exception as e:
        errors.append(f"IPv6: {type(e).__name__}: {e}")

    if not ips and errors:
        db.add_log(f"DNS解析失败 {domain}: {'; '.join(errors)}", 'error')
    return ips

def get_geo_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp"
        session = get_proxy_session() if CONFIG['proxy_enabled'] else None
        resp = (session or requests).get(url, timeout=5)
        if resp.status_code == 200:
            d = resp.json()
            return {'country': d.get('country', 'Unknown'), 'country_code': d.get('countryCode', 'XX'), 'isp': d.get('isp', 'Unknown')}
    except:
        pass
    return {'country': 'Unknown', 'country_code': 'XX', 'isp': 'Unknown'}

def tcp_ping(ip, port=80):
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(CONFIG['timeout'])
        t = time.time()
        s.connect((ip, port))
        latency = int((time.time() - t) * 1000)
        s.close()
        return True, latency, None
    except socket.timeout:
        return False, -1, f"超时(>{CONFIG['timeout']}s)"
    except ConnectionRefusedError:
        return False, -1, "连接被拒绝"
    except OSError as e:
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        return False, -1, f"{type(e).__name__}: {e}"

def udp_ping(ip, port=80):
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(CONFIG['timeout'])
        packet = struct.pack('!QQL', 0x41727101980, 0, random.randint(0, 2**32 - 1))
        t = time.time()
        s.sendto(packet, (ip, port))
        try:
            data, _ = s.recvfrom(1024)
            latency = int((time.time() - t) * 1000)
            s.close()
            if len(data) >= 16 and struct.unpack('!L', data[0:4])[0] == 0:
                return True, latency, None
            return False, -1, "无效响应"
        except socket.timeout:
            s.close()
            return False, -1, f"超时(>{CONFIG['timeout']}s)"
    except OSError as e:
        return False, -1, f"网络错误: {e}"
    except Exception as e:
        return False, -1, f"{type(e).__name__}: {e}"

def parse_tracker_url(url):
    url = url.strip()
    # 纯 IP:port
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$', url)
    if m:
        return 'tcp', m.group(1), int(m.group(2))
    # 标准 scheme://host:port/path
    m = re.match(r'^(udp|http|https)://([^:/\s]+)(?::(\d+))?(?:/.*)?$', url, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        host = m.group(2)
        port = int(m.group(3)) if m.group(3) else (443 if scheme == 'https' else 80)
        return scheme, host, port
    return None, None, None

# ==================== 监控线程 ====================

def check_tracker_ip(domain, ip_info, retry=True):
    ip = ip_info['ip']
    with db.lock:
        td = db.trackers.get(domain, {})
        port = td.get('port', 80)
        protocol = td.get('protocol', 'tcp')

    if protocol == 'udp':
        ok, latency, err = udp_ping(ip, port)
    else:
        ok, latency, err = tcp_ping(ip, port)

    if not ok and retry:
        time.sleep(CONFIG['retry_interval'])
        if protocol == 'udp':
            ok, latency, err = udp_ping(ip, port)
        else:
            ok, latency, err = tcp_ping(ip, port)

    status_str = 'online' if ok else 'offline'
    db.update_tracker_status(domain, ip, status_str, latency)
    return status_str, latency, err

def monitor_worker():
    db.add_log("监控服务启动", 'info')
    while True:
        try:
            trackers = db.get_trackers()
            for domain, data in trackers.items():
                port = data.get('port', 80)
                protocol = data.get('protocol', 'tcp').upper()
                for ip_info in data['ips']:
                    try:
                        status, latency, err = check_tracker_ip(domain, ip_info, retry=True)
                        latency_str = f"{latency}ms" if latency >= 0 else "N/A"
                        if status == 'online':
                            db.add_log(f"✓ {domain}:{port} [{protocol}] ({ip_info['ip']}) {latency_str}", 'debug')
                        else:
                            reason = f" | {err}" if err else ""
                            db.add_log(f"✗ {domain}:{port} [{protocol}] ({ip_info['ip']}) 离线{reason}", 'error')
                    except Exception as e:
                        db.add_log(f"检查异常 {domain}:{port} ({ip_info['ip']}): {type(e).__name__}: {e}", 'error')
            s = db.get_stats()
            db.add_log(f"轮检完成 | 总:{s['total']} 在线:{s['alive']} v4:{s['ipv4']} v6:{s['ipv6']}", 'info')
        except Exception as e:
            db.add_log(f"监控线程错误: {type(e).__name__}: {e}", 'error')
        time.sleep(CONFIG['check_interval'])

# ==================== API ====================

def get_html_path():
    base = os.path.dirname(os.path.abspath(__file__))
    for p in [os.path.join(base, 'templates', 'index.html'), os.path.join(base, 'index.html')]:
        if os.path.exists(p):
            return p
    return None

@app.route('/')
def index():
    p = get_html_path()
    if not p:
        return "index.html not found. Place it in templates/ or same directory.", 404
    with open(p, 'r', encoding='utf-8') as f:
        content = f.read()
    return make_response(content, 200, {'Content-Type': 'text/html; charset=utf-8'})

@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())

@app.route('/api/trackers')
def api_trackers():
    return jsonify(db.get_trackers())

@app.route('/api/tracker/add', methods=['POST'])
def api_add_tracker():
    data = request.json
    raw = data.get('urls', data.get('url', ''))
    if not raw:
        return jsonify({'error': 'URL不能为空'}), 400

    lines = raw.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    results, errors = [], []

    for line in lines:
        line = line.strip()
        if not line or line.startswith('|'):
            continue

        scheme, domain, port = parse_tracker_url(line)
        if not domain:
            errors.append(f"无效格式: {line}")
            continue

        protocol = 'udp' if scheme == 'udp' else 'tcp'
        is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', domain)) or ':' in domain

        if is_ip:
            geo = get_geo_info(domain)
            version = 'ipv6' if ':' in domain else 'ipv4'
            ip_list = [{'ip': domain, 'version': version, 'country': geo}]
        else:
            ip_list = resolve_domain(domain)
            if not ip_list:
                errors.append(f"DNS解析失败: {domain}")
                continue

        db.add_tracker(domain, port, protocol, ip_list)
        db.add_log(f"添加 {domain}:{port} [{protocol.upper()}] 解析{len(ip_list)}个IP", 'info')

        def bg_check(d=domain):
            with db.lock:
                td = db.trackers.get(d, {})
                ips = list(td.get('ips', []))
            for ipi in ips:
                try:
                    check_tracker_ip(d, ipi, retry=False)
                except:
                    pass
        threading.Thread(target=bg_check, daemon=True).start()
        results.append({'domain': domain, 'port': port, 'protocol': protocol, 'ip_count': len(ip_list)})

    if not results and errors:
        return jsonify({'error': '; '.join(errors)}), 400

    return jsonify({'success': True, 'added': len(results), 'results': results, 'errors': errors})

@app.route('/api/tracker/delete', methods=['POST'])
def api_delete_tracker():
    data = request.json
    domain = data.get('domain', '').strip()
    with db.lock:
        if domain in db.trackers:
            del db.trackers[domain]
            db._recalculate_stats()
            db._save_to_disk()
            db.add_log(f"删除 {domain}", 'info')
            return jsonify({'success': True})
    return jsonify({'error': 'Tracker不存在'}), 404

@app.route('/api/tracker/check', methods=['POST'])
def api_check_tracker():
    data = request.json
    domain = data.get('domain', '').strip()
    target_ip = data.get('ip', None)

    with db.lock:
        if domain not in db.trackers:
            return jsonify({'error': 'Tracker不存在'}), 404
        port = db.trackers[domain].get('port', 80)
        protocol = db.trackers[domain].get('protocol', 'tcp')
        ips_copy = list(db.trackers[domain]['ips'])

    target_str = f" IP:{target_ip}" if target_ip else " 全部IP"
    db.add_log(f"手动重试: {domain}:{port} [{protocol.upper()}]{target_str}", 'info')

    results = []
    for ip_info in ips_copy:
        if target_ip and ip_info['ip'] != target_ip:
            continue
        status, latency, err = check_tracker_ip(domain, ip_info, retry=True)
        latency_str = f"{latency}ms" if latency >= 0 else "N/A"
        reason = f" | {err}" if err and status == 'offline' else ""
        db.add_log(f"重试: {domain}:{port} ({ip_info['ip']}) → {status} {latency_str}{reason}", 'info')
        results.append({'ip': ip_info['ip'], 'status': status, 'latency': latency, 'error': err})

    return jsonify({'success': True, 'domain': domain, 'port': port, 'protocol': protocol, 'results': results})

@app.route('/api/ranking/<period>')
def api_ranking(period):
    if period not in ['24h', '7d', '30d']:
        period = '24h'
    limit = request.args.get('limit', 200, type=int)
    only_100 = request.args.get('only100', 'true').lower() == 'true'
    ranking = db.get_ranking(period, limit, only_100=only_100)
    return jsonify({'period': period, 'ranking': ranking})

@app.route('/api/logs')
def api_logs():
    limit = request.args.get('limit', 200, type=int)
    return jsonify(db.get_logs(limit))

@app.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    db.clear_logs()
    return jsonify({'success': True})

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'POST':
        data = request.json
        for key in ['log_to_disk', 'check_interval', 'timeout', 'retry_interval',
                    'http_proxy', 'udp_proxy', 'proxy_enabled']:
            if key in data:
                CONFIG[key] = data[key]
        save_config_to_disk(CONFIG)
        db.add_log("配置已更新并持久化", 'info')
        return jsonify({'success': True, 'config': {k: CONFIG[k] for k in
                        ['check_interval', 'timeout', 'retry_interval', 'log_to_disk',
                         'http_proxy', 'udp_proxy', 'proxy_enabled']}})
    return jsonify({k: v for k, v in CONFIG.items() if k not in ['data_file', 'log_file']})

# ==================== 主程序 ====================
if __name__ == '__main__':
    db.load_from_disk()
    db.add_log("网络监控服务启动", 'info')

    t = threading.Thread(target=monitor_worker, daemon=True)
    t.start()

    print(f"\n{'='*55}")
    print(f"  网络监控 - Network Monitor")
    print(f"{'='*55}")
    print(f"  访问地址  : http://localhost:{CONFIG['port']}")
    print(f"  监控间隔  : {CONFIG['check_interval']}秒")
    print(f"  超时时间  : {CONFIG['timeout']}秒")
    print(f"  失败重试  : {CONFIG['retry_interval']}秒后")
    print(f"  磁盘日志  : {'开启' if CONFIG['log_to_disk'] else '关闭'}")
    print(f"  代理      : {'启用 ' + CONFIG.get('http_proxy','') if CONFIG['proxy_enabled'] else '关闭'}")
    print(f"{'='*55}")
    print(f"  index.html 放在 templates/ 目录或同级目录下")
    print(f"{'='*55}\n")

    try:
        from waitress import serve
        print("  使用 waitress 生产服务器 (无WARNING提示)\n")
        serve(app, host='0.0.0.0', port=CONFIG['port'], threads=8)
    except ImportError:
        print("  提示: pip install waitress 可消除开发服务器WARNING\n")
        app.run(host='0.0.0.0', port=CONFIG['port'], debug=False)