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
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_from_directory, make_response
from flask_cors import CORS
import dns.resolver
import requests

# ==================== 配置 ====================
app = Flask(__name__, static_folder='static')
CORS(app)

CONFIG = {
    'port': 443,
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
        """添加tracker，存储完整信息包含协议和端口"""
        with self.lock:
            if domain not in self.trackers:
                self.trackers[domain] = {
                    'domain': domain,
                    'port': port,
                    'protocol': protocol,  # 'tcp' or 'udp'
                    'ips': [],
                    'history_24h': [],
                    'history_7d': [],
                    'history_30d': [],
                    'added_time': datetime.now().isoformat()
                }
            else:
                # 更新端口和协议（如果重新添加）
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

    def get_ranking(self, period='24h', limit=100):
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
                    continue

                uptime = sum(history) / len(history) * 100
                if uptime >= 100.0:
                    ranking.append({
                        'domain': domain,
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
            if len(self.logs) > 1000:
                self.logs.pop(0)
            if CONFIG['log_to_disk']:
                try:
                    with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
                        f.write(f"[{log_entry['time']}] [{level.upper()}] {message}\n")
                except:
                    pass

    def get_logs(self, limit=100):
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

# 全局数据库
db = TrackerDatabase()

# ==================== 工具函数 ====================

def resolve_domain(domain):
    """解析域名获取所有IP (IPv4 + IPv6)"""
    ips = []
    try:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = CONFIG['timeout']
            resolver.lifetime = CONFIG['timeout']
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                geo = get_geo_info(ip)
                ips.append({
                    'ip': ip,
                    'version': 'ipv4',
                    'country': geo
                })
        except Exception:
            pass

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = CONFIG['timeout']
            resolver.lifetime = CONFIG['timeout']
            answers = resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                ip = str(rdata)
                geo = get_geo_info(ip)
                ips.append({
                    'ip': ip,
                    'version': 'ipv6',
                    'country': geo
                })
        except Exception:
            pass

    except Exception as e:
        db.add_log(f"DNS解析失败 {domain}: {str(e)}", 'error')

    return ips

def get_geo_info(ip):
    """获取IP地理位置和ISP信息，只调用一次API"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp"
        session = get_proxy_session() if CONFIG['proxy_enabled'] else None
        if session:
            response = session.get(url, timeout=CONFIG['timeout'])
        else:
            response = requests.get(url, timeout=CONFIG['timeout'])
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', 'XX'),
                'isp': data.get('isp', 'Unknown')
            }
    except:
        pass
    return {'country': 'Unknown', 'country_code': 'XX', 'isp': 'Unknown'}

def tcp_ping(ip, port=80):
    """TCP连接测试"""
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(CONFIG['timeout'])
        start = time.time()
        sock.connect((ip, port))
        latency = int((time.time() - start) * 1000)
        sock.close()
        return True, latency
    except:
        return False, -1

def udp_ping(ip, port=80):
    """UDP连接测试 - 发送BitTorrent UDP Tracker协议握手包"""
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(CONFIG['timeout'])

        connect_id = 0x41727101980
        action = 0
        transaction_id = random.randint(0, 2**32 - 1)
        packet = struct.pack('!QQL', connect_id, action, transaction_id)

        start = time.time()
        sock.sendto(packet, (ip, port))

        try:
            data, addr = sock.recvfrom(1024)
            latency = int((time.time() - start) * 1000)
            sock.close()
            if len(data) >= 16:
                resp_action = struct.unpack('!L', data[0:4])[0]
                if resp_action == 0:
                    return True, latency
        except socket.timeout:
            pass

        sock.close()
        return False, -1
    except:
        return False, -1

def parse_tracker_url(url):
    """解析tracker URL，返回 (scheme, host, port)"""
    pattern = r'^(udp|http|https)://([^:/]+)(?::(\d+))?(?:/.*)?$'
    match = re.match(pattern, url.strip(), re.IGNORECASE)
    if match:
        scheme = match.group(1).lower()
        host = match.group(2)
        if match.group(3):
            port = int(match.group(3))
        else:
            port = 443 if scheme == 'https' else 80
        return scheme, host, port
    return None, None, None

# ==================== 监控线程 ====================

def check_tracker(domain, ip_info, retry=True):
    """检查单个tracker的TCP和UDP状态"""
    ip = ip_info['ip']

    tracker_data = db.trackers.get(domain, {})
    port = tracker_data.get('port', 80)
    protocol = tracker_data.get('protocol', 'tcp')

    if protocol == 'udp':
        status, latency = udp_ping(ip, port)
    else:
        status, latency = tcp_ping(ip, port)

    if not status and retry:
        time.sleep(CONFIG['retry_interval'])
        if protocol == 'udp':
            status, latency = udp_ping(ip, port)
        else:
            status, latency = tcp_ping(ip, port)

    status_str = 'online' if status else 'offline'
    db.update_tracker_status(domain, ip, status_str, latency)
    return status_str, latency

def monitor_worker():
    """监控工作线程"""
    db.add_log("监控服务启动", 'info')
    while True:
        try:
            trackers = db.get_trackers()
            for domain, data in trackers.items():
                for ip_info in data['ips']:
                    try:
                        status, latency = check_tracker(domain, ip_info, retry=True)
                        db.add_log(f"检查 {domain} ({ip_info['ip']}): {status} {latency}ms", 'debug')
                    except Exception as e:
                        db.add_log(f"检查失败 {domain} ({ip_info['ip']}): {str(e)}", 'error')
            db.add_log(f"一轮检查完成，统计: {db.get_stats()}", 'info')
        except Exception as e:
            db.add_log(f"监控线程错误: {str(e)}", 'error')
        time.sleep(CONFIG['check_interval'])

# ==================== API路由 ====================

@app.route('/')
def index():
    """直接返回 index.html 内容，绕过 Jinja2 模板引擎"""
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'index.html')
    if not os.path.exists(html_path):
        # 尝试同目录
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')
    with open(html_path, 'r', encoding='utf-8') as f:
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
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL不能为空'}), 400

    scheme, domain, port = parse_tracker_url(url)
    if not domain:
        return jsonify({'error': '无效的URL格式，请使用 udp://host:port/announce 格式'}), 400

    # 确定协议：udp scheme → UDP ping；http/https → TCP ping
    protocol = 'udp' if scheme == 'udp' else 'tcp'

    # 解析IP
    ips = resolve_domain(domain)
    if not ips:
        return jsonify({'error': f'无法解析域名: {domain}，请检查域名是否正确'}), 400

    db.add_tracker(domain, port, protocol, ips)
    db.add_log(f"添加tracker: {domain} (端口:{port} 协议:{protocol.upper()} IP数:{len(ips)})", 'info')

    # 立即触发一次检查（在后台线程）
    def immediate_check():
        tracker_data = db.trackers.get(domain, {})
        for ip_info in tracker_data.get('ips', []):
            try:
                check_tracker(domain, ip_info, retry=False)
            except:
                pass
    threading.Thread(target=immediate_check, daemon=True).start()

    return jsonify({
        'success': True,
        'domain': domain,
        'port': port,
        'protocol': protocol,
        'ip_count': len(ips),
        'ips': ips
    })

@app.route('/api/tracker/delete', methods=['POST'])
def api_delete_tracker():
    data = request.json
    domain = data.get('domain', '').strip()
    with db.lock:
        if domain in db.trackers:
            del db.trackers[domain]
            db._recalculate_stats()
            db._save_to_disk()
            db.add_log(f"删除tracker: {domain}", 'info')
            return jsonify({'success': True})
    return jsonify({'error': 'Tracker不存在'}), 404

@app.route('/api/tracker/check', methods=['POST'])
def api_check_tracker():
    data = request.json
    domain = data.get('domain', '').strip()
    trackers = db.get_trackers()
    if domain not in trackers:
        return jsonify({'error': 'Tracker不存在'}), 404
    results = []
    for ip_info in trackers[domain]['ips']:
        status, latency = check_tracker(domain, ip_info, retry=True)
        results.append({'ip': ip_info['ip'], 'status': status, 'latency': latency})
    return jsonify({'success': True, 'results': results})

@app.route('/api/ranking/<period>')
def api_ranking(period):
    if period not in ['24h', '7d', '30d']:
        period = '24h'
    limit = request.args.get('limit', 100, type=int)
    ranking = db.get_ranking(period, limit)
    return jsonify({'period': period, 'ranking': ranking})

@app.route('/api/logs')
def api_logs():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(db.get_logs(limit))

@app.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    db.clear_logs()
    return jsonify({'success': True})

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'POST':
        data = request.json
        allowed_keys = ['log_to_disk', 'check_interval', 'timeout', 'retry_interval',
                        'http_proxy', 'udp_proxy', 'proxy_enabled']
        for key in allowed_keys:
            if key in data:
                CONFIG[key] = data[key]
        db.add_log(f"配置已更新", 'info')
        return jsonify({'success': True, 'config': CONFIG})
    # GET - 返回不含敏感信息的配置
    safe_config = {k: v for k, v in CONFIG.items() if k not in ['data_file', 'log_file']}
    return jsonify(safe_config)

# ==================== 主程序 ====================

if __name__ == '__main__':
    db.load_from_disk()
    db.add_log("网络监控服务启动", 'info')

    monitor_thread = threading.Thread(target=monitor_worker, daemon=True)
    monitor_thread.start()

    print(f"\n{'='*50}")
    print(f"网络监控 - Network Monitor")
    print(f"{'='*50}")
    print(f"访问地址: http://localhost:{CONFIG['port']}")
    print(f"监控间隔: {CONFIG['check_interval']}秒")
    print(f"超时时间: {CONFIG['timeout']}秒")
    print(f"失败重试: {CONFIG['retry_interval']}秒后")
    print(f"日志磁盘存储: {'开启' if CONFIG['log_to_disk'] else '关闭'}")
    print(f"代理启用: {'是' if CONFIG['proxy_enabled'] else '否'}")
    print(f"{'='*50}\n")

    app.run(host='0.0.0.0', port=CONFIG['port'], debug=False)