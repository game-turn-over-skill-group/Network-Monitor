# -*- coding: utf-8 -*-
"""
history.json → history.npz 转换脚本

用法:
  python history_json_to_npz.py          # 转换 history.json -> history.npz
  python history_json_to_npz.py --stats  # 只显示统计信息，不转换

功能:
  - 将 history.json 转换为高效的 NumPy 二进制格式 history.npz
  - 转换前自动备份已存在的 history.npz 为 history.npz.bak
"""

import os
import sys
import json
import time
import numpy as np

# 切换到脚本所在目录，确保双击运行时能找到正确的文件
os.chdir(os.path.dirname(os.path.abspath(__file__)))

HISTORY_JSON = 'history.json'
HISTORY_NUMPY = 'history.npz'

_INVALID_IPS = {'[::]', '::', '0.0.0.0', '127.0.0.1', '::1'}

def is_invalid_ip(ip_str):
    ip = ip_str.lower().strip()
    return ip in _INVALID_IPS

def backup_file(filepath):
    if os.path.exists(filepath):
        bak_path = filepath + '.bak'
        if os.path.exists(bak_path):
            os.remove(bak_path)
        os.rename(filepath, bak_path)
        print(f"[INFO] 已备份: {filepath} -> {bak_path}")
        return True
    return False

def print_stats():
    if not os.path.exists(HISTORY_JSON):
        print(f"[错误] 未找到 {HISTORY_JSON}")
        return

    with open(HISTORY_JSON, 'r', encoding='utf-8') as f:
        raw = json.load(f)

    total_domains = len(raw)
    total_ips = 0
    total_records = 0

    for domain, ip_map in raw.items():
        if not isinstance(ip_map, dict):
            continue
        for ik, pts in ip_map.items():
            if isinstance(pts, list):
                total_ips += 1
                total_records += len(pts)

    print("=" * 40)
    print("history.json 统计信息")
    print("=" * 40)
    print(f"域名数量: {total_domains}")
    print(f"IP key数量: {total_ips}")
    print(f"总记录数: {total_records:,}")
    print(f"文件大小: {os.path.getsize(HISTORY_JSON)/(1024*1024):.1f} MB")
    print("=" * 40)

def convert():
    if not os.path.exists(HISTORY_JSON):
        print(f"[错误] 未找到 {HISTORY_JSON}")
        return False

    backup_file(HISTORY_NUMPY)

    print(f"[INFO] 开始转换 {HISTORY_JSON} -> {HISTORY_NUMPY}")
    start_time = time.time()

    cutoff = int(time.time()) - 30 * 86400
    numpy_data = {}

    with open(HISTORY_JSON, 'r', encoding='utf-8') as f:
        raw = json.load(f)

    total_domains = 0
    total_ips = 0
    skipped_ips = 0
    skipped_records = 0

    for domain, ip_map in raw.items():
        if not isinstance(ip_map, dict):
            continue

        domain_data = {}

        for ik, pts in ip_map.items():
            if not isinstance(pts, list):
                continue

            raw_ip = ik[3:] if ik.startswith('ip:') else ik
            if is_invalid_ip(raw_ip):
                skipped_ips += 1
                continue

            ts_list = []
            v_list = []

            for ts, v in pts:
                if ts >= cutoff:
                    ts_list.append(int(ts))
                    v_list.append(int(v))

            if ts_list:
                domain_data[ik] = {
                    'ts': np.array(ts_list, dtype=np.int32),
                    'v': np.array(v_list, dtype=np.int8)
                }
                total_ips += 1
            else:
                skipped_records += 1

        if domain_data:
            numpy_data[domain] = domain_data
            total_domains += 1

    if skipped_ips:
        print(f"[INFO] 已跳过 {skipped_ips} 个无效IP记录")

    print(f"[INFO] 转换统计: {total_domains} 域名, {total_ips} IP key, 跳过 {skipped_records} 空记录")

    np.savez_compressed(HISTORY_NUMPY.replace('.npz', ''), data=numpy_data)

    elapsed = time.time() - start_time

    if os.path.exists(HISTORY_NUMPY):
        numpy_size = os.path.getsize(HISTORY_NUMPY) / (1024 * 1024)
        json_size = os.path.getsize(HISTORY_JSON) / (1024 * 1024)
        print(f"[INFO] 转换完成! 耗时: {elapsed:.2f}秒")
        print(f"[INFO] JSON大小: {json_size:.1f} MB -> NumPy大小: {numpy_size:.1f} MB")
        print(f"[INFO] 压缩率: {numpy_size/json_size*100:.1f}%")
        print(f"[INFO] NumPy文件: {HISTORY_NUMPY}")
    else:
        print(f"[ERROR] 转换完成但文件未生成!")
    return True

if __name__ == '__main__':
    print("=" * 50)
    print("history.json -> history.npz 转换工具")
    print("=" * 50)

    if len(sys.argv) > 1:
        if sys.argv[1] == '--stats':
            print_stats()
            input("\n按回车键退出...")
            sys.exit(0)
        elif sys.argv[1] in ('--help', '-h'):
            print(__doc__)
            input("\n按回车键退出...")
            sys.exit(0)

    success = convert()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
