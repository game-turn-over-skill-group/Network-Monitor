# -*- coding: utf-8 -*-
"""
history.npz → history.json 转换脚本

用法:
  python history_npz_to_json.py          # 导出 history.npz -> history.json
  python history_npz_to_json.py --stats  # 只显示统计信息，不导出

功能:
  - 将 NumPy 二进制格式 history.npz 转换为可读的 JSON 格式
  - 导出前自动备份已存在的 history.json 为 history.json.bak
  - 便于人工检查、编辑修复错误数据
"""

import os
import sys
import json
import time
import numpy as np

HISTORY_NUMPY = 'history.npz'
HISTORY_JSON = 'history.json'

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
    if not os.path.exists(HISTORY_NUMPY):
        print(f"[错误] 未找到 {HISTORY_NUMPY}")
        return

    loaded = np.load(HISTORY_NUMPY, allow_pickle=True)
    numpy_data = loaded['data'].item()

    total_domains = len(numpy_data)
    total_ips = sum(len(ip_map) for ip_map in numpy_data.values())
    total_records = 0

    for domain, ip_map in numpy_data.items():
        for ik, data in ip_map.items():
            total_records += len(data['ts'])

    print("=" * 40)
    print(f"history.npz 统计信息")
    print("=" * 40)
    print(f"域名数量: {total_domains}")
    print(f"IP key数量: {total_ips}")
    print(f"总记录数: {total_records:,}")
    print(f"文件大小: {os.path.getsize(HISTORY_NUMPY)/(1024*1024):.1f} MB")
    print("=" * 40)

def convert():
    if not os.path.exists(HISTORY_NUMPY):
        print(f"[错误] 未找到 {HISTORY_NUMPY}")
        return False

    backup_file(HISTORY_JSON)

    print(f"[INFO] 开始转换 {HISTORY_NUMPY} -> {HISTORY_JSON}")
    start_time = time.time()

    loaded = np.load(HISTORY_NUMPY, allow_pickle=True)
    numpy_data = loaded['data'].item()

    total_domains = 0
    total_ips = 0

    output_data = {}

    for domain, ip_map in numpy_data.items():
        domain_data = {}

        for ik, data in ip_map.items():
            ts_arr = data['ts']
            v_arr = data['v']

            if len(ts_arr) == 0:
                continue

            pts = [[int(ts), int(v)] for ts, v in zip(ts_arr, v_arr)]
            pts.sort(key=lambda x: x[0])

            domain_data[ik] = pts
            total_ips += 1

        if domain_data:
            output_data[domain] = domain_data
            total_domains += 1

    print(f"[INFO] 转换统计: {total_domains} 域名, {total_ips} IP key")

    with open(HISTORY_JSON, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, separators=(',', ':'), ensure_ascii=False)

    elapsed = time.time() - start_time

    if os.path.exists(HISTORY_JSON):
        numpy_size = os.path.getsize(HISTORY_NUMPY) / (1024 * 1024)
        json_size = os.path.getsize(HISTORY_JSON) / (1024 * 1024)
        print(f"[INFO] 转换完成! 耗时: {elapsed:.2f}秒")
        print(f"[INFO] NumPy大小: {numpy_size:.1f} MB -> JSON大小: {json_size:.1f} MB")
        print(f"[INFO] 膨胀率: {json_size/numpy_size*100:.1f}%")
        print(f"[INFO] JSON文件: {HISTORY_JSON}")
    else:
        print(f"[ERROR] 转换完成但文件未生成!")
    return True

if __name__ == '__main__':
    print("=" * 50)
    print("history.npz -> history.json 转换工具")
    print("=" * 50)

    if len(sys.argv) > 1:
        if sys.argv[1] == '--stats':
            print_stats()
            sys.exit(0)
        elif sys.argv[1] in ('--help', '-h'):
            print(__doc__)
            sys.exit(0)

    success = convert()
    sys.exit(0 if success else 1)
