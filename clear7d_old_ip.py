# -*- coding: utf-8 -*-
"""
history.json 7天过期IP清理工具
================================
功能：
  1. 清理 history.json 中超过7天没有任何请求记录的IP数据
  2. 以行为单位检测每个IP的最后请求时间戳
  3. 如果最后请求时间在7天前，整行移除该IP数据
  4. 原子写入：先写临时文件，再替换，避免数据损坏
  5. 自动备份原文件

用法：
  双击运行本脚本即可（需确保 Python 已安装）
  或：python clear7d_old_ip.py

注意：
  - 本脚本会自动跳过无效IP（::, 0.0.0.0, 127.0.0.1 等）
  - 清理前会自动备份原文件到 history.json.bak
"""

import os
import sys
import json
import shutil
from datetime import datetime, timedelta

# ── 配置 ──────────────────────────────────────────────
HISTORY_FILE = 'history.json'
DAYS_TO_KEEP = 7  # 保留最近7天有请求的IP

# 无效IP列表（自动跳过）
INVALID_IPS = {'[::]', '::', '0.0.0.0', '127.0.0.1', '::1', '[::1]'}

def is_invalid(ip_str: str) -> bool:
    """检查IP是否为无效地址"""
    return ip_str.strip().lower() in INVALID_IPS

def main():
    # 切换到脚本所在目录（解决双击运行时工作目录错误的问题）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    print(f"=== history.json {DAYS_TO_KEEP}天过期IP清理工具 ===")
    print(f"目标文件: {os.path.abspath(HISTORY_FILE)}\n")

    # 1. 检查文件是否存在
    if not os.path.exists(HISTORY_FILE):
        print(f"[错误] 文件不存在: {HISTORY_FILE}")
        print("请将本脚本放在 history.json 所在目录")
        input("\n按 Enter 键退出...")
        sys.exit(1)

    file_size = os.path.getsize(HISTORY_FILE)
    print(f"文件大小: {file_size / 1024:.1f} KB")

    # 2. 尝试解析 JSON
    print("正在解析 JSON...")
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        print("✓ JSON 格式正常")
    except json.JSONDecodeError as e:
        print(f"✗ JSON 解析失败: {e}")
        input("\n按 Enter 键退出...")
        sys.exit(1)

    if not isinstance(raw, dict):
        print("[错误] history.json 顶层不是 dict，格式异常")
        input("\n按 Enter 键退出...")
        sys.exit(1)

    # 3. 计算时间阈值（当前时间 - DAYS_TO_KEEP 天）
    threshold_ts = (datetime.now() - timedelta(days=DAYS_TO_KEEP)).timestamp()
    threshold_dt = datetime.fromtimestamp(threshold_ts)
    print(f"\n时间阈值: {threshold_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"将删除最后请求时间早于上述时间的IP\n")

    # 4. 遍历并清理过期IP
    stats = {
        'total_domains': len(raw),
        'total_ips': 0,
        'kept_ips': 0,
        'deleted_ips': 0,
        'deleted_detail': []  # [(domain, ip, last_time), ...]
    }

    cleaned = {}
    for domain, ip_map in raw.items():
        if not isinstance(ip_map, dict):
            print(f"[跳过] 域名 {domain} 的数据格式异常")
            continue
        
        new_ip_map = {}
        for ip_key, points in ip_map.items():
            stats['total_ips'] += 1
            
            # 提取IP地址（格式通常是 "ip:1.2.3.4"）
            raw_ip = ip_key[3:] if ip_key.startswith('ip:') else ip_key
            
            # 跳过无效IP
            if is_invalid(raw_ip):
                continue
            
            # 检查是否有有效时间戳
            if not isinstance(points, list) or len(points) == 0:
                stats['deleted_ips'] += 1
                stats['deleted_detail'].append((domain, raw_ip, '无数据'))
                continue
            
            # 获取最后一个时间戳
            last_point = points[-1]
            if not isinstance(last_point, list) or len(last_point) < 1:
                stats['deleted_ips'] += 1
                stats['deleted_detail'].append((domain, raw_ip, '格式异常'))
                continue
            
            last_ts = last_point[0]
            
            # 检查是否过期
            if last_ts < threshold_ts:
                last_dt = datetime.fromtimestamp(last_ts)
                stats['deleted_ips'] += 1
                stats['deleted_detail'].append((domain, raw_ip, last_dt.strftime('%Y-%m-%d %H:%M:%S')))
            else:
                new_ip_map[ip_key] = points
                stats['kept_ips'] += 1
        
        if new_ip_map:
            cleaned[domain] = new_ip_map

    # 5. 输出统计信息
    print(f"统计结果：")
    print(f"  域名总数     : {stats['total_domains']}")
    print(f"  IP记录总数   : {stats['total_ips']}")
    print(f"  保留IP数     : {stats['kept_ips']}")
    print(f"  删除过期IP数 : {stats['deleted_ips']}")

    # 6. 如果有删除，显示删除详情
    if stats['deleted_detail']:
        print("\n已删除的过期IP：")
        for domain, ip, last_time in stats['deleted_detail'][:20]:  # 最多显示20条
            print(f"  [{domain}]  {ip}  (最后请求: {last_time})")
        if len(stats['deleted_detail']) > 20:
            print(f"  ... 还有 {len(stats['deleted_detail']) - 20} 条未显示")

    # 7. 如果没有变化，直接退出
    if stats['deleted_ips'] == 0:
        print("\n✓ 没有需要清理的过期IP")
        input("\n按 Enter 键退出...")
        sys.exit(0)

    # 8. 备份原文件
    backup = HISTORY_FILE + '.bak'
    shutil.copy2(HISTORY_FILE, backup)
    print(f"\n✓ 已备份原文件到: {backup}")

    # 9. 原子写入清理后的文件
    tmp_file = HISTORY_FILE + '.tmp'
    try:
        with open(tmp_file, 'w', encoding='utf-8') as f:
            # 格式化输出，每个域名和IP单独一行
            f.write('{\n')
            domain_list = list(cleaned.items())
            for d_idx, (domain, ip_map) in enumerate(domain_list):
                f.write(f'  {json.dumps(domain, ensure_ascii=False)}: {{\n')
                ip_items = list(ip_map.items())
                for i_idx, (ip_key, points) in enumerate(ip_items):
                    pts_str = json.dumps(points, separators=(',', ':'))
                    comma = ',' if i_idx < len(ip_items) - 1 else ''
                    f.write(f'    {json.dumps(ip_key)}: {pts_str}{comma}\n')
                domain_comma = ',' if d_idx < len(domain_list) - 1 else ''
                f.write(f'  }}{domain_comma}\n')
            f.write('}\n')
        os.replace(tmp_file, HISTORY_FILE)
        print(f"✓ 已写入清理后的文件: {HISTORY_FILE}")
    except Exception as e:
        print(f"[错误] 写入失败: {e}")
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        input("\n按 Enter 键退出...")
        sys.exit(1)

    # 10. 显示最终结果
    new_size = os.path.getsize(HISTORY_FILE)
    print(f"\n=== 清理完成 ===")
    print(f"原文件大小: {file_size / 1024:.1f} KB")
    print(f"新文件大小: {new_size / 1024:.1f} KB")
    print(f"释放空间  : {(file_size - new_size) / 1024:.1f} KB")
    input("\n按 Enter 键退出...")

if __name__ == '__main__':
    main()
