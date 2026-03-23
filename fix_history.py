# -*- coding: utf-8 -*-
"""
history.json 修复 & 格式化工具
================================
功能：
  1. 验证 history.json 是否是合法 JSON（修复前先检查）
  2. 自动过滤无效IP：[::]、::、127.0.0.1、0.0.0.0、::1
     （CF安全DNS 2606:4700:4700::1113 / ::1003 会将不可达tracker解析成这些地址）
  3. 将紧凑格式重新格式化：每个域名、每个IP单独一行，方便手动编辑删除
  4. 原子写入：先写 history.json.tmp，再替换，避免写入中断损坏数据

用法（把本脚本放到与 history.json 同一目录）：
  python fix_history.py              # 默认处理 history.json
  python fix_history.py my.json      # 处理指定文件

完成后会输出统计：有多少域名/IP、过滤了多少无效IP。
"""

import sys
import os
import json
import shutil
from datetime import datetime

# ── 配置 ──────────────────────────────────────────────
HISTORY_FILE = sys.argv[1] if len(sys.argv) > 1 else 'history.json'

# CF安全DNS（及其他DNS劫持）可能返回的无效地址
INVALID_IPS = {'[::]', '::', '0.0.0.0', '127.0.0.1', '::1', '[::1]'}

def is_invalid(ip_str: str) -> bool:
    return ip_str.strip().lower() in INVALID_IPS

# ── 主逻辑 ─────────────────────────────────────────────
def main():
    print(f"=== history.json 修复工具 ===")
    print(f"目标文件: {os.path.abspath(HISTORY_FILE)}\n")

    # 1. 检查文件是否存在
    if not os.path.exists(HISTORY_FILE):
        print(f"[错误] 文件不存在: {HISTORY_FILE}")
        sys.exit(1)

    file_size = os.path.getsize(HISTORY_FILE)
    print(f"文件大小: {file_size / 1024:.1f} KB")

    # 2. 尝试解析 JSON
    print("正在解析 JSON...")
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        print("✓ JSON 格式正常\n")
    except json.JSONDecodeError as e:
        print(f"✗ JSON 解析失败: {e}")
        print("\n提示：你可以尝试用文本编辑器定位到错误位置手动修复，")
        print(f"      错误在第 {e.lineno} 行，第 {e.colno} 列（字符位置 {e.pos}）")
        sys.exit(1)

    if not isinstance(raw, dict):
        print("[错误] history.json 顶层不是 dict，格式异常。")
        sys.exit(1)

    # 3. 统计 & 过滤
    total_domains  = len(raw)
    total_ips      = 0
    filtered_ips   = 0
    filtered_detail = {}  # domain -> [filtered ip strings]

    cleaned = {}
    for domain, ip_map in raw.items():
        if not isinstance(ip_map, dict):
            print(f"[跳过] 域名 {domain} 的数据格式异常，已忽略")
            continue
        new_ip_map = {}
        for ik, pts in ip_map.items():
            total_ips += 1
            # ik 格式通常是 "ip:1.2.3.4" 或 "ip:[::1]"
            raw_ip = ik[3:] if ik.startswith('ip:') else ik
            if is_invalid(raw_ip):
                filtered_ips += 1
                filtered_detail.setdefault(domain, []).append(raw_ip)
                continue
            if not isinstance(pts, list):
                continue
            new_ip_map[ik] = pts
        if new_ip_map:
            cleaned[domain] = new_ip_map

    print(f"统计：")
    print(f"  域名总数  : {total_domains}")
    print(f"  IP记录总数: {total_ips}")
    print(f"  过滤无效IP: {filtered_ips} 个")

    if filtered_detail:
        print("\n已过滤的无效IP（CF安全DNS劫持）：")
        for domain, ips in filtered_detail.items():
            for ip in ips:
                print(f"  [{domain}]  {ip}")

    # 4. 备份原文件
    backup = HISTORY_FILE + '.bak'
    shutil.copy2(HISTORY_FILE, backup)
    print(f"\n✓ 已备份原文件到: {backup}")

    # 5. 原子写入格式化后的文件
    tmp_file = HISTORY_FILE + '.tmp'
    try:
        with open(tmp_file, 'w', encoding='utf-8') as f:
            # 每个 domain 和 IP 单独一行，便于肉眼区分和手动编辑
            f.write('{\n')
            domain_list = list(cleaned.items())
            for d_idx, (domain, ip_map) in enumerate(domain_list):
                f.write(f'  {json.dumps(domain, ensure_ascii=False)}: {{\n')
                ip_items = list(ip_map.items())
                for i_idx, (ik, pts) in enumerate(ip_items):
                    pts_str = json.dumps(pts, separators=(',', ':'))
                    comma = ',' if i_idx < len(ip_items) - 1 else ''
                    f.write(f'    {json.dumps(ik)}: {pts_str}{comma}\n')
                domain_comma = ',' if d_idx < len(domain_list) - 1 else ''
                f.write(f'  }}{domain_comma}\n')
            f.write('}\n')
        os.replace(tmp_file, HISTORY_FILE)
        print(f"✓ 已写入格式化文件: {HISTORY_FILE}")
    except Exception as e:
        print(f"[错误] 写入失败: {e}")
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        sys.exit(1)

    new_size = os.path.getsize(HISTORY_FILE)
    print(f"\n完成！新文件大小: {new_size / 1024:.1f} KB")
    print("\n格式说明（格式化后）：")
    print('  每个 domain 一个缩进块，每个 IP 单独一行')
    print('  要删除某个IP：找到对应行，整行删除，注意最后一个IP后面不能有逗号')
    print('  示例：')
    print('    "example.com": {')
    print('      "ip:1.2.3.4": [[1700000000,1],[1700000030,0]],   <-- 删除这行时同时删逗号')
    print('      "ip:5.6.7.8": [[1700000000,1]]                   <-- 最后一个IP无逗号')
    print('    }')

if __name__ == '__main__':
    main()