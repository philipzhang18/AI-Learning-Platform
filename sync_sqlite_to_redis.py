#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLite 数据同步到 Redis 脚本
将 SQLite 中的全部数据同步到 Redis 缓存
"""

import sqlite3
import json
import os
import sys
from pathlib import Path
from redis_manager import RedisDataManager

# 设置标准输出编码为UTF-8
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')


def sync_cve_data_to_redis():
    """同步 CVE 数据从 SQLite 到 Redis"""
    print("开始同步 CVE 数据...")

    # 连接数据库
    db_path = Path("cve_data/cve_database.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 初始化 Redis
    redis_manager = RedisDataManager(password=os.getenv('REDIS_PASSWORD', ''))

    # 检查 Redis 连接
    if not redis_manager.ping():
        print("[FAIL] Redis 连接失败！")
        return False

    print("[OK] Redis 连接成功")

    # 查询所有 CVE 数据
    cursor.execute("SELECT cve_id, data FROM cves")
    records = cursor.fetchall()

    print(f"SQLite 中共有 {len(records)} 条 CVE 数据")

    # 同步到 Redis
    success_count = 0
    error_count = 0

    for i, (cve_id, data_str) in enumerate(records, 1):
        try:
            if data_str:
                cve_data = json.loads(data_str)
                redis_manager.store_cve(cve_data)
                success_count += 1

                # 每1000条显示进度
                if i % 1000 == 0:
                    print(f"已同步 {i}/{len(records)} 条 CVE...")
        except Exception as e:
            error_count += 1
            if error_count <= 5:  # 只显示前5个错误
                print(f"同步失败 {cve_id}: {e}")

    conn.close()

    print(f"\n[OK] CVE 数据同步完成")
    print(f"  - 成功: {success_count} 条")
    print(f"  - 失败: {error_count} 条")

    return True


def sync_dell_data_to_redis():
    """同步 Dell 数据从 SQLite 到 Redis"""
    print("\n开始同步 Dell 数据...")

    # 连接数据库
    db_path = Path("cve_data/cve_database.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 初始化 Redis
    redis_manager = RedisDataManager(password=os.getenv('REDIS_PASSWORD', ''))

    # 查询所有 Dell 数据
    cursor.execute("SELECT data FROM dell_advisories")
    records = cursor.fetchall()

    print(f"SQLite 中共有 {len(records)} 条 Dell 数据")

    # 同步到 Redis
    success_count = 0
    error_count = 0

    for data_str, in records:
        try:
            if data_str:
                dell_data = json.loads(data_str)
                redis_manager.store_dell_advisory(dell_data)
                success_count += 1
        except Exception as e:
            error_count += 1
            if error_count <= 5:
                print(f"同步失败: {e}")

    conn.close()

    print(f"\n[OK] Dell 数据同步完成")
    print(f"  - 成功: {success_count} 条")
    print(f"  - 失败: {error_count} 条")

    return True


def verify_redis_data():
    """验证 Redis 中的数据"""
    print("\n验证 Redis 数据...")

    redis_manager = RedisDataManager(password=os.getenv('REDIS_PASSWORD', ''))

    # 获取数据量
    try:
        cve_count = redis_manager.get_cves_count()
        dell_count = redis_manager.get_dell_count()

        print(f"\nRedis 数据统计:")
        print(f"  - CVE 数据: {cve_count} 条")
        print(f"  - Dell 数据: {dell_count} 条")

        return cve_count > 0 and dell_count > 0
    except Exception as e:
        print(f"验证失败: {e}")
        return False


def main():
    """主函数"""
    print("="*60)
    print("SQLite 数据同步到 Redis")
    print("="*60)

    # 同步 CVE 数据
    if not sync_cve_data_to_redis():
        print("\n[FAIL] CVE 数据同步失败，退出")
        return

    # 同步 Dell 数据
    if not sync_dell_data_to_redis():
        print("\n[FAIL] Dell 数据同步失败，退出")
        return

    # 验证数据
    if verify_redis_data():
        print("\n[OK] 数据同步和验证成功！")
        print("\n现在可以启用 Redis 模式了：")
        print("1. 编辑 .env 文件")
        print("2. 设置 USE_REDIS=true")
        print("3. 重启程序: python cve_integrated_gui.py")
    else:
        print("\n[FAIL] 数据验证失败")


if __name__ == "__main__":
    main()
