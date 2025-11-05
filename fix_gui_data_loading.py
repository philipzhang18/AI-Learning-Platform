#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CVE GUI 数据加载修复脚本
用途：验证数据库并重新加载 GUI
"""

import sqlite3
import os
from pathlib import Path

def check_database():
    """检查数据库状态"""
    db_path = Path("cve_data/cve_database.db")

    if not db_path.exists():
        print("❌ 错误：数据库文件不存在")
        print(f"   路径: {db_path.absolute()}")
        return False

    print(f"✓ 数据库文件存在: {db_path.absolute()}")
    print(f"✓ 文件大小: {db_path.stat().st_size / 1024 / 1024:.2f} MB")

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # 检查 CVE 数据
        cursor.execute("SELECT COUNT(*) FROM cves")
        cve_count = cursor.fetchone()[0]
        print(f"✓ CVE 记录数: {cve_count:,}")

        # 检查 Dell 数据
        cursor.execute("SELECT COUNT(*) FROM dell_advisories")
        dell_count = cursor.fetchone()[0]
        print(f"✓ Dell 记录数: {dell_count:,}")

        # 检查数据示例
        cursor.execute("SELECT cve_id, data FROM cves LIMIT 1")
        sample = cursor.fetchone()
        if sample and sample[1]:
            print(f"✓ 数据完整性: OK（示例: {sample[0]}）")
        else:
            print("⚠ 警告：数据可能不完整")

        conn.close()
        return True

    except sqlite3.Error as e:
        print(f"❌ 数据库错误: {e}")
        return False

def main():
    print("=" * 60)
    print("CVE GUI 数据加载诊断工具")
    print("=" * 60)
    print()

    # 检查工作目录
    cwd = os.getcwd()
    print(f"当前目录: {cwd}")
    print()

    # 检查数据库
    print("【检查数据库状态】")
    if check_database():
        print()
        print("=" * 60)
        print("✅ 数据库状态正常")
        print("=" * 60)
        print()
        print("【建议操作】")
        print("1. 在 GUI 中点击 '📁 加载本地数据' 按钮")
        print("2. 或者关闭 GUI 并重新启动程序")
        print("3. 如仍无法加载，查看 GUI 的 '📝 操作日志' 标签")
        print()
    else:
        print()
        print("=" * 60)
        print("❌ 数据库存在问题")
        print("=" * 60)
        print()
        print("【修复建议】")
        print("1. 检查数据库文件路径是否正确")
        print("2. 尝试从备份恢复:")
        print("   cp backups/cve_database_backup_*.db cve_data/cve_database.db")
        print("3. 或者重新运行数据迁移脚本")
        print()

if __name__ == "__main__":
    main()
