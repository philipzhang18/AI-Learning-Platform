"""
SQLite to Redis Data Migration Script
Migrate existing CVE and Dell security advisories from SQLite to Redis
"""
import sys
import io
import sqlite3
import json
from pathlib import Path
from redis_manager import RedisDataManager
from datetime import datetime

# 设置标准输出编码为 UTF-8，避免 Windows 编码问题
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def migrate_sqlite_to_redis(sqlite_db_path: str, redis_manager: RedisDataManager):
    """将SQLite数据迁移到Redis

    Args:
        sqlite_db_path: SQLite数据库文件路径
        redis_manager: Redis管理器实例
    """
    print("=" * 80)
    print("SQLite → Redis 数据迁移工具")
    print("=" * 80)
    print()

    # 检查SQLite数据库是否存在
    db_path = Path(sqlite_db_path)
    if not db_path.exists():
        print(f"[ERROR] SQLite database does not exist: {sqlite_db_path}")
        return

    # 检查Redis连接
    if not redis_manager.ping():
        print("[ERROR] Redis connection failed, ensure Redis is running")
        print("  Start with: docker-compose up -d redis")
        return

    print(f"[OK] SQLite数据库: {sqlite_db_path}")
    print(f"[OK] Redis连接成功: {redis_manager.host}:{redis_manager.port}")
    print()

    # 连接SQLite数据库
    conn = sqlite3.connect(sqlite_db_path)
    cursor = conn.cursor()

    # ==================== 迁移CVE数据 ====================
    print("[1/2] 迁移CVE数据...")
    print("-" * 80)

    try:
        cursor.execute("SELECT cve_id, data FROM cves")
        cve_rows = cursor.fetchall()

        print(f"Found {len(cve_rows)} CVErecords")

        cve_stats = {'new': 0, 'skipped': 0, 'error': 0}

        for idx, (cve_id, data_str) in enumerate(cve_rows, 1):
            try:
                if data_str:
                    cve_data = json.loads(data_str)
                    is_new = redis_manager.store_cve(cve_data)

                    if is_new:
                        cve_stats['new'] += 1
                    else:
                        cve_stats['skipped'] += 1

                    # 每 1000 条显示一次进度
                    if idx % 1000 == 0 or idx == len(cve_rows):
                        progress = (idx / len(cve_rows)) * 100
                        print(f"  Progress: {idx}/{len(cve_rows)} ({progress:.1f}%) - New: {cve_stats['new']}, Skipped: {cve_stats['skipped']}")
            except Exception as e:
                cve_stats['error'] += 1
                if cve_stats['error'] <= 10:  # 只显示前10个错误
                    print(f"  [ERROR] {cve_id} migration failed: {str(e)[:100]}")

        print()
        print(f"CVEmigration completed:")
        print(f"  new: {cve_stats['new']} ")
        print(f"  skipped: {cve_stats['skipped']} ")
        print(f"  errors: {cve_stats['error']} ")
        print()

    except sqlite3.Error as e:
        print(f"[ERROR] CVE数据migration failed: {e}")

    # ==================== 迁移Dell安全公告 ====================
    print("[2/2] 迁移Dell安全公告...")
    print("-" * 80)

    try:
        cursor.execute("SELECT dsa_id, data FROM dell_advisories")
        dell_rows = cursor.fetchall()

        print(f"Found {len(dell_rows)} Dell公告")

        dell_stats = {'new': 0, 'skipped': 0, 'error': 0}

        for idx, (dsa_id, data_str) in enumerate(dell_rows, 1):
            try:
                if data_str:
                    advisory_data = json.loads(data_str)
                    is_new = redis_manager.store_dell_advisory(advisory_data)

                    if is_new:
                        dell_stats['new'] += 1
                        print(f"  [{idx}/{len(dell_rows)}] [OK] {dsa_id} (new)")
                    else:
                        dell_stats['skipped'] += 1
                        # Dell 公告数量较少，只在新增时显示
            except Exception as e:
                dell_stats['error'] += 1
                if dell_stats['error'] <= 10:
                    print(f"  [ERROR] {dsa_id} migration failed: {str(e)[:100]}")

        print()
        print(f"Dell公告migration completed:")
        print(f"  new: {dell_stats['new']} ")
        print(f"  skipped: {dell_stats['skipped']} ")
        print(f"  errors: {dell_stats['error']} ")
        print()

    except sqlite3.Error as e:
        print(f"[ERROR] Dell数据migration failed: {e}")

    # 关闭SQLite连接
    conn.close()

    # ==================== 显示Migration Summary ====================
    print("=" * 80)
    print("Migration Summary")
    print("=" * 80)

    redis_stats = redis_manager.get_stats()
    print(f"RedisCVEtotal: {redis_stats['cve_count']}")
    print(f"RedisDell公告total: {redis_stats['dell_count']}")
    print(f"Redismemory used: {redis_stats['redis_info'].get('used_memory_human', 'N/A')}")
    print()

    print("[OK] migration completed！")
    print()


def verify_migration(sqlite_db_path: str, redis_manager: RedisDataManager):
    """验证数据迁移是否成功

    Args:
        sqlite_db_path: SQLite数据库文件路径
        redis_manager: Redis管理器实例
    """
    print("=" * 80)
    print("Verifying Data Integrity")
    print("=" * 80)

    # 连接SQLite
    conn = sqlite3.connect(sqlite_db_path)
    cursor = conn.cursor()

    # 统计SQLite数据
    cursor.execute("SELECT COUNT(*) FROM cves")
    sqlite_cve_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM dell_advisories")
    sqlite_dell_count = cursor.fetchone()[0]

    # 统计Redis数据
    redis_cve_count = redis_manager.get_cves_count()
    redis_dell_count = redis_manager.get_dell_count()

    print(f"CVE数据:")
    print(f"  SQLite: {sqlite_cve_count} ")
    print(f"  Redis:  {redis_cve_count} ")
    if sqlite_cve_count == redis_cve_count:
        print(f"  [OK] matched")
    else:
        print(f"  [ERROR] 不matched (difference: {abs(sqlite_cve_count - redis_cve_count)})")

    print()
    print(f"Dell公告:")
    print(f"  SQLite: {sqlite_dell_count} ")
    print(f"  Redis:  {redis_dell_count} ")
    if sqlite_dell_count == redis_dell_count:
        print(f"  [OK] matched")
    else:
        print(f"  [ERROR] 不matched (difference: {abs(sqlite_dell_count - redis_dell_count)})")

    conn.close()
    print()


def main():
    """主函数"""
    # 默认SQLite数据库路径
    sqlite_db_path = "cve_data/cve_database.db"

    # 创建Redis管理器（使用默认密码）
    print("初始化Redis连接...")
    redis_manager = RedisDataManager(password='defaultpassword')

    # 执行迁移
    migrate_sqlite_to_redis(sqlite_db_path, redis_manager)

    # 验证迁移
    verify_migration(sqlite_db_path, redis_manager)

    # 关闭连接
    redis_manager.close()


if __name__ == "__main__":
    main()
