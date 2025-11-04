"""
混合数据管理器 - Redis缓存 + SQLite持久化
实现智能缓存策略，提升读写性能
"""
import json
import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from redis_manager import RedisDataManager


class HybridDataManager:
    """混合数据管理器 - 结合Redis缓存和SQLite持久化"""

    def __init__(self, sqlite_db_path: str, redis_host='localhost',
                 redis_port=6379, redis_password=None, cache_ttl_days=7):
        """初始化混合数据管理器

        Args:
            sqlite_db_path: SQLite数据库路径
            redis_host: Redis服务器地址
            redis_port: Redis端口
            redis_password: Redis密码
            cache_ttl_days: 缓存有效期（天）
        """
        self.sqlite_db_path = sqlite_db_path
        self.cache_ttl_days = cache_ttl_days

        # 初始化Redis管理器
        self.redis_manager = RedisDataManager(
            host=redis_host,
            port=redis_port,
            password=redis_password
        )

        # 验证连接
        if not self.redis_manager.ping():
            raise ConnectionError("Redis连接失败")

        print(f"[OK] 混合数据管理器初始化成功")
        print(f"  - Redis: {redis_host}:{redis_port}")
        print(f"  - SQLite: {sqlite_db_path}")
        print(f"  - 缓存TTL: {cache_ttl_days} 天")

    # ==================== CVE 数据操作 ====================

    def get_cve(self, cve_id: str, use_cache=True) -> Optional[Dict[str, Any]]:
        """获取CVE数据（优先从缓存）

        Args:
            cve_id: CVE编号
            use_cache: 是否使用缓存

        Returns:
            CVE数据字典
        """
        if use_cache:
            # 先从Redis缓存获取
            cached_data = self.redis_manager.get_cve(cve_id)
            if cached_data:
                return cached_data

        # 缓存未命中，从SQLite读取
        conn = sqlite3.connect(self.sqlite_db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,))
        result = cursor.fetchone()

        conn.close()

        if result and result[0]:
            try:
                data = json.loads(result[0])

                # 写入Redis缓存
                if use_cache:
                    self.redis_manager.store_cve(data)

                return data
            except json.JSONDecodeError:
                return None

        return None

    def get_recent_cves(self, days: int = 7, use_cache=True) -> List[Dict[str, Any]]:
        """获取最近的CVE数据（优先从缓存）

        Args:
            days: 最近几天的数据
            use_cache: 是否使用缓存

        Returns:
            CVE数据列表
        """
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

        if use_cache:
            # 从Redis获取所有缓存的CVE
            cached_cves = self.redis_manager.get_all_cves()

            # 筛选最近的数据
            recent_cves = [
                cve for cve in cached_cves
                if cve.get('published_date', '') >= cutoff_date
            ]

            if recent_cves:
                return recent_cves

        # 从SQLite读取
        conn = sqlite3.connect(self.sqlite_db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT data FROM cves
            WHERE published_date >= ?
            ORDER BY published_date DESC
        """, (cutoff_date,))

        results = cursor.fetchall()
        conn.close()

        cves = []
        for result in results:
            if result[0]:
                try:
                    data = json.loads(result[0])
                    cves.append(data)

                    # 写入Redis缓存
                    if use_cache:
                        self.redis_manager.store_cve(data)
                except json.JSONDecodeError:
                    pass

        return cves

    def get_all_cves_from_sqlite(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """从SQLite获取所有CVE数据（不使用缓存）

        Args:
            limit: 最大返回数量

        Returns:
            CVE数据列表
        """
        conn = sqlite3.connect(self.sqlite_db_path)
        cursor = conn.cursor()

        if limit:
            cursor.execute(f"SELECT data FROM cves LIMIT {limit}")
        else:
            cursor.execute("SELECT data FROM cves")

        results = cursor.fetchall()
        conn.close()

        cves = []
        for result in results:
            if result[0]:
                try:
                    cves.append(json.loads(result[0]))
                except json.JSONDecodeError:
                    pass

        return cves

    def warm_cache(self, days: int = 7):
        """预热缓存 - 将最近的数据加载到Redis

        Args:
            days: 预热最近几天的数据
        """
        print(f"[缓存预热] 正在加载最近 {days} 天的数据到 Redis...")

        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

        conn = sqlite3.connect(self.sqlite_db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT data FROM cves
            WHERE published_date >= ?
        """, (cutoff_date,))

        results = cursor.fetchall()
        conn.close()

        count = 0
        for result in results:
            if result[0]:
                try:
                    data = json.loads(result[0])
                    self.redis_manager.store_cve(data)
                    count += 1
                except json.JSONDecodeError:
                    pass

        print(f"[缓存预热完成] 已加载 {count} 条CVE数据到 Redis")
        return count

    # ==================== Dell 数据操作 ====================

    def get_dell_advisory(self, dsa_id: str, use_cache=True) -> Optional[Dict[str, Any]]:
        """获取Dell安全公告（优先从缓存）

        Args:
            dsa_id: Dell安全公告编号
            use_cache: 是否使用缓存

        Returns:
            Dell公告数据字典
        """
        if use_cache:
            cached_data = self.redis_manager.get_dell_advisory(dsa_id)
            if cached_data:
                return cached_data

        # 从SQLite读取Dell数据需要单独实现
        # 这里返回None，因为当前SQLite主要存储CVE数据
        return None

    # ==================== 统计信息 ====================

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        redis_stats = self.redis_manager.get_stats()

        # SQLite统计
        conn = sqlite3.connect(self.sqlite_db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM cves")
        sqlite_cve_count = cursor.fetchone()[0]

        conn.close()

        return {
            'redis': {
                'cve_count': redis_stats['cve_count'],
                'dell_count': redis_stats['dell_count'],
                'memory_used': redis_stats['redis_info'].get('used_memory_human'),
            },
            'sqlite': {
                'cve_count': sqlite_cve_count,
            },
            'cache_ttl_days': self.cache_ttl_days,
            'cache_hit_potential': f"{(redis_stats['cve_count'] / sqlite_cve_count * 100):.1f}%" if sqlite_cve_count > 0 else "0%"
        }

    def close(self):
        """关闭所有连接"""
        self.redis_manager.close()


# 测试代码
if __name__ == "__main__":
    # 创建混合管理器
    manager = HybridDataManager(
        sqlite_db_path="cve_data/cve_database.db",
        redis_password='defaultpassword',
        cache_ttl_days=7
    )

    # 显示统计信息
    stats = manager.get_stats()
    print("\n" + "=" * 60)
    print("混合数据管理器统计")
    print("=" * 60)
    print(f"\n[Redis缓存层]")
    print(f"  CVE数量: {stats['redis']['cve_count']}")
    print(f"  Dell公告: {stats['redis']['dell_count']}")
    print(f"  内存占用: {stats['redis']['memory_used']}")
    print(f"\n[SQLite持久层]")
    print(f"  CVE总数: {stats['sqlite']['cve_count']}")
    print(f"\n[缓存效率]")
    print(f"  缓存命中潜力: {stats['cache_hit_potential']}")
    print(f"  缓存TTL: {stats['cache_ttl_days']} 天")

    # 预热缓存测试
    print("\n" + "=" * 60)
    cache_count = manager.warm_cache(days=7)

    # 更新统计
    stats = manager.get_stats()
    print(f"\n[缓存预热后]")
    print(f"  Redis CVE数量: {stats['redis']['cve_count']}")
    print(f"  缓存命中潜力: {stats['cache_hit_potential']}")

    manager.close()
