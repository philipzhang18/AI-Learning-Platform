"""
Redis数据管理器 - 高性能CVE和Dell数据存储
使用Redis替代SQLite以提升读写性能
"""
import json
import redis
from redis.connection import ConnectionPool
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import os


class RedisDataManager:
    """Redis数据管理器 - 管理CVE和Dell安全公告数据"""

    def __init__(self, host='localhost', port=6379, password=None, db=0):
        """初始化Redis连接

        Args:
            host: Redis服务器地址
            port: Redis端口
            password: Redis密码（如果有）
            db: Redis数据库编号
        """
        self.host = host
        self.port = port
        self.password = password
        self.db = db

        # 从环境变量读取Redis配置（WSL Redis 支持）
        self.host = os.getenv('REDIS_HOST', host)
        self.port = int(os.getenv('REDIS_PORT', port))
        redis_pwd = os.getenv('REDIS_PASSWORD', password)
        # 空字符串视为无密码
        self.password = redis_pwd if redis_pwd and redis_pwd.strip() else None
        self.db = int(os.getenv('REDIS_DB', db))

        # 创建连接池和客户端
        self.pool = self._create_pool(self.password)
        self.redis_client = redis.Redis(connection_pool=self.pool)

        # Redis键前缀
        self.CVE_PREFIX = "cve:"
        self.DELL_PREFIX = "dell:"
        self.CVE_SET = "cve:all_ids"
        self.DELL_SET = "dell:all_ids"
        self.COLLECTION_HISTORY = "collection:history"

    def _create_pool(self, password):
        """创建 Redis 连接池"""
        return ConnectionPool(
            host=self.host,
            port=self.port,
            password=password,
            db=self.db,
            decode_responses=True,
            max_connections=50,
            socket_timeout=5,
            socket_connect_timeout=5,
            socket_keepalive=True,
            socket_keepalive_options={
                1: 1,   # TCP_KEEPIDLE
                2: 1,   # TCP_KEEPINTVL
                3: 3    # TCP_KEEPCNT
            } if os.name != 'nt' else None,
            retry_on_timeout=True,
            health_check_interval=30
        )

    def ping(self) -> bool:
        """测试Redis连接（密码认证失败时自动尝试无密码连接）"""
        try:
            return self.redis_client.ping()
        except redis.AuthenticationError:
            # 密码不匹配：Redis 服务端未设密码但客户端带了密码，尝试无密码重连
            if self.password is not None:
                self.password = None
                self.pool.disconnect()
                self.pool = self._create_pool(None)
                self.redis_client = redis.Redis(connection_pool=self.pool)
                try:
                    return self.redis_client.ping()
                except (redis.ConnectionError, redis.AuthenticationError):
                    return False
            return False
        except redis.ConnectionError:
            return False

    def get_info(self) -> Dict[str, Any]:
        """获取Redis服务器信息"""
        try:
            info = self.redis_client.info()
            return {
                'connected': True,
                'version': info.get('redis_version'),
                'used_memory_human': info.get('used_memory_human'),
                'total_connections_received': info.get('total_connections_received'),
                'total_commands_processed': info.get('total_commands_processed'),
                'keyspace': info.get(f'db{self.db}', {})
            }
        except redis.ConnectionError as e:
            return {'connected': False, 'error': str(e)}

    # ==================== CVE 数据操作 ====================

    def store_cve(self, cve_data: Dict[str, Any]) -> bool:
        """存储CVE数据到Redis

        Args:
            cve_data: CVE数据字典

        Returns:
            True if new, False if updated existing
        """
        cve_id = cve_data.get('cve_id')
        if not cve_id:
            return False

        key = f"{self.CVE_PREFIX}{cve_id}"

        # 检查是否已存在
        is_new = not self.redis_client.exists(key)

        # 存储CVE数据
        self.redis_client.set(key, json.dumps(cve_data, ensure_ascii=False))

        # 添加到CVE ID集合
        self.redis_client.sadd(self.CVE_SET, cve_id)

        # 添加到采集历史
        self.redis_client.zadd(
            self.COLLECTION_HISTORY,
            {cve_id: datetime.now().timestamp()}
        )

        return is_new

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """根据CVE ID获取数据

        Args:
            cve_id: CVE编号

        Returns:
            CVE数据字典，如果不存在返回None
        """
        key = f"{self.CVE_PREFIX}{cve_id}"
        data = self.redis_client.get(key)

        if data:
            return json.loads(data)
        return None

    def get_all_cve_ids(self) -> Set[str]:
        """获取所有CVE ID"""
        return self.redis_client.smembers(self.CVE_SET)

    def get_all_cves(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """获取所有CVE数据（使用 MGET 批量获取优化）

        Args:
            limit: 最大返回数量，None表示全部

        Returns:
            CVE数据列表
        """
        cve_ids = list(self.get_all_cve_ids())

        if limit:
            cve_ids = cve_ids[:limit]

        if not cve_ids:
            return []

        # 使用 MGET 批量获取数据（比 Pipeline 更快）
        # 分批处理以避免单次请求过大
        batch_size = 1000
        all_cves = []

        for i in range(0, len(cve_ids), batch_size):
            batch_ids = cve_ids[i:i + batch_size]
            keys = [f"{self.CVE_PREFIX}{cve_id}" for cve_id in batch_ids]

            # MGET 批量获取
            results = self.redis_client.mget(keys)

            # 解析结果
            for data in results:
                if data:
                    try:
                        all_cves.append(json.loads(data))
                    except json.JSONDecodeError:
                        pass  # Skip invalid JSON

        return all_cves

    def get_cves_count(self) -> int:
        """获取CVE总数"""
        return self.redis_client.scard(self.CVE_SET)

    def delete_cve(self, cve_id: str) -> bool:
        """删除CVE数据

        Args:
            cve_id: CVE编号

        Returns:
            是否删除成功
        """
        key = f"{self.CVE_PREFIX}{cve_id}"
        result = self.redis_client.delete(key)
        self.redis_client.srem(self.CVE_SET, cve_id)
        return result > 0

    # ==================== Dell 安全公告操作 ====================

    def store_dell_advisory(self, advisory_data: Dict[str, Any]) -> bool:
        """存储Dell安全公告到Redis（Upsert：有则合并更新，无则插入）

        Args:
            advisory_data: Dell公告数据字典

        Returns:
            True if new, False if updated existing
        """
        dsa_id = advisory_data.get('dell_security_advisory')
        if not dsa_id:
            return False

        key = f"{self.DELL_PREFIX}{dsa_id}"

        # 检查是否已存在
        is_new = not self.redis_client.exists(key)

        if is_new:
            advisory_data['collected_date'] = datetime.now().isoformat()
        else:
            # 合并：用已有数据打底，新数据覆盖（保留旧字段，更新新字段）
            existing = self.redis_client.get(key)
            if existing:
                try:
                    old = json.loads(existing)
                    old.update({k: v for k, v in advisory_data.items() if v})
                    advisory_data = old
                except (json.JSONDecodeError, TypeError):
                    pass

        self.redis_client.set(key, json.dumps(advisory_data, ensure_ascii=False))

        # 添加到Dell ID集合
        self.redis_client.sadd(self.DELL_SET, dsa_id)

        # 更新CVE ID索引
        cve_ids = advisory_data.get('cve_ids', [])
        for cve_id in cve_ids:
            self.redis_client.sadd(f"cve_to_dell:{cve_id}", dsa_id)

        return is_new

    def get_dell_advisory(self, dsa_id: str) -> Optional[Dict[str, Any]]:
        """根据DSA ID获取Dell公告

        Args:
            dsa_id: Dell安全公告编号

        Returns:
            Dell公告数据字典，如果不存在返回None
        """
        key = f"{self.DELL_PREFIX}{dsa_id}"
        data = self.redis_client.get(key)

        if data:
            return json.loads(data)
        return None

    def get_all_dell_ids(self) -> Set[str]:
        """获取所有Dell公告ID"""
        return self.redis_client.smembers(self.DELL_SET)

    def get_all_dell_advisories(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """获取所有Dell安全公告（使用 MGET 批量获取优化）

        Args:
            limit: 最大返回数量，None表示全部

        Returns:
            Dell公告数据列表
        """
        dell_ids = list(self.get_all_dell_ids())

        if not dell_ids:
            return []

        # 使用 MGET 批量获取数据（分批处理）
        batch_size = 1000
        advisories = []

        for i in range(0, len(dell_ids), batch_size):
            batch_ids = dell_ids[i:i + batch_size]
            keys = [f"{self.DELL_PREFIX}{dsa_id}" for dsa_id in batch_ids]

            # MGET 批量获取
            results = self.redis_client.mget(keys)

            # 解析结果
            for data in results:
                if data:
                    try:
                        advisories.append(json.loads(data))
                    except json.JSONDecodeError:
                        pass  # Skip invalid JSON

        # 按发布日期降序排序
        advisories.sort(
            key=lambda x: x.get('published_date', ''),
            reverse=True
        )

        if limit:
            advisories = advisories[:limit]

        return advisories

    def get_dell_advisories_paginated(self, page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """分页获取Dell安全公告（性能优化）

        Args:
            page: 页码（从1开始）
            per_page: 每页数量

        Returns:
            {
                'data': 公告列表,
                'total': 总数,
                'page': 当前页,
                'per_page': 每页数量,
                'total_pages': 总页数
            }
        """
        # 获取所有ID
        dell_ids = list(self.get_all_dell_ids())
        total = len(dell_ids)

        if total == 0:
            return {
                'data': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0
            }

        # 计算分页
        total_pages = (total + per_page - 1) // per_page
        page = max(1, min(page, total_pages))  # 确保页码有效

        # 获取当前页的数据
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total)

        # 按发布日期排序所有ID（需要先获取数据来排序）
        # 优化：批量获取所有数据再排序（因为需要按日期排序）
        advisories = self.get_all_dell_advisories()

        # 返回当前页数据
        page_data = advisories[start_idx:end_idx]

        return {
            'data': page_data,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        }

    def get_dell_count(self) -> int:
        """获取Dell公告总数"""
        return self.redis_client.scard(self.DELL_SET)

    def get_dell_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """根据CVE ID查找相关的Dell公告

        Args:
            cve_id: CVE编号

        Returns:
            相关Dell公告列表
        """
        dsa_ids = self.redis_client.smembers(f"cve_to_dell:{cve_id}")
        advisories = []

        for dsa_id in dsa_ids:
            advisory = self.get_dell_advisory(dsa_id)
            if advisory:
                advisories.append(advisory)

        return advisories

    def delete_dell_advisory(self, dsa_id: str) -> bool:
        """删除Dell公告

        Args:
            dsa_id: Dell安全公告编号

        Returns:
            是否删除成功
        """
        # 先获取数据以删除CVE索引
        advisory = self.get_dell_advisory(dsa_id)
        if advisory:
            cve_ids = advisory.get('cve_ids', [])
            for cve_id in cve_ids:
                self.redis_client.srem(f"cve_to_dell:{cve_id}", dsa_id)

        key = f"{self.DELL_PREFIX}{dsa_id}"
        result = self.redis_client.delete(key)
        self.redis_client.srem(self.DELL_SET, dsa_id)
        return result > 0

    # ==================== 批量操作 ====================

    def batch_store_cves(self, cves: List[Dict[str, Any]]) -> Dict[str, int]:
        """批量存储CVE数据

        Args:
            cves: CVE数据列表

        Returns:
            统计信息 {'new': 新增数, 'updated': 更新数}
        """
        stats = {'new': 0, 'updated': 0}

        for cve in cves:
            is_new = self.store_cve(cve)
            if is_new:
                stats['new'] += 1
            else:
                stats['updated'] += 1

        return stats

    def batch_store_dell_advisories(self, advisories: List[Dict[str, Any]]) -> Dict[str, int]:
        """批量存储Dell公告（增量）

        Args:
            advisories: Dell公告数据列表

        Returns:
            统计信息 {'new': 新增数, 'skipped': 跳过数}
        """
        stats = {'new': 0, 'skipped': 0}

        for advisory in advisories:
            is_new = self.store_dell_advisory(advisory)
            if is_new:
                stats['new'] += 1
            else:
                stats['skipped'] += 1

        return stats

    # ==================== 数据清理 ====================

    def clear_all_cves(self) -> int:
        """清空所有CVE数据

        Returns:
            删除的数量
        """
        cve_ids = self.get_all_cve_ids()
        count = 0

        for cve_id in cve_ids:
            if self.delete_cve(cve_id):
                count += 1

        return count

    def clear_all_dell(self) -> int:
        """清空所有Dell公告

        Returns:
            删除的数量
        """
        dell_ids = self.get_all_dell_ids()
        count = 0

        for dsa_id in dell_ids:
            if self.delete_dell_advisory(dsa_id):
                count += 1

        return count

    def clear_all_data(self) -> Dict[str, int]:
        """清空所有数据

        Returns:
            统计信息
        """
        cve_count = self.clear_all_cves()
        dell_count = self.clear_all_dell()

        # 清空采集历史
        self.redis_client.delete(self.COLLECTION_HISTORY)

        return {
            'cve_count': cve_count,
            'dell_count': dell_count
        }

    # ==================== 统计信息 ====================

    def get_stats(self) -> Dict[str, Any]:
        """获取数据统计信息"""
        cve_count = self.get_cves_count()
        dell_count = self.get_dell_count()

        # 获取最近采集时间
        last_collection = self.redis_client.zrange(
            self.COLLECTION_HISTORY, -1, -1, withscores=True
        )
        last_collection_time = None
        if last_collection:
            timestamp = last_collection[0][1]
            last_collection_time = datetime.fromtimestamp(timestamp).isoformat()

        return {
            'cve_count': cve_count,
            'dell_count': dell_count,
            'last_collection': last_collection_time,
            'redis_info': self.get_info()
        }

    def close(self):
        """✅ 修复 #3: 关闭Redis连接并释放连接池"""
        try:
            # 关闭客户端连接
            if hasattr(self, 'redis_client') and self.redis_client:
                self.redis_client.close()

            # 断开连接池中的所有连接
            if hasattr(self, 'pool') and self.pool:
                self.pool.disconnect()
                print("Redis 连接池已释放")
        except Exception as e:
            print(f"关闭 Redis 连接时出错: {e}")


# 测试代码
if __name__ == "__main__":
    # 创建Redis管理器
    manager = RedisDataManager()

    # 测试连接
    if manager.ping():
        print("[OK] Redis connection successful")

        # 显示统计信息
        stats = manager.get_stats()
        print(f"CVE count: {stats['cve_count']}")
        print(f"Dell advisories: {stats['dell_count']}")
        print(f"Last collection: {stats['last_collection']}")
        print(f"Redis version: {stats['redis_info'].get('version')}")
        print(f"Memory used: {stats['redis_info'].get('used_memory_human')}")
    else:
        print("[ERROR] Redis connection failed")
        print("Please ensure Redis server is running:")
        print("  - WSL: sudo service redis-server start")

    manager.close()
