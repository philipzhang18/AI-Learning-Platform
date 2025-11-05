"""
统一数据管理器
整合Redis缓存和MongoDB存储，提供统一的数据访问接口

架构:
- 缓存优先读取（Cache-Aside Pattern）
- 双写策略（Write-Through Pattern）
- 自动缓存失效
- 连接池管理

功能:
- CVE数据CRUD（分页、搜索、统计）
- Dell安全公告CRUD
- CVE-Dell关联查询
- 统计分析
"""

import os
import json
import hashlib
import asyncio
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
import aioredis
import logging

from mongodb_manager import MongoDBManager

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UnifiedDataManager:
    """统一数据管理器（Redis缓存 + MongoDB存储）"""

    def __init__(
        self,
        # MongoDB配置
        mongo_host: str = "localhost",
        mongo_port: int = 27017,
        mongo_username: str = "admin",
        mongo_password: str = "secure_password",
        mongo_database: str = "cve_database",

        # Redis配置
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: str = "defaultpassword",
        redis_db: int = 0,

        # 缓存配置
        cache_ttl_cve: int = 3600,      # CVE缓存1小时
        cache_ttl_dell: int = 0,         # Dell永久缓存（数据量小）
        cache_ttl_page: int = 1800,      # 分页缓存30分钟
        cache_ttl_stats: int = 300,      # 统计缓存5分钟
        cache_ttl_search: int = 900      # 搜索缓存15分钟
    ):
        """
        初始化统一数据管理器

        Args:
            mongo_*: MongoDB配置参数
            redis_*: Redis配置参数
            cache_ttl_*: 各类缓存的TTL（秒）
        """
        # MongoDB管理器
        self.mongodb = MongoDBManager(
            host=mongo_host,
            port=mongo_port,
            username=mongo_username,
            password=mongo_password,
            database=mongo_database
        )

        # Redis配置
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_password = redis_password
        self.redis_db = redis_db
        self.redis = None

        # 缓存TTL配置
        self.cache_ttl = {
            'cve': cache_ttl_cve,
            'dell': cache_ttl_dell,
            'page': cache_ttl_page,
            'stats': cache_ttl_stats,
            'search': cache_ttl_search
        }

        # 连接状态
        self.connected = False

    async def connect(self) -> bool:
        """建立所有连接"""
        try:
            # 连接MongoDB
            mongo_ok = await self.mongodb.connect()
            if not mongo_ok:
                logger.error("MongoDB连接失败")
                return False

            # 连接Redis
            try:
                self.redis = await aioredis.create_redis_pool(
                    f'redis://{self.redis_host}:{self.redis_port}',
                    password=self.redis_password,
                    db=self.redis_db,
                    minsize=5,
                    maxsize=20,
                    encoding='utf-8'
                )
                await self.redis.ping()
                logger.info(f"✓ Redis连接成功: {self.redis_host}:{self.redis_port}")
            except Exception as e:
                logger.warning(f"⚠ Redis连接失败: {e}, 将不使用缓存")
                self.redis = None

            self.connected = True
            return True

        except Exception as e:
            logger.error(f"统一数据管理器连接失败: {e}")
            return False

    async def close(self):
        """关闭所有连接"""
        if self.mongodb:
            await self.mongodb.close()

        if self.redis:
            self.redis.close()
            await self.redis.wait_closed()
            logger.info("Redis连接已关闭")

        self.connected = False

    def _hash_key(self, data: Any) -> str:
        """生成数据的哈希键"""
        return hashlib.md5(str(data).encode()).hexdigest()[:16]

    # ==================== CVE 数据操作 ====================

    async def store_cve(self, cve_data: Dict[str, Any]) -> bool:
        """
        存储CVE数据（双写：MongoDB + Redis）

        Args:
            cve_data: CVE数据

        Returns:
            bool: 是否为新数据
        """
        cve_id = cve_data.get('cve_id')
        if not cve_id:
            return False

        # 1. 写入MongoDB（持久化）
        is_new = await self.mongodb.store_cve(cve_data)

        # 2. 更新Redis缓存
        if self.redis:
            try:
                cache_key = f"cve:{cve_id}"

                # 将cve_data转换为可序列化的格式
                cache_data = self._prepare_for_cache(cve_data)

                # 使用hash存储
                await self.redis.hmset_dict(cache_key, cache_data)

                # 设置过期时间
                if self.cache_ttl['cve'] > 0:
                    await self.redis.expire(cache_key, self.cache_ttl['cve'])

                # 使相关缓存失效
                await self._invalidate_cve_caches()

            except Exception as e:
                logger.warning(f"更新Redis缓存失败: {e}")

        return is_new

    async def bulk_store_cves(self, cves: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        批量存储CVE数据

        Args:
            cves: CVE数据列表

        Returns:
            dict: 统计信息
        """
        # 批量写入MongoDB
        stats = await self.mongodb.bulk_store_cves(cves)

        # 批量更新Redis缓存
        if self.redis and cves:
            try:
                pipe = self.redis.pipeline()

                for cve in cves:
                    cve_id = cve.get('cve_id')
                    if cve_id:
                        cache_key = f"cve:{cve_id}"
                        cache_data = self._prepare_for_cache(cve)

                        # 添加到pipeline
                        pipe.hmset_dict(cache_key, cache_data)
                        if self.cache_ttl['cve'] > 0:
                            pipe.expire(cache_key, self.cache_ttl['cve'])

                # 执行pipeline
                await pipe.execute()

                logger.info(f"✓ Redis缓存已更新: {len(cves)}条CVE")

                # 使相关缓存失效
                await self._invalidate_cve_caches()

            except Exception as e:
                logger.warning(f"批量更新Redis缓存失败: {e}")

        return stats

    async def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        获取单个CVE数据（缓存优先）

        Args:
            cve_id: CVE ID

        Returns:
            dict or None: CVE数据
        """
        cache_key = f"cve:{cve_id}"

        # 1. 先查Redis缓存
        if self.redis:
            try:
                cached = await self.redis.hgetall(cache_key)
                if cached:
                    # 缓存命中
                    return self._restore_from_cache(cached)
            except Exception as e:
                logger.warning(f"Redis查询失败: {e}")

        # 2. 缓存未命中，查询MongoDB
        cve = await self.mongodb.get_cve(cve_id)

        # 3. 更新Redis缓存
        if cve and self.redis:
            try:
                cache_data = self._prepare_for_cache(cve)
                await self.redis.hmset_dict(cache_key, cache_data)
                if self.cache_ttl['cve'] > 0:
                    await self.redis.expire(cache_key, self.cache_ttl['cve'])
            except Exception as e:
                logger.warning(f"更新缓存失败: {e}")

        return cve

    async def get_cves(
        self,
        page: int = 1,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: str = "published_date",
        sort_order: int = -1
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        分页获取CVE数据（缓存优先）

        Args:
            page: 页码
            limit: 每页数量
            filters: 过滤条件
            sort_by: 排序字段
            sort_order: 排序方向

        Returns:
            tuple: (CVE列表, 总数)
        """
        # 1. 构建缓存key
        filter_hash = self._hash_key(filters) if filters else "all"
        cache_key_ids = f"cve:page:{page}:{limit}:{filter_hash}:{sort_by}:{sort_order}"
        cache_key_count = f"cve:count:{filter_hash}"

        # 2. 尝试从Redis获取分页ID列表
        cached_ids = None
        cached_count = None

        if self.redis:
            try:
                # 获取ID列表
                cached_ids = await self.redis.lrange(cache_key_ids, 0, -1)

                # 获取总数
                cached_count_str = await self.redis.get(cache_key_count)
                if cached_count_str:
                    cached_count = int(cached_count_str)

            except Exception as e:
                logger.warning(f"Redis查询失败: {e}")

        # 3. 如果缓存命中，批量获取CVE详情
        if cached_ids:
            cves = []
            for cve_id in cached_ids:
                cve = await self.get_cve(cve_id)
                if cve:
                    cves.append(cve)

            # 如果成功获取所有CVE，直接返回
            if len(cves) == len(cached_ids):
                total = cached_count if cached_count is not None else len(cves)
                return cves, total

        # 4. 缓存未命中或不完整，查询MongoDB
        cves = await self.mongodb.get_cves(
            page=page,
            limit=limit,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order
        )

        total = await self.mongodb.get_cves_count(filters)

        # 5. 更新Redis缓存
        if self.redis and cves:
            try:
                # 缓存ID列表
                cve_ids = [cve['cve_id'] for cve in cves]

                await self.redis.delete(cache_key_ids)
                if cve_ids:
                    await self.redis.rpush(cache_key_ids, *cve_ids)
                    await self.redis.expire(cache_key_ids, self.cache_ttl['page'])

                # 缓存总数
                await self.redis.set(cache_key_count, str(total), expire=self.cache_ttl['stats'])

                # 缓存每个CVE的详情
                for cve in cves:
                    cve_key = f"cve:{cve['cve_id']}"
                    cache_data = self._prepare_for_cache(cve)
                    await self.redis.hmset_dict(cve_key, cache_data)
                    if self.cache_ttl['cve'] > 0:
                        await self.redis.expire(cve_key, self.cache_ttl['cve'])

            except Exception as e:
                logger.warning(f"更新分页缓存失败: {e}")

        return cves, total

    async def get_cves_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        获取CVE总数（缓存优先）

        Args:
            filters: 过滤条件

        Returns:
            int: CVE总数
        """
        filter_hash = self._hash_key(filters) if filters else "all"
        cache_key = f"stats:cve:count:{filter_hash}"

        # 1. 先查Redis
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    return int(cached)
            except Exception as e:
                logger.warning(f"Redis查询失败: {e}")

        # 2. 查询MongoDB
        count = await self.mongodb.get_cves_count(filters)

        # 3. 更新缓存
        if self.redis:
            try:
                await self.redis.set(cache_key, str(count), expire=self.cache_ttl['stats'])
            except Exception as e:
                logger.warning(f"更新计数缓存失败: {e}")

        return count

    async def search_cves(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        全文搜索CVE（缓存搜索结果）

        Args:
            keyword: 搜索关键词
            limit: 返回数量

        Returns:
            list: CVE列表
        """
        search_hash = self._hash_key(keyword)
        cache_key = f"search:cve:{search_hash}:{limit}"

        # 1. 先查缓存
        if self.redis:
            try:
                cached_ids = await self.redis.lrange(cache_key, 0, -1)
                if cached_ids:
                    # 批量获取详情
                    cves = []
                    for cve_id in cached_ids:
                        cve = await self.get_cve(cve_id)
                        if cve:
                            cves.append(cve)

                    if len(cves) == len(cached_ids):
                        return cves

            except Exception as e:
                logger.warning(f"Redis搜索缓存查询失败: {e}")

        # 2. 执行搜索
        cves = await self.mongodb.search_cves(keyword, limit)

        # 3. 缓存搜索结果
        if self.redis and cves:
            try:
                cve_ids = [cve['cve_id'] for cve in cves]
                await self.redis.delete(cache_key)
                await self.redis.rpush(cache_key, *cve_ids)
                await self.redis.expire(cache_key, self.cache_ttl['search'])
            except Exception as e:
                logger.warning(f"缓存搜索结果失败: {e}")

        return cves

    # ==================== Dell 数据操作 ====================

    async def store_dell_advisory(self, dell_data: Dict[str, Any]) -> bool:
        """
        存储Dell安全公告（双写）

        Args:
            dell_data: Dell公告数据

        Returns:
            bool: 是否为新数据
        """
        dsa_id = dell_data.get('dell_security_advisory') or dell_data.get('dsa_id')
        if not dsa_id:
            return False

        # 1. 写入MongoDB
        is_new = await self.mongodb.store_dell_advisory(dell_data)

        # 2. 更新Redis缓存
        if self.redis:
            try:
                cache_key = f"dell:{dsa_id}"
                cache_data = self._prepare_for_cache(dell_data)

                await self.redis.hmset_dict(cache_key, cache_data)

                # Dell数据量小，可以永久缓存或长期缓存
                if self.cache_ttl['dell'] > 0:
                    await self.redis.expire(cache_key, self.cache_ttl['dell'])

                # 使相关缓存失效
                await self._invalidate_dell_caches()

            except Exception as e:
                logger.warning(f"更新Dell缓存失败: {e}")

        return is_new

    async def bulk_store_dell_advisories(self, dell_advisories: List[Dict[str, Any]]) -> Dict[str, int]:
        """批量存储Dell公告"""
        stats = await self.mongodb.bulk_store_dell_advisories(dell_advisories)

        # 批量更新Redis
        if self.redis and dell_advisories:
            try:
                pipe = self.redis.pipeline()

                for dell in dell_advisories:
                    dsa_id = dell.get('dell_security_advisory') or dell.get('dsa_id')
                    if dsa_id:
                        cache_key = f"dell:{dsa_id}"
                        cache_data = self._prepare_for_cache(dell)
                        pipe.hmset_dict(cache_key, cache_data)

                        if self.cache_ttl['dell'] > 0:
                            pipe.expire(cache_key, self.cache_ttl['dell'])

                await pipe.execute()
                logger.info(f"✓ Redis缓存已更新: {len(dell_advisories)}条Dell公告")

                await self._invalidate_dell_caches()

            except Exception as e:
                logger.warning(f"批量更新Dell缓存失败: {e}")

        return stats

    async def get_dell_advisory(self, dsa_id: str) -> Optional[Dict[str, Any]]:
        """获取单个Dell公告（缓存优先）"""
        cache_key = f"dell:{dsa_id}"

        # 1. 先查Redis
        if self.redis:
            try:
                cached = await self.redis.hgetall(cache_key)
                if cached:
                    return self._restore_from_cache(cached)
            except Exception as e:
                logger.warning(f"Redis查询Dell失败: {e}")

        # 2. 查询MongoDB
        dell = await self.mongodb.get_dell_advisory(dsa_id)

        # 3. 更新缓存
        if dell and self.redis:
            try:
                cache_data = self._prepare_for_cache(dell)
                await self.redis.hmset_dict(cache_key, cache_data)
                if self.cache_ttl['dell'] > 0:
                    await self.redis.expire(cache_key, self.cache_ttl['dell'])
            except Exception as e:
                logger.warning(f"更新Dell缓存失败: {e}")

        return dell

    async def get_dell_advisories(
        self,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        获取所有Dell公告（缓存优先）

        Args:
            filters: 过滤条件

        Returns:
            list: Dell公告列表
        """
        filter_hash = self._hash_key(filters) if filters else "all"
        cache_key = f"dell:list:{filter_hash}"

        # 1. 先查缓存
        if self.redis:
            try:
                cached_ids = await self.redis.lrange(cache_key, 0, -1)
                if cached_ids:
                    # 批量获取详情
                    advisories = []
                    for dsa_id in cached_ids:
                        dell = await self.get_dell_advisory(dsa_id)
                        if dell:
                            advisories.append(dell)

                    if len(advisories) == len(cached_ids):
                        return advisories

            except Exception as e:
                logger.warning(f"Redis查询Dell列表失败: {e}")

        # 2. 查询MongoDB
        advisories = await self.mongodb.get_dell_advisories(filters)

        # 3. 更新缓存
        if self.redis and advisories:
            try:
                dsa_ids = [adv.get('dsa_id') or adv.get('dell_security_advisory') for adv in advisories]
                dsa_ids = [id for id in dsa_ids if id]  # 过滤None

                if dsa_ids:
                    await self.redis.delete(cache_key)
                    await self.redis.rpush(cache_key, *dsa_ids)

                    # Dell数据变化少，可以长期缓存
                    await self.redis.expire(cache_key, 7200)  # 2小时

                    # 缓存每个Dell的详情
                    for dell in advisories:
                        dsa_id = dell.get('dsa_id') or dell.get('dell_security_advisory')
                        if dsa_id:
                            dell_key = f"dell:{dsa_id}"
                            cache_data = self._prepare_for_cache(dell)
                            await self.redis.hmset_dict(dell_key, cache_data)
                            if self.cache_ttl['dell'] > 0:
                                await self.redis.expire(dell_key, self.cache_ttl['dell'])

            except Exception as e:
                logger.warning(f"更新Dell列表缓存失败: {e}")

        return advisories

    async def get_dell_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """获取Dell公告总数（缓存优先）"""
        filter_hash = self._hash_key(filters) if filters else "all"
        cache_key = f"stats:dell:count:{filter_hash}"

        # 1. 先查Redis
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    return int(cached)
            except Exception as e:
                logger.warning(f"Redis查询Dell计数失败: {e}")

        # 2. 查询MongoDB
        count = await self.mongodb.get_dell_count(filters)

        # 3. 更新缓存
        if self.redis:
            try:
                await self.redis.set(cache_key, str(count), expire=self.cache_ttl['stats'])
            except Exception as e:
                logger.warning(f"更新Dell计数缓存失败: {e}")

        return count

    async def find_dell_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        根据CVE ID查找关联的Dell公告（缓存优先）

        Args:
            cve_id: CVE ID

        Returns:
            list: Dell公告列表
        """
        cache_key = f"matched:cve:{cve_id}"

        # 1. 先查缓存
        if self.redis:
            try:
                cached_ids = await self.redis.smembers(cache_key)
                if cached_ids:
                    # 批量获取详情
                    advisories = []
                    for dsa_id in cached_ids:
                        dell = await self.get_dell_advisory(dsa_id)
                        if dell:
                            advisories.append(dell)
                    return advisories

            except Exception as e:
                logger.warning(f"Redis查询CVE关联Dell失败: {e}")

        # 2. 查询MongoDB
        advisories = await self.mongodb.find_dell_by_cve(cve_id)

        # 3. 更新缓存
        if self.redis and advisories:
            try:
                dsa_ids = [adv.get('dsa_id') or adv.get('dell_security_advisory') for adv in advisories]
                dsa_ids = [id for id in dsa_ids if id]

                if dsa_ids:
                    await self.redis.delete(cache_key)
                    await self.redis.sadd(cache_key, *dsa_ids)
                    await self.redis.expire(cache_key, 1800)  # 30分钟

            except Exception as e:
                logger.warning(f"更新CVE关联缓存失败: {e}")

        return advisories

    # ==================== 统计功能 ====================

    async def get_severity_stats(self) -> Dict[str, int]:
        """获取CVE严重程度统计（缓存优先）"""
        cache_key = "stats:cve:severity"

        # 1. 先查缓存
        if self.redis:
            try:
                cached = await self.redis.hgetall(cache_key)
                if cached:
                    return {k: int(v) for k, v in cached.items()}
            except Exception as e:
                logger.warning(f"Redis查询统计失败: {e}")

        # 2. 查询MongoDB
        stats = await self.mongodb.get_severity_stats()

        # 3. 更新缓存
        if self.redis:
            try:
                cache_data = {k: str(v) for k, v in stats.items()}
                await self.redis.hmset_dict(cache_key, cache_data)
                await self.redis.expire(cache_key, self.cache_ttl['stats'])
            except Exception as e:
                logger.warning(f"更新统计缓存失败: {e}")

        return stats

    async def get_statistics(self) -> Dict[str, Any]:
        """
        获取综合统计信息

        Returns:
            dict: 统计数据
        """
        # 并发查询多个统计数据
        cve_count_task = self.get_cves_count()
        dell_count_task = self.get_dell_count()
        severity_task = self.get_severity_stats()

        cve_count, dell_count, severity_stats = await asyncio.gather(
            cve_count_task,
            dell_count_task,
            severity_task
        )

        # CVE-Dell关联统计
        match_stats = await self.mongodb.get_cve_dell_match_stats()

        return {
            "cve_total": cve_count,
            "dell_total": dell_count,
            "severity": severity_stats,
            "matched_cves": match_stats.get('matched_cves', 0),
            "avg_dell_per_cve": match_stats.get('avg_dell_per_cve', 0)
        }

    # ==================== 辅助方法 ====================

    def _prepare_for_cache(self, data: Dict[str, Any]) -> Dict[str, str]:
        """准备数据用于Redis缓存（转换为字符串）"""
        cache_data = {}
        for key, value in data.items():
            if key == '_id':
                # 跳过MongoDB的_id
                continue
            elif isinstance(value, (dict, list)):
                # 复杂类型转JSON
                cache_data[key] = json.dumps(value, default=str)
            elif isinstance(value, datetime):
                # 日期转ISO字符串
                cache_data[key] = value.isoformat()
            else:
                # 其他类型转字符串
                cache_data[key] = str(value) if value is not None else ""
        return cache_data

    def _restore_from_cache(self, cached: Dict[str, str]) -> Dict[str, Any]:
        """从Redis缓存恢复数据（转换回原类型）"""
        data = {}
        for key, value in cached.items():
            if not value:
                data[key] = None
            elif value.startswith('[') or value.startswith('{'):
                # 尝试解析JSON
                try:
                    data[key] = json.loads(value)
                except:
                    data[key] = value
            else:
                data[key] = value
        return data

    async def _invalidate_cve_caches(self):
        """使CVE相关缓存失效"""
        if not self.redis:
            return

        try:
            # 删除分页缓存
            cursor = b'0'
            while cursor:
                cursor, keys = await self.redis.scan(cursor, match=b'cve:page:*', count=100)
                if keys:
                    await self.redis.delete(*keys)
                if cursor == b'0':
                    break

            # 删除统计缓存
            await self.redis.delete('stats:cve:count:all')
            await self.redis.delete('stats:cve:severity')

        except Exception as e:
            logger.warning(f"失效CVE缓存失败: {e}")

    async def _invalidate_dell_caches(self):
        """使Dell相关缓存失效"""
        if not self.redis:
            return

        try:
            # 删除Dell列表缓存
            cursor = b'0'
            while cursor:
                cursor, keys = await self.redis.scan(cursor, match=b'dell:list:*', count=100)
                if keys:
                    await self.redis.delete(*keys)
                if cursor == b'0':
                    break

            # 删除统计缓存
            await self.redis.delete('stats:dell:count:all')

            # 删除关联缓存
            cursor = b'0'
            while cursor:
                cursor, keys = await self.redis.scan(cursor, match=b'matched:cve:*', count=100)
                if keys:
                    await self.redis.delete(*keys)
                if cursor == b'0':
                    break

        except Exception as e:
            logger.warning(f"失效Dell缓存失败: {e}")


# ==================== 测试代码 ====================

async def test_unified_manager():
    """测试统一数据管理器"""
    manager = UnifiedDataManager(
        mongo_password="secure_password",
        redis_password="defaultpassword"
    )

    # 连接
    connected = await manager.connect()
    if not connected:
        print("✗ 连接失败")
        return

    print("✓ 连接成功")

    # 测试存储CVE
    test_cve = {
        "cve_id": "CVE-2024-TEST-001",
        "description": "Test CVE for unified manager",
        "cvss_score": 8.5,
        "cvss_severity": "HIGH",
        "published_date": datetime.utcnow()
    }

    is_new = await manager.store_cve(test_cve)
    print(f"存储CVE: {'新增' if is_new else '更新'}")

    # 测试查询（应该命中缓存）
    cve = await manager.get_cve("CVE-2024-TEST-001")
    print(f"查询CVE: {cve['cve_id'] if cve else 'None'}")

    # 测试分页
    cves, total = await manager.get_cves(page=1, limit=10)
    print(f"分页查询: {len(cves)}条, 总计{total}条")

    # 测试统计
    stats = await manager.get_statistics()
    print(f"统计信息: CVE={stats['cve_total']}, Dell={stats['dell_total']}")

    # 关闭连接
    await manager.close()
    print("✓ 测试完成")


if __name__ == "__main__":
    asyncio.run(test_unified_manager())
