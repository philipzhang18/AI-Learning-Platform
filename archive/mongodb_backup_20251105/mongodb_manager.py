"""
MongoDB数据管理器
用于CVE漏洞监控系统的MongoDB数据库操作

功能:
- CVE数据的CRUD操作
- Dell安全公告的CRUD操作
- 批量插入和更新
- 索引管理
- 查询优化
"""

import os
import asyncio
from datetime import datetime
from typing import List, Dict, Optional, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import UpdateOne, ASCENDING, DESCENDING, TEXT
from pymongo.errors import DuplicateKeyError, BulkWriteError
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MongoDBManager:
    """MongoDB数据管理器（异步版本）"""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 27017,
        username: str = "admin",
        password: str = "secure_password",
        database: str = "cve_database",
        max_pool_size: int = 50,
        min_pool_size: int = 10
    ):
        """
        初始化MongoDB连接

        Args:
            host: MongoDB主机地址
            port: MongoDB端口
            username: 用户名
            password: 密码
            database: 数据库名
            max_pool_size: 最大连接池大小
            min_pool_size: 最小连接池大小
        """
        self.host = host
        self.port = port
        self.database_name = database

        # 构建连接URI
        self.uri = f"mongodb://{username}:{password}@{host}:{port}/"

        # 初始化客户端（延迟连接）
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None

        # 连接池配置
        self.max_pool_size = max_pool_size
        self.min_pool_size = min_pool_size

        # Collection名称
        self.cve_collection_name = "cve_collection"
        self.dell_collection_name = "dell_collection"
        self.history_collection_name = "collection_history"

    async def connect(self):
        """建立MongoDB连接"""
        try:
            self.client = AsyncIOMotorClient(
                self.uri,
                maxPoolSize=self.max_pool_size,
                minPoolSize=self.min_pool_size,
                maxIdleTimeMS=45000,
                waitQueueTimeoutMS=5000
            )

            # 获取数据库
            self.db = self.client[self.database_name]

            # 测试连接
            await self.client.admin.command('ping')
            logger.info(f"✓ MongoDB连接成功: {self.host}:{self.port}")

            # 确保索引存在
            await self.ensure_indexes()

            return True

        except Exception as e:
            logger.error(f"✗ MongoDB连接失败: {e}")
            return False

    async def close(self):
        """关闭MongoDB连接"""
        if self.client:
            self.client.close()
            logger.info("MongoDB连接已关闭")

    async def ensure_indexes(self):
        """确保所有必要的索引都已创建"""
        try:
            # CVE Collection索引
            cve_collection = self.db[self.cve_collection_name]

            await cve_collection.create_index(
                [("cve_id", ASCENDING)],
                unique=True,
                name="idx_cve_id"
            )

            await cve_collection.create_index(
                [("published_date", DESCENDING), ("cvss_severity", ASCENDING)],
                name="idx_published_severity"
            )

            await cve_collection.create_index(
                [("cvss_severity", ASCENDING)],
                name="idx_severity"
            )

            await cve_collection.create_index(
                [("collected_date", DESCENDING)],
                name="idx_collected"
            )

            await cve_collection.create_index(
                [("description", TEXT), ("cve_id", TEXT)],
                name="idx_fulltext"
            )

            # Dell Collection索引
            dell_collection = self.db[self.dell_collection_name]

            await dell_collection.create_index(
                [("dsa_id", ASCENDING)],
                unique=True,
                name="idx_dsa_id"
            )

            await dell_collection.create_index(
                [("cve_ids", ASCENDING)],
                name="idx_cve_ids"
            )

            await dell_collection.create_index(
                [("published_date", DESCENDING)],
                name="idx_published"
            )

            await dell_collection.create_index(
                [("collected_date", DESCENDING)],
                name="idx_collected"
            )

            await dell_collection.create_index(
                [("title", TEXT), ("summary", TEXT)],
                name="idx_fulltext"
            )

            # Collection History索引
            history_collection = self.db[self.history_collection_name]

            await history_collection.create_index(
                [("start_time", DESCENDING)],
                name="idx_start_time"
            )

            await history_collection.create_index(
                [("type", ASCENDING), ("start_time", DESCENDING)],
                name="idx_type_time"
            )

            logger.info("✓ MongoDB索引创建完成")

        except Exception as e:
            logger.error(f"✗ 创建索引失败: {e}")

    # ==================== CVE 数据操作 ====================

    async def store_cve(self, cve_data: Dict[str, Any]) -> bool:
        """
        存储单个CVE数据

        Args:
            cve_data: CVE数据字典

        Returns:
            bool: 是否成功存储
        """
        try:
            cve_id = cve_data.get('cve_id')
            if not cve_id:
                logger.warning("CVE数据缺少cve_id")
                return False

            # 添加collected_date
            if 'collected_date' not in cve_data:
                cve_data['collected_date'] = datetime.utcnow()

            # Upsert操作（存在则更新，不存在则插入）
            collection = self.db[self.cve_collection_name]
            result = await collection.update_one(
                {"cve_id": cve_id},
                {"$set": cve_data},
                upsert=True
            )

            is_new = result.upserted_id is not None
            return is_new

        except DuplicateKeyError:
            logger.debug(f"CVE {cve_id} 已存在，跳过")
            return False
        except Exception as e:
            logger.error(f"存储CVE数据失败: {e}")
            return False

    async def bulk_store_cves(self, cves: List[Dict[str, Any]], batch_size: int = 1000) -> Dict[str, int]:
        """
        批量存储CVE数据

        Args:
            cves: CVE数据列表
            batch_size: 批次大小

        Returns:
            dict: 统计信息 {new: 新增数, updated: 更新数, failed: 失败数}
        """
        stats = {"new": 0, "updated": 0, "failed": 0}

        collection = self.db[self.cve_collection_name]

        # 分批处理
        for i in range(0, len(cves), batch_size):
            batch = cves[i:i + batch_size]

            try:
                # 构建bulk操作
                operations = []
                for cve in batch:
                    cve_id = cve.get('cve_id')
                    if not cve_id:
                        stats['failed'] += 1
                        continue

                    # 添加collected_date
                    if 'collected_date' not in cve:
                        cve['collected_date'] = datetime.utcnow()

                    operations.append(
                        UpdateOne(
                            {"cve_id": cve_id},
                            {"$set": cve},
                            upsert=True
                        )
                    )

                if operations:
                    # 执行批量操作
                    result = await collection.bulk_write(operations, ordered=False)

                    stats['new'] += result.upserted_count
                    stats['updated'] += result.modified_count

                    logger.info(f"批量存储CVE: {i}-{i+len(batch)}/{len(cves)}, "
                                f"新增={result.upserted_count}, 更新={result.modified_count}")

            except BulkWriteError as e:
                logger.warning(f"批量写入部分失败: {e.details}")
                stats['failed'] += len([err for err in e.details.get('writeErrors', [])])

            except Exception as e:
                logger.error(f"批量存储CVE失败: {e}")
                stats['failed'] += len(batch)

        logger.info(f"✓ CVE批量存储完成: 新增={stats['new']}, 更新={stats['updated']}, 失败={stats['failed']}")
        return stats

    async def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        获取单个CVE数据

        Args:
            cve_id: CVE ID

        Returns:
            dict or None: CVE数据
        """
        try:
            collection = self.db[self.cve_collection_name]
            cve = await collection.find_one({"cve_id": cve_id})
            return cve
        except Exception as e:
            logger.error(f"获取CVE数据失败: {e}")
            return None

    async def get_cves(
        self,
        page: int = 1,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: str = "published_date",
        sort_order: int = -1
    ) -> List[Dict[str, Any]]:
        """
        分页获取CVE数据

        Args:
            page: 页码（从1开始）
            limit: 每页数量
            filters: 过滤条件
            sort_by: 排序字段
            sort_order: 排序方向（1=升序，-1=降序）

        Returns:
            list: CVE数据列表
        """
        try:
            collection = self.db[self.cve_collection_name]

            # 构建查询条件
            query = filters if filters else {}

            # 计算跳过数量
            skip = (page - 1) * limit

            # 执行查询
            cursor = collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
            cves = await cursor.to_list(length=limit)

            return cves

        except Exception as e:
            logger.error(f"查询CVE数据失败: {e}")
            return []

    async def get_cves_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        获取CVE总数

        Args:
            filters: 过滤条件

        Returns:
            int: CVE总数
        """
        try:
            collection = self.db[self.cve_collection_name]
            query = filters if filters else {}
            count = await collection.count_documents(query)
            return count
        except Exception as e:
            logger.error(f"查询CVE总数失败: {e}")
            return 0

    async def search_cves(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        全文搜索CVE

        Args:
            keyword: 搜索关键词
            limit: 返回数量限制

        Returns:
            list: CVE数据列表
        """
        try:
            collection = self.db[self.cve_collection_name]

            # 使用全文索引搜索
            cursor = collection.find(
                {"$text": {"$search": keyword}},
                {"score": {"$meta": "textScore"}}
            ).sort([("score", {"$meta": "textScore"})]).limit(limit)

            cves = await cursor.to_list(length=limit)
            return cves

        except Exception as e:
            logger.error(f"全文搜索CVE失败: {e}")
            return []

    # ==================== Dell 数据操作 ====================

    async def store_dell_advisory(self, dell_data: Dict[str, Any]) -> bool:
        """
        存储单个Dell安全公告

        Args:
            dell_data: Dell公告数据

        Returns:
            bool: 是否为新数据
        """
        try:
            dsa_id = dell_data.get('dell_security_advisory') or dell_data.get('dsa_id')
            if not dsa_id:
                logger.warning("Dell数据缺少dsa_id")
                return False

            # 标准化字段名
            if 'dell_security_advisory' in dell_data and 'dsa_id' not in dell_data:
                dell_data['dsa_id'] = dell_data['dell_security_advisory']

            # 添加collected_date
            if 'collected_date' not in dell_data:
                dell_data['collected_date'] = datetime.utcnow()

            # Upsert操作
            collection = self.db[self.dell_collection_name]
            result = await collection.update_one(
                {"dsa_id": dsa_id},
                {"$set": dell_data},
                upsert=True
            )

            is_new = result.upserted_id is not None
            return is_new

        except DuplicateKeyError:
            logger.debug(f"Dell公告 {dsa_id} 已存在，跳过")
            return False
        except Exception as e:
            logger.error(f"存储Dell数据失败: {e}")
            return False

    async def bulk_store_dell_advisories(
        self,
        dell_advisories: List[Dict[str, Any]],
        batch_size: int = 1000
    ) -> Dict[str, int]:
        """
        批量存储Dell安全公告

        Args:
            dell_advisories: Dell公告列表
            batch_size: 批次大小

        Returns:
            dict: 统计信息
        """
        stats = {"new": 0, "updated": 0, "failed": 0}

        collection = self.db[self.dell_collection_name]

        # 分批处理
        for i in range(0, len(dell_advisories), batch_size):
            batch = dell_advisories[i:i + batch_size]

            try:
                operations = []
                for dell in batch:
                    dsa_id = dell.get('dell_security_advisory') or dell.get('dsa_id')
                    if not dsa_id:
                        stats['failed'] += 1
                        continue

                    # 标准化字段名
                    if 'dell_security_advisory' in dell and 'dsa_id' not in dell:
                        dell['dsa_id'] = dell['dell_security_advisory']

                    # 添加collected_date
                    if 'collected_date' not in dell:
                        dell['collected_date'] = datetime.utcnow()

                    operations.append(
                        UpdateOne(
                            {"dsa_id": dsa_id},
                            {"$set": dell},
                            upsert=True
                        )
                    )

                if operations:
                    result = await collection.bulk_write(operations, ordered=False)

                    stats['new'] += result.upserted_count
                    stats['updated'] += result.modified_count

                    logger.info(f"批量存储Dell: {i}-{i+len(batch)}/{len(dell_advisories)}, "
                                f"新增={result.upserted_count}, 更新={result.modified_count}")

            except BulkWriteError as e:
                logger.warning(f"批量写入部分失败: {e.details}")
                stats['failed'] += len([err for err in e.details.get('writeErrors', [])])

            except Exception as e:
                logger.error(f"批量存储Dell失败: {e}")
                stats['failed'] += len(batch)

        logger.info(f"✓ Dell批量存储完成: 新增={stats['new']}, 更新={stats['updated']}, 失败={stats['failed']}")
        return stats

    async def get_dell_advisory(self, dsa_id: str) -> Optional[Dict[str, Any]]:
        """获取单个Dell安全公告"""
        try:
            collection = self.db[self.dell_collection_name]
            dell = await collection.find_one({"dsa_id": dsa_id})
            return dell
        except Exception as e:
            logger.error(f"获取Dell数据失败: {e}")
            return None

    async def get_dell_advisories(
        self,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: str = "published_date",
        sort_order: int = -1,
        limit: int = 0
    ) -> List[Dict[str, Any]]:
        """
        获取Dell安全公告列表

        Args:
            filters: 过滤条件
            sort_by: 排序字段
            sort_order: 排序方向
            limit: 返回数量限制（0=无限制）

        Returns:
            list: Dell公告列表
        """
        try:
            collection = self.db[self.dell_collection_name]
            query = filters if filters else {}

            cursor = collection.find(query).sort(sort_by, sort_order)
            if limit > 0:
                cursor = cursor.limit(limit)

            advisories = await cursor.to_list(length=None)
            return advisories

        except Exception as e:
            logger.error(f"查询Dell数据失败: {e}")
            return []

    async def get_dell_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """获取Dell公告总数"""
        try:
            collection = self.db[self.dell_collection_name]
            query = filters if filters else {}
            count = await collection.count_documents(query)
            return count
        except Exception as e:
            logger.error(f"查询Dell总数失败: {e}")
            return 0

    async def find_dell_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        根据CVE ID查找关联的Dell公告

        Args:
            cve_id: CVE ID

        Returns:
            list: Dell公告列表
        """
        try:
            collection = self.db[self.dell_collection_name]

            # 使用数组索引查询
            cursor = collection.find({"cve_ids": cve_id})
            advisories = await cursor.to_list(length=None)

            return advisories

        except Exception as e:
            logger.error(f"查询CVE关联Dell失败: {e}")
            return []

    # ==================== 统计和聚合 ====================

    async def get_severity_stats(self) -> Dict[str, int]:
        """
        获取CVE严重程度统计

        Returns:
            dict: {'CRITICAL': 100, 'HIGH': 500, ...}
        """
        try:
            collection = self.db[self.cve_collection_name]

            pipeline = [
                {
                    "$group": {
                        "_id": "$cvss_severity",
                        "count": {"$sum": 1}
                    }
                }
            ]

            cursor = collection.aggregate(pipeline)
            results = await cursor.to_list(length=None)

            # 转换为字典
            stats = {item['_id']: item['count'] for item in results if item['_id']}

            # 确保所有严重等级都有
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if level not in stats:
                    stats[level] = 0

            return stats

        except Exception as e:
            logger.error(f"统计严重程度失败: {e}")
            return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    async def get_cve_dell_match_stats(self) -> Dict[str, Any]:
        """
        获取CVE-Dell关联统计

        Returns:
            dict: 统计信息
        """
        try:
            dell_collection = self.db[self.dell_collection_name]

            pipeline = [
                {"$unwind": "$cve_ids"},
                {
                    "$group": {
                        "_id": "$cve_ids",
                        "dell_count": {"$sum": 1},
                        "dell_ids": {"$push": "$dsa_id"}
                    }
                },
                {
                    "$group": {
                        "_id": None,
                        "total_matched_cves": {"$sum": 1},
                        "avg_dell_per_cve": {"$avg": "$dell_count"}
                    }
                }
            ]

            cursor = dell_collection.aggregate(pipeline)
            results = await cursor.to_list(length=None)

            if results:
                return {
                    "matched_cves": results[0].get('total_matched_cves', 0),
                    "avg_dell_per_cve": round(results[0].get('avg_dell_per_cve', 0), 2)
                }

            return {"matched_cves": 0, "avg_dell_per_cve": 0}

        except Exception as e:
            logger.error(f"统计CVE-Dell关联失败: {e}")
            return {"matched_cves": 0, "avg_dell_per_cve": 0}

    # ==================== 采集历史 ====================

    async def log_collection_history(self, history_data: Dict[str, Any]) -> bool:
        """
        记录采集历史

        Args:
            history_data: 历史记录数据

        Returns:
            bool: 是否成功
        """
        try:
            collection = self.db[self.history_collection_name]
            await collection.insert_one(history_data)
            return True
        except Exception as e:
            logger.error(f"记录采集历史失败: {e}")
            return False


# ==================== 同步版本（兼容性） ====================

class MongoDBManagerSync:
    """MongoDB数据管理器（同步版本）- 用于非异步环境"""

    def __init__(self, *args, **kwargs):
        """初始化时创建异步管理器"""
        self.async_manager = MongoDBManager(*args, **kwargs)
        self.loop = None

    def _run_async(self, coro):
        """在同步环境中运行异步函数"""
        if self.loop is None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

        return self.loop.run_until_complete(coro)

    def connect(self):
        """建立连接（同步）"""
        return self._run_async(self.async_manager.connect())

    def close(self):
        """关闭连接（同步）"""
        return self._run_async(self.async_manager.close())

    def store_cve(self, cve_data):
        """存储CVE（同步）"""
        return self._run_async(self.async_manager.store_cve(cve_data))

    def get_cve(self, cve_id):
        """获取CVE（同步）"""
        return self._run_async(self.async_manager.get_cve(cve_id))

    def get_cves(self, page=1, limit=100, filters=None):
        """获取CVE列表（同步）"""
        return self._run_async(self.async_manager.get_cves(page, limit, filters))

    def get_cves_count(self, filters=None):
        """获取CVE总数（同步）"""
        return self._run_async(self.async_manager.get_cves_count(filters))

    def store_dell_advisory(self, dell_data):
        """存储Dell公告（同步）"""
        return self._run_async(self.async_manager.store_dell_advisory(dell_data))

    def get_dell_advisories(self, filters=None):
        """获取Dell公告列表（同步）"""
        return self._run_async(self.async_manager.get_dell_advisories(filters))

    def get_dell_count(self, filters=None):
        """获取Dell总数（同步）"""
        return self._run_async(self.async_manager.get_dell_count(filters))

    def find_dell_by_cve(self, cve_id):
        """查找CVE关联的Dell公告（同步）"""
        return self._run_async(self.async_manager.find_dell_by_cve(cve_id))


# ==================== 测试代码 ====================

async def test_mongodb_manager():
    """测试MongoDB管理器"""
    # 创建管理器
    manager = MongoDBManager(
        host="localhost",
        port=27017,
        username="admin",
        password="secure_password"
    )

    # 连接
    connected = await manager.connect()
    if not connected:
        print("连接失败")
        return

    # 测试存储CVE
    test_cve = {
        "cve_id": "CVE-2024-TEST",
        "description": "Test CVE",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "published_date": datetime.utcnow()
    }

    is_new = await manager.store_cve(test_cve)
    print(f"存储CVE: {'新增' if is_new else '更新'}")

    # 测试查询
    cve = await manager.get_cve("CVE-2024-TEST")
    print(f"查询CVE: {cve['cve_id'] if cve else 'None'}")

    # 测试统计
    count = await manager.get_cves_count()
    print(f"CVE总数: {count}")

    stats = await manager.get_severity_stats()
    print(f"严重程度统计: {stats}")

    # 关闭连接
    await manager.close()


if __name__ == "__main__":
    # 运行测试
    asyncio.run(test_mongodb_manager())
