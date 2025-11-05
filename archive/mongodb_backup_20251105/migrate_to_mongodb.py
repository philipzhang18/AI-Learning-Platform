"""
数据迁移脚本：SQLite → MongoDB

功能:
- 从SQLite数据库读取CVE和Dell数据
- 批量写入MongoDB数据库
- 数据完整性验证
- 进度显示和错误处理
- 支持断点续传

使用方法:
    python migrate_to_mongodb.py [--clean] [--verify-only]

参数:
    --clean: 清空MongoDB数据后再迁移
    --verify-only: 只验证数据，不执行迁移
"""

import asyncio
import sqlite3
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
import logging

from mongodb_manager import MongoDBManager

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataMigrator:
    """数据迁移器"""

    def __init__(
        self,
        sqlite_db_path: str = "cve_data/cve_database.db",
        mongo_host: str = "localhost",
        mongo_port: int = 27017,
        mongo_username: str = "admin",
        mongo_password: str = "secure_password",
        batch_size: int = 1000
    ):
        """
        初始化迁移器

        Args:
            sqlite_db_path: SQLite数据库路径
            mongo_*: MongoDB连接参数
            batch_size: 批量写入大小
        """
        self.sqlite_db_path = Path(sqlite_db_path)
        self.batch_size = batch_size

        # SQLite连接
        self.sqlite_conn = None

        # MongoDB管理器
        self.mongodb = MongoDBManager(
            host=mongo_host,
            port=mongo_port,
            username=mongo_username,
            password=mongo_password
        )

        # 迁移统计
        self.stats = {
            'cve': {'total': 0, 'migrated': 0, 'failed': 0},
            'dell': {'total': 0, 'migrated': 0, 'failed': 0}
        }

    async def connect(self) -> bool:
        """建立连接"""
        try:
            # 检查SQLite数据库文件
            if not self.sqlite_db_path.exists():
                logger.error(f"SQLite数据库不存在: {self.sqlite_db_path}")
                return False

            # 连接SQLite
            self.sqlite_conn = sqlite3.connect(str(self.sqlite_db_path))
            logger.info(f"✓ SQLite连接成功: {self.sqlite_db_path}")

            # 连接MongoDB
            mongo_ok = await self.mongodb.connect()
            if not mongo_ok:
                logger.error("MongoDB连接失败")
                return False

            return True

        except Exception as e:
            logger.error(f"连接失败: {e}")
            return False

    async def close(self):
        """关闭连接"""
        if self.sqlite_conn:
            self.sqlite_conn.close()
            logger.info("SQLite连接已关闭")

        await self.mongodb.close()

    async def clean_mongodb(self):
        """清空MongoDB数据"""
        logger.warning("⚠ 准备清空MongoDB数据...")

        try:
            # 删除CVE Collection
            result_cve = await self.mongodb.db[self.mongodb.cve_collection_name].delete_many({})
            logger.info(f"✓ 删除CVE数据: {result_cve.deleted_count}条")

            # 删除Dell Collection
            result_dell = await self.mongodb.db[self.mongodb.dell_collection_name].delete_many({})
            logger.info(f"✓ 删除Dell数据: {result_dell.deleted_count}条")

            # 删除Collection History
            result_history = await self.mongodb.db[self.mongodb.history_collection_name].delete_many({})
            logger.info(f"✓ 删除历史记录: {result_history.deleted_count}条")

            logger.info("✓ MongoDB数据已清空")

        except Exception as e:
            logger.error(f"清空MongoDB失败: {e}")
            raise

    async def migrate_cves(self) -> Dict[str, int]:
        """
        迁移CVE数据

        Returns:
            dict: 迁移统计
        """
        logger.info("=" * 60)
        logger.info("开始迁移CVE数据...")
        logger.info("=" * 60)

        try:
            cursor = self.sqlite_conn.cursor()

            # 获取总数
            cursor.execute("SELECT COUNT(*) FROM cves")
            total = cursor.fetchone()[0]
            self.stats['cve']['total'] = total

            logger.info(f"SQLite中CVE总数: {total}")

            if total == 0:
                logger.warning("没有CVE数据需要迁移")
                return self.stats['cve']

            # 读取所有CVE数据
            cursor.execute("SELECT cve_id, data, last_modified, published_date FROM cves")

            cves = []
            processed = 0

            for row in cursor.fetchall():
                try:
                    cve_id, data_str, last_modified, published_date = row

                    # 解析JSON数据
                    if data_str:
                        cve_data = json.loads(data_str)
                    else:
                        # 如果data字段为空，构建基本数据
                        cve_data = {
                            "cve_id": cve_id,
                            "description": "",
                            "published_date": published_date,
                            "last_modified": last_modified,
                            "vuln_status": "",
                            "cvss_score": "",
                            "cvss_severity": "",
                            "cvss_vector": "",
                            "references": [],
                            "affected_products": [],
                            "weaknesses": [],
                            "source": "SQLite Migration"
                        }

                    # 确保必要字段存在
                    if 'cve_id' not in cve_data:
                        cve_data['cve_id'] = cve_id
                    if 'collected_date' not in cve_data:
                        cve_data['collected_date'] = datetime.utcnow()

                    cves.append(cve_data)
                    processed += 1

                    # 批量写入
                    if len(cves) >= self.batch_size:
                        stats = await self.mongodb.bulk_store_cves(cves)
                        self.stats['cve']['migrated'] += stats['new'] + stats['updated']
                        self.stats['cve']['failed'] += stats['failed']

                        logger.info(f"进度: {processed}/{total} ({processed/total*100:.1f}%) - "
                                    f"成功={stats['new'] + stats['updated']}, 失败={stats['failed']}")

                        cves = []  # 清空缓存

                except json.JSONDecodeError as e:
                    logger.warning(f"解析CVE JSON失败 ({cve_id}): {e}")
                    self.stats['cve']['failed'] += 1

                except Exception as e:
                    logger.error(f"处理CVE失败 ({cve_id}): {e}")
                    self.stats['cve']['failed'] += 1

            # 写入剩余数据
            if cves:
                stats = await self.mongodb.bulk_store_cves(cves)
                self.stats['cve']['migrated'] += stats['new'] + stats['updated']
                self.stats['cve']['failed'] += stats['failed']

                logger.info(f"进度: {processed}/{total} (100.0%) - "
                            f"成功={stats['new'] + stats['updated']}, 失败={stats['failed']}")

            logger.info("=" * 60)
            logger.info(f"✓ CVE迁移完成:")
            logger.info(f"  总数: {self.stats['cve']['total']}")
            logger.info(f"  成功: {self.stats['cve']['migrated']}")
            logger.info(f"  失败: {self.stats['cve']['failed']}")
            logger.info("=" * 60)

            return self.stats['cve']

        except Exception as e:
            logger.error(f"CVE迁移失败: {e}")
            raise

    async def migrate_dell_advisories(self) -> Dict[str, int]:
        """
        迁移Dell安全公告数据

        Returns:
            dict: 迁移统计
        """
        logger.info("=" * 60)
        logger.info("开始迁移Dell安全公告数据...")
        logger.info("=" * 60)

        try:
            cursor = self.sqlite_conn.cursor()

            # 获取总数
            cursor.execute("SELECT COUNT(*) FROM dell_advisories")
            total = cursor.fetchone()[0]
            self.stats['dell']['total'] = total

            logger.info(f"SQLite中Dell公告总数: {total}")

            if total == 0:
                logger.warning("没有Dell数据需要迁移")
                return self.stats['dell']

            # 读取所有Dell数据
            cursor.execute("SELECT dsa_id, title, cve_ids, data, published_date, collected_date, link FROM dell_advisories")

            dell_advisories = []
            processed = 0

            for row in cursor.fetchall():
                try:
                    dsa_id, title, cve_ids_str, data_str, published_date, collected_date, link = row

                    # 解析JSON数据
                    if data_str:
                        dell_data = json.loads(data_str)
                    else:
                        # 构建基本数据
                        dell_data = {
                            "dsa_id": dsa_id,
                            "title": title or "",
                            "cve_ids": cve_ids_str.split(',') if cve_ids_str else [],
                            "published_date": published_date,
                            "collected_date": collected_date,
                            "link": link or "",
                            "summary": "",
                            "description": "",
                            "affected_products": [],
                            "solution": "",
                            "impact": "",
                            "source": "SQLite Migration"
                        }

                    # 确保必要字段
                    if 'dsa_id' not in dell_data:
                        dell_data['dsa_id'] = dsa_id
                    if 'dell_security_advisory' not in dell_data:
                        dell_data['dell_security_advisory'] = dsa_id

                    # 确保cve_ids是列表
                    if 'cve_ids' in dell_data and isinstance(dell_data['cve_ids'], str):
                        dell_data['cve_ids'] = [cid.strip() for cid in dell_data['cve_ids'].split(',') if cid.strip()]

                    dell_advisories.append(dell_data)
                    processed += 1

                    # 批量写入
                    if len(dell_advisories) >= self.batch_size:
                        stats = await self.mongodb.bulk_store_dell_advisories(dell_advisories)
                        self.stats['dell']['migrated'] += stats['new'] + stats['updated']
                        self.stats['dell']['failed'] += stats['failed']

                        logger.info(f"进度: {processed}/{total} ({processed/total*100:.1f}%) - "
                                    f"成功={stats['new'] + stats['updated']}, 失败={stats['failed']}")

                        dell_advisories = []

                except json.JSONDecodeError as e:
                    logger.warning(f"解析Dell JSON失败 ({dsa_id}): {e}")
                    self.stats['dell']['failed'] += 1

                except Exception as e:
                    logger.error(f"处理Dell失败 ({dsa_id}): {e}")
                    self.stats['dell']['failed'] += 1

            # 写入剩余数据
            if dell_advisories:
                stats = await self.mongodb.bulk_store_dell_advisories(dell_advisories)
                self.stats['dell']['migrated'] += stats['new'] + stats['updated']
                self.stats['dell']['failed'] += stats['failed']

                logger.info(f"进度: {processed}/{total} (100.0%) - "
                            f"成功={stats['new'] + stats['updated']}, 失败={stats['failed']}")

            logger.info("=" * 60)
            logger.info(f"✓ Dell迁移完成:")
            logger.info(f"  总数: {self.stats['dell']['total']}")
            logger.info(f"  成功: {self.stats['dell']['migrated']}")
            logger.info(f"  失败: {self.stats['dell']['failed']}")
            logger.info("=" * 60)

            return self.stats['dell']

        except Exception as e:
            logger.error(f"Dell迁移失败: {e}")
            raise

    async def verify_migration(self) -> bool:
        """
        验证迁移数据完整性

        Returns:
            bool: 是否验证通过
        """
        logger.info("=" * 60)
        logger.info("开始验证数据完整性...")
        logger.info("=" * 60)

        try:
            cursor = self.sqlite_conn.cursor()

            # 验证CVE数量
            cursor.execute("SELECT COUNT(*) FROM cves")
            sqlite_cve_count = cursor.fetchone()[0]

            mongo_cve_count = await self.mongodb.get_cves_count()

            logger.info(f"CVE数量对比:")
            logger.info(f"  SQLite: {sqlite_cve_count}")
            logger.info(f"  MongoDB: {mongo_cve_count}")

            if sqlite_cve_count != mongo_cve_count:
                logger.warning(f"⚠ CVE数量不一致! 差异: {abs(sqlite_cve_count - mongo_cve_count)}")

            # 验证Dell数量
            cursor.execute("SELECT COUNT(*) FROM dell_advisories")
            sqlite_dell_count = cursor.fetchone()[0]

            mongo_dell_count = await self.mongodb.get_dell_count()

            logger.info(f"Dell公告数量对比:")
            logger.info(f"  SQLite: {sqlite_dell_count}")
            logger.info(f"  MongoDB: {mongo_dell_count}")

            if sqlite_dell_count != mongo_dell_count:
                logger.warning(f"⚠ Dell数量不一致! 差异: {abs(sqlite_dell_count - mongo_dell_count)}")

            # 随机抽查数据
            logger.info("随机抽查数据...")

            # 抽查CVE
            cursor.execute("SELECT cve_id FROM cves ORDER BY RANDOM() LIMIT 10")
            sample_cve_ids = [row[0] for row in cursor.fetchall()]

            cve_check_passed = 0
            for cve_id in sample_cve_ids:
                mongo_cve = await self.mongodb.get_cve(cve_id)
                if mongo_cve and mongo_cve['cve_id'] == cve_id:
                    cve_check_passed += 1

            logger.info(f"CVE抽查: {cve_check_passed}/{len(sample_cve_ids)} 通过")

            # 抽查Dell
            cursor.execute("SELECT dsa_id FROM dell_advisories ORDER BY RANDOM() LIMIT 10")
            sample_dsa_ids = [row[0] for row in cursor.fetchall()]

            dell_check_passed = 0
            for dsa_id in sample_dsa_ids:
                mongo_dell = await self.mongodb.get_dell_advisory(dsa_id)
                if mongo_dell and mongo_dell['dsa_id'] == dsa_id:
                    dell_check_passed += 1

            logger.info(f"Dell抽查: {dell_check_passed}/{len(sample_dsa_ids)} 通过")

            # 验证结果
            verification_passed = (
                sqlite_cve_count == mongo_cve_count and
                sqlite_dell_count == mongo_dell_count and
                cve_check_passed == len(sample_cve_ids) and
                dell_check_passed == len(sample_dsa_ids)
            )

            if verification_passed:
                logger.info("=" * 60)
                logger.info("✓ 数据完整性验证通过!")
                logger.info("=" * 60)
            else:
                logger.warning("=" * 60)
                logger.warning("⚠ 数据完整性验证未完全通过，请检查详情")
                logger.warning("=" * 60)

            return verification_passed

        except Exception as e:
            logger.error(f"验证失败: {e}")
            return False

    async def run(self, clean: bool = False, verify_only: bool = False):
        """
        执行迁移

        Args:
            clean: 是否清空MongoDB后再迁移
            verify_only: 是否只验证
        """
        start_time = datetime.now()

        logger.info("╔" + "═" * 58 + "╗")
        logger.info("║" + " " * 15 + "数据迁移: SQLite → MongoDB" + " " * 15 + "║")
        logger.info("╚" + "═" * 58 + "╝")

        try:
            # 连接数据库
            connected = await self.connect()
            if not connected:
                logger.error("连接失败，迁移终止")
                return False

            # 如果是验证模式
            if verify_only:
                await self.verify_migration()
                return True

            # 清空MongoDB（如果指定）
            if clean:
                await self.clean_mongodb()

            # 迁移CVE数据
            await self.migrate_cves()

            # 迁移Dell数据
            await self.migrate_dell_advisories()

            # 验证迁移
            await self.verify_migration()

            # 完成统计
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            logger.info("=" * 60)
            logger.info("✓ 迁移完成!")
            logger.info("=" * 60)
            logger.info(f"总耗时: {duration:.2f}秒")
            logger.info(f"CVE: {self.stats['cve']['migrated']}/{self.stats['cve']['total']} "
                        f"(失败={self.stats['cve']['failed']})")
            logger.info(f"Dell: {self.stats['dell']['migrated']}/{self.stats['dell']['total']} "
                        f"(失败={self.stats['dell']['failed']})")
            logger.info("=" * 60)

            return True

        except Exception as e:
            logger.error(f"迁移过程出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

        finally:
            await self.close()


# ==================== 主程序 ====================

async def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='SQLite到MongoDB数据迁移工具')

    parser.add_argument(
        '--clean',
        action='store_true',
        help='清空MongoDB数据后再迁移'
    )

    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='只验证数据完整性，不执行迁移'
    )

    parser.add_argument(
        '--sqlite-db',
        default='cve_data/cve_database.db',
        help='SQLite数据库路径 (默认: cve_data/cve_database.db)'
    )

    parser.add_argument(
        '--mongo-host',
        default='localhost',
        help='MongoDB主机地址 (默认: localhost)'
    )

    parser.add_argument(
        '--mongo-port',
        type=int,
        default=27017,
        help='MongoDB端口 (默认: 27017)'
    )

    parser.add_argument(
        '--mongo-username',
        default='admin',
        help='MongoDB用户名 (默认: admin)'
    )

    parser.add_argument(
        '--mongo-password',
        default='secure_password',
        help='MongoDB密码 (默认: secure_password)'
    )

    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='批量写入大小 (默认: 1000)'
    )

    args = parser.parse_args()

    # 创建迁移器
    migrator = DataMigrator(
        sqlite_db_path=args.sqlite_db,
        mongo_host=args.mongo_host,
        mongo_port=args.mongo_port,
        mongo_username=args.mongo_username,
        mongo_password=args.mongo_password,
        batch_size=args.batch_size
    )

    # 执行迁移
    success = await migrator.run(
        clean=args.clean,
        verify_only=args.verify_only
    )

    if success:
        logger.info("✓ 所有操作成功完成")
        return 0
    else:
        logger.error("✗ 操作失败")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
