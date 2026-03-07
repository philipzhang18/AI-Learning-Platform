"""
CVE漏洞检测系统(Dell安全公告版)
集成 NVD CVE 数据和 Dell 安全公告
支持离线数据查看和 CVE ID 关联匹配
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import aiohttp
import feedparser
import json
import csv
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import threading
import queue
import os
import atexit
import signal
import sys

# 导入自定义模块
from collect_cves import CVECollector
from dell_security_scraper import DellSecurityScraper
from redis_manager import RedisDataManager


class CVEIntegratedGUI:
    """CVE 漏洞监控系统整合界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("CVE漏洞检测系统(Dell安全公告版)")
        self.root.geometry("1400x900")

        # 设置主题颜色
        self.bg_color = "#f0f0f0"
        self.primary_color = "#2c3e50"
        self.success_color = "#27ae60"
        self.danger_color = "#e74c3c"
        self.warning_color = "#f39c12"
        self.info_color = "#3498db"

        self.root.configure(bg=self.bg_color)

        # 数据队列（用于线程间通信）
        self.data_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.dell_queue = queue.Queue()
        self.sqlite_backup_queue = queue.Queue()  # SQLite 异步备份队列
        self.matched_tree_queue = queue.Queue()  # 关联树视图队列

        # ✅ 修复 #2: 添加数据库访问锁（线程安全）
        self.db_lock = threading.Lock()

        # ✅ 修复 #4: 添加清理标志（防止重复清理）
        self._cleaned_up = False
        self._cleanup_lock = threading.Lock()

        # 数据存储
        self.cve_data = []
        self.dell_advisories = []
        self.is_collecting = False
        self.is_collecting_dell = False

        # IT新闻早晚报数据
        self.news_articles = []          # 采集到的新闻文章列表
        self.is_collecting_news = False  # 新闻采集状态标志
        self.news_brief_text = ""        # 当前生成的简报文本
        self._tts_process = None         # TTS 播放子进程句柄

        # 智能学习数据
        self.learn_messages = []         # 费曼对话历史
        self.learn_topic = ""            # 当前学习主题
        self.learn_source_content = ""   # 加载的内容上下文
        self.is_learn_generating = False # AI生成状态标志

        # 数据目录
        self.data_dir = Path("cve_data")
        self.data_dir.mkdir(exist_ok=True)

        # 初始化 Redis 数据管理器（根据配置决定是否使用）
        self.use_redis = False
        self.redis_init_message = ""

        # 检查环境变量配置
        use_redis_config = os.getenv('USE_REDIS', 'false').lower() == 'true'
        redis_enabled_config = os.getenv('REDIS_ENABLED', 'false').lower() == 'true'

        # 只有配置明确启用 Redis 时才尝试连接
        if use_redis_config or redis_enabled_config:
            try:
                self.redis_manager = RedisDataManager(
                    password=os.getenv('REDIS_PASSWORD', '')
                )
                if self.redis_manager.ping():
                    self.use_redis = True
                    self.redis_init_message = "Redis 已连接 - 使用高性能缓存模式"
                else:
                    self.redis_init_message = "Redis 连接失败 - 回退到 SQLite 模式"
            except Exception as e:
                self.redis_init_message = f"Redis 初始化失败: {e} - 回退到 SQLite 模式"
        else:
            self.redis_init_message = "Redis 已禁用 - 使用 SQLite 独立模式"

        # 初始化本地数据库（作为备份）
        self.init_database()

        # 创建界面
        self.create_widgets()

        # 显示 Redis 初始化消息
        if self.redis_init_message:
            self.log(self.redis_init_message)

        # 启动 SQLite 异步备份线程
        self.start_sqlite_backup_thread()

        # 启动队列检查
        self.check_queues()

        # 加载本地数据 (修改：仅加载统计数据，不自动开始采集)
        self.load_local_data_summary()

        # ✅ 修复 #4: 注册退出处理程序和信号处理
        atexit.register(self.cleanup)

        # 处理系统信号（仅在非 Windows 或支持的情况下）
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (AttributeError, ValueError) as e:
            # Windows 或某些环境可能不支持所有信号
            self.log(f"信号处理器注册部分失败（可忽略）: {e}")

    def init_database(self):
        """初始化本地数据库（性能优化版）"""
        self.db_path = self.data_dir / "cve_database.db"

        # 创建数据库连接（允许多线程）
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db_conn = self.conn  # 为了兼容旧代码，设置db_conn别名

        # SQLite 性能优化配置
        optimizations = [
            'PRAGMA journal_mode=WAL',           # WAL 模式，提升并发性能
            'PRAGMA cache_size=20000',           # 增加缓存大小（~80MB）for better performance
            'PRAGMA synchronous=NORMAL',         # 平衡性能和安全
            'PRAGMA temp_store=MEMORY',          # 临时数据存储在内存
            'PRAGMA mmap_size=30000000000',      # 内存映射 I/O（30GB）
            'PRAGMA page_size=4096',             # 页大小 4KB
            'PRAGMA auto_vacuum=INCREMENTAL',    # 增量自动清理
            'PRAGMA foreign_keys=ON',            # 启用外键约束
            'PRAGMA locking_mode=NORMAL',        # Set appropriate locking mode
            'PRAGMA busy_timeout=30000'          # 30s timeout for busy operations
        ]

        for pragma in optimizations:
            self.conn.execute(pragma)

        self.create_tables()
        # 检查并更新数据库表结构（如果需要）
        self.update_database_schema()
        
    def create_tables(self):
        """创建数据库表"""
        try:
            cursor = self.conn.cursor()

            # CVE数据表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    last_modified TEXT,
                    published_date TEXT
                )
            ''')

            # Dell安全公告表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dell_advisories (
                    dsa_id TEXT PRIMARY KEY,
                    title TEXT,
                    cve_ids TEXT,
                    data TEXT NOT NULL,
                    published_date TEXT,
                    collected_date TEXT,
                    link TEXT
                )
            ''')

            # 采集历史表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    collected_date TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
                )
            ''')

            # AI解决方案表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_solutions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    dell_advisory_id TEXT NOT NULL,
                    analysis_time TEXT NOT NULL,
                    model_name TEXT,
                    prompt TEXT,
                    result TEXT,
                    status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indexes for better query performance
            # Index on published_date for date-based queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_last_modified ON cves(last_modified)")

            # Index for Dell advisories
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dell_published_date ON dell_advisories(published_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dell_cve_ids ON dell_advisories(cve_ids)")

            # Index for AI solutions
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_cve ON ai_solutions(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_advisory ON ai_solutions(dell_advisory_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_time ON ai_solutions(analysis_time)")

            self.conn.commit()
        except sqlite3.Error as e:
            self.log(f"创建数据库表失败: {str(e)}")
    
    def update_database_schema(self):
        """更新数据库表结构（如果需要）"""
        try:
            cursor = self.conn.cursor()

            # 检查表结构信息
            # PRAGMA table_info返回: (cid, name, type, notnull, dflt_value, pk)
            cursor.execute("PRAGMA table_info(cves)")
            columns_info = cursor.fetchall()
            columns = [col[1] for col in columns_info]
            primary_keys = [col[1] for col in columns_info if col[5] == 1]

            # 如果没有 'data' 列，则添加
            if 'data' not in columns:
                # 重新创建表以添加缺失的列
                cursor.execute("ALTER TABLE cves ADD COLUMN data TEXT DEFAULT ''")

            # 检查并修复其他可能的问题
            # 如果主键定义不当，重新创建表
            if 'cve_id' not in columns or 'cve_id' not in primary_keys:
                # Create the proper table if it doesn't exist
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cves_new (
                        cve_id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        last_modified TEXT,
                        published_date TEXT
                    )
                ''')

                # Copy data from old table if it exists and has data
                try:
                    cursor.execute("SELECT cve_id, last_modified, published_date FROM cves")
                    rows = cursor.fetchall()
                    for row in rows:
                        cursor.execute('''
                            INSERT OR REPLACE INTO cves_new (cve_id, data, last_modified, published_date)
                            VALUES (?, ?, ?, ?)
                        ''', (row[0], '', row[1], row[2]))

                    # Drop old table and rename new table
                    cursor.execute("DROP TABLE cves")
                    cursor.execute("ALTER TABLE cves_new RENAME TO cves")
                    self.log("数据库表结构已更新，主键已修正")
                except sqlite3.Error as e:
                    # If the old table structure is different, just create the new one
                    self.log(f"数据库表迁移失败，将创建新表: {e}")

            self.conn.commit()
        except sqlite3.Error as e:
            self.log(f"更新数据库表结构失败: {str(e)}")
    
    def get_existing_cve_ids(self):
        """获取数据库中已存在的CVE IDs"""
        try:
            cursor = self.conn.cursor()
            # Optimize query: use a more efficient approach for large datasets
            cursor.execute("SELECT cve_id FROM cves")
            # Use fetchmany for better memory usage with large datasets
            existing_ids = []
            while True:
                rows = cursor.fetchmany(1000)  # Fetch 1000 rows at a time
                if not rows:
                    break
                existing_ids.extend([row[0] for row in rows])
            return set(existing_ids)
        except sqlite3.Error as e:
            self.log(f"查询现有CVE IDs失败: {str(e)}")
            return set()

    def start_sqlite_backup_thread(self):
        """启动 SQLite 异步备份线程"""
        def backup_worker():
            """SQLite 备份工作线程"""
            while True:
                try:
                    # 从队列获取备份任务（阻塞等待）
                    data_type, data = self.sqlite_backup_queue.get(timeout=1)

                    if data_type == 'cve':
                        self._store_cve_to_sqlite(data)
                    elif data_type == 'dell':
                        self._store_dell_to_sqlite(data)

                    # 标记任务完成
                    self.sqlite_backup_queue.task_done()

                except queue.Empty:
                    # 队列为空，继续等待
                    continue
                except Exception as e:
                    # 记录错误但不停止线程
                    print(f"SQLite 备份线程错误: {e}")
                    continue

        # 创建守护线程（应用退出时自动结束）
        backup_thread = threading.Thread(target=backup_worker, daemon=True)
        backup_thread.start()
        self.log("SQLite 异步备份线程已启动")

    def store_cve_data(self, cve_data):
        """存储单个CVE数据到数据库（Redis主存储，SQLite异步备份）"""
        # 生产环境：只使用 Redis，SQLite 异步备份
        if self.use_redis:
            try:
                is_new = self.redis_manager.store_cve(cve_data)

                # ✅ 异步备份到 SQLite
                self.sqlite_backup_queue.put(('cve', cve_data))

                return is_new
            except Exception as e:
                self.log(f"存储到 Redis 失败: {e}, 回退到 SQLite")
                # Redis 失败时直接写 SQLite
                return self._store_cve_to_sqlite(cve_data)

        # SQLite 存储（回退方案）
        return self._store_cve_to_sqlite(cve_data)

    def bulk_store_cve_data(self, cve_list):
        """批量存储CVE数据到数据库（优化大量数据插入性能）"""
        if not cve_list:
            return

        if self.use_redis:
            try:
                # Bulk store to Redis if supported
                new_count = 0
                for cve_data in cve_list:
                    is_new = self.redis_manager.store_cve(cve_data)
                    if is_new:
                        new_count += 1

                # Add all to SQLite backup queue
                for cve_data in cve_list:
                    self.sqlite_backup_queue.put(('cve', cve_data))

                return new_count
            except Exception as e:
                self.log(f"批量存储到 Redis 失败: {e}, 回退到 SQLite")
                # Fall back to SQLite bulk insert
                return self._bulk_store_cve_to_sqlite(cve_list)

        # SQLite bulk storage (fallback)
        return self._bulk_store_cve_to_sqlite(cve_list)

    def _bulk_store_cve_to_sqlite(self, cve_list):
        """批量存储CVE数据到SQLite（事务处理，提高性能）"""
        with self.db_lock:
            try:
                cursor = self.conn.cursor()

                # Start transaction for better performance
                cursor.execute("BEGIN TRANSACTION")

                new_count = 0

                for cve_data in cve_list:
                    cve_id = cve_data.get('cve_id', '')
                    if not cve_id:
                        continue

                    data_str = json.dumps(cve_data) if cve_data else '{}'

                    # Use INSERT OR REPLACE to handle both new and update cases efficiently
                    cursor.execute('''
                        INSERT OR REPLACE INTO cves (cve_id, data, last_modified, published_date)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        cve_id,
                        data_str,
                        cve_data.get('last_modified', '') or '',
                        cve_data.get('published_date', '') or ''
                    ))

                    # Insert into collection history
                    cursor.execute('''
                        INSERT INTO collection_history (cve_id, collected_date)
                        VALUES (?, ?)
                    ''', (cve_id, datetime.now().isoformat()))

                    new_count += 1

                self.conn.commit()
                return new_count
            except sqlite3.Error as e:
                self.log(f"批量存储CVE数据失败: {str(e)}")
                try:
                    self.conn.rollback()
                except sqlite3.Error as rollback_err:
                    self.log(f"批量存储回滚失败: {rollback_err}")
                return 0
            except Exception as e:
                self.log(f"批量存储CVE数据时发生未知错误: {str(e)}")
                return 0

    def _store_cve_to_sqlite(self, cve_data):
        """存储 CVE 数据到 SQLite（内部方法，线程安全）"""
        # ✅ 修复 #2: 使用锁保护数据库操作
        with self.db_lock:
            try:
                cursor = self.conn.cursor()

                cve_id = cve_data.get('cve_id', '')
                if not cve_id:
                    return False

                # Ensure the data field is not None
                data_str = json.dumps(cve_data) if cve_data else '{}'

                # 检查是否已存在
                cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
                is_new = cursor.fetchone() is None

                if not is_new:
                    # 更新现有记录
                    cursor.execute('''
                        UPDATE cves
                        SET data = ?, last_modified = ?, published_date = ?
                        WHERE cve_id = ?
                    ''', (
                        data_str,
                        cve_data.get('last_modified', '') or '',
                        cve_data.get('published_date', '') or '',
                        cve_id
                    ))
                else:
                    # 插入新记录
                    cursor.execute('''
                        INSERT INTO cves (cve_id, data, last_modified, published_date)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        cve_id,
                        data_str,
                        cve_data.get('last_modified', '') or '',
                        cve_data.get('published_date', '') or ''
                    ))

                # 添加到采集历史
                cursor.execute('''
                    INSERT INTO collection_history (cve_id, collected_date)
                    VALUES (?, ?)
                ''', (cve_id, datetime.now().isoformat()))

                self.conn.commit()
                return is_new
            except sqlite3.Error as e:
                self.log(f"存储CVE数据失败: {str(e)}")
                # 尝试回滚事务
                try:
                    self.conn.rollback()
                except sqlite3.Error as rollback_err:
                    self.log(f"回滚失败: {rollback_err}")
                return False
            except Exception as e:
                self.log(f"存储CVE数据时发生未知错误: {str(e)}")
                return False
    
    def load_cve_data_from_db(self, cve_ids=None):
        """从数据库加载CVE数据（优先使用 Redis）"""
        # 优先从 Redis 加载
        if self.use_redis:
            try:
                if cve_ids:
                    # 加载指定的 CVE
                    cve_data = []
                    for cve_id in cve_ids:
                        data = self.redis_manager.get_cve(cve_id)
                        if data:
                            cve_data.append(data)
                else:
                    # 加载所有 CVE
                    cve_data = self.redis_manager.get_all_cves()

                self.log(f"从 Redis 加载了 {len(cve_data)} 条 CVE 数据")
                return cve_data
            except Exception as e:
                self.log(f"Redis 加载失败: {e}, 回退到 SQLite")
                # 如果 Redis 失败，继续使用 SQLite

        # 从 SQLite 加载（回退方案）
        try:
            cursor = self.conn.cursor()
            if cve_ids:
                placeholders = ','.join(['?' for _ in cve_ids])
                cursor.execute(f"SELECT cve_id, data, last_modified, published_date FROM cves WHERE cve_id IN ({placeholders})", cve_ids)
            else:
                cursor.execute("SELECT cve_id, data, last_modified, published_date FROM cves")

            # Optimize memory usage for large datasets
            cve_data = []
            batch_size = 1000  # Process in batches to optimize memory

            while True:
                records = cursor.fetchmany(batch_size)  # Fetch in batches
                if not records:
                    break

                for record in records:
                    try:
                        # First try to load the stored JSON data
                        if record[1]:  # The data field is not empty
                            data = json.loads(record[1])
                            cve_data.append(data)
                        else:
                            # If data is empty but we have basic info, create a minimal record
                            # This handles cases where the schema may be inconsistent
                            cve_entry = {
                                "cve_id": record[0],
                                "description": "",
                                "published_date": record[3],
                                "last_modified": record[2],
                                "vuln_status": "",
                                "cvss_score": "",
                                "cvss_severity": "",
                                "cvss_vector": "",
                                "references": [],
                                "affected_products": [],
                                "weaknesses": [],
                                "source": "Database"
                            }
                            cve_data.append(cve_entry)
                    except json.JSONDecodeError:
                        # If JSON parsing fails, create a minimal record
                        cve_entry = {
                            "cve_id": record[0],
                            "description": "",
                            "published_date": record[3],
                            "last_modified": record[2],
                            "vuln_status": "",
                            "cvss_score": "",
                            "cvss_severity": "",
                            "cvss_vector": "",
                            "references": [],
                            "affected_products": [],
                            "weaknesses": [],
                            "source": "Database"
                        }
                        cve_data.append(cve_entry)
            return cve_data
        except sqlite3.Error as e:
            self.log(f"从数据库加载CVE数据失败: {str(e)}")
            return []

    def load_recent_cve_data(self, limit=2000):
        """从数据库加载最近的CVE数据（按发布日期倒序）

        Args:
            limit: 加载数量限制

        Returns:
            list: CVE数据列表
        """
        # 优先从 Redis 加载
        if self.use_redis:
            try:
                # Redis 加载全部后排序取最近的
                all_cves = self.redis_manager.get_all_cves()
                # 按发布日期排序
                sorted_cves = sorted(all_cves, key=lambda x: x.get('published_date', ''), reverse=True)
                return sorted_cves[:limit]
            except Exception as e:
                self.log(f"Redis 加载失败: {e}, 回退到 SQLite")

        # 从 SQLite 加载最近的数据
        try:
            cursor = self.conn.cursor()
            # 按发布日期倒序，只取最近的 limit 条
            cursor.execute(f"SELECT cve_id, data, last_modified, published_date FROM cves ORDER BY published_date DESC LIMIT {limit}")

            records = cursor.fetchall()
            cve_data = []
            for record in records:
                try:
                    if record[1]:
                        data = json.loads(record[1])
                        cve_data.append(data)
                    else:
                        cve_entry = {
                            "cve_id": record[0],
                            "description": "",
                            "published_date": record[3],
                            "last_modified": record[2],
                            "vuln_status": "",
                            "cvss_score": "",
                            "cvss_severity": "",
                            "cvss_vector": "",
                            "references": [],
                            "affected_products": [],
                            "weaknesses": [],
                            "source": "Database"
                        }
                        cve_data.append(cve_entry)
                except json.JSONDecodeError:
                    cve_entry = {
                        "cve_id": record[0],
                        "description": "",
                        "published_date": record[3],
                        "last_modified": record[2],
                        "vuln_status": "",
                        "cvss_score": "",
                        "cvss_severity": "",
                        "cvss_vector": "",
                        "references": [],
                        "affected_products": [],
                        "weaknesses": [],
                        "source": "Database"
                    }
                    cve_data.append(cve_entry)
            return cve_data
        except sqlite3.Error as e:
            self.log(f"从数据库加载最近CVE数据失败: {str(e)}")
            return []

    def get_last_collection_date(self):
        """获取最近一次采集时间"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT MAX(collected_date) FROM collection_history
            ''')
            result = cursor.fetchone()
            return result[0] if result and result[0] else None
        except sqlite3.Error as e:
            self.log(f"查询最近采集时间失败: {str(e)}")
            return None

    # ==================== Dell 数据库操作方法 ====================

    def get_existing_dell_ids(self):
        """获取数据库中已存在的Dell安全公告IDs"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT dsa_id FROM dell_advisories")
            existing_ids = [row[0] for row in cursor.fetchall()]
            return set(existing_ids)
        except sqlite3.Error as e:
            self.log(f"查询现有Dell IDs失败: {str(e)}")
            return set()

    def store_dell_advisory(self, advisory_data):
        """存储单个Dell安全公告到数据库（Redis主存储，SQLite异步备份）"""
        # 生产环境：只使用 Redis，SQLite 异步备份
        if self.use_redis:
            try:
                is_new = self.redis_manager.store_dell_advisory(advisory_data)

                # ✅ 异步备份到 SQLite
                self.sqlite_backup_queue.put(('dell', advisory_data))

                return is_new  # 返回是否是新数据
            except Exception as e:
                self.log(f"存储 Dell 数据到 Redis 失败: {e}, 回退到 SQLite")
                # Redis 失败时直接写 SQLite
                return self._store_dell_to_sqlite(advisory_data)

        # SQLite 存储（回退方案）
        return self._store_dell_to_sqlite(advisory_data)

    def _store_dell_to_sqlite(self, advisory_data):
        """存储 Dell 数据到 SQLite（内部方法，线程安全）"""
        # ✅ 修复 #2: 使用锁保护数据库操作
        with self.db_lock:
            try:
                cursor = self.conn.cursor()

                dsa_id = advisory_data.get('dell_security_advisory', '')
                if not dsa_id:
                    return False  # 返回False表示未存储

                # 检查是否已存在
                cursor.execute("SELECT 1 FROM dell_advisories WHERE dsa_id = ?", (dsa_id,))
                is_new = cursor.fetchone() is None

                if not is_new:
                    # 已存在，跳过
                    return False

                # 不存在，插入新记录
                cve_ids_str = ','.join(advisory_data.get('cve_ids', []))
                data_str = json.dumps(advisory_data, ensure_ascii=False)

                cursor.execute('''
                    INSERT INTO dell_advisories
                    (dsa_id, title, cve_ids, data, published_date, collected_date, link)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    dsa_id,
                    advisory_data.get('title', ''),
                    cve_ids_str,
                    data_str,
                    advisory_data.get('published_date', ''),
                    datetime.now().isoformat(),
                    advisory_data.get('link', '')
                ))

                self.conn.commit()
                return True  # 返回True表示新增了记录
            except sqlite3.Error as e:
                self.log(f"存储Dell数据失败: {str(e)}")
                return False

    def get_dell_count_from_db(self):
        """获取Dell安全公告总数（从实际数据库）

        Returns:
            int: Dell记录总数
        """
        if self.use_redis:
            try:
                return self.redis_manager.get_dell_count()
            except Exception as e:
                self.log(f"从Redis获取Dell总数失败: {e}")
                # 回退到SQLite
                pass

        # SQLite模式或Redis失败时
        try:
            # Use a more efficient COUNT query with index
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM dell_advisories")
            count = cursor.fetchone()[0]
            return count
        except Exception as e:
            self.log(f"从SQLite获取Dell总数失败: {e}")
            return 0

    def get_cve_count_from_db(self):
        """获取CVE总数（从实际数据库）

        Returns:
            int: CVE记录总数
        """
        if self.use_redis:
            try:
                return self.redis_manager.get_cves_count()
            except Exception as e:
                self.log(f"从Redis获取CVE总数失败: {e}")
                pass

        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cves")
            count = cursor.fetchone()[0]
            return count
        except Exception as e:
            self.log(f"从SQLite获取CVE总数失败: {e}")
            return 0

    def get_matched_count_from_db(self):
        """从数据库计算CVE-Dell关联匹配数（不依赖内存）

        Returns:
            int: 匹配的CVE数量
        """
        try:
            cursor = self.conn.cursor()

            # 1. 获取所有Dell公告中的CVE IDs
            cursor.execute('SELECT data FROM dell_advisories')
            records = cursor.fetchall()

            all_dell_cve_ids = set()
            for record in records:
                try:
                    data = json.loads(record[0])
                    cve_ids = data.get('cve_ids', [])
                    all_dell_cve_ids.update(cve_ids)
                except:
                    continue

            if not all_dell_cve_ids:
                return 0

            # 2. 查询这些CVE IDs在数据库中的存在情况
            # 使用批量查询提高性能
            placeholders = ','.join(['?' for _ in all_dell_cve_ids])
            query = f'SELECT COUNT(DISTINCT cve_id) FROM cves WHERE cve_id IN ({placeholders})'
            cursor.execute(query, list(all_dell_cve_ids))

            count = cursor.fetchone()[0]
            return count

        except Exception as e:
            self.log(f"计算关联匹配数失败: {e}")
            return 0

    def load_dell_from_database(self, limit=100, async_load=True):
        """从数据库加载Dell安全公告（优化版：限制数量 + 异步加载）

        Args:
            limit: 加载数量限制，None表示全部（默认100条，避免UI卡顿）
            async_load: 是否异步加载（默认True）
        """
        if async_load:
            # 异步后台加载
            self.log(f"正在后台加载 Dell 数据（最多 {limit if limit else '全部'} 条）...")
            threading.Thread(
                target=self._load_dell_background,
                args=(limit,),
                daemon=True
            ).start()
        else:
            # 同步加载
            self._load_dell_background(limit)

    def _load_dell_background(self, limit=100):
        """后台线程加载Dell数据"""
        try:
            # 优先从 Redis 加载
            if self.use_redis:
                try:
                    # 使用限制数量加载
                    self.dell_advisories = self.redis_manager.get_all_dell_advisories(limit=limit)

                    # 将数据推送到队列，由主线程处理UI更新
                    self.log_queue.put(f"从 Redis 加载 {len(self.dell_advisories)} 条 Dell 安全公告")

                    # 清空树形视图（使用队列通知主线程）
                    self.dell_queue.put(('clear', None))

                    # 批量添加数据 with performance optimization
                    processed_count = 0
                    for advisory in self.dell_advisories:
                        self.dell_queue.put(('add', advisory))
                        processed_count += 1

                        # Yield control periodically to prevent GUI freezing
                        if processed_count % 20 == 0:  # Update every 20 items for Dell data
                            import time
                            time.sleep(0.001)  # Small pause to allow other operations

                    # 通知加载完成
                    total_count = self.redis_manager.get_dell_count()
                    if limit and total_count > limit:
                        self.log_queue.put(f"✓ Dell 数据加载完成（显示 {limit}/{total_count} 条）")
                        self.log_queue.put(f"💡 提示：点击按钮多次可加载更多数据")
                    else:
                        self.log_queue.put(f"✓ Dell 数据加载完成（共 {len(self.dell_advisories)} 条）")

                    # 刷新关联数据（使用后台线程）
                    self.log_queue.put("正在计算 CVE-Dell 关联匹配...")
                    # Only refresh if we have both CVE and Dell data available
                    if self.cve_data and self.dell_advisories:
                        self._refresh_matched_data_background()

                    return

                except Exception as e:
                    self.log_queue.put(f"Redis 加载 Dell 数据失败: {e}, 回退到 SQLite")
                    # 继续使用 SQLite

            # 从 SQLite 加载（回退方案）
            cursor = self.conn.cursor()
            if limit:
                cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC LIMIT ?", (limit,))
            else:
                cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")

            records = cursor.fetchall()
            self.dell_advisories = []

            for record in records:
                try:
                    if record[0]:
                        data = json.loads(record[0])
                        self.dell_advisories.append(data)
                except json.JSONDecodeError:
                    continue

            # 清空树形视图
            self.dell_queue.put(('clear', None))

            # 显示数据 with performance optimization
            processed_count = 0
            for advisory in self.dell_advisories:
                self.dell_queue.put(('add', advisory))
                processed_count += 1

                # Yield control periodically to prevent GUI freezing
                if processed_count % 20 == 0:  # Update every 20 items for Dell data
                    import time
                    time.sleep(0.001)  # Small pause to allow other operations

            self.log_queue.put(f"从 SQLite 加载 {len(self.dell_advisories)} 条 Dell 安全公告")

            # 更新关联数据
            if self.cve_data:
                self._refresh_matched_data_background()

        except sqlite3.Error as e:
            self.log_queue.put(f"从数据库加载Dell数据失败: {str(e)}")
        except Exception as e:
            self.log_queue.put(f"加载Dell数据出错: {str(e)}")

    def enhance_dell_advisory(self, advisory):
        """增强Dell安全公告的解决方案信息"""
        # 查找关联的CVE数据，提供更详细的解决方案
        cve_ids = advisory.get('cve_ids', [])

        if cve_ids and self.cve_data:
            # 尝试找到关联的CVE
            related_cves = []
            for cve in self.cve_data:
                if cve.get('cve_id') in cve_ids:
                    related_cves.append(cve)

            if related_cves:
                # 生成综合解决方案
                enhanced_solution = advisory.get('solution', '')
                enhanced_solution += "\n\n【CVE关联信息】\n"

                for cve in related_cves:
                    enhanced_solution += f"\n- {cve.get('cve_id')}:"
                    enhanced_solution += f" CVSS评分 {cve.get('cvss_score', 'N/A')}"
                    enhanced_solution += f" ({cve.get('cvss_severity', 'N/A')})"

                    # 添加参考链接
                    refs = cve.get('references', [])
                    if refs:
                        enhanced_solution += "\n  参考链接:"
                        for ref in refs[:2]:  # 只取前2个
                            enhanced_solution += f"\n    {ref.get('url', '')}"

                advisory['enhanced_solution'] = enhanced_solution

        return advisory

    def create_widgets(self):
        """创建界面组件"""

        # 顶部标题栏
        header_frame = tk.Frame(self.root, bg=self.primary_color, height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="🛡️ CVE漏洞检测系统(Dell安全公告版)",
            font=("Microsoft YaHei", 24, "bold"),
            fg="white",
            bg=self.primary_color
        )
        title_label.pack(pady=20)

        # 主要内容区域（使用 Notebook 创建标签页）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 0. IT新闻早晚报标签页（放在最前面）
        self.news_frame = tk.Frame(self.notebook, bg="white")
        self.news_tab_id = self.notebook.add(self.news_frame, text="📰 IT新闻早晚报")

        # 1. NVD CVE 数据标签页
        self.nvd_frame = tk.Frame(self.notebook, bg="white")
        self.nvd_tab_id = self.notebook.add(self.nvd_frame, text="📊 NVD CVE 数据")

        # 2. Dell 安全公告标签页
        self.dell_frame = tk.Frame(self.notebook, bg="white")
        self.dell_tab_id = self.notebook.add(self.dell_frame, text="🏢 Dell 安全公告")

        # 3. 关联数据标签页
        self.matched_frame = tk.Frame(self.notebook, bg="white")
        self.matched_tab_id = self.notebook.add(self.matched_frame, text="🔗 CVE-Dell 关联")

        # 4. 解决方案标签页
        self.solution_frame = tk.Frame(self.notebook, bg="white")
        self.solution_tab_id = self.notebook.add(self.solution_frame, text="💡 解决方案")

        # 5. 统计分析标签页
        self.stats_frame = tk.Frame(self.notebook, bg="white")
        self.stats_tab_id = self.notebook.add(self.stats_frame, text="📈 统计分析")

        # 6. 智能学习标签页（位于统计分析和操作日志之间）
        self.learn_frame = tk.Frame(self.notebook, bg="white")
        self.learn_tab_id = self.notebook.add(self.learn_frame, text="🧠 智能学习")

        # 7. 日志标签页
        self.log_frame = tk.Frame(self.notebook, bg="white")
        self.log_tab_id = self.notebook.add(self.log_frame, text="📝 操作日志")

        # 创建各个标签页的内容
        self.create_news_view()
        self.create_nvd_view()
        self.create_dell_view()
        self.create_matched_view()
        self.create_solution_view()
        self.create_stats_view()
        self.create_learn_view()
        self.create_log_view()

        # 底部状态栏
        status_bar = tk.Frame(self.root, bg=self.primary_color, height=50)  # Increased height to accommodate progress bar
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)

        # Top section of status bar
        status_top = tk.Frame(status_bar, bg=self.primary_color)
        status_top.pack(fill=tk.X, padx=10, pady=(5, 0))

        self.bottom_status = tk.Label(
            status_top,
            text="准备就绪 | 支持离线数据查看",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 9)
        )
        self.bottom_status.pack(side=tk.LEFT)

        self.cve_count_label = tk.Label(
            status_top,
            text="NVD CVE: 0 | Dell 公告: 0 | 关联: 0",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold")
        )
        self.cve_count_label.pack(side=tk.RIGHT)

        # Progress bar (hidden by default)
        self.progress_frame = tk.Frame(status_bar, bg=self.primary_color)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=(2, 5))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=300
        )
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_bar.pack_forget()  # Hide by default

        self.progress_text = tk.Label(
            self.progress_frame,
            text="",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 8)
        )
        self.progress_text.pack(side=tk.RIGHT, padx=(5, 0))
        self.progress_text.pack_forget()  # Hide by default

    # ==================== IT新闻早晚报 ====================

    # IT新闻 RSS 源配置
    IT_NEWS_RSS_FEEDS = [
        {"name": "TechCrunch",       "url": "https://techcrunch.com/feed/"},
        {"name": "The Verge",        "url": "https://www.theverge.com/rss/index.xml"},
        {"name": "Ars Technica",     "url": "https://feeds.arstechnica.com/arstechnica/index"},
        {"name": "Hacker News",      "url": "https://hnrss.org/frontpage"},
        {"name": "ZDNet",            "url": "https://www.zdnet.com/news/rss.xml"},
        {"name": "InfoQ",            "url": "https://feed.infoq.com/"},
        {"name": "MIT Tech Review",  "url": "https://www.technologyreview.com/feed/"},
        {"name": "Wired",            "url": "https://www.wired.com/feed/rss"},
    ]

    def create_news_view(self):
        """创建 IT新闻早晚报 标签页内容"""
        # ── 顶部控制栏 ──────────────────────────────────────────────
        ctrl = tk.Frame(self.news_frame, bg="white", pady=8)
        ctrl.pack(fill=tk.X, padx=10)

        tk.Label(
            ctrl,
            text="IT新闻早晚报 — 每日自动采集科技资讯，AI生成500字简报",
            bg="white",
            font=("Microsoft YaHei", 11, "bold"),
            fg=self.primary_color,
        ).pack(side=tk.LEFT)

        btn_frame = tk.Frame(ctrl, bg="white")
        btn_frame.pack(side=tk.RIGHT)

        self.news_collect_btn = tk.Button(
            btn_frame, text="🔄 采集新闻", command=self.collect_it_news,
            bg=self.info_color, fg="white", font=("Microsoft YaHei", 10, "bold"),
            padx=12, pady=4, relief=tk.FLAT, cursor="hand2",
        )
        self.news_collect_btn.pack(side=tk.LEFT, padx=4)

        self.news_brief_btn = tk.Button(
            btn_frame, text="📝 生成简报", command=self.generate_news_brief,
            bg=self.success_color, fg="white", font=("Microsoft YaHei", 10, "bold"),
            padx=12, pady=4, relief=tk.FLAT, cursor="hand2",
        )
        self.news_brief_btn.pack(side=tk.LEFT, padx=4)

        self.news_podcast_btn = tk.Button(
            btn_frame, text="🎙️ 生成播客", command=self.generate_podcast,
            bg=self.warning_color, fg="white", font=("Microsoft YaHei", 10, "bold"),
            padx=12, pady=4, relief=tk.FLAT, cursor="hand2",
        )
        self.news_podcast_btn.pack(side=tk.LEFT, padx=4)

        # ── 水平分割：左=文章区  右=简报/播客 ──────────────────────
        h_paned = tk.PanedWindow(
            self.news_frame, orient=tk.HORIZONTAL, bg="#d0d0d0", sashwidth=5, sashrelief=tk.RAISED
        )
        h_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 4))

        # ── 左侧：文章列表（上）+ 文章详情（下）竖向排列 ──────────
        v_paned = tk.PanedWindow(
            h_paned, orient=tk.VERTICAL, bg="#d0d0d0", sashwidth=5, sashrelief=tk.RAISED
        )
        h_paned.add(v_paned, minsize=320, width=380)

        # 上：文章列表
        list_frame = tk.Frame(v_paned, bg="white")
        v_paned.add(list_frame, minsize=120)

        tk.Label(
            list_frame, text="今日文章列表",
            bg="white", font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color,
        ).pack(anchor="w", padx=8, pady=(6, 2))

        list_inner = tk.Frame(list_frame, bg="white")
        list_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        list_scroll_y = tk.Scrollbar(list_inner, orient=tk.VERTICAL)
        list_scroll_x = tk.Scrollbar(list_inner, orient=tk.HORIZONTAL)
        self.news_listbox = tk.Listbox(
            list_inner,
            yscrollcommand=list_scroll_y.set,
            xscrollcommand=list_scroll_x.set,
            font=("Microsoft YaHei", 9),
            selectmode=tk.SINGLE,
            activestyle="dotbox",
            wrap=None,              # 不自动换行，让水平滚动条生效
        )
        list_scroll_y.config(command=self.news_listbox.yview)
        list_scroll_x.config(command=self.news_listbox.xview)
        self.news_listbox.grid(row=0, column=0, sticky="nsew")
        list_scroll_y.grid(row=0, column=1, sticky="ns")
        list_scroll_x.grid(row=1, column=0, sticky="ew")
        list_inner.rowconfigure(0, weight=1)
        list_inner.columnconfigure(0, weight=1)
        self.news_listbox.bind("<<ListboxSelect>>", self._on_news_article_select)

        # 下：文章详情
        detail_frame = tk.Frame(v_paned, bg="white")
        v_paned.add(detail_frame, minsize=100)

        tk.Label(
            detail_frame, text="文章详情",
            bg="white", font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color,
        ).pack(anchor="w", padx=8, pady=(6, 2))

        self.news_article_detail = scrolledtext.ScrolledText(
            detail_frame, wrap=tk.WORD,
            font=("Microsoft YaHei", 9), bg="#f8f9fa", state=tk.DISABLED,
        )
        self.news_article_detail.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        # ── 右侧：简报 / 播客脚本 Notebook ──────────────────────────
        right_frame = tk.Frame(h_paned, bg="white")
        h_paned.add(right_frame, minsize=420)

        self.news_right_notebook = ttk.Notebook(right_frame)
        self.news_right_notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ── 简报子标签页 ─────────────────────────────────────────────
        brief_sub = tk.Frame(self.news_right_notebook, bg="white")
        self.news_right_notebook.add(brief_sub, text="📰 每日简报")

        # 简报工具栏
        brief_tb = tk.Frame(brief_sub, bg="#f0f4f8", pady=4)
        brief_tb.pack(fill=tk.X, padx=4, pady=(4, 0))

        self.news_brief_info = tk.Label(
            brief_tb, text="尚未生成简报",
            bg="#f0f4f8", font=("Microsoft YaHei", 9), fg="#555",
        )
        self.news_brief_info.pack(side=tk.LEFT, padx=8)

        tk.Button(
            brief_tb, text="💾 保存简报", command=self._save_news_brief,
            bg=self.primary_color, fg="white", font=("Microsoft YaHei", 9, "bold"),
            padx=10, pady=2, relief=tk.FLAT, cursor="hand2",
        ).pack(side=tk.RIGHT, padx=6)

        self.news_brief_area = scrolledtext.ScrolledText(
            brief_sub, wrap=tk.WORD, font=("Microsoft YaHei", 10), bg="white",
        )
        self.news_brief_area.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ── 播客脚本子标签页 ─────────────────────────────────────────
        podcast_sub = tk.Frame(self.news_right_notebook, bg="#fffdf0")
        self.news_right_notebook.add(podcast_sub, text="🎙️ 播客脚本")

        # 播客工具栏
        pod_tb = tk.Frame(podcast_sub, bg="#f5f0e0", pady=4)
        pod_tb.pack(fill=tk.X, padx=4, pady=(4, 0))

        tk.Label(
            pod_tb, text="声音：", bg="#f5f0e0", font=("Microsoft YaHei", 9),
        ).pack(side=tk.LEFT, padx=(8, 2))

        self.tts_voice_var = tk.StringVar()
        self.tts_voice_combo = ttk.Combobox(
            pod_tb, textvariable=self.tts_voice_var,
            state="readonly", width=28, font=("Microsoft YaHei", 9),
        )
        self.tts_voice_combo.pack(side=tk.LEFT, padx=(0, 10))

        self.tts_play_btn = tk.Button(
            pod_tb, text="▶ 播放", command=self._play_podcast_tts,
            bg=self.success_color, fg="white", font=("Microsoft YaHei", 9, "bold"),
            padx=10, pady=2, relief=tk.FLAT, cursor="hand2",
        )
        self.tts_play_btn.pack(side=tk.LEFT, padx=4)

        self.tts_stop_btn = tk.Button(
            pod_tb, text="⏹ 停止", command=self._stop_podcast_tts,
            bg=self.danger_color, fg="white", font=("Microsoft YaHei", 9, "bold"),
            padx=10, pady=2, relief=tk.FLAT, cursor="hand2", state=tk.DISABLED,
        )
        self.tts_stop_btn.pack(side=tk.LEFT, padx=4)

        self.tts_status_label = tk.Label(
            pod_tb, text="", bg="#f5f0e0", font=("Microsoft YaHei", 8), fg="#666",
        )
        self.tts_status_label.pack(side=tk.LEFT, padx=8)

        self.news_podcast_area = scrolledtext.ScrolledText(
            podcast_sub, wrap=tk.WORD, font=("Microsoft YaHei", 10), bg="#fffdf0",
        )
        self.news_podcast_area.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ── 底部状态栏 ───────────────────────────────────────────────
        self.news_status_label = tk.Label(
            self.news_frame, text="就绪 — 点击「采集新闻」获取今日科技资讯",
            bg="white", fg="#666", font=("Microsoft YaHei", 9), anchor="w",
        )
        self.news_status_label.pack(fill=tk.X, padx=12, pady=(0, 4))

        # 异步加载可用 TTS 声音
        threading.Thread(target=self._load_sapi_voices, daemon=True).start()

    def _load_sapi_voices(self):
        """后台查询 SAPI 声音列表：自动注册 OneCore 中文男声，过滤非中文声音"""
        try:
            import subprocess

            # ── 第一步：将 OneCore 中文声音（如 Kangkang）注册到 SAPI5 HKLM ──
            #   OneCore 声音在 Speech_OneCore 注册表下，SAPI5 .NET 只读 Speech 下
            #   通过复制注册表项（需要管理员权限，应用通常有权限）实现对齐
            reg_script = r"""
Add-Type -AssemblyName System.Speech
$srcBase = 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Voices\Tokens'
$dstBase = 'HKLM:\SOFTWARE\Microsoft\Speech\Voices\Tokens'
$voiceDataDir = 'C:\Windows\Speech_OneCore\Engines\TTS\zh-CN'

# 需要注册的 OneCore 中文声音（含正确 VoicePath 修正）
$targets = @{
    'MSTTS_V110_zhCN_KangkangM' = 'M2052Kangkang'
    'MSTTS_V110_zhCN_YaoyaoM'   = 'M2052Yaoyao'
}

foreach ($tokenName in $targets.Keys) {
    $src = "$srcBase\$tokenName"
    $dst = "$dstBase\$tokenName"
    if (-not (Test-Path $src)) { continue }
    if (Test-Path $dst) { continue }   # 已存在则跳过
    try {
        New-Item -Path $dst -Force | Out-Null
        $props = Get-ItemProperty $src
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            Set-ItemProperty -Path $dst -Name $_.Name -Value $_.Value
        }
        # 修正 VoicePath 为实际的 Kangkang / Yaoyao 文件
        $correctPath = Join-Path $voiceDataDir $targets[$tokenName]
        Set-ItemProperty -Path $dst -Name 'VoicePath' -Value $correctPath
        # 添加 SpLexicon（SAPI5 桌面声音必需）
        Set-ItemProperty -Path $dst -Name '(default)' -Value (($props.'(default)') -replace ' - Chinese.*', ' Desktop - Chinese (Simplified)')

        # 复制 Attributes 子键
        $attrSrc = "$src\Attributes"
        $attrDst = "$dst\Attributes"
        if (Test-Path $attrSrc) {
            New-Item -Path $attrDst -Force | Out-Null
            $ap = Get-ItemProperty $attrSrc
            $ap.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                Set-ItemProperty -Path $attrDst -Name $_.Name -Value $_.Value
            }
            # SpLexicon 使 SAPI5 正确工作
            Set-ItemProperty -Path $attrDst -Name 'SpLexicon' -Value '{0655E396-25D0-11D3-9C26-00C04F8EF87C}'
            $oldName = (Get-ItemProperty $attrDst).Name
            Set-ItemProperty -Path $attrDst -Name 'Name' -Value "$oldName Desktop"
        }
        Write-Output "REGISTERED:$tokenName"
    } catch {
        Write-Output "SKIP_ERROR:$tokenName:$_"
    }
}
"""
            # 写 ps1 到临时文件执行，避免命令行转义问题
            import tempfile, os as _os
            tmp = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8-sig", suffix=".ps1", delete=False, dir=str(self.data_dir)
            )
            tmp.write(reg_script)
            tmp.close()
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp.name],
                capture_output=True, timeout=15,
            )
            _os.remove(tmp.name)

            # ── 第二步：读取 SAPI5 已安装声音，仅保留中文声音 ──────────
            list_script = (
                "Add-Type -AssemblyName System.Speech; "
                "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                "$s.GetInstalledVoices() | Where-Object {$_.Enabled} | ForEach-Object { "
                "  $v = $_.VoiceInfo; "
                "  Write-Output ($v.Name + '|' + $v.Gender + '|' + $v.Culture.Name) "
                "}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", list_script],
                capture_output=True, timeout=15,
            )
            output = result.stdout.decode("utf-8", errors="replace").strip()

            gender_map = {"Male": "男声", "Female": "女声", "NotSet": ""}
            lang_map = {"zh": "中文", "en": "英语"}

            voices = []
            for line in output.splitlines():
                parts = line.strip().split("|")
                if len(parts) < 3:
                    continue
                name, gender, culture = parts[0], parts[1], parts[2]
                # 只保留中文声音（跳过 Zira 等英文语音，它们无法正确朗读中文）
                if not culture.startswith("zh"):
                    continue
                lang_label = lang_map.get(culture[:2], culture)
                gender_label = gender_map.get(gender, gender)
                label = f"{gender_label} ({lang_label}) — {name}"
                voices.append((label, name))

            if not voices:
                # 降级：保留全部声音
                for line in output.splitlines():
                    parts = line.strip().split("|")
                    if len(parts) < 3:
                        continue
                    name, gender, culture = parts[0], parts[1], parts[2]
                    lang_label = lang_map.get(culture[:2], culture)
                    gender_label = gender_map.get(gender, gender)
                    voices.append((f"{gender_label} ({lang_label}) — {name}", name))

            if not voices:
                voices = [("默认声音", "")]

            def _update():
                labels = [v[0] for v in voices]
                self.tts_voice_combo["values"] = labels
                self.tts_voice_combo.current(0)
                self._tts_voice_names = [v[1] for v in voices]

            self.root.after(0, _update)

        except Exception as e:
            self.root.after(0, self.log, f"加载 TTS 声音失败: {e}")
            self.root.after(0, lambda: self.tts_voice_combo.config(values=["默认声音"]))
            self._tts_voice_names = [""]

    def _on_news_article_select(self, event):
        """点击文章列表时，在详情区显示摘要与出处"""
        sel = self.news_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self.news_articles):
            return
        art = self.news_articles[idx]
        detail = (
            f"标题：{art.get('title', '')}\n"
            f"来源：{art.get('source', '')}\n"
            f"时间：{art.get('published', '')}\n"
            f"链接：{art.get('url', '')}\n\n"
            f"{art.get('summary', '')}"
        )
        self.news_article_detail.config(state=tk.NORMAL)
        self.news_article_detail.delete(1.0, tk.END)
        self.news_article_detail.insert(tk.END, detail)
        self.news_article_detail.config(state=tk.DISABLED)

    def collect_it_news(self):
        """采集IT新闻（后台线程）"""
        if self.is_collecting_news:
            messagebox.showinfo("提示", "新闻采集正在进行中，请稍候...")
            return
        self.is_collecting_news = True
        self.news_collect_btn.config(state=tk.DISABLED, text="采集中...")
        self.news_status_label.config(text="正在采集 IT 新闻，请稍候...")
        threading.Thread(target=self._collect_news_thread, daemon=True).start()

    def _collect_news_thread(self):
        """后台线程：从 RSS 源抓取文章"""
        import html as html_mod
        import re as _re
        try:
            all_articles = []
            for feed_info in self.IT_NEWS_RSS_FEEDS:
                try:
                    feed = feedparser.parse(feed_info["url"])
                    for entry in feed.entries[:8]:
                        raw_summary = ""
                        if hasattr(entry, "summary"):
                            raw_summary = entry.summary
                        elif hasattr(entry, "description"):
                            raw_summary = entry.description
                        clean_summary = _re.sub(r"<[^>]+>", "", raw_summary)
                        clean_summary = html_mod.unescape(clean_summary).strip()[:300]

                        published = ""
                        if hasattr(entry, "published"):
                            published = entry.published
                        elif hasattr(entry, "updated"):
                            published = entry.updated

                        all_articles.append({
                            "title": entry.get("title", ""),
                            "url": entry.get("link", ""),
                            "source": feed_info["name"],
                            "published": published,
                            "summary": clean_summary,
                        })
                except Exception as e:
                    self.root.after(0, self.log, f"采集 {feed_info['name']} 失败: {e}")

            seen = set()
            unique = []
            for a in all_articles:
                key = a["url"] or a["title"]
                if key and key not in seen:
                    seen.add(key)
                    unique.append(a)
            self.news_articles = unique[:50]

            self.root.after(0, self._update_news_listbox)
        except Exception as e:
            self.root.after(0, self.log, f"新闻采集异常: {e}")
        finally:
            self.is_collecting_news = False
            self.root.after(0, self.news_collect_btn.config, {"state": tk.NORMAL, "text": "🔄 采集新闻"})

    def _update_news_listbox(self):
        """将采集结果刷新到列表"""
        self.news_listbox.delete(0, tk.END)
        for art in self.news_articles:
            label = f"[{art['source']}]  {art['title']}"
            self.news_listbox.insert(tk.END, label)
        count = len(self.news_articles)
        self.news_status_label.config(
            text=f"已采集 {count} 篇文章 — 点击「生成简报」获得 AI 摘要"
        )
        self.log(f"新闻采集完成：共 {count} 篇")

    def generate_news_brief(self):
        """调用 AI 生成每日简报（后台线程）"""
        if not self.news_articles:
            messagebox.showwarning("提示", "请先点击「采集新闻」获取今日资讯")
            return
        self.news_brief_btn.config(state=tk.DISABLED, text="生成中...")
        self.news_status_label.config(text="AI 正在生成每日简报...")
        threading.Thread(target=self._generate_brief_thread, daemon=True).start()

    def _generate_brief_thread(self):
        """后台线程：调用 Qwen 生成 500 字简报，来源列出文章名+链接"""
        try:
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                msg = "未设置 QWEN_API_KEY 或 DASHSCOPE_API_KEY，无法调用 AI"
                self.root.after(0, messagebox.showerror, "配置错误", msg)
                return

            model = os.getenv("QWEN_MODEL", "qwen-max-latest")
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

            today = datetime.now().strftime("%Y年%m月%d日")
            article_lines = []
            for i, art in enumerate(self.news_articles[:20], 1):
                line = f"{i}. 【{art['source']}】{art['title']}"
                if art.get("url"):
                    line += f"\n   链接：{art['url']}"
                if art.get("summary"):
                    line += f"\n   摘要：{art['summary'][:150]}"
                article_lines.append(line)
            articles_text = "\n".join(article_lines)

            prompt = f"""今天是 {today}。以下是从各大科技媒体采集到的 IT 新闻（含标题、链接、摘要）：

{articles_text}

请根据以上内容，为技术人员撰写一份今日 IT 科技简报，要求：
1. 总字数约 500 字（中文）
2. 按重要性筛选 5～8 条值得关注的新闻，每条新闻后面用括号标注出处媒体名
3. 语言简洁专业，突出新闻的核心价值和影响
4. 简报正文之后，单独用"---\n【参考来源】"分隔，列出所有引用文章的：媒体名、文章标题、链接
5. 直接输出简报正文，不要加额外说明
"""

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一位专业的 IT 科技编辑，擅长将科技新闻提炼成简洁有力的日报简报。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.6,
                max_tokens=1500,
            )
            brief = response.choices[0].message.content.strip()
            self.news_brief_text = brief

            self.root.after(0, self._show_news_brief, brief)
        except Exception as e:
            self.root.after(0, self.log, f"生成简报失败: {e}")
            self.root.after(0, messagebox.showerror, "错误", f"生成简报失败：{e}")
        finally:
            self.root.after(0, self.news_brief_btn.config, {"state": tk.NORMAL, "text": "📝 生成简报"})

    def _show_news_brief(self, brief):
        """在简报区域显示内容并切换到简报子标签"""
        self.news_brief_area.delete(1.0, tk.END)
        self.news_brief_area.insert(tk.END, brief)
        self.news_right_notebook.select(0)
        ts = datetime.now().strftime("%H:%M:%S")
        self.news_status_label.config(text=f"简报生成完成 — {ts}")
        self.news_brief_info.config(text=f"生成于 {datetime.now().strftime('%Y-%m-%d %H:%M')}，共 {len(brief)} 字")
        self.log("IT新闻简报生成完成")

    def _save_news_brief(self):
        """保存简报到文件，方便回看"""
        brief = self.news_brief_area.get(1.0, tk.END).strip()
        if not brief:
            messagebox.showwarning("提示", "简报内容为空，请先生成简报")
            return
        # 保存目录
        save_dir = self.data_dir / "news_briefs"
        save_dir.mkdir(exist_ok=True)
        filename = save_dir / f"brief_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"IT新闻早晚报 — {datetime.now().strftime('%Y年%m月%d日 %H:%M')}\n")
                f.write("=" * 60 + "\n\n")
                f.write(brief)
                f.write("\n\n" + "=" * 60 + "\n")
                # 附上原始文章列表
                f.write("【原始采集文章列表】\n")
                for i, art in enumerate(self.news_articles, 1):
                    f.write(f"{i}. [{art['source']}] {art['title']}\n")
                    if art.get("url"):
                        f.write(f"   {art['url']}\n")
            self.log(f"简报已保存：{filename}")
            messagebox.showinfo("保存成功", f"简报已保存至：\n{filename}")
        except Exception as e:
            messagebox.showerror("保存失败", f"写入文件失败：{e}")

    def generate_podcast(self):
        """一键生成播客脚本（后台线程）"""
        if not self.news_brief_text and not self.news_articles:
            messagebox.showwarning("提示", "请先生成简报，再一键生成播客脚本")
            return
        self.news_podcast_btn.config(state=tk.DISABLED, text="生成中...")
        self.news_status_label.config(text="AI 正在生成播客脚本...")
        threading.Thread(target=self._generate_podcast_thread, daemon=True).start()

    def _generate_podcast_thread(self):
        """后台线程：将简报转换为播客口播脚本"""
        try:
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                msg = "未设置 QWEN_API_KEY 或 DASHSCOPE_API_KEY，无法调用 AI"
                self.root.after(0, messagebox.showerror, "配置错误", msg)
                return

            model = os.getenv("QWEN_MODEL", "qwen-max-latest")
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

            today = datetime.now().strftime("%Y年%m月%d日")
            source_content = self.news_brief_text if self.news_brief_text else "\n".join(
                f"【{a['source']}】{a['title']}" for a in self.news_articles[:15]
            )

            prompt = f"""请根据以下 {today} 的 IT 科技简报内容，创作一段适合播客节目的口播脚本：

{source_content}

脚本要求：
1. 风格轻松专业，像真实播客主持人在讲述，有开场白和结束语
2. 将新闻内容用更口语化的方式表达，避免生硬的书面语
3. 在每条新闻之间加入自然的过渡语句
4. 全程约 600～800 字，适合 3～5 分钟的音频播出
5. 在提到新闻时保留来源媒体名（如"TechCrunch 报道..."）
6. 直接输出脚本正文，不要加说明
"""

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一位经验丰富的科技播客主持人，擅长用生动有趣的方式讲解科技新闻。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.75,
                max_tokens=1500,
            )
            script = response.choices[0].message.content.strip()

            self.root.after(0, self._show_podcast_script, script)
        except Exception as e:
            self.root.after(0, self.log, f"生成播客脚本失败: {e}")
            self.root.after(0, messagebox.showerror, "错误", f"生成播客脚本失败：{e}")
        finally:
            self.root.after(0, self.news_podcast_btn.config, {"state": tk.NORMAL, "text": "🎙️ 生成播客"})

    def _show_podcast_script(self, script):
        """在播客区域显示脚本并切换到播客子标签"""
        self.news_podcast_area.delete(1.0, tk.END)
        self.news_podcast_area.insert(tk.END, script)
        self.news_right_notebook.select(1)
        self.news_status_label.config(text=f"播客脚本生成完成 — {datetime.now().strftime('%H:%M:%S')}")
        self.tts_status_label.config(text="脚本已就绪，可点击播放")
        self.log("IT新闻播客脚本生成完成")

    def _play_podcast_tts(self):
        """使用 Windows SAPI 朗读播客脚本"""
        script = self.news_podcast_area.get(1.0, tk.END).strip()
        if not script:
            messagebox.showwarning("提示", "播客脚本为空，请先生成播客脚本")
            return
        if self._tts_process and self._tts_process.poll() is None:
            messagebox.showinfo("提示", "正在播放中，请先点击停止")
            return

        # 获取选中的声音名称
        voice_name = ""
        try:
            idx = self.tts_voice_combo.current()
            voices = getattr(self, "_tts_voice_names", [""])
            if 0 <= idx < len(voices):
                voice_name = voices[idx]
        except Exception:
            pass

        self.tts_play_btn.config(state=tk.DISABLED)
        self.tts_stop_btn.config(state=tk.NORMAL)
        self.tts_status_label.config(text="播放中...")
        threading.Thread(target=self._tts_thread, args=(script, voice_name), daemon=True).start()

    def _tts_thread(self, text: str, voice_name: str):
        """后台线程：将文本写入临时文件，调用 PowerShell SAPI 朗读播客脚本"""
        import subprocess, tempfile
        txt_path = None
        ps1_path = None
        try:
            # 文本临时文件（UTF-8，PowerShell 从文件读取避免命令行转义）
            txt = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".txt",
                delete=False, dir=str(self.data_dir)
            )
            txt.write(text)
            txt.close()
            txt_path = txt.name
            ps_txt = txt_path.replace("\\", "\\\\")

            # 构建 PowerShell 脚本内容（UTF-8 BOM 使 PS5 正确识别）
            select_voice_line = (
                f'$s.SelectVoice("{voice_name}");' if voice_name else ""
            )
            ps_content = (
                "Add-Type -AssemblyName System.Speech\n"
                "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer\n"
                f"{select_voice_line}\n"
                f'$t = [System.IO.File]::ReadAllText("{ps_txt}", [System.Text.Encoding]::UTF8)\n'
                "$s.Speak($t)\n"
            )
            # 写 ps1（UTF-8 BOM，PowerShell 5 需要 BOM 才能正确读中文字符串）
            ps1 = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8-sig", suffix=".ps1",
                delete=False, dir=str(self.data_dir)
            )
            ps1.write(ps_content)
            ps1.close()
            ps1_path = ps1.name

            self._tts_process = subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._tts_process.wait()
        except Exception as e:
            self.root.after(0, self.log, f"TTS 播放失败: {e}")
        finally:
            import os as _os
            for p in (txt_path, ps1_path):
                try:
                    if p:
                        _os.remove(p)
                except Exception:
                    pass
            self._tts_process = None
            self.root.after(0, self._tts_finished)

    def _tts_finished(self):
        """TTS 播放结束，恢复按钮状态"""
        self.tts_play_btn.config(state=tk.NORMAL)
        self.tts_stop_btn.config(state=tk.DISABLED)
        self.tts_status_label.config(text="播放已结束")

    def _stop_podcast_tts(self):
        """停止 TTS 播放"""
        if self._tts_process and self._tts_process.poll() is None:
            try:
                self._tts_process.terminate()
                # 同时终止子进程树（PowerShell 可能启动子进程）
                import subprocess
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self._tts_process.pid)],
                    capture_output=True,
                )
            except Exception as e:
                self.log(f"停止 TTS 失败: {e}")
        self.tts_play_btn.config(state=tk.NORMAL)
        self.tts_stop_btn.config(state=tk.DISABLED)
        self.tts_status_label.config(text="已停止")

    def create_nvd_view(self):
        """创建 NVD CVE 数据视图"""
        # 控制面板
        control_frame = tk.Frame(self.nvd_frame, bg="white", pady=10)
        control_frame.pack(fill=tk.X, padx=10)

        # 左侧控制按钮
        left_control = tk.Frame(control_frame, bg="white")
        left_control.pack(side=tk.LEFT)

        # 天数选择
        tk.Label(left_control, text="采集范围：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))

        self.nvd_time_range_var = tk.StringVar(value="1年")
        time_range_combo = ttk.Combobox(
            left_control,
            textvariable=self.nvd_time_range_var,
            values=["最近一周", "1个月", "3个月", "半年", "1年"],
            width=10,
            state="readonly"
        )
        time_range_combo.pack(side=tk.LEFT, padx=(0, 20))

        # API Key 状态显示
        api_key_env = os.getenv("NVD_API_KEY")
        if api_key_env:
            api_status = "✓ API Key 已配置"
            api_color = self.success_color
        else:
            api_status = "⚠ 未配置 API Key（速度较慢）"
            api_color = self.warning_color

        self.api_key_status_label = tk.Label(
            left_control,
            text=api_status,
            bg="white",
            fg=api_color,
            font=("Microsoft YaHei", 9, "bold")
        )
        self.api_key_status_label.pack(side=tk.LEFT, padx=(0, 20))

        # 开始采集按钮
        self.nvd_collect_btn = tk.Button(
            left_control,
            text="▶ 采集 NVD 数据",
            command=self.start_nvd_collection,
            bg=self.success_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.nvd_collect_btn.pack(side=tk.LEFT, padx=5)

        # 停止按钮
        self.nvd_stop_btn = tk.Button(
            left_control,
            text="■ 停止",
            command=self.stop_nvd_collection,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.nvd_stop_btn.pack(side=tk.LEFT, padx=5)

        # 从数据库加载按钮
        load_db_btn = tk.Button(
            left_control,
            text="💾 从数据库加载",
            command=self.load_nvd_from_database,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        load_db_btn.pack(side=tk.LEFT, padx=5)

        # 加载本地数据按钮（从JSON文件）
        load_btn = tk.Button(
            left_control,
            text="📁 加载本地文件",
            command=self.load_local_nvd_data,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        load_btn.pack(side=tk.LEFT, padx=5)

        # 数据展示区域
        data_container = tk.Frame(self.nvd_frame, bg="white")
        data_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # 搜索框
        search_frame = tk.Frame(data_container, bg="white")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="搜索：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.nvd_search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.nvd_search_var, width=35, font=("Microsoft YaHei", 10))
        search_entry.pack(side=tk.LEFT, padx=(0, 5))

        # 搜索按钮
        search_btn = tk.Button(
            search_frame,
            text="🔍 搜索",
            command=self.filter_nvd_data,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        search_btn.pack(side=tk.LEFT, padx=(0, 10))

        # 删除选中按钮
        nvd_delete_btn = tk.Button(
            search_frame,
            text="🗑 删除选中",
            command=self.delete_nvd_selected,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        nvd_delete_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(search_frame, text="(支持 CVE ID、描述、严重等级搜索，自动从数据库查询全部数据；Ctrl/Shift 多选后可删除)", bg="white", font=("Microsoft YaHei", 9), fg="gray").pack(side=tk.LEFT)

        # 创建 Treeview 来展示 CVE 数据
        columns = ("CVE ID", "严重等级", "CVSS评分", "发布日期", "描述", "来源")

        # 创建滚动条
        tree_scroll_y = tk.Scrollbar(data_container, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(data_container, orient=tk.HORIZONTAL)

        self.nvd_tree = ttk.Treeview(
            data_container,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=20
        )

        # 配置滚动条
        tree_scroll_y.config(command=self.nvd_tree.yview)
        tree_scroll_x.config(command=self.nvd_tree.xview)

        # 设置列标题和宽度
        self.nvd_tree.heading("CVE ID", text="CVE 编号")
        self.nvd_tree.heading("严重等级", text="严重等级")
        self.nvd_tree.heading("CVSS评分", text="CVSS 评分")
        self.nvd_tree.heading("发布日期", text="发布日期")
        self.nvd_tree.heading("描述", text="描述")
        self.nvd_tree.heading("来源", text="数据来源")

        self.nvd_tree.column("CVE ID", width=150, minwidth=100)
        self.nvd_tree.column("严重等级", width=100, minwidth=80)
        self.nvd_tree.column("CVSS评分", width=100, minwidth=80)
        self.nvd_tree.column("发布日期", width=150, minwidth=100)
        self.nvd_tree.column("描述", width=500, minwidth=300)
        self.nvd_tree.column("来源", width=100, minwidth=80)

        # 布局
        self.nvd_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 0))
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # 添加标签样式
        self.nvd_tree.tag_configure("CRITICAL", background="#ffebee", foreground="#b71c1c")
        self.nvd_tree.tag_configure("HIGH", background="#fff3e0", foreground="#e65100")
        self.nvd_tree.tag_configure("MEDIUM", background="#fff9c4", foreground="#f57f17")
        self.nvd_tree.tag_configure("LOW", background="#f1f8e9", foreground="#33691e")

        # 绑定双击事件
        self.nvd_tree.bind("<Double-1>", self.on_nvd_item_double_click)

    def create_dell_view(self):
        """创建 Dell 安全公告视图"""
        # 提示信息框
        info_banner = tk.Frame(self.dell_frame, bg="#d1ecf1", pady=8)
        info_banner.pack(fill=tk.X, padx=10, pady=(10, 0))

        info_text = "ℹ️ Dell安全公告采集：选择时间范围后点击采集按钮，数据将存储到本地数据库，支持离线查看和CVE关联分析。"
        info_label = tk.Label(
            info_banner,
            text=info_text,
            bg="#d1ecf1",
            fg="#0c5460",
            font=("Microsoft YaHei", 9),
            wraplength=1200,
            justify=tk.LEFT
        )
        info_label.pack(padx=10)

        # 控制面板
        control_frame = tk.Frame(self.dell_frame, bg="white", pady=10)
        control_frame.pack(fill=tk.X, padx=10)

        # 左侧控制按钮
        left_control = tk.Frame(control_frame, bg="white")
        left_control.pack(side=tk.LEFT)

        # 时间范围选择标签和下拉框
        tk.Label(left_control, text="采集范围：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))

        self.dell_time_range_var = tk.StringVar(value="1个月")
        time_range_combo = ttk.Combobox(
            left_control,
            textvariable=self.dell_time_range_var,
            values=["最近一周", "1个月", "3个月", "半年", "1年"],
            state="readonly",
            width=10,
            font=("Microsoft YaHei", 9)
        )
        time_range_combo.pack(side=tk.LEFT, padx=(0, 10))

        # 开始采集按钮
        self.dell_collect_btn = tk.Button(
            left_control,
            text="▶ 采集Dell安全公告",
            command=self.start_dell_collection,
            bg=self.success_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.dell_collect_btn.pack(side=tk.LEFT, padx=5)

        # 停止按钮
        self.dell_stop_btn = tk.Button(
            left_control,
            text="■ 停止",
            command=self.stop_dell_collection,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.dell_stop_btn.pack(side=tk.LEFT, padx=5)

        # 加载本地数据按钮
        load_btn = tk.Button(
            left_control,
            text="📁 从数据库加载",
            command=self.load_dell_from_database,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        load_btn.pack(side=tk.LEFT, padx=5)

        # 加载CSV数据按钮
        load_csv_btn = tk.Button(
            left_control,
            text="📊 加载CSV数据",
            command=self.load_csv_data,
            bg=self.warning_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        load_csv_btn.pack(side=tk.LEFT, padx=5)

        # URL单条抓取区域
        url_fetch_frame = tk.LabelFrame(
            self.dell_frame,
            text="🔗 单条网页抓取",
            bg="white",
            font=("Microsoft YaHei", 10, "bold"),
            fg=self.primary_color,
            padx=10, pady=8
        )
        url_fetch_frame.pack(fill=tk.X, padx=10, pady=(5, 0))

        url_input_row = tk.Frame(url_fetch_frame, bg="white")
        url_input_row.pack(fill=tk.X)

        tk.Label(
            url_input_row, text="公告URL：",
            bg="white", font=("Microsoft YaHei", 10)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.dell_url_entry = tk.Entry(
            url_input_row,
            width=70,
            font=("Microsoft YaHei", 10),
        )
        self.dell_url_entry.insert(0, "https://www.dell.com/support/kbdoc/en-us/...")
        self.dell_url_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)

        self.dell_fetch_btn = tk.Button(
            url_input_row,
            text="⬇ 抓取并入库",
            command=self.fetch_dell_advisory_from_url,
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=12, pady=4,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.dell_fetch_btn.pack(side=tk.LEFT)

        self.dell_fetch_status = tk.Label(
            url_fetch_frame,
            text="输入Dell安全公告页面URL后点击抓取，内容将自动解析并存入数据库（优先使用Exa API，失败时回退至直接请求）",
            bg="white",
            fg="gray",
            font=("Microsoft YaHei", 9),
            wraplength=900,
            justify=tk.LEFT
        )
        self.dell_fetch_status.pack(anchor=tk.W, pady=(4, 0))

        # 数据展示区域
        data_container = tk.Frame(self.dell_frame, bg="white")
        data_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # 搜索框
        search_frame = tk.Frame(data_container, bg="white")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="搜索：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.dell_search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.dell_search_var, width=35, font=("Microsoft YaHei", 10))
        search_entry.pack(side=tk.LEFT, padx=(0, 5))

        # 搜索按钮
        search_btn = tk.Button(
            search_frame,
            text="🔍 搜索",
            command=self.filter_dell_data,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        search_btn.pack(side=tk.LEFT, padx=(0, 10))

        # 删除选中按钮
        dell_delete_btn = tk.Button(
            search_frame,
            text="🗑 删除选中",
            command=self.delete_dell_selected,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        dell_delete_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(search_frame, text="(支持 公告ID、CVE ID、标题、产品搜索；Ctrl/Shift 多选后可删除)", bg="white", font=("Microsoft YaHei", 9), fg="gray").pack(side=tk.LEFT)

        # 创建 Treeview 来展示 Dell 安全公告
        columns = ("公告ID", "标题", "CVE IDs", "发布日期", "受影响产品数")

        # 创建滚动条
        tree_scroll_y = tk.Scrollbar(data_container, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(data_container, orient=tk.HORIZONTAL)

        self.dell_tree = ttk.Treeview(
            data_container,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=20
        )

        # 配置滚动条
        tree_scroll_y.config(command=self.dell_tree.yview)
        tree_scroll_x.config(command=self.dell_tree.xview)

        # 设置列标题和宽度
        self.dell_tree.heading("公告ID", text="公告 ID")
        self.dell_tree.heading("标题", text="标题")
        self.dell_tree.heading("CVE IDs", text="相关 CVE")
        self.dell_tree.heading("发布日期", text="发布日期")
        self.dell_tree.heading("受影响产品数", text="受影响产品数")

        self.dell_tree.column("公告ID", width=150, minwidth=100)
        self.dell_tree.column("标题", width=500, minwidth=300)
        self.dell_tree.column("CVE IDs", width=300, minwidth=200)
        self.dell_tree.column("发布日期", width=150, minwidth=100)
        self.dell_tree.column("受影响产品数", width=120, minwidth=80)

        # 布局
        self.dell_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 0))
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # 绑定双击事件
        self.dell_tree.bind("<Double-1>", self.on_dell_item_double_click)

    def create_matched_view(self):
        """创建关联数据视图"""
        # 说明文本
        info_frame = tk.Frame(self.matched_frame, bg="white", pady=10)
        info_frame.pack(fill=tk.X, padx=10)

        info_label = tk.Label(
            info_frame,
            text="此页面显示 NVD CVE 数据与 Dell 安全公告的关联匹配结果，双击查看详细信息",
            bg="white",
            font=("Microsoft YaHei", 10),
            fg=self.info_color
        )
        info_label.pack()

        # 刷新按钮
        refresh_btn = tk.Button(
            info_frame,
            text="🔄 刷新关联数据",
            command=self.refresh_matched_data,
            bg=self.success_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # AI解决方案按钮
        ai_solution_btn = tk.Button(
            info_frame,
            text="🤖 AI解决方案",
            command=self.ai_solution_click,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        ai_solution_btn.pack(side=tk.LEFT, padx=5)

        # 数据展示区域
        data_container = tk.Frame(self.matched_frame, bg="white")
        data_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # 创建 Treeview 来展示关联数据
        columns = ("CVE ID", "严重等级", "CVSS评分", "Dell公告", "产品型号", "解决方案")

        # 创建滚动条
        tree_scroll_y = tk.Scrollbar(data_container, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(data_container, orient=tk.HORIZONTAL)

        self.matched_tree = ttk.Treeview(
            data_container,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=22
        )

        # 配置滚动条
        tree_scroll_y.config(command=self.matched_tree.yview)
        tree_scroll_x.config(command=self.matched_tree.xview)

        # 设置列标题和宽度
        self.matched_tree.heading("CVE ID", text="CVE 编号")
        self.matched_tree.heading("严重等级", text="严重等级")
        self.matched_tree.heading("CVSS评分", text="CVSS 评分")
        self.matched_tree.heading("Dell公告", text="Dell 公告 ID")
        self.matched_tree.heading("产品型号", text="受影响产品")
        self.matched_tree.heading("解决方案", text="解决方案预览")

        self.matched_tree.column("CVE ID", width=150, minwidth=100)
        self.matched_tree.column("严重等级", width=100, minwidth=80)
        self.matched_tree.column("CVSS评分", width=100, minwidth=80)
        self.matched_tree.column("Dell公告", width=150, minwidth=100)
        self.matched_tree.column("产品型号", width=300, minwidth=200)
        self.matched_tree.column("解决方案", width=400, minwidth=300)

        # 布局
        self.matched_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 0))
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # 添加标签样式
        self.matched_tree.tag_configure("CRITICAL", background="#ffebee", foreground="#b71c1c")
        self.matched_tree.tag_configure("HIGH", background="#fff3e0", foreground="#e65100")
        self.matched_tree.tag_configure("MEDIUM", background="#fff9c4", foreground="#f57f17")
        self.matched_tree.tag_configure("LOW", background="#f1f8e9", foreground="#33691e")

        # 绑定双击事件
        self.matched_tree.bind("<Double-1>", self.on_matched_item_double_click)

    def create_solution_view(self):
        """创建AI解决方案视图"""
        # 说明文本
        info_frame = tk.Frame(self.solution_frame, bg="white", pady=10)
        info_frame.pack(fill=tk.X, padx=10)

        info_label = tk.Label(
            info_frame,
            text="此页面显示AI解决方案分析的历史记录。选中项目可查看详细分析结果",
            bg="white",
            font=("Microsoft YaHei", 10),
            fg=self.info_color
        )
        info_label.pack(side=tk.LEFT)

        # 导出和清空按钮
        export_btn = tk.Button(
            info_frame,
            text="📥 导出历史记录",
            command=self.export_solution_history,
            bg=self.success_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        export_btn.pack(side=tk.RIGHT, padx=5)

        clear_btn = tk.Button(
            info_frame,
            text="🗑️ 清空历史记录",
            command=self.clear_solution_history,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        clear_btn.pack(side=tk.RIGHT, padx=5)

        # 历史记录展示区域
        data_container = tk.Frame(self.solution_frame, bg="white")
        data_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # 创建 Treeview 来展示历史记录
        columns = ("时间戳", "CVE ID", "Dell公告", "分析状态", "结果预览")

        # 创建滚动条
        tree_scroll_y = tk.Scrollbar(data_container, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(data_container, orient=tk.HORIZONTAL)

        self.solution_tree = ttk.Treeview(
            data_container,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=10
        )

        # 配置滚动条
        tree_scroll_y.config(command=self.solution_tree.yview)
        tree_scroll_x.config(command=self.solution_tree.xview)

        # 设置列标题和宽度
        self.solution_tree.heading("时间戳", text="分析时间")
        self.solution_tree.heading("CVE ID", text="CVE 编号")
        self.solution_tree.heading("Dell公告", text="Dell 公告 ID")
        self.solution_tree.heading("分析状态", text="分析状态")
        self.solution_tree.heading("结果预览", text="结果预览")

        self.solution_tree.column("时间戳", width=180, minwidth=150)
        self.solution_tree.column("CVE ID", width=150, minwidth=100)
        self.solution_tree.column("Dell公告", width=150, minwidth=100)
        self.solution_tree.column("分析状态", width=100, minwidth=80)
        self.solution_tree.column("结果预览", width=400, minwidth=300)

        # 布局
        self.solution_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 0))
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # 绑定双击事件
        self.solution_tree.bind("<Double-1>", self.on_solution_item_double_click)

        # 详细结果显示区域
        detail_frame = tk.Frame(self.solution_frame, bg="white")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Label(
            detail_frame,
            text="详细分析结果",
            bg="white",
            font=("Microsoft YaHei", 12, "bold")
        ).pack(anchor="w", pady=(10, 5))

        self.solution_detail_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            width=100,
            height=8,
            font=("Consolas", 9),
            bg="#f8f9fa"
        )
        self.solution_detail_text.pack(fill=tk.BOTH, expand=True)

        # 初始化数据
        self.solution_history = []
        self.load_ai_solution_history()

    def create_stats_view(self):
        """创建统计视图"""
        # 统计信息容器
        stats_container = tk.Frame(self.stats_frame, bg="white")
        stats_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 统计卡片
        self.stats_cards = {}

        # 创建统计卡片
        cards_info = [
            ("NVD CVE总数", "0", self.primary_color),
            ("Dell公告数", "0", self.info_color),
            ("关联匹配数", "0", self.success_color),
            ("严重", "0", "#b71c1c"),
            ("高危", "0", "#e65100"),
            ("中危", "0", "#f57f17"),
            ("低危", "0", "#33691e")
        ]

        for i, (title, value, color) in enumerate(cards_info):
            card = self.create_stats_card(stats_container, title, value, color)
            card.grid(row=i // 4, column=i % 4, padx=10, pady=10, sticky="nsew")
            self.stats_cards[title] = card

        # 配置列权重
        for i in range(4):
            stats_container.columnconfigure(i, weight=1)

        # 详细统计文本区域
        detail_frame = tk.Frame(self.stats_frame, bg="white")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        tk.Label(
            detail_frame,
            text="详细统计报告",
            bg="white",
            font=("Microsoft YaHei", 12, "bold")
        ).pack(anchor="w", pady=(10, 5))

        self.stats_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            width=80,
            height=15,
            font=("Consolas", 10),
            bg="#f8f9fa"
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)

    def create_stats_card(self, parent, title, value, color):
        """创建统计卡片"""
        card = tk.Frame(parent, bg="white", relief=tk.RAISED, borderwidth=1)

        # 标题
        title_label = tk.Label(
            card,
            text=title,
            bg="white",
            fg=color,
            font=("Microsoft YaHei", 10)
        )
        title_label.pack(pady=(10, 5))

        # 数值
        value_label = tk.Label(
            card,
            text=value,
            bg="white",
            fg=color,
            font=("Microsoft YaHei", 24, "bold")
        )
        value_label.pack(pady=(0, 10))

        # 保存值标签的引用
        card.value_label = value_label

        return card

    def create_learn_view(self):
        """创建智能学习（费曼学习法）标签页内容"""
        # ── 顶部说明栏 ────────────────────────────────────────────────
        top_bar = tk.Frame(self.learn_frame, bg="#e8f4fd", pady=8)
        top_bar.pack(fill=tk.X, padx=10, pady=(8, 0))
        tk.Label(
            top_bar,
            text="🧠 智能费曼学习助手  ·  通过费曼教学法深化对CVE/安全知识的理解",
            bg="#e8f4fd",
            fg=self.primary_color,
            font=("Microsoft YaHei", 10, "bold"),
        ).pack(side=tk.LEFT, padx=8)

        # ── 主体水平分栏 ──────────────────────────────────────────────
        main_paned = tk.PanedWindow(
            self.learn_frame, orient=tk.HORIZONTAL,
            sashrelief=tk.RAISED, sashwidth=5, bg="#cccccc"
        )
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        # ── 左侧控制面板 ──────────────────────────────────────────────
        left_outer = tk.Frame(main_paned, bg="white")
        main_paned.add(left_outer, width=300, minsize=220)

        left_canvas = tk.Canvas(left_outer, bg="white", highlightthickness=0)
        left_scroll = tk.Scrollbar(left_outer, orient=tk.VERTICAL, command=left_canvas.yview)
        left_canvas.configure(yscrollcommand=left_scroll.set)
        left_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        left_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        left_panel = tk.Frame(left_canvas, bg="white")
        left_canvas.create_window((0, 0), window=left_panel, anchor="nw")
        left_panel.bind(
            "<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        )

        # 1. 学习内容来源
        data_frame = tk.LabelFrame(
            left_panel, text="📚 学习内容来源", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        data_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        self.learn_source_var = tk.StringVar(value="db")
        rb_db = tk.Radiobutton(
            data_frame, text="🗄️ 从数据库选取", variable=self.learn_source_var,
            value="db", bg="white", font=("Microsoft YaHei", 9),
            command=self._on_learn_source_change
        )
        rb_db.pack(anchor="w", padx=8, pady=2)
        rb_file = tk.Radiobutton(
            data_frame, text="📁 上传本地文件", variable=self.learn_source_var,
            value="file", bg="white", font=("Microsoft YaHei", 9),
            command=self._on_learn_source_change
        )
        rb_file.pack(anchor="w", padx=8, pady=2)

        # 数据库子选项
        self.learn_db_type_frame = tk.Frame(data_frame, bg="white")
        self.learn_db_type_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
        tk.Label(
            self.learn_db_type_frame, text="数据类型:", bg="white",
            font=("Microsoft YaHei", 9)
        ).pack(side=tk.LEFT)
        self.learn_db_type_combo = ttk.Combobox(
            self.learn_db_type_frame,
            values=["CVE漏洞数据", "Dell安全公告", "AI分析记录"],
            state="readonly", width=13, font=("Microsoft YaHei", 9)
        )
        self.learn_db_type_combo.current(0)
        self.learn_db_type_combo.pack(side=tk.LEFT, padx=4)

        load_btn = tk.Button(
            data_frame, text="⬇ 加载内容", command=self._load_learn_content,
            bg=self.info_color, fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=3
        )
        load_btn.pack(fill=tk.X, padx=8, pady=(2, 4))

        # 内容预览
        tk.Label(
            data_frame, text="内容预览:", bg="white",
            font=("Microsoft YaHei", 8), fg="#666666"
        ).pack(anchor="w", padx=8)
        self.learn_preview_text = tk.Text(
            data_frame, height=6, wrap=tk.WORD,
            font=("Microsoft YaHei", 8), bg="#f8f9fa",
            relief=tk.FLAT, state=tk.DISABLED
        )
        self.learn_preview_text.pack(fill=tk.X, padx=8, pady=(0, 6))

        # 2. 学习主题
        topic_frame = tk.LabelFrame(
            left_panel, text="🎯 学习主题", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        topic_frame.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(
            topic_frame, text="输入要学习的主题或概念：",
            bg="white", font=("Microsoft YaHei", 8), fg="#666666"
        ).pack(anchor="w", padx=8, pady=(4, 0))
        self.learn_topic_entry = tk.Entry(
            topic_frame, font=("Microsoft YaHei", 10),
            relief=tk.SOLID, bd=1
        )
        self.learn_topic_entry.pack(fill=tk.X, padx=8, pady=(2, 8))
        self.learn_topic_entry.insert(0, "CVE漏洞分析")

        # 3. 学习层次
        level_frame = tk.LabelFrame(
            left_panel, text="📊 学习层次", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        level_frame.pack(fill=tk.X, padx=8, pady=4)
        self.learn_level_var = tk.StringVar(value="入门")
        levels = [
            ("🌱 入门  — 简单类比，零基础理解", "入门"),
            ("💼 专业  — 技术深度，行业标准", "专业"),
            ("🏆 精通  — 苏格拉底挑战，跨域连接", "精通"),
        ]
        for text, val in levels:
            tk.Radiobutton(
                level_frame, text=text, variable=self.learn_level_var,
                value=val, bg="white", font=("Microsoft YaHei", 9),
                anchor="w"
            ).pack(fill=tk.X, padx=8, pady=2)

        # 4. 操作按钮
        btn_frame = tk.Frame(left_panel, bg="white")
        btn_frame.pack(fill=tk.X, padx=8, pady=8)
        self.learn_start_btn = tk.Button(
            btn_frame, text="🚀 开始学习",
            command=self._start_learn_session,
            bg=self.success_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=6
        )
        self.learn_start_btn.pack(fill=tk.X, pady=(0, 4))
        tk.Button(
            btn_frame, text="🔄 重置会话",
            command=self._reset_learn_session,
            bg=self.warning_color, fg="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT, cursor="hand2", pady=4
        ).pack(fill=tk.X)

        # ── 右侧对话区域 ──────────────────────────────────────────────
        right_panel = tk.Frame(main_paned, bg="white")
        main_paned.add(right_panel)

        chat_lf = tk.LabelFrame(
            right_panel, text="💬 费曼对话",
            bg="white", font=("Microsoft YaHei", 9, "bold"),
            fg=self.primary_color
        )
        chat_lf.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 4))

        self.learn_chat_area = scrolledtext.ScrolledText(
            chat_lf, wrap=tk.WORD,
            font=("Microsoft YaHei", 10),
            bg="#f0f4f8", relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.learn_chat_area.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        # 配置文字样式标签
        self.learn_chat_area.tag_config("system", foreground="#888888", font=("Microsoft YaHei", 9, "italic"))
        self.learn_chat_area.tag_config("ai", foreground=self.primary_color, font=("Microsoft YaHei", 10))
        self.learn_chat_area.tag_config("user", foreground=self.success_color, font=("Microsoft YaHei", 10, "bold"))
        self.learn_chat_area.tag_config("header", foreground=self.info_color, font=("Microsoft YaHei", 10, "bold"))

        # 用户输入区
        input_lf = tk.LabelFrame(
            right_panel, text="✍️ 输入您的理解或提问",
            bg="white", font=("Microsoft YaHei", 9, "bold"),
            fg=self.primary_color
        )
        input_lf.pack(fill=tk.X, padx=6, pady=(0, 4))

        self.learn_user_input = tk.Text(
            input_lf, height=4, wrap=tk.WORD,
            font=("Microsoft YaHei", 10),
            relief=tk.SOLID, bd=1
        )
        self.learn_user_input.pack(fill=tk.X, padx=6, pady=(4, 4))
        self.learn_user_input.bind("<Control-Return>", lambda e: self._send_learn_message())

        send_bar = tk.Frame(input_lf, bg="white")
        send_bar.pack(fill=tk.X, padx=6, pady=(0, 6))
        tk.Label(
            send_bar, text="Ctrl+Enter 快捷发送",
            bg="white", fg="#999999", font=("Microsoft YaHei", 8)
        ).pack(side=tk.LEFT)
        self.learn_send_btn = tk.Button(
            send_bar, text="💬 提交解释",
            command=self._send_learn_message,
            bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=20, pady=4
        )
        self.learn_send_btn.pack(side=tk.RIGHT)

        # ── 底部状态栏 ────────────────────────────────────────────────
        self.learn_status_label = tk.Label(
            self.learn_frame, text="就绪  |  请选择学习内容来源，输入主题，然后点击「开始学习」",
            bg="#f5f5f5", fg="#555555",
            font=("Microsoft YaHei", 9), anchor="w", padx=10
        )
        self.learn_status_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=4)

        # 显示欢迎信息
        self._learn_append_message(
            "【费曼学习法助手已就绪】\n\n"
            "费曼学习法四步骤：\n"
            "  1️⃣  选择一个概念\n"
            "  2️⃣  用简单语言解释它（如同教给12岁孩子）\n"
            "  3️⃣  找出你无法解释清楚的部分\n"
            "  4️⃣  回顾原始资料，重新解释直到清晰\n\n"
            "请在左侧选择学习内容来源和层次，输入主题后点击「开始学习」。",
            tag="system"
        )

    def _on_learn_source_change(self):
        """数据来源单选切换时显示/隐藏数据库子选项"""
        if self.learn_source_var.get() == "db":
            self.learn_db_type_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
        else:
            self.learn_db_type_frame.pack_forget()

    def _load_learn_content(self):
        """加载学习内容到预览框"""
        source = self.learn_source_var.get()
        if source == "db":
            self._load_learn_from_db()
        else:
            self._load_learn_from_file()

    def _load_learn_from_db(self):
        """从 SQLite 数据库加载内容"""
        db_type = self.learn_db_type_combo.get()
        try:
            cursor = self.conn.cursor()
            content_lines = []

            if db_type == "CVE漏洞数据":
                cursor.execute(
                    "SELECT cve_id, data FROM cves ORDER BY published_date DESC LIMIT 20"
                )
                rows = cursor.fetchall()
                if not rows:
                    self._learn_set_preview("数据库中暂无 CVE 数据，请先采集。")
                    return
                for cve_id, data_str in rows:
                    try:
                        d = json.loads(data_str)
                        desc = ""
                        descs = d.get("descriptions", [])
                        for item in descs:
                            if item.get("lang") == "en":
                                desc = item.get("value", "")[:120]
                                break
                        metrics = d.get("metrics", {})
                        cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                        severity = ""
                        if cvss:
                            severity = cvss[0].get("cvssData", {}).get("baseSeverity", "")
                        content_lines.append(
                            f"[{cve_id}] 严重性:{severity}\n  {desc}"
                        )
                    except Exception:
                        content_lines.append(f"[{cve_id}] 数据解析失败")
                topic_hint = "CVE漏洞分析与安全修复"

            elif db_type == "Dell安全公告":
                cursor.execute(
                    "SELECT dsa_id, title, cve_ids FROM dell_advisories ORDER BY published_date DESC LIMIT 20"
                )
                rows = cursor.fetchall()
                if not rows:
                    self._learn_set_preview("数据库中暂无 Dell 安全公告，请先采集。")
                    return
                for dsa_id, title, cve_ids in rows:
                    content_lines.append(f"[{dsa_id}] {title}\n  关联CVE: {cve_ids or '无'}")
                topic_hint = "Dell安全公告与漏洞管理"

            elif db_type == "AI分析记录":
                cursor.execute(
                    "SELECT cve_id, dell_advisory_id, result, analysis_time FROM ai_solutions "
                    "ORDER BY created_at DESC LIMIT 10"
                )
                rows = cursor.fetchall()
                if not rows:
                    self._learn_set_preview("数据库中暂无 AI 分析记录。")
                    return
                for cve_id, dsa_id, result, ts in rows:
                    snippet = (result or "")[:150].replace("\n", " ")
                    content_lines.append(
                        f"[{ts[:16]}] {cve_id} / {dsa_id}\n  {snippet}..."
                    )
                topic_hint = "AI安全分析结果解读"
            else:
                return

            self.learn_source_content = "\n\n".join(content_lines)
            self._learn_set_preview(self.learn_source_content)
            # 自动填入建议主题
            current = self.learn_topic_entry.get().strip()
            if not current or current == "CVE漏洞分析":
                self.learn_topic_entry.delete(0, tk.END)
                self.learn_topic_entry.insert(0, topic_hint)
            self.learn_status_label.config(
                text=f"已从数据库加载 {len(content_lines)} 条{db_type}记录"
            )
        except Exception as e:
            self._learn_set_preview(f"加载失败: {e}")

    def _load_learn_from_file(self):
        """从本地文件加载内容"""
        path = filedialog.askopenfilename(
            title="选择学习资料文件",
            filetypes=[
                ("文本文件", "*.txt"),
                ("Markdown", "*.md"),
                ("所有文件", "*.*"),
            ]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.learn_source_content = content[:8000]  # 最多8000字符作为上下文
            preview = content[:600] + ("\n..." if len(content) > 600 else "")
            self._learn_set_preview(preview)
            # 用文件名作为主题提示
            fname = Path(path).stem
            self.learn_topic_entry.delete(0, tk.END)
            self.learn_topic_entry.insert(0, fname)
            self.learn_status_label.config(
                text=f"已加载文件: {Path(path).name}  ({len(content)} 字符)"
            )
        except Exception as e:
            self._learn_set_preview(f"文件读取失败: {e}")

    def _learn_set_preview(self, text: str):
        """更新内容预览框"""
        self.learn_preview_text.config(state=tk.NORMAL)
        self.learn_preview_text.delete("1.0", tk.END)
        self.learn_preview_text.insert("1.0", text)
        self.learn_preview_text.config(state=tk.DISABLED)

    def _learn_append_message(self, text: str, tag: str = "ai", prefix: str = ""):
        """向对话区追加一条消息"""
        self.learn_chat_area.config(state=tk.NORMAL)
        if prefix:
            self.learn_chat_area.insert(tk.END, prefix + "\n", "header")
        self.learn_chat_area.insert(tk.END, text + "\n\n", tag)
        self.learn_chat_area.see(tk.END)
        self.learn_chat_area.config(state=tk.DISABLED)

    def _start_learn_session(self):
        """开始一个新的费曼学习会话"""
        topic = self.learn_topic_entry.get().strip()
        if not topic:
            messagebox.showwarning("提示", "请先输入学习主题")
            return
        if self.is_learn_generating:
            return

        self.learn_topic = topic
        self.learn_messages = []

        level = self.learn_level_var.get()
        level_desc = {
            "入门": "初学者（用日常类比和简单语言）",
            "专业": "专业开发者（技术深度，精确术语）",
            "精通": "领域专家（苏格拉底挑战式，跨域联接）",
        }.get(level, level)

        # 构造系统提示词
        system_prompt = self._get_learn_system_prompt(level)

        # 构造启动用户消息（含内容上下文）
        context_part = ""
        if self.learn_source_content:
            snippet = self.learn_source_content[:2000]
            context_part = f"\n\n【参考资料（节选）】\n{snippet}"

        user_msg = (
            f"我想用费曼学习法学习：「{topic}」\n"
            f"我的学习层次：{level_desc}{context_part}\n\n"
            f"请按费曼学习法引导我：先简单介绍这个主题，然后请我用自己的话解释它。"
        )

        self.learn_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ]

        # 清空对话区并显示开始信息
        self.learn_chat_area.config(state=tk.NORMAL)
        self.learn_chat_area.delete("1.0", tk.END)
        self.learn_chat_area.config(state=tk.DISABLED)
        self._learn_append_message(
            f"▶ 开始学习：{topic}  |  层次：{level}",
            tag="header"
        )
        self._learn_append_message(f"您: {user_msg[:200]}...", tag="user", prefix="")

        self._set_learn_buttons(False)
        self.learn_status_label.config(text="AI 正在生成费曼引导内容...")
        threading.Thread(
            target=self._learn_ai_thread,
            args=(list(self.learn_messages),),
            daemon=True
        ).start()

    def _send_learn_message(self):
        """用户提交解释/回答"""
        if self.is_learn_generating:
            return
        if not self.learn_messages:
            messagebox.showinfo("提示", "请先点击「开始学习」启动会话")
            return
        user_text = self.learn_user_input.get("1.0", tk.END).strip()
        if not user_text:
            return

        # 清空输入框
        self.learn_user_input.delete("1.0", tk.END)

        # 记录到历史
        self.learn_messages.append({"role": "user", "content": user_text})
        self._learn_append_message(user_text, tag="user", prefix="── 您的解释 ──")

        self._set_learn_buttons(False)
        self.learn_status_label.config(text="AI 正在分析您的解释...")
        threading.Thread(
            target=self._learn_ai_thread,
            args=(list(self.learn_messages),),
            daemon=True
        ).start()

    def _learn_ai_thread(self, messages: list):
        """后台线程：调用 Qwen AI 进行费曼对话"""
        self.is_learn_generating = True
        try:
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                self.root.after(
                    0, messagebox.showerror, "配置错误",
                    "未设置 QWEN_API_KEY 或 DASHSCOPE_API_KEY，无法调用 AI"
                )
                return

            model = os.getenv("QWEN_MODEL", "qwen-max-latest")
            base_url = os.getenv(
                "QWEN_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1"
            )

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.7,
                max_tokens=1500,
            )
            reply = response.choices[0].message.content

            # 追加到历史
            self.learn_messages.append({"role": "assistant", "content": reply})
            # 保持历史不超过20条（节省token）
            if len(self.learn_messages) > 21:
                # 保留system消息 + 最近20条
                self.learn_messages = self.learn_messages[:1] + self.learn_messages[-20:]

            self.root.after(0, self._learn_append_message, reply, "ai", "── AI 导师 ──")
            self.root.after(0, self.learn_status_label.config,
                            {"text": f"对话进行中  |  主题：{self.learn_topic}  |  共 {len(self.learn_messages)} 轮"})

        except Exception as e:
            err = f"AI 调用失败: {e}"
            self.root.after(0, self._learn_append_message, err, "system")
            self.root.after(0, self.learn_status_label.config, {"text": err})
        finally:
            self.is_learn_generating = False
            self.root.after(0, self._set_learn_buttons, True)

    def _set_learn_buttons(self, enabled: bool):
        """启用/禁用学习相关按钮"""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.learn_start_btn.config(state=state)
        self.learn_send_btn.config(state=state)

    def _reset_learn_session(self):
        """重置费曼学习会话"""
        self.learn_messages = []
        self.learn_topic = ""
        self.learn_source_content = ""
        self._learn_set_preview("")
        self.learn_chat_area.config(state=tk.NORMAL)
        self.learn_chat_area.delete("1.0", tk.END)
        self.learn_chat_area.config(state=tk.DISABLED)
        self._learn_append_message(
            "会话已重置。请重新选择学习内容来源和主题，然后点击「开始学习」。",
            tag="system"
        )
        self.learn_status_label.config(text="会话已重置")
        self._set_learn_buttons(True)

    def _get_learn_system_prompt(self, level: str) -> str:
        """根据学习层次返回对应的系统提示词"""
        prompts = {
            "入门": (
                "你是一位耐心的费曼学习法导师，面向零基础学习者。\n"
                "原则：\n"
                "1. 始终使用日常类比和生活化比喻解释技术概念，绝不堆砌专业术语\n"
                "2. 每次只聚焦一个核心概念，循序渐进\n"
                "3. 对用户的解释给予充分鼓励，用温和方式指出不足\n"
                "4. 每次回应结尾提出一个简单的引导问题\n"
                "5. 如果用户说'不知道'，用更简单的比喻重新解释，而非批评\n"
                "语气：温暖、鼓励、耐心"
            ),
            "专业": (
                "你是一位资深技术导师，采用费曼学习法面向专业工程师。\n"
                "原则：\n"
                "1. 使用准确的技术术语和行业标准表达\n"
                "2. 关注实现细节、架构设计、权衡取舍和最佳实践\n"
                "3. 对用户解释的技术准确性进行严格评估，指出精确性不足之处\n"
                "4. 每次回应结尾提出一个深度技术问题或实际应用场景\n"
                "5. 引用相关标准（如CVE评分标准、CVSS）或行业实践\n"
                "语气：专业、精准、有深度"
            ),
            "精通": (
                "你是一位顶级领域专家，运用苏格拉底式提问进行费曼教学，面向领域专家。\n"
                "原则：\n"
                "1. 挑战用户思维的边界，深挖理解的盲点和假设\n"
                "2. 关注跨领域知识联接（如安全与系统设计、密码学与实现的关系）\n"
                "3. 引导用户发现反直觉结论、边界条件和精微概念辨析\n"
                "4. 每次提出一个能引发更深思考的苏格拉底式问题\n"
                "5. 要求用户能够'教授他人'这个概念——这是费曼法的最高标准\n"
                "语气：严谨、挑战性、启发式"
            ),
        }
        return prompts.get(level, prompts["入门"])

    # ==================== 操作日志 ====================

    def create_log_view(self):
        """创建日志视图"""
        # 日志文本区域
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            wrap=tk.WORD,
            width=80,
            height=25,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 清空日志按钮
        clear_btn = tk.Button(
            self.log_frame,
            text="清空日志",
            command=self.clear_log,
            bg=self.warning_color,
            fg="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT,
            cursor="hand2"
        )
        clear_btn.pack(pady=(0, 10))

    # ==================== Progress Bar Control ====================

    def show_progress(self, text=""):
        """显示进度条"""
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_text.config(text=text)
        self.progress_text.pack(side=tk.RIGHT, padx=(5, 0))
        self.progress_var.set(0)

    def update_progress(self, value, text=""):
        """更新进度条"""
        self.progress_var.set(value)
        if text:
            self.progress_text.config(text=text)
        self.root.update_idletasks()  # Update the GUI

    def hide_progress(self):
        """隐藏进度条"""
        self.progress_bar.pack_forget()
        self.progress_text.pack_forget()
        self.bottom_status.config(text="准备就绪 | 支持离线数据查看")

    # ==================== NVD CVE 采集功能 ====================

    def start_nvd_collection(self):
        """开始采集 NVD CVE 数据"""
        if self.is_collecting:
            return

        self.is_collecting = True
        self.nvd_collect_btn.config(state=tk.DISABLED)
        self.nvd_stop_btn.config(state=tk.NORMAL)

        # ✅ 修复：只清空树视图，不清空内存数据
        for item in self.nvd_tree.get_children():
            self.nvd_tree.delete(item)

        # ✅ 不再清空内存数据，保留现有数据
        # self.cve_data = []  # 已注释

        # 获取时间范围并转换为天数
        time_range = self.nvd_time_range_var.get()
        time_range_map = {
            "最近一周": 7,
            "1个月": 30,
            "3个月": 90,
            "半年": 180,
            "1年": 365
        }
        days = time_range_map.get(time_range, 365)

        # Show progress bar
        self.show_progress(f"开始采集 NVD CVE 数据 ({time_range})...")
        self.bottom_status.config(text=f"正在采集 NVD CVE 数据...")

        # 优先使用环境变量的 API Key
        api_key = os.getenv("NVD_API_KEY")

        # 在新线程中运行采集
        thread = threading.Thread(target=self.run_nvd_collection, args=(days, api_key))
        thread.daemon = True
        thread.start()

        self.log(f"开始采集 NVD CVE 数据（{time_range}）...")
        if api_key:
            self.log("✓ 使用环境变量 API Key，采集速度更快")
        else:
            self.log("⚠ 未配置 API Key，采集速度较慢")
            self.log("提示：设置环境变量 NVD_API_KEY 可提升速度 10 倍")

    def stop_nvd_collection(self):
        """停止采集 NVD 数据"""
        self.is_collecting = False
        self.nvd_collect_btn.config(state=tk.NORMAL)
        self.nvd_stop_btn.config(state=tk.DISABLED)
        self.log("NVD CVE 数据采集已停止")

    def run_nvd_collection(self, days, api_key):
        """在线程中运行 NVD 采集"""
        try:
            # 运行异步采集
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.run(self.collect_nvd_cves_async(days, api_key))
        except Exception as e:
            self.log_queue.put(f"NVD 采集出错: {str(e)}")
        finally:
            self.is_collecting = False
            # Schedule the UI updates to run in the main thread
            self.root.after(0, self._finish_nvd_collection)

    def _finish_nvd_collection(self):
        """Finish NVD collection UI updates (run in main thread)"""
        self.nvd_collect_btn.config(state=tk.NORMAL)
        self.nvd_stop_btn.config(state=tk.DISABLED)
        self.hide_progress()

    async def collect_nvd_cves_async(self, days, api_key):
        """异步采集 NVD CVE 数据（优化版）"""
        end_date = datetime.now().replace(hour=23, minute=59, second=59, microsecond=999999)
        start_date = end_date - timedelta(days=days)

        self.log_queue.put(f"时间范围: {start_date.date()} 至 {end_date.date()}")

        # 获取数据库中已存在的CVE IDs
        existing_cve_ids = self.get_existing_cve_ids()
        self.log_queue.put(f"数据库中已存在 {len(existing_cve_ids)} 个CVE记录")

        async with CVECollector(api_key=api_key) as collector:
            try:
                # Collect data in chunks to avoid API date range limitations
                all_raw_cves = []

                current_start = start_date
                chunk_size = timedelta(days=120)  # Use 120-day chunks to avoid 404 errors

                while current_start < end_date and self.is_collecting:
                    current_end = min(current_start + chunk_size, end_date)

                    self.log_queue.put(f"正在获取 {current_start.date()} 到 {current_end.date()} 的数据...")

                    try:
                        # Get data for this chunk
                        chunk_cves = await collector.fetch_cves(current_start, current_end)
                        all_raw_cves.extend(chunk_cves)

                        self.log_queue.put(f"批次完成: {len(chunk_cves)} 条 CVE 数据")

                        # Move to next chunk
                        current_start = current_end

                        # Brief pause between chunks
                        await asyncio.sleep(0.5)

                    except Exception as chunk_error:
                        self.log_queue.put(f"批次采集错误: {str(chunk_error)}")
                        current_start = current_end
                        continue

                if all_raw_cves:
                    new_cves_count = 0
                    updated_count = 0
                    self.log_queue.put(f"成功获取总计 {len(all_raw_cves)} 条 CVE 数据，正在解析...")

                    # 解析并存储数据（只存储到数据库）
                    new_cves = []  # 收集新增的 CVE for GUI updates
                    cves_to_store = []  # Collect all parsed CVEs for bulk storage

                    # Process in batches to keep UI responsive
                    batch_size = 50  # Larger batch for bulk processing
                    for i, raw_cve in enumerate(all_raw_cves):
                        if not self.is_collecting:
                            self.log_queue.put(f"采集被用户中断，已处理 {i}/{len(all_raw_cves)} 条数据")
                            break

                        parsed = collector.parse_cve(raw_cve)
                        cve_id = parsed.get("cve_id", "")

                        if cve_id:
                            is_new = cve_id not in existing_cve_ids

                            if is_new:
                                new_cves.append(parsed)  # For GUI updates
                                new_cves_count += 1
                                # 添加到已存在列表
                                existing_cve_ids.add(cve_id)
                                cves_to_store.append(parsed)  # For bulk storage
                            else:
                                updated_count += 1

                        # Process in bulk batches for better performance
                        if len(cves_to_store) >= batch_size or i == len(all_raw_cves) - 1:
                            if cves_to_store:
                                # Bulk store to Redis/SQLite
                                if self.use_redis:
                                    for cve_to_store in cves_to_store:
                                        self.redis_manager.store_cve(cve_to_store)
                                        # Add to SQLite backup queue
                                        self.sqlite_backup_queue.put(('cve', cve_to_store))
                                else:
                                    # Fall back to SQLite bulk storage
                                    self._bulk_store_cve_to_sqlite(cves_to_store)

                                # Clear the batch
                                cves_to_store = []

                        # Provide progress updates and allow other tasks to run
                        if i % 20 == 0 and i > 0:  # Update progress every 20 items
                            progress_percent = int((i / len(all_raw_cves)) * 100)
                            self.log_queue.put(f"正在处理: {i}/{len(all_raw_cves)} ({progress_percent}%)")
                            await asyncio.sleep(0.01)  # Yield to other async tasks

                    self.log_queue.put(f"数据解析完成: 新增 {new_cves_count}, 更新 {updated_count}")

                    # 优化：只将新增的 CVE 添加到内存和 GUI（不重新加载全部数据）
                    if new_cves:
                        self.log_queue.put(f"正在处理 {len(new_cves)} 条新增 CVE...")

                        # 批量添加到内存
                        self.cve_data.extend(new_cves)

                        # 批量添加到 GUI（通过队列）- limit to avoid GUI freezing
                        processed_count = 0
                        for cve in new_cves:
                            self.data_queue.put(('nvd', cve))
                            processed_count += 1

                            # Yield control periodically to prevent GUI freezing
                            if processed_count % 50 == 0:  # Update every 50 items
                                await asyncio.sleep(0.01)  # Small pause to yield to other tasks

                    # 显示统计
                    total_in_db = len(existing_cve_ids)
                    self.log_queue.put(f"✓ NVD CVE 数据采集完成！")
                    self.log_queue.put(f"  新增: {new_cves_count} 条")
                    if updated_count > 0:
                        self.log_queue.put(f"  更新: {updated_count} 条")
                    self.log_queue.put(f"  数据库总计: {total_in_db} 条")

                    # ✅ 修复：采集完成后重新加载全部数据 - only if needed
                    self.log_queue.put("正在从数据库重新加载全部CVE数据...")
                    all_cves = self.load_cve_data_from_db()
                    self.cve_data = all_cves

                    # 重新填充树视图 (with performance optimization for large datasets)
                    display_cves = all_cves[:500]  # Only show first 500 in UI to prevent freezing
                    processed_count = 0
                    for cve in display_cves:
                        self.data_queue.put(('nvd', cve))
                        processed_count += 1

                        # Yield control periodically to prevent GUI freezing
                        if processed_count % 50 == 0:
                            await asyncio.sleep(0.01)  # Small pause to yield to other tasks

                    if len(all_cves) > 500:
                        self.log_queue.put(f"✓ 已加载 {len(display_cves)} 条CVE到界面 (共 {len(all_cves)} 条，使用搜索功能查询全部)")
                    else:
                        self.log_queue.put(f"✓ 已加载 {len(all_cves)} 条CVE到界面")
                else:
                    # 从数据库加载现有数据
                    all_cves = self.load_cve_data_from_db()
                    self.cve_data = all_cves
                    self.log_queue.put(f"未获取到新的 CVE 数据，从数据库加载 {len(all_cves)} 条记录")

                    # ✅ 修复：即使没有新数据也要显示到界面
                    for cve in all_cves:
                        self.data_queue.put(('nvd', cve))

            except Exception as e:
                self.log_queue.put(f"采集过程出错: {str(e)}")
                import traceback
                self.log_queue.put(f"详细错误: {traceback.format_exc()}")

    # ==================== Dell URL单条网页抓取功能 ====================

    def fetch_dell_advisory_from_url(self):
        """从用户输入的URL抓取单条Dell安全公告并存入数据库"""
        url = self.dell_url_entry.get().strip()
        placeholder = "https://www.dell.com/support/kbdoc/en-us/..."
        if not url or url == placeholder:
            messagebox.showwarning("请输入URL", "请先输入Dell安全公告的网页URL")
            return
        if not url.startswith("http"):
            messagebox.showwarning("URL格式错误", "请输入有效的HTTP/HTTPS URL")
            return
        self.dell_fetch_btn.config(state=tk.DISABLED)
        self.dell_fetch_status.config(text="⏳ 正在抓取页面内容...", fg=self.info_color)
        self.log(f"开始抓取Dell安全公告: {url}")
        thread = threading.Thread(
            target=self._fetch_advisory_thread, args=(url,), daemon=True
        )
        thread.start()

    def _fetch_advisory_thread(self, url: str):
        """后台线程：抓取并解析单条Dell安全公告"""
        try:
            content = ""
            exa_api_key = os.getenv("EXA_API_KEY")
            # 1. 优先使用Exa API
            if exa_api_key:
                self.log_queue.put("使用Exa API获取页面内容...")
                content = self._fetch_with_exa(url, exa_api_key)
            # 2. Fallback：直接HTTP请求 + BeautifulSoup
            if not content:
                self.log_queue.put("回退：使用直接HTTP请求获取页面...")
                content = self._fetch_with_requests(url)
            if not content:
                self.root.after(0, self._fetch_done, None,
                                "❌ 无法获取页面内容，请检查URL是否有效或网络连接")
                return
            # 3. 解析内容构建advisory结构
            advisory = self._parse_dell_page_content(url, content)
            # 4. 保证DSA ID不为空
            if not advisory.get('dell_security_advisory'):
                dsa_id = self._extract_dsa_id_from_url(url)
                if dsa_id:
                    advisory['dell_security_advisory'] = dsa_id
                else:
                    self.root.after(0, self._fetch_done, None,
                                    "⚠️ 未能识别DSA公告ID，请确认是Dell安全公告页面")
                    return
            # 5. 存入数据库
            is_new = self.store_dell_advisory(advisory)
            dsa_id = advisory['dell_security_advisory']
            if is_new:
                msg = f"✅ 新公告已入库：{dsa_id}（CVE数量：{len(advisory.get('cve_ids', []))}）"
            else:
                msg = f"ℹ️ 公告已存在，跳过：{dsa_id}"
            self.root.after(0, self._fetch_done, advisory, msg)
        except Exception as e:
            import traceback
            self.log_queue.put(f"URL抓取异常: {traceback.format_exc()}")
            self.root.after(0, self._fetch_done, None, f"❌ 抓取失败: {str(e)}")

    def _fetch_with_exa(self, url: str, api_key: str) -> str:
        """使用Exa API获取页面正文文本"""
        import requests as req
        try:
            response = req.post(
                "https://api.exa.ai/contents",
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "x-api-key": api_key,
                },
                json={"ids": [url], "text": True},
                timeout=30,
            )
            if response.status_code == 200:
                results = response.json().get("results", [])
                if results:
                    return results[0].get("text", "")
            else:
                self.log_queue.put(f"Exa API返回 HTTP {response.status_code}")
        except Exception as e:
            self.log_queue.put(f"Exa API调用失败: {e}")
        return ""

    def _fetch_with_requests(self, url: str) -> str:
        """直接HTTP请求 + BeautifulSoup 提取正文文本"""
        import requests as req
        from bs4 import BeautifulSoup
        try:
            response = req.get(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                },
                timeout=30,
            )
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
                tag.decompose()
            return soup.get_text(separator='\n', strip=True)
        except Exception as e:
            self.log_queue.put(f"直接HTTP抓取失败: {e}")
        return ""

    def _extract_dsa_id_from_url(self, url: str) -> str:
        """从URL路径中推断DSA ID"""
        match = re.search(r'dsa[-_](\d{4}[-_]\d+)', url, re.IGNORECASE)
        if match:
            return "DSA-" + match.group(1).replace('_', '-')
        match = re.search(r'/(\d{9})', url)
        if match:
            return f"KB-{match.group(1)}"
        return ""

    def _parse_dell_page_content(self, url: str, content: str) -> dict:
        """从页面文本内容提取Dell安全公告各字段"""
        scraper = DellSecurityScraper()
        # DSA ID
        dsa_match = re.search(r'DSA-\d{4}-\d+', content, re.IGNORECASE)
        dsa_id = dsa_match.group(0).upper() if dsa_match else ""
        # CVE IDs（去重，统一大写）
        cve_ids = list(set(
            c.upper() for c in re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE)
        ))
        # 标题：取前几行中含关键词的行
        lines = [l.strip() for l in content.split('\n') if l.strip()]
        title = lines[0][:200] if lines else url
        for line in lines[:8]:
            if (len(line) > 15 and
                    ('DSA' in line.upper() or 'Dell' in line or 'Security' in line)
                    and len(line) < 300):
                title = line
                break
        # 发布日期
        published_date = datetime.now().isoformat()
        date_patterns = [
            (r'(\w+ \d{1,2},?\s+\d{4})', ['%B %d, %Y', '%B %d %Y']),
            (r'(\d{4}-\d{2}-\d{2})',       ['%Y-%m-%d']),
            (r'(\d{1,2}/\d{1,2}/\d{4})',   ['%m/%d/%Y']),
        ]
        for pattern, fmts in date_patterns:
            m = re.search(pattern, content)
            if m:
                for fmt in fmts:
                    try:
                        published_date = datetime.strptime(m.group(1), fmt).isoformat()
                        break
                    except ValueError:
                        continue
                break
        # 影响级别
        impact = ""
        impact_match = (
            re.search(r'\b(Critical|High|Medium|Low)\b.*?[Ss]everity', content) or
            re.search(r'[Ss]everity[:\s]*(Critical|High|Medium|Low)', content)
        )
        if impact_match:
            impact = impact_match.group(1).capitalize()
        # 产品和解决方案
        products = scraper.extract_products_from_text(content)
        solution = scraper.extract_solution_from_text(content)
        # 摘要（前500字符，压缩空白）
        summary = ' '.join(content.split())[:500]
        return {
            'dell_security_advisory': dsa_id,
            'title': title,
            'cve_ids': cve_ids,
            'published_date': published_date,
            'link': url,
            'summary': summary,
            'description': content[:2000],
            'affected_products': products,
            'solution': solution,
            'impact': impact,
            'source': 'URL Fetch',
        }

    def _fetch_done(self, advisory, message: str):
        """抓取完成后在主线程更新UI状态"""
        self.dell_fetch_btn.config(state=tk.NORMAL)
        if advisory:
            self.dell_fetch_status.config(text=message, fg=self.success_color)
            self.log(message)
            self.dell_queue.put(('refresh_database', None))
        else:
            self.dell_fetch_status.config(text=message, fg=self.danger_color)
            self.log(f"URL抓取: {message}")

    # ==================== Dell 安全公告采集功能 ====================

    def start_dell_collection(self):
        """开始采集 Dell 安全公告"""
        if self.is_collecting_dell:
            return

        # 获取选择的时间范围
        time_range = self.dell_time_range_var.get()
        self.log(f"准备采集 Dell 安全公告 - 时间范围: {time_range}")

        self.is_collecting_dell = True
        self.dell_collect_btn.config(state=tk.DISABLED)
        self.dell_stop_btn.config(state=tk.NORMAL)

        # Show progress bar
        self.show_progress(f"开始采集 Dell 安全公告 ({time_range})...")
        self.bottom_status.config(text=f"正在采集 Dell 安全公告...")

        # ✅ 修复：只清空树视图，不清空内存数据
        # 采集完成后会从数据库重新加载全部数据
        for item in self.dell_tree.get_children():
            self.dell_tree.delete(item)

        # ✅ 不再清空内存数据，保留现有数据
        # self.dell_advisories = []  # 已注释

        # 在新线程中运行采集
        thread = threading.Thread(target=self.run_dell_collection, args=(time_range,))
        thread.daemon = True
        thread.start()

        self.log(f"开始采集 Dell 安全公告（范围：{time_range}）...")

    def stop_dell_collection(self):
        """停止采集 Dell 数据"""
        self.is_collecting_dell = False
        self.dell_collect_btn.config(state=tk.NORMAL)
        self.dell_stop_btn.config(state=tk.DISABLED)
        self.log("Dell 安全公告采集已停止")

    def run_dell_collection(self, time_range):
        """在线程中运行 Dell 采集"""
        try:
            # 运行异步采集
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.run(self.collect_dell_advisories_async(time_range))
        except Exception as e:
            self.log_queue.put(f"Dell 采集出错: {str(e)}")
        finally:
            self.is_collecting_dell = False
            # Schedule the UI updates to run in the main thread
            self.root.after(0, self._finish_dell_collection)

    def _finish_dell_collection(self):
        """Finish Dell collection UI updates (run in main thread)"""
        self.dell_collect_btn.config(state=tk.NORMAL)
        self.dell_stop_btn.config(state=tk.DISABLED)
        self.hide_progress()

    async def collect_dell_advisories_async(self, time_range):
        """异步采集 Dell 安全公告（优化版）"""
        scraper = DellSecurityScraper()
        try:
            # 计算日期范围
            time_range_map = {
                "最近一周": 7,
                "1个月": 30,
                "3个月": 90,
                "半年": 180,
                "1年": 365
            }
            days = time_range_map.get(time_range, 30)

            self.log_queue.put(f"正在采集最近 {days} 天的 Dell 安全公告...")
            self.log_queue.put("尝试访问Dell官网获取真实数据...")

            # 传递days参数
            items = await scraper.fetch_security_advisories(days=days)

            if items:
                self.log_queue.put(f"✓ 成功获取 {len(items)} 条 Dell 安全公告（{time_range}范围）")

                # 统计增量存储
                new_count = 0
                existing_count = 0
                new_advisories = []  # 收集新增的公告

                # Process in batches to keep UI responsive
                batch_size = 5  # Smaller batch for Dell data
                for i, item in enumerate(items):
                    if not self.is_collecting_dell:
                        self.log_queue.put(f"采集被用户中断，已处理 {i}/{len(items)} 条数据")
                        break

                    # 增强解决方案信息
                    item = self.enhance_dell_advisory(item)

                    # 存储到数据库（增量，优先 Redis）
                    is_new = self.store_dell_advisory(item)
                    if is_new:
                        new_count += 1
                        new_advisories.append(item)
                    else:
                        existing_count += 1

                    # Provide progress updates and allow other tasks to run
                    if i % batch_size == 0 and i > 0:
                        progress_percent = int((i / len(items)) * 100)
                        self.log_queue.put(f"Dell数据处理: {i}/{len(items)} ({progress_percent}%)")
                        await asyncio.sleep(0.01)  # Yield to other async tasks

                # 优化：批量添加到 GUI（只添加新数据）
                if new_advisories:
                    self.log_queue.put(f"正在显示 {len(new_advisories)} 条新增公告...")

                    # 批量添加到内存
                    self.dell_advisories.extend(new_advisories)

                    # 批量发送到队列 with performance optimization
                    processed_count = 0
                    for advisory in new_advisories:
                        self.dell_queue.put(advisory)
                        processed_count += 1

                        # Yield control periodically to prevent GUI freezing
                        if processed_count % 20 == 0:  # Update every 20 items for Dell data
                            await asyncio.sleep(0.01)  # Small pause to yield to other tasks

                # 显示增量统计
                if new_count > 0:
                    self.log_queue.put(f"✓ 新增 {new_count} 条 Dell 安全公告到数据库")
                if existing_count > 0:
                    self.log_queue.put(f"ℹ 跳过 {existing_count} 条已存在的公告")

                # 只在有新数据时保存 JSON 文件
                if new_advisories:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = self.data_dir / f"dell_advisories_new_{timestamp}.json"
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(new_advisories, f, ensure_ascii=False, indent=2)
                    self.log_queue.put(f"新增数据已保存到: {filename}")

                # ✅ 修复：使用正确的方法计算数据库总数
                total_count = self.get_dell_count_from_db()

                self.log_queue.put("✓ Dell 安全公告采集完成！")
                self.log_queue.put(f"✓ 数据库总计 {total_count} 条记录")

                # ✅ 修复：采集完成后重新加载全部数据
                self.log_queue.put("正在从数据库重新加载全部Dell数据...")
                self.dell_queue.put(('refresh_database', None))
            else:
                self.log_queue.put("未获取到任何数据")

        except Exception as e:
            self.log_queue.put(f"采集数据出错: {str(e)}")
            import traceback
            self.log_queue.put(f"详细错误: {traceback.format_exc()}")

    # ==================== 数据加载和显示功能 ====================

    def load_local_data(self):
        """加载本地数据（优化版：自动加载Dell数据，不加载CVE数据）"""
        try:
            # 只获取数据库中的统计信息
            cve_total = self.get_cve_count_from_db()
            dell_total = self.redis_manager.get_dell_count() if self.use_redis else 0

            # 如果未使用Redis，从SQLite获取Dell总数
            if not self.use_redis:
                try:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM dell_advisories")
                    dell_total = cursor.fetchone()[0]
                except Exception:
                    dell_total = 0

            # 显示统计信息
            self.log("=" * 60)
            self.log("📊 数据库状态概览")
            self.log(f"  CVE 数据：{cve_total:,} 条")
            self.log(f"  Dell 安全公告：{dell_total:,} 条")
            self.log("=" * 60)
            self.log("")

            # ✅ 自动加载Dell数据到内存（用于关联匹配）
            if dell_total > 0:
                self.log("⚡ 正在自动加载Dell安全公告数据...")
                try:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
                    records = cursor.fetchall()
                    self.dell_advisories = []

                    for record in records:
                        try:
                            if record[0]:
                                data = json.loads(record[0])
                                self.dell_advisories.append(data)
                        except json.JSONDecodeError:
                            continue

                    # 显示Dell数据到界面 with performance optimization
                    processed_count = 0
                    for advisory in self.dell_advisories:
                        self.dell_queue.put(('add', advisory))  # Use queue instead of direct add
                        processed_count += 1

                        # Yield control periodically to prevent GUI freezing
                        if processed_count % 20 == 0:  # Update every 20 items
                            import time
                            time.sleep(0.001)  # Small pause to allow other operations

                    self.log(f"✓ 已加载 {len(self.dell_advisories)} 条Dell安全公告数据")
                except Exception as e:
                    self.log(f"⚠ Dell数据加载失败: {e}")
            else:
                self.log("ℹ️ 数据库中暂无Dell安全公告数据")

            self.log("")
            self.log("⚡ 性能优化：CVE数据不会自动加载到界面")
            self.log("💡 使用方法：")
            self.log("  1. 点击 [💾 从数据库加载] 按钮加载最新500条NVD CVE数据")
            self.log("  2. 点击 [▶ 采集Dell安全公告] 按钮采集最新Dell数据")
            self.log("  3. 加载CVE和Dell数据后，系统会自动计算关联匹配")
            self.log("  4. 切换到 [🔗 CVE-Dell 关联] 标签页查看匹配结果")
            self.log("")
            self.log(f"✓ {'Redis 缓存' if self.use_redis else 'SQLite'} 模式已就绪")

            # 更新统计显示
            self.update_stats()

        except Exception as e:
            self.log(f"加载数据库信息出错: {str(e)}")

    def load_local_data_summary(self):
        """仅加载数据库统计信息，不自动开始数据采集（优化启动速度）"""
        try:
            # 只获取数据库中的统计信息
            cve_total = self.get_cve_count_from_db()
            dell_total = self.redis_manager.get_dell_count() if self.use_redis else 0

            # 如果未使用Redis，从SQLite获取Dell总数
            if not self.use_redis:
                try:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM dell_advisories")
                    dell_total = cursor.fetchone()[0]
                except Exception:
                    dell_total = 0

            # 显示统计信息
            self.log("=" * 60)
            self.log("📊 数据库状态概览")
            self.log(f"  CVE 数据：{cve_total:,} 条")
            self.log(f"  Dell 安全公告：{dell_total:,} 条")
            self.log("=" * 60)
            self.log("")

            self.log("💡 使用方法：")
            self.log("  1. 点击 [💾 从数据库加载] 按钮加载最新NVD CVE数据")
            self.log("  2. 点击 [📁 从数据库加载] 按钮加载Dell安全公告")
            self.log("  3. 点击 [▶ 采集 NVD 数据] 或 [▶ 采集Dell安全公告] 手动采集最新数据")
            self.log("  4. 切换到 [🔗 CVE-Dell 关联] 标签页查看匹配结果")
            self.log("")
            self.log(f"✓ {'Redis 缓存' if self.use_redis else 'SQLite'} 模式已就绪")

            # 更新统计显示
            self.update_stats()

        except Exception as e:
            self.log(f"加载数据库统计信息出错: {str(e)}")

    def load_local_nvd_data(self):
        """手动加载本地 NVD 数据（从JSON文件）"""
        filename = filedialog.askopenfilename(
            title="选择 NVD CVE 数据文件",
            initialdir=self.data_dir,
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")]
        )

        if filename:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    loaded_cves = json.load(f)

                # 将新数据存储到数据库并加载现有数据
                for cve in loaded_cves:
                    self.store_cve_data(cve)

                # 从数据库重新加载最新500条数据
                self.cve_data = self.load_cve_data_from_db()

                # 清空并重新加载树视图（只显示最新500条）
                for item in self.nvd_tree.get_children():
                    self.nvd_tree.delete(item)

                # 按发布日期排序，取最新500条
                sorted_cves = sorted(
                    self.cve_data,
                    key=lambda x: x.get('published_date', '') or '',
                    reverse=True
                )[:500]

                for cve in sorted_cves:
                    self.add_nvd_to_tree(cve)

                self.log(f"成功加载 NVD 数据: {Path(filename).name} ({len(loaded_cves)} 条)，现在数据库中共有 {len(self.cve_data)} 条")
                if len(self.cve_data) > 500:
                    self.log(f"显示最新 500 条数据，使用搜索功能可查询全部数据")
                self.update_stats()

                # 刷新关联数据
                if self.dell_advisories:
                    self.refresh_matched_data()

            except Exception as e:
                messagebox.showerror("加载失败", f"加载文件失败：{str(e)}")
                self.log(f"加载文件失败: {str(e)}")

    def load_nvd_from_database(self, limit=500, async_load=True):
        """从数据库加载NVD CVE数据（优化版：限制数量 + 异步加载）

        Args:
            limit: 加载数量限制，最多显示最新的N条数据（默认500条）
            async_load: 是否异步加载（默认True）
        """
        if async_load:
            # 异步后台加载
            self.log(f"正在后台加载 NVD CVE 数据（最新 {limit} 条）...")
            threading.Thread(
                target=self._load_nvd_background,
                args=(limit,),
                daemon=True
            ).start()
        else:
            # 同步加载
            self._load_nvd_background(limit)

    def _load_nvd_background(self, limit=500):
        """后台线程加载NVD CVE数据"""
        try:
            # 优先从 Redis 加载
            if self.use_redis:
                try:
                    # 从Redis加载数据（按日期倒序，取最新limit条）
                    all_cves = self.redis_manager.get_all_cves()

                    # 按发布日期排序，取最新limit条
                    sorted_cves = sorted(
                        all_cves,
                        key=lambda x: x.get('published_date', '') or '',
                        reverse=True
                    )[:limit]

                    self.cve_data = sorted_cves

                    # 将数据推送到队列，由主线程处理UI更新
                    self.log_queue.put(f"从 Redis 加载 {len(self.cve_data)} 条 NVD CVE 数据")

                    # 清空树形视图（使用队列通知主线程）
                    self.data_queue.put(('clear_nvd', None))

                    # 批量添加数据 with performance optimization
                    processed_count = 0
                    for cve in self.cve_data:
                        self.data_queue.put(('add_nvd', cve))
                        processed_count += 1

                        # Yield control periodically to prevent GUI freezing
                        if processed_count % 50 == 0:  # Update every 50 items
                            import time
                            time.sleep(0.001)  # Small pause to allow other operations

                    # 通知加载完成
                    total_count = len(all_cves)
                    if total_count > limit:
                        self.log_queue.put(f"✓ NVD CVE 数据加载完成（显示最新 {limit}/{total_count} 条）")
                        self.log_queue.put(f"💡 提示：使用搜索功能可查询全部数据")
                    else:
                        self.log_queue.put(f"✓ NVD CVE 数据加载完成（共 {len(self.cve_data)} 条）")

                    # 刷新关联数据（使用后台线程）
                    if self.dell_advisories:
                        self.log_queue.put("正在计算 CVE-Dell 关联匹配...")
                        self._refresh_matched_data_background()

                    return

                except Exception as e:
                    self.log_queue.put(f"Redis 加载 NVD CVE 数据失败: {e}, 回退到 SQLite")
                    # 继续使用 SQLite

            # 从 SQLite 加载（回退方案）
            cursor = self.conn.cursor()

            # 查询最新的limit条记录（按发布日期倒序）
            cursor.execute("""
                SELECT data FROM cves
                ORDER BY published_date DESC
                LIMIT ?
            """, (limit,))

            records = cursor.fetchall()
            self.cve_data = []

            for record in records:
                try:
                    if record[0]:
                        data = json.loads(record[0])
                        self.cve_data.append(data)
                    else:
                        # 如果data字段为空，尝试从其他字段构建基本信息
                        continue
                except json.JSONDecodeError:
                    continue

            # 清空树形视图
            self.data_queue.put(('clear_nvd', None))

            # 显示数据 with performance optimization
            processed_count = 0
            for cve in self.cve_data:
                self.data_queue.put(('add_nvd', cve))
                processed_count += 1

                # Yield control periodically to prevent GUI freezing
                if processed_count % 50 == 0:  # Update every 50 items
                    import time
                    time.sleep(0.001)  # Small pause to allow other operations

            # 获取总数量
            cursor.execute("SELECT COUNT(*) FROM cves")
            total_count = cursor.fetchone()[0]

            self.log_queue.put(f"从 SQLite 数据库加载 {len(self.cve_data)} 条 NVD CVE 数据")
            if total_count > limit:
                self.log_queue.put(f"✓ 显示最新 {limit}/{total_count} 条数据")
                self.log_queue.put(f"💡 提示：使用搜索功能可查询全部数据")

            # 更新关联数据
            # Only refresh if we have both CVE and Dell data available
            if self.cve_data and self.dell_advisories:
                self._refresh_matched_data_background()

        except sqlite3.Error as e:
            self.log_queue.put(f"从数据库加载NVD CVE数据失败: {str(e)}")
        except Exception as e:
            self.log_queue.put(f"加载NVD CVE数据出错: {str(e)}")

    def load_local_dell_data(self):
        """手动加载本地 Dell 数据"""
        filename = filedialog.askopenfilename(
            title="选择 Dell 安全公告数据文件",
            initialdir=self.data_dir,
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")]
        )

        if filename:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    self.dell_advisories = json.load(f)

                # 清空并重新加载树视图
                for item in self.dell_tree.get_children():
                    self.dell_tree.delete(item)

                for advisory in self.dell_advisories:
                    self.add_dell_to_tree(advisory)

                self.log(f"成功加载 Dell 数据: {Path(filename).name} ({len(self.dell_advisories)} 条)")
                self.update_stats()

                # 刷新关联数据
                if self.cve_data:
                    self.refresh_matched_data()

            except Exception as e:
                messagebox.showerror("加载失败", f"加载文件失败：{str(e)}")
                self.log(f"加载文件失败: {str(e)}")

    def load_csv_data(self):
        """加载离线 CSV 数据"""
        # 默认从cve_data目录打开文件选择对话框
        initial_dir = str(self.data_dir)
        csv_file = filedialog.askopenfilename(
            title="选择 CSV 数据文件",
            initialdir=initial_dir,
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")]
        )

        if csv_file:
            try:
                import csv
                with open(csv_file, 'r', encoding='utf-8-sig') as f:
                    # 尝试读取CSV文件
                    reader = csv.DictReader(f)
                    fieldnames = reader.fieldnames

                    # 检测是否是Dell DSA CSV格式
                    is_dell_csv = all(col in fieldnames for col in ['TITLE', 'CVE IDENTIFIER', 'PUBLISHED', 'IMPACT'])

                    if is_dell_csv:
                        self.log("检测到Dell安全公告CSV格式，开始解析...")
                        # 在后台线程中加载
                        thread = threading.Thread(target=self.run_dell_csv_loading, args=(csv_file,))
                        thread.daemon = True
                        thread.start()
                    else:
                        # 原有的NVD CVE CSV处理逻辑
                        self.load_nvd_csv(csv_file, reader, fieldnames)

            except Exception as e:
                messagebox.showerror("加载失败", f"加载CSV文件失败：{str(e)}")
                self.log(f"加载CSV文件失败: {str(e)}")
                import traceback
                self.log(f"详细错误信息: {traceback.format_exc()}")

    def run_dell_csv_loading(self, csv_file):
        """在后台线程中运行Dell CSV加载"""
        try:
            self.load_dell_csv(csv_file)
        except Exception as e:
            self.log_queue.put(f"Dell CSV加载出错: {str(e)}")
            import traceback
            self.log_queue.put(f"详细错误: {traceback.format_exc()}")

    def load_dell_csv(self, csv_file):
        """加载Dell安全公告CSV数据（保存到本地并更新界面）"""
        try:
            dell_data = []
            new_count = 0
            existing_count = 0
            new_advisories = []  # 收集新增的公告

            # 打开CSV文件并创建新的reader
            with open(csv_file, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    title_field = row.get('TITLE', '').strip()
                    if not title_field:
                        continue

                    # 解析TITLE字段，提取DSA ID和标题
                    # 格式: "DSA-2025-386: Security Update for Dell Secure Connect Gateway REST API"
                    if ':' in title_field:
                        parts = title_field.split(':', 1)
                        dsa_id = parts[0].strip()
                        title = parts[1].strip()
                    else:
                        dsa_id = title_field
                        title = title_field

                    # 提取CVE IDs
                    cve_str = row.get('CVE IDENTIFIER', '').strip()
                    cve_ids = []
                    if cve_str:
                        # CVE可能用逗号分隔
                        cve_ids = [cve.strip() for cve in cve_str.split(',') if cve.strip()]

                    # 解析发布日期
                    published_str = row.get('PUBLISHED', '').strip()
                    # 将"OCT 29 2025"格式转换为ISO格式
                    published_date = self.parse_dell_date(published_str)

                    # 获取影响级别
                    impact = row.get('IMPACT', '').strip()

                    # 构建Dell advisory数据
                    advisory = {
                        'dell_security_advisory': dsa_id,
                        'title': title,
                        'cve_ids': cve_ids,
                        'published_date': published_date,
                        'link': f'https://www.dell.com/support/kbdoc/en-us/{dsa_id.lower().replace("dsa-", "")}',
                        'summary': f'{impact} severity security update.',
                        'description': title,
                        'affected_products': [
                            {
                                'name': '如标题',
                                'model': '如标题',
                                'version_range': '如标题'
                            }
                        ],
                        'solution': f'Refer to {dsa_id} for detailed remediation steps.',
                        'impact': impact,
                        'source': 'CSV Import'
                    }

                    # 存储到数据库（增量，Redis主存储）
                    is_new = self.store_dell_advisory(advisory)
                    if is_new:
                        new_count += 1
                        new_advisories.append(advisory)  # 收集新增数据
                    else:
                        existing_count += 1

                    dell_data.append(advisory)

            # ✅ 保存 CSV 数据到本地 JSON 文件
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if new_advisories:
                # 只保存新增数据
                filename = self.data_dir / f"dell_csv_new_{timestamp}.json"
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(new_advisories, f, ensure_ascii=False, indent=2)
                self.log_queue.put(f"✓ 新增数据已保存到: {filename.name}")

            # 保存全量数据（可选）
            full_filename = self.data_dir / f"dell_csv_full_{timestamp}.json"
            with open(full_filename, "w", encoding="utf-8") as f:
                json.dump(dell_data, f, ensure_ascii=False, indent=2)

            # 发送日志到队列
            self.log_queue.put(f"✓ 成功加载Dell CSV数据: {Path(csv_file).name}")
            self.log_queue.put(f"  总计: {len(dell_data)} 条DSA")
            if new_count > 0:
                self.log_queue.put(f"  新增: {new_count} 条Dell安全公告到数据库")
            if existing_count > 0:
                self.log_queue.put(f"  跳过: {existing_count} 条已存在的公告")
            self.log_queue.put(f"✓ 全量数据已保存到: {full_filename.name}")

            # ✅ 通知主线程刷新GUI（从数据库重新加载）
            self.dell_queue.put(('refresh_database', None))

            # 通知主线程更新统计
            self.dell_queue.put(('update_stats', None))

            self.log_queue.put(f"✓ Dell CSV加载完成")

        except Exception as e:
            self.log_queue.put(f"加载Dell CSV失败: {str(e)}")
            import traceback
            self.log_queue.put(f"详细错误信息: {traceback.format_exc()}")
            # 即使失败也尝试刷新数据库显示
            self.dell_queue.put(('refresh_database', None))

    def parse_dell_date(self, date_str):
        """解析Dell日期格式 (例如: OCT 29 2025) 为ISO格式"""
        if not date_str:
            return datetime.now().isoformat()

        try:
            from datetime import datetime
            # 月份映射
            months = {
                'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4,
                'MAY': 5, 'JUN': 6, 'JUL': 7, 'AUG': 8,
                'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12
            }

            parts = date_str.split()
            if len(parts) == 3:
                month_str, day_str, year_str = parts
                month = months.get(month_str.upper(), 1)
                day = int(day_str)
                year = int(year_str)

                dt = datetime(year, month, day)
                return dt.isoformat()
        except Exception:
            pass

        return datetime.now().isoformat()

    def load_nvd_csv(self, csv_file, reader, fieldnames):
        """加载NVD CVE CSV数据"""
        try:
            csv_data = []

            # 检查是否包含CVE ID列
            cve_field = None
            for field in fieldnames:
                if 'cve' in field.lower() or 'id' in field.lower():
                    cve_field = field
                    break

            if not cve_field:
                # 如果没有找到可能的CVE字段，则使用第一列作为CVE ID
                cve_field = fieldnames[0] if fieldnames else None
                if not cve_field:
                    raise ValueError("CSV文件中未找到有效的列")

            for row in reader:
                cve_id = row.get(cve_field, "").strip()
                if cve_id:  # 确保不是空值
                    # 将CSV行转换为NVD CVE数据格式
                    cve_entry = {
                        "cve_id": cve_id,
                        "description": row.get('description', row.get('title', row.get('summary', 'No Description'))),
                        "published_date": row.get('published_date', row.get('date', row.get('publish_date', ''))),
                        "last_modified": row.get('last_modified', row.get('update_date', '')),
                        "vuln_status": row.get('status', row.get('vuln_status', 'Analyzed')),
                        "cvss_score": row.get('cvss_score', row.get('score', 'N/A')),
                        "cvss_severity": row.get('cvss_severity', row.get('severity', 'UNKNOWN')),
                        "cvss_vector": row.get('cvss_vector', row.get('vector', '')),
                        "references": [],
                        "affected_products": [],
                        "weaknesses": [],
                        "source": "CSV Import"
                    }

                    # 解析参考链接
                    refs = row.get('references', row.get('refs', ''))
                    if refs:
                        for ref in refs.split(','):
                            ref = ref.strip()
                            if ref:
                                cve_entry["references"].append({
                                    "url": ref,
                                    "source": "",
                                    "tags": []
                                })

                    # 解析受影响的产品
                    products = row.get('products', row.get('affected_products', ''))
                    if products:
                        for product in products.split(','):
                            product = product.strip()
                            if product:
                                cve_entry["affected_products"].append({
                                    "cpe": "",
                                    "vendor": "",
                                    "product": product,
                                    "version": "*",
                                    "versionEndExcluding": None,
                                    "versionEndIncluding": None,
                                    "versionStartExcluding": None,
                                    "versionStartIncluding": None
                                })

                    csv_data.append(cve_entry)

            # 将CSV数据存储到数据库
            for cve in csv_data:
                self.store_cve_data(cve)

            # 从数据库加载所有数据
            self.cve_data = self.load_cve_data_from_db()

            # 添加到树视图
            for item in self.nvd_tree.get_children():
                self.nvd_tree.delete(item)

            for cve in self.cve_data:
                self.add_nvd_to_tree(cve)

            self.log(f"成功加载 CSV 数据: {Path(csv_file).name} ({len(csv_data)} 条), 现在数据库中共有 {len(self.cve_data)} 条")
            self.update_stats()

            # 如果已有Dell数据，则刷新关联数据
            if self.dell_advisories:
                self.refresh_matched_data()

        except Exception as e:
            messagebox.showerror("加载失败", f"加载NVD CSV失败：{str(e)}")
            self.log(f"加载NVD CSV失败: {str(e)}")
            import traceback
            self.log(f"详细错误信息: {traceback.format_exc()}")

    def add_nvd_to_tree(self, cve_data):
        """添加 NVD CVE 数据到树视图"""
        severity = cve_data.get("cvss_severity", "未知")
        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else ""

        # 格式化发布日期
        published = cve_data.get("published_date", "")
        if published:
            try:
                dt = datetime.fromisoformat(published.replace("Z", ""))
                published = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError) as e:
                # 日期格式无效，保持原样
                pass

        # 截断描述
        description = cve_data.get("description", "")
        if len(description) > 150:
            description = description[:150] + "..."

        self.nvd_tree.insert(
            "",
            "end",
            values=(
                cve_data.get("cve_id", ""),
                severity,
                cve_data.get("cvss_score", "N/A"),
                published,
                description,
                cve_data.get("source", "NVD")
            ),
            tags=(tag,)
        )

    def add_dell_to_tree(self, advisory):
        """添加 Dell 安全公告到树视图"""
        # 格式化 CVE IDs
        cve_ids = advisory.get("cve_ids", [])
        cve_ids_str = ", ".join(cve_ids) if cve_ids else "无"

        # 格式化发布日期
        published = advisory.get("published_date", "")
        if published:
            try:
                # 尝试解析日期
                from dateutil import parser
                dt = parser.parse(published)
                published = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError, ImportError) as e:
                # 日期解析失败或dateutil未安装，保持原样
                pass

        # 受影响产品数
        affected_products = advisory.get("affected_products", [])
        products_count = len(affected_products)

        self.dell_tree.insert(
            "",
            "end",
            values=(
                advisory.get("dell_security_advisory", "N/A"),
                advisory.get("title", ""),
                cve_ids_str,
                published,
                products_count
            )
        )

    def _refresh_matched_data_background(self):
        """在后台线程中刷新关联数据（避免UI阻塞）"""
        try:
            # ✅ 修复：从数据库加载数据，不依赖内存
            # 检查Dell数据
            if not hasattr(self, 'dell_advisories') or not self.dell_advisories:
                # 如果内存中没有Dell数据，从数据库加载
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
                records = cursor.fetchall()
                dell_advisories = []
                for record in records:
                    try:
                        if record[0]:
                            data = json.loads(record[0])
                            dell_advisories.append(data)
                    except:
                        continue

                if not dell_advisories:
                    self.log_queue.put("无法刷新关联数据：数据库中无Dell数据")
                    return
            else:
                dell_advisories = self.dell_advisories

            # ✅ 修复：从数据库加载CVE数据用于关联匹配
            # 获取所有Dell公告中的CVE IDs
            all_dell_cve_ids = set()
            for advisory in dell_advisories:
                cve_ids = advisory.get("cve_ids", [])
                all_dell_cve_ids.update(cve_ids)

            if not all_dell_cve_ids:
                self.log_queue.put("无法刷新关联数据：Dell公告中无CVE ID")
                return

            # 从数据库查询这些CVE的详细信息
            cursor = self.conn.cursor()
            placeholders = ','.join(['?' for _ in all_dell_cve_ids])
            query = f'SELECT data FROM cves WHERE cve_id IN ({placeholders})'
            cursor.execute(query, list(all_dell_cve_ids))

            cve_records = cursor.fetchall()
            cve_dict = {}
            for record in cve_records:
                try:
                    if record[0]:
                        cve_data = json.loads(record[0])
                        cve_id = cve_data.get("cve_id", "")
                        if cve_id:
                            cve_dict[cve_id] = cve_data
                except:
                    continue

            if not cve_dict:
                self.log_queue.put("无法刷新关联数据：数据库中无匹配的CVE数据")
                return

            self.log_queue.put(f"从数据库加载了 {len(cve_dict)} 个匹配的CVE用于关联显示")

            # 匹配 CVE ID
            matched_count = 0
            matched_items = []  # 收集所有匹配项

            for advisory in dell_advisories:  # ✅ 使用本地变量而非self.dell_advisories
                advisory_cve_ids = advisory.get("cve_ids", [])

                for cve_id in advisory_cve_ids:
                    if cve_id in cve_dict:
                        cve = cve_dict[cve_id]

                        # 提取产品型号
                        products = advisory.get("affected_products", [])
                        product_names = [p.get("name", "") for p in products[:3]]
                        products_str = ", ".join(product_names) if product_names else "详见公告"

                        # 提取解决方案预览
                        solution = advisory.get("solution", "")
                        if len(solution) > 100:
                            solution = solution[:100] + "..."
                        if not solution:
                            solution = "详见公告详情"

                        severity = cve.get("cvss_severity", "未知")
                        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else ""

                        matched_items.append({
                            "values": (
                                cve_id,
                                severity,
                                cve.get("cvss_score", "N/A"),
                                advisory.get("dell_security_advisory", "N/A"),
                                products_str,
                                solution
                            ),
                            "tag": tag
                        })
                        matched_count += 1

            # 只显示前 500 条（性能优化）
            max_display = 500
            items_to_display = matched_items[:max_display]

            # 清空并更新UI（通过队列）
            # 使用特殊标记来清空关联树
            self.matched_tree_queue.put(('clear', None))

            # 添加新数据
            for item_data in items_to_display:
                self.matched_tree_queue.put(('add', item_data))

            # 记录日志
            if matched_count > max_display:
                self.log_queue.put(f"关联匹配完成：找到 {matched_count} 条匹配数据，显示前 {max_display} 条（性能优化）")
            else:
                self.log_queue.put(f"关联匹配完成：找到 {matched_count} 条匹配的 CVE-Dell 数据")

            # 通知更新统计
            self.dell_queue.put(('update_stats', None))

        except Exception as e:
            self.log_queue.put(f"后台关联匹配出错: {str(e)}")
            import traceback
            self.log_queue.put(f"详细错误: {traceback.format_exc()}")

    def refresh_matched_data(self):
        """刷新关联数据（优化版，使用哈希表加速，从数据库加载数据）"""
        # 清空关联树视图
        for item in self.matched_tree.get_children():
            self.matched_tree.delete(item)

        # ✅ 修复：从数据库加载数据，不依赖内存（与 _refresh_matched_data_background 一致）
        try:
            # 检查Dell数据
            if not hasattr(self, 'dell_advisories') or not self.dell_advisories:
                # 如果内存中没有Dell数据，从数据库加载
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
                records = cursor.fetchall()
                dell_advisories = []
                for record in records:
                    try:
                        if record[0]:
                            data = json.loads(record[0])
                            dell_advisories.append(data)
                    except:
                        continue

                if not dell_advisories:
                    self.log("无法刷新关联数据：数据库中无Dell数据")
                    return
            else:
                dell_advisories = self.dell_advisories

            # 从数据库加载CVE数据用于关联匹配
            # 获取所有Dell公告中的CVE IDs
            all_dell_cve_ids = set()
            for advisory in dell_advisories:
                cve_ids = advisory.get("cve_ids", [])
                all_dell_cve_ids.update(cve_ids)

            if not all_dell_cve_ids:
                self.log("无法刷新关联数据：Dell公告中无CVE ID")
                return

            # 从数据库查询这些CVE的详细信息
            cursor = self.conn.cursor()
            placeholders = ','.join(['?' for _ in all_dell_cve_ids])
            query = f'SELECT data FROM cves WHERE cve_id IN ({placeholders})'
            cursor.execute(query, list(all_dell_cve_ids))

            cve_records = cursor.fetchall()
            cve_dict = {}
            for record in cve_records:
                try:
                    if record[0]:
                        cve_data = json.loads(record[0])
                        cve_id = cve_data.get("cve_id", "")
                        if cve_id:
                            cve_dict[cve_id] = cve_data
                except:
                    continue

            if not cve_dict:
                self.log("无法刷新关联数据：数据库中无匹配的CVE数据")
                return

            self.log(f"从数据库加载了 {len(cve_dict)} 个匹配的CVE用于关联显示")

            # 匹配 CVE ID
            matched_count = 0
            matched_items = []  # 收集所有匹配项

            for advisory in dell_advisories:  # 使用本地变量而非self.dell_advisories
                advisory_cve_ids = advisory.get("cve_ids", [])

                for cve_id in advisory_cve_ids:
                    if cve_id in cve_dict:
                        cve = cve_dict[cve_id]

                        # 提取产品型号
                        products = advisory.get("affected_products", [])
                        product_names = [p.get("name", "") for p in products[:3]]
                        products_str = ", ".join(product_names) if product_names else "详见公告"

                        # 提取解决方案预览
                        solution = advisory.get("solution", "")
                        if len(solution) > 100:
                            solution = solution[:100] + "..."
                        if not solution:
                            solution = "详见公告详情"

                        severity = cve.get("cvss_severity", "未知")
                        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else ""

                        matched_items.append({
                            "values": (
                                cve_id,
                                severity,
                                cve.get("cvss_score", "N/A"),
                                advisory.get("dell_security_advisory", "N/A"),
                                products_str,
                                solution
                            ),
                            "tag": tag
                        })
                        matched_count += 1

            # 批量插入到树视图（减少 GUI 更新次数）
            # 如果数据太多，只显示前 1000 条
            max_display = 1000
            items_to_display = matched_items[:max_display]

            processed_count = 0
            for item_data in items_to_display:
                self.matched_tree.insert(
                    "",
                    "end",
                    values=item_data["values"],
                    tags=(item_data["tag"],)
                )
                processed_count += 1

                # Yield control periodically to prevent GUI freezing for large batches
                if processed_count % 30 == 0:
                    self.root.update_idletasks()  # Process pending GUI events

            if matched_count > max_display:
                self.log(f"关联匹配完成：找到 {matched_count} 条匹配数据，显示前 {max_display} 条（性能优化）")
            else:
                self.log(f"关联匹配完成：找到 {matched_count} 条匹配的 CVE-Dell 数据")

            self.update_stats()

        except Exception as e:
            self.log(f"刷新关联数据时出错: {str(e)}")
            import traceback
            self.log(f"详细错误信息: {traceback.format_exc()}")

    # ==================== 搜索过滤功能 ====================

    def filter_nvd_data(self, *args):
        """过滤 NVD 数据（优化：支持从数据库搜索）"""
        search_term = self.nvd_search_var.get().strip()

        if not search_term:
            # 如果搜索框为空，显示内存中的数据（最多500条）
            for item in self.nvd_tree.get_children():
                self.nvd_tree.delete(item)

            for cve in self.cve_data[:500]:
                self.add_nvd_to_tree(cve)

            self.log(f"显示 {min(len(self.cve_data), 500)} 条数据")
            return

        search_upper = search_term.upper()

        # 清空树视图
        for item in self.nvd_tree.get_children():
            self.nvd_tree.delete(item)

        # 先在内存中搜索
        memory_results = []
        for cve in self.cve_data:
            cve_id = cve.get("cve_id", "") or ""
            description = cve.get("description", "") or ""
            severity = cve.get("cvss_severity", "") or ""

            if (search_upper in cve_id.upper() or
                search_upper in description.upper() or
                search_upper in severity.upper()):
                memory_results.append(cve)

        # 如果在内存中找到了结果，显示内存结果
        if memory_results:
            for cve in memory_results[:500]:  # 最多显示500条
                self.add_nvd_to_tree(cve)
            self.log(f"在已加载数据中找到 {len(memory_results)} 条匹配记录（显示 {min(len(memory_results), 500)} 条）")
            return

        # 如果内存中没有找到，尝试从数据库搜索
        self.log(f"在内存中未找到匹配数据，正在从数据库搜索...")
        threading.Thread(
            target=self._search_nvd_from_database,
            args=(search_term,),
            daemon=True
        ).start()

    def _search_nvd_from_database(self, search_term):
        """从数据库搜索NVD数据（后台线程）"""
        try:
            search_upper = search_term.upper()
            cursor = self.conn.cursor()

            # 使用LIKE进行模糊搜索（限制500条结果）
            cursor.execute("""
                SELECT data FROM cves
                WHERE UPPER(cve_id) LIKE ?
                   OR UPPER(data) LIKE ?
                ORDER BY published_date DESC
                LIMIT 500
            """, (f'%{search_upper}%', f'%{search_upper}%'))

            records = cursor.fetchall()
            results = []

            for record in records:
                try:
                    if record[0]:
                        data = json.loads(record[0])
                        results.append(data)
                except json.JSONDecodeError:
                    continue

            # 清空树形视图
            self.data_queue.put(('clear_nvd', None))

            # 显示搜索结果
            for cve in results:
                self.data_queue.put(('add_nvd', cve))

            if results:
                self.log_queue.put(f"✓ 从数据库找到 {len(results)} 条匹配记录")
            else:
                self.log_queue.put(f"未找到匹配 '{search_term}' 的数据")

        except sqlite3.Error as e:
            self.log_queue.put(f"数据库搜索失败: {str(e)}")
        except Exception as e:
            self.log_queue.put(f"搜索出错: {str(e)}")

    def delete_nvd_selected(self):
        """删除NVD列表中当前选中的记录（支持多选）"""
        selected = self.nvd_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的记录（支持 Ctrl/Shift 多选）")
            return
        count = len(selected)
        if not messagebox.askyesno(
            "确认删除",
            f"确定要永久删除选中的 {count} 条 CVE 记录吗？\n此操作不可撤销，数据将从数据库中彻底删除。"
        ):
            return
        cve_ids_to_delete = [self.nvd_tree.item(iid, 'values')[0] for iid in selected
                              if self.nvd_tree.item(iid, 'values')]
        try:
            cursor = self.conn.cursor()
            params = [(cid,) for cid in cve_ids_to_delete]
            # 先删子表（外键约束），再删主表
            cursor.executemany("DELETE FROM collection_history WHERE cve_id = ?", params)
            cursor.executemany("DELETE FROM cves WHERE cve_id = ?", params)
            self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("删除失败", f"数据库操作失败：{e}")
            return
        cve_id_set = set(cve_ids_to_delete)
        self.cve_data = [c for c in self.cve_data if c.get('cve_id') not in cve_id_set]
        for iid in selected:
            self.nvd_tree.delete(iid)
        preview = ', '.join(cve_ids_to_delete[:5])
        suffix = '...' if count > 5 else ''
        self.log(f"已永久删除 {count} 条CVE记录：{preview}{suffix}")
        self.update_stats()

    def filter_dell_data(self, *args):
        """过滤 Dell 数据（支持公告ID、CVE ID、标题、产品搜索）"""
        search_term = self.dell_search_var.get().strip()
        search_upper = search_term.upper()

        # 清空树视图
        for item in self.dell_tree.get_children():
            self.dell_tree.delete(item)

        # 如果搜索框为空，显示所有内存中的数据
        if not search_term:
            for advisory in self.dell_advisories:
                self.add_dell_to_tree(advisory)
            return

        # 先在内存中搜索
        matched = []
        for advisory in self.dell_advisories:
            advisory_id = advisory.get("dell_security_advisory", "") or ""
            cve_ids = advisory.get("cve_ids", [])
            cve_ids_str = ", ".join(cve_ids) if cve_ids else ""
            title = advisory.get("title", "") or ""
            product_names = [p.get("name", "") for p in advisory.get("affected_products", [])]
            products = ", ".join(product_names) if product_names else ""

            if (search_upper in advisory_id.upper() or
                    search_upper in cve_ids_str.upper() or
                    search_upper in title.upper() or
                    search_upper in products.upper()):
                matched.append(advisory)

        if matched:
            for advisory in matched:
                self.add_dell_to_tree(advisory)
            self.log(f"在已加载数据中找到 {len(matched)} 条匹配记录")
            return

        # 内存中未找到，回退到数据库全量搜索
        self.log(f"内存中未找到匹配，正在从数据库搜索 '{search_term}'...")
        threading.Thread(
            target=self._search_dell_from_database,
            args=(search_term,),
            daemon=True
        ).start()

    def _search_dell_from_database(self, search_term: str):
        """从数据库全量搜索Dell公告（后台线程）"""
        try:
            search_upper = f"%{search_term.upper()}%"
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT data FROM dell_advisories
                WHERE UPPER(dsa_id)   LIKE ?
                   OR UPPER(title)    LIKE ?
                   OR UPPER(cve_ids)  LIKE ?
                   OR UPPER(data)     LIKE ?
                ORDER BY published_date DESC
                LIMIT 200
            """, (search_upper, search_upper, search_upper, search_upper))

            results = []
            for (raw,) in cursor.fetchall():
                try:
                    if raw:
                        results.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            # 清空树并显示结果（通过队列回主线程）
            self.dell_queue.put(('clear', None))
            for advisory in results:
                self.dell_queue.put(('add', advisory))

            if results:
                self.log_queue.put(f"✓ 数据库中找到 {len(results)} 条匹配 '{search_term}' 的记录")
            else:
                self.log_queue.put(f"未找到匹配 '{search_term}' 的Dell公告（已搜索全部数据库）")

        except sqlite3.Error as e:
            self.log_queue.put(f"数据库搜索失败: {str(e)}")
        except Exception as e:
            self.log_queue.put(f"Dell搜索出错: {str(e)}")

    def delete_dell_selected(self):
        """删除Dell列表中当前选中的记录（支持多选）"""
        selected = self.dell_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的记录（支持 Ctrl/Shift 多选）")
            return
        count = len(selected)
        if not messagebox.askyesno(
            "确认删除",
            f"确定要永久删除选中的 {count} 条 Dell 安全公告吗？\n此操作不可撤销，数据将从数据库中彻底删除。"
        ):
            return
        dsa_ids_to_delete = [self.dell_tree.item(iid, 'values')[0] for iid in selected
                              if self.dell_tree.item(iid, 'values')]
        try:
            cursor = self.conn.cursor()
            cursor.executemany("DELETE FROM dell_advisories WHERE dsa_id = ?",
                               [(did,) for did in dsa_ids_to_delete])
            self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("删除失败", f"数据库操作失败：{e}")
            return
        dsa_id_set = set(dsa_ids_to_delete)
        self.dell_advisories = [a for a in self.dell_advisories
                                 if a.get('dell_security_advisory') not in dsa_id_set]
        for iid in selected:
            self.dell_tree.delete(iid)
        preview = ', '.join(dsa_ids_to_delete[:5])
        suffix = '...' if count > 5 else ''
        self.log(f"已永久删除 {count} 条Dell安全公告：{preview}{suffix}")
        self.update_stats()

    # ==================== 详情显示功能 ====================

    def on_nvd_item_double_click(self, event):
        """处理 NVD 项目双击事件"""
        selection = self.nvd_tree.selection()
        if selection:
            item = self.nvd_tree.item(selection[0])
            cve_id = item['values'][0]

            # 查找详细数据
            for cve in self.cve_data:
                if cve.get('cve_id') == cve_id:
                    self.show_nvd_detail(cve)
                    break

    def show_nvd_detail(self, cve):
        """显示 NVD CVE 详细信息"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"CVE 详细信息 - {cve.get('cve_id')}")
        detail_window.geometry("800x600")

        # 详细信息文本
        text = scrolledtext.ScrolledText(
            detail_window,
            wrap=tk.WORD,
            width=90,
            height=30,
            font=("Consolas", 10)
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 格式化详细信息
        detail_text = f"""
CVE 编号: {cve.get('cve_id', 'N/A')}
严重等级: {cve.get('cvss_severity', '未知')}
CVSS 评分: {cve.get('cvss_score', 'N/A')}
CVSS 向量: {cve.get('cvss_vector', 'N/A')}
发布日期: {cve.get('published_date', 'N/A')}
最后修改: {cve.get('last_modified', 'N/A')}
状态: {cve.get('vuln_status', 'N/A')}

描述:
{cve.get('description', '无描述')}

CWE 分类:
{', '.join(cve.get('weaknesses', [])) if cve.get('weaknesses') else '无'}

受影响的产品:
"""
        # 添加受影响的产品
        for product in cve.get('affected_products', [])[:10]:  # 最多显示10个
            detail_text += f"  - {product.get('vendor', 'N/A')}/{product.get('product', 'N/A')} "
            detail_text += f"(版本: {product.get('version', '*')})\n"

        if len(cve.get('affected_products', [])) > 10:
            detail_text += f"  ... 还有 {len(cve['affected_products']) - 10} 个产品\n"

        detail_text += f"\n参考链接:\n"
        for ref in cve.get('references', [])[:5]:  # 最多显示5个
            detail_text += f"  - {ref.get('url', 'N/A')}\n"

        detail_text += f"\nNVD 链接:\nhttps://nvd.nist.gov/vuln/detail/{cve.get('cve_id')}\n"

        text.insert(tk.END, detail_text)
        text.config(state=tk.DISABLED)

    def on_dell_item_double_click(self, event):
        """处理 Dell 项目双击事件"""
        selection = self.dell_tree.selection()
        if selection:
            item = self.dell_tree.item(selection[0])
            advisory_id = item['values'][0]

            # 查找详细数据
            for advisory in self.dell_advisories:
                if advisory.get('dell_security_advisory') == advisory_id:
                    self.show_dell_detail(advisory)
                    break

    def show_dell_detail(self, advisory):
        """显示 Dell 安全公告详细信息"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Dell 安全公告 - {advisory.get('dell_security_advisory', 'N/A')}")
        detail_window.geometry("900x700")

        # 详细信息文本
        text = scrolledtext.ScrolledText(
            detail_window,
            wrap=tk.WORD,
            width=100,
            height=35,
            font=("Consolas", 10)
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 格式化详细信息
        detail_text = f"""
{'=' * 80}
Dell 安全公告详细信息
{'=' * 80}

公告 ID: {advisory.get('dell_security_advisory', 'N/A')}
标题: {advisory.get('title', 'N/A')}
发布日期: {advisory.get('published_date', 'N/A')}

相关 CVE:
{', '.join(advisory.get('cve_ids', [])) if advisory.get('cve_ids') else '无'}

摘要:
{advisory.get('summary', advisory.get('description', '无'))}

受影响的产品:
"""
        # 添加受影响的产品详情
        products = advisory.get('affected_products', [])
        if products:
            for i, product in enumerate(products, 1):
                detail_text += f"\n  {i}. 产品名称: {product.get('name', 'N/A')}\n"
                if product.get('model'):
                    detail_text += f"     型号: {product.get('model', 'N/A')}\n"
                if product.get('version_range'):
                    detail_text += f"     版本范围: {product.get('version_range', 'N/A')}\n"
        else:
            detail_text += "  详见公告链接\n"

        detail_text += f"\n解决方案:\n"
        solution = advisory.get('solution', '')
        if solution:
            detail_text += f"{solution}\n"
        else:
            detail_text += "请访问下方链接查看详细解决方案\n"

        detail_text += f"\n公告链接:\n{advisory.get('link', 'N/A')}\n"
        detail_text += f"\n{'=' * 80}\n"

        text.insert(tk.END, detail_text)
        text.config(state=tk.DISABLED)

    # ==================== AI解决方案功能 ====================

    def ai_solution_click(self):
        """AI解决方案按钮点击事件"""
        try:
            # 获取当前选中的关联数据
            selection = self.matched_tree.selection()

            if not selection:
                messagebox.showwarning("提示", "请先选择要分析的CVE-Dell关联数据")
                return

            # 收集所有选中的数据用于AI分析
            selected_data = []
            for item_id in selection:
                item = self.matched_tree.item(item_id)
                values = item['values']
                cve_id = values[0]
                severity = values[1]
                cvss_score = values[2]
                advisory_id = values[3]
                affected_product = values[4]

                selected_data.append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'advisory_id': advisory_id,
                    'affected_product': affected_product
                })

            # 如果选中多个，只处理第一个（可后续扩展）
            data = selected_data[0]
            cve_id = data['cve_id']
            advisory_id = data['advisory_id']

            # 查找详细数据
            cve_detail = None
            dell_detail = None

            for cve in self.cve_data:
                if cve.get('cve_id') == cve_id:
                    cve_detail = cve
                    break

            for advisory in self.dell_advisories:
                if advisory.get('dell_security_advisory') == advisory_id:
                    dell_detail = advisory
                    break

            if not cve_detail:
                # 尝试从数据库查询
                try:
                    with self.db_lock:
                        cursor = self.db_conn.cursor()
                        cursor.execute(
                            "SELECT * FROM cves WHERE cve_id = ?",
                            (cve_id,)
                        )
                        row = cursor.fetchone()
                        if row:
                            # 将数据库行转换为字典
                            cols = [desc[0] for desc in cursor.description]
                            cve_detail = dict(zip(cols, row))
                except Exception as e:
                    self.log(f"从数据库查询CVE数据失败: {str(e)}")

            if not dell_detail:
                # 尝试从数据库查询
                try:
                    with self.db_lock:
                        cursor = self.db_conn.cursor()
                        # 注意：数据库列名是dsa_id，不是dell_security_advisory
                        cursor.execute(
                            "SELECT * FROM dell_advisories WHERE dsa_id = ?",
                            (advisory_id,)
                        )
                        row = cursor.fetchone()
                        if row:
                            cols = [desc[0] for desc in cursor.description]
                            dell_detail = dict(zip(cols, row))
                except Exception as e:
                    self.log(f"从数据库查询Dell公告数据失败: {str(e)}")

            if cve_detail and dell_detail:
                # 在后台线程中调用AI分析
                self.log(f"正在调用AI分析: {cve_id} - {advisory_id}...")
                threading.Thread(
                    target=self._call_ai_solution_thread,
                    args=(cve_detail, dell_detail),
                    daemon=True
                ).start()
            else:
                messagebox.showerror("错误", "无法找到完整的CVE或Dell公告数据")

        except Exception as e:
            error_msg = f"AI解决方案处理失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def _call_ai_solution_thread(self, cve_data, dell_advisory_data):
        """在后台线程中调用AI分析"""
        try:
            # 读取环境变量配置
            # 模型名称：从QWEN_MODEL环境变量读取，默认为qwen-max-latest
            model_name = os.getenv("QWEN_MODEL", "qwen-max-latest")

            # API密钥：优先读取QWEN_API_KEY，回退到DASHSCOPE_API_KEY
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")

            # API基础URL
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

            # 详细的错误诊断
            if not api_key:
                error_info = f"""
Qwen API密钥未设置。

请检查以下环境变量：
1. QWEN_API_KEY (优先级更高)
2. DASHSCOPE_API_KEY (备选)

当前检测到的环境变量值：
- QWEN_API_KEY: {repr(os.getenv('QWEN_API_KEY'))}
- DASHSCOPE_API_KEY: {'已设置' if os.getenv('DASHSCOPE_API_KEY') else '未设置'}
- QWEN_MODEL: {repr(os.getenv('QWEN_MODEL'))}
- QWEN_BASE_URL: {repr(os.getenv('QWEN_BASE_URL'))}

解决方案：
1. 设置环境变量: setx DASHSCOPE_API_KEY your_api_key_here
2. 重启应用
3. 重试分析
"""
                raise ValueError(error_info)

            # 构建AI请求的提示
            prompt = self._build_ai_solution_prompt(cve_data, dell_advisory_data)

            # 调用Qwen API (OpenAI兼容)
            try:
                from openai import OpenAI

                client = OpenAI(
                    api_key=api_key,
                    base_url=base_url
                )

                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": "你是一个企业级安全顾问，专业提供CVE漏洞分析和解决方案建议"
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.7,
                    max_tokens=2000
                )

                solution_result = response.choices[0].message.content

                # 在主线程中显示结果
                self.root.after(
                    0,
                    self._show_ai_solution_result,
                    solution_result,
                    cve_data,
                    dell_advisory_data
                )

            except ImportError:
                raise ImportError("openai库未安装。请运行: pip install openai")
            except Exception as e:
                error_msg = f"AI API调用失败: {str(e)}"
                self.root.after(0, self.log, error_msg)
                self.root.after(0, messagebox.showerror, "错误", error_msg)

        except Exception as e:
            error_msg = f"AI解决方案分析失败: {str(e)}"
            self.root.after(0, self.log, error_msg)
            self.root.after(0, messagebox.showerror, "错误", error_msg)

    def _build_ai_solution_prompt(self, cve_data, dell_advisory_data):
        """构建AI分析的提示词"""
        # 兼容两种Dell公告ID字段名
        advisory_id = dell_advisory_data.get('dell_security_advisory') or dell_advisory_data.get('dsa_id', 'N/A')

        prompt = f"""
请为以下CVE漏洞和Dell安全公告提供专业的安全解决方案分析：

【CVE信息】
- CVE编号: {cve_data.get('cve_id', 'N/A')}
- 严重等级: {cve_data.get('cvss_severity', '未知')}
- CVSS评分: {cve_data.get('cvss_score', 'N/A')}
- 发布日期: {cve_data.get('published_date', 'N/A')}
- 描述: {cve_data.get('description', '无详细描述')[:500]}

【Dell安全公告】
- 公告编号: {advisory_id}
- 标题: {dell_advisory_data.get('title', 'N/A')}
- 发布日期: {dell_advisory_data.get('published_date', 'N/A')}
- 影响产品: {', '.join([p.get('name', 'N/A') for p in dell_advisory_data.get('affected_products', [])])}

【分析要求】
请提供以下内容：
1. 漏洞详细分析：包括漏洞原理、攻击向量和影响范围
2. Dell受影响产品清单及版本范围
3. 推荐的修复和缓解方案
4. 临时解决措施（如果完整修复不可用）
5. 监控和检测建议
6. 相关参考资源和链接

请以专业、结构清晰的格式组织答案。
"""
        return prompt

    def _show_ai_solution_result(self, result, cve_data, dell_advisory_data):
        """显示AI分析结果"""
        try:
            # 保存到数据库
            self.save_ai_solution_to_db(cve_data, dell_advisory_data, result, "成功")

            # 刷新解决方案列表
            self.load_ai_solution_history()

            # 在详细结果区域显示
            if hasattr(self, 'solution_detail_text'):
                self.solution_detail_text.config(state=tk.NORMAL)
                self.solution_detail_text.delete(1.0, tk.END)

                # 兼容两种Dell公告ID字段名
                advisory_id = dell_advisory_data.get('dell_security_advisory') or dell_advisory_data.get('dsa_id')

                header = f"""
【AI解决方案分析】
CVE编号: {cve_data.get('cve_id')} | 公告ID: {advisory_id}
分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 80}

"""
                self.solution_detail_text.insert(tk.END, header)
                self.solution_detail_text.insert(tk.END, result)
                self.solution_detail_text.config(state=tk.DISABLED)

            # 切换到解决方案标签页
            # 使用保存的标签页ID而不是尝试从tabs列表中查找
            self.notebook.select(self.solution_tab_id)

            self.log(f"AI分析完成: {cve_data.get('cve_id')}")

        except Exception as e:
            error_msg = f"显示分析结果失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def save_ai_solution_to_db(self, cve_data, dell_advisory_data, result, status="成功"):
        """保存AI分析结果到数据库"""
        try:
            with self.db_lock:
                cursor = self.db_conn.cursor()
                # 兼容两种Dell公告ID字段名：dell_security_advisory 或 dsa_id
                advisory_id = dell_advisory_data.get('dell_security_advisory') or dell_advisory_data.get('dsa_id')

                cursor.execute(
                    """
                    INSERT INTO ai_solutions
                    (cve_id, dell_advisory_id, analysis_time, model_name, prompt, result, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve_data.get('cve_id'),
                        advisory_id,
                        datetime.now().isoformat(),
                        os.getenv("qwen3-max-2026-01-23", "qwen-max-latest"),
                        "",  # 提示词可选
                        result[:10000],  # 限制长度
                        status
                    )
                )
                self.db_conn.commit()
        except sqlite3.OperationalError as e:
            # 表可能不存在，尝试创建
            self.log(f"数据库操作失败，尝试创建ai_solutions表: {str(e)}")

    def load_ai_solution_history(self):
        """从数据库加载历史记录"""
        try:
            # 清空TreeView
            for item in self.solution_tree.get_children():
                self.solution_tree.delete(item)

            with self.db_lock:
                cursor = self.db_conn.cursor()
                cursor.execute(
                    """
                    SELECT id, cve_id, dell_advisory_id, analysis_time, status, result
                    FROM ai_solutions
                    ORDER BY analysis_time DESC
                    LIMIT 100
                    """
                )
                rows = cursor.fetchall()

                for row in rows:
                    id, cve_id, advisory_id, analysis_time, status, result = row

                    # 格式化时间戳
                    try:
                        dt = datetime.fromisoformat(analysis_time)
                        time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        time_str = analysis_time

                    # 生成结果预览
                    preview = result[:100].replace('\n', ' ') if result else "无结果"

                    # 状态颜色标签
                    tag = "success" if status == "成功" else "error"

                    self.solution_tree.insert(
                        "",
                        tk.END,
                        values=(time_str, cve_id, advisory_id, status, preview),
                        tags=(tag,)
                    )

                    # 存储完整结果供双击查看
                    self.solution_history.append({
                        'id': id,
                        'cve_id': cve_id,
                        'advisory_id': advisory_id,
                        'time': time_str,
                        'status': status,
                        'result': result
                    })

            # 配置标签样式
            self.solution_tree.tag_configure("success", background="#f0f0f0", foreground="#27ae60")
            self.solution_tree.tag_configure("error", background="#fff3f3", foreground="#e74c3c")

        except sqlite3.OperationalError:
            self.log("ai_solutions表不存在，暂无历史记录")
        except Exception as e:
            self.log(f"加载AI解决方案历史记录失败: {str(e)}")

    def on_solution_item_double_click(self, event):
        """处理解决方案项目双击事件"""
        selection = self.solution_tree.selection()
        if selection:
            item = self.solution_tree.item(selection[0])
            values = item['values']

            # 从历史记录中找完整结果
            cve_id = values[1]
            advisory_id = values[2]

            for history in self.solution_history:
                if history['cve_id'] == cve_id and history['advisory_id'] == advisory_id:
                    # 显示详细结果
                    self.solution_detail_text.config(state=tk.NORMAL)
                    self.solution_detail_text.delete(1.0, tk.END)

                    header = f"""
【AI解决方案详情】
CVE编号: {cve_id} | 公告ID: {advisory_id}
分析时间: {history['time']} | 状态: {history['status']}
{'=' * 80}

"""
                    self.solution_detail_text.insert(tk.END, header)
                    self.solution_detail_text.insert(tk.END, history['result'])
                    self.solution_detail_text.config(state=tk.DISABLED)
                    break

    def export_solution_history(self):
        """导出解决方案历史记录"""
        try:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("CSV文件", "*.csv"), ("所有文件", "*.*")]
            )

            if not filepath:
                return

            with open(filepath, 'w', encoding='utf-8') as f:
                if filepath.endswith('.csv'):
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(['分析时间', 'CVE编号', '公告编号', '分析状态', '结果'])
                    for history in self.solution_history:
                        writer.writerow([
                            history['time'],
                            history['cve_id'],
                            history['advisory_id'],
                            history['status'],
                            history['result'][:200]
                        ])
                else:
                    for history in self.solution_history:
                        f.write(f"\n{'=' * 80}\n")
                        f.write(f"CVE编号: {history['cve_id']}\n")
                        f.write(f"公告编号: {history['advisory_id']}\n")
                        f.write(f"分析时间: {history['time']}\n")
                        f.write(f"状态: {history['status']}\n")
                        f.write(f"\n{history['result']}\n")

            self.log(f"解决方案历史记录已导出: {filepath}")
            messagebox.showinfo("成功", f"历史记录已导出到:\n{filepath}")

        except Exception as e:
            error_msg = f"导出历史记录失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def clear_solution_history(self):
        """清空解决方案历史记录"""
        if not messagebox.askyesno("确认", "确定要清空所有AI解决方案历史记录吗？"):
            return

        try:
            with self.db_lock:
                cursor = self.db_conn.cursor()
                cursor.execute("DELETE FROM ai_solutions")
                self.db_conn.commit()

            self.solution_history = []
            self.load_ai_solution_history()
            self.log("AI解决方案历史记录已清空")
            messagebox.showinfo("成功", "历史记录已清空")

        except sqlite3.OperationalError:
            self.log("ai_solutions表不存在")
        except Exception as e:
            error_msg = f"清空历史记录失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def on_matched_item_double_click(self, event):
        """处理关联项目双击事件"""
        selection = self.matched_tree.selection()
        if selection:
            item = self.matched_tree.item(selection[0])
            cve_id = item['values'][0]
            advisory_id = item['values'][3]

            # 查找详细数据
            cve_detail = None
            dell_detail = None

            for cve in self.cve_data:
                if cve.get('cve_id') == cve_id:
                    cve_detail = cve
                    break

            for advisory in self.dell_advisories:
                if advisory.get('dell_security_advisory') == advisory_id:
                    dell_detail = advisory
                    break

            if cve_detail and dell_detail:
                self.show_matched_detail(cve_detail, dell_detail)

    def show_matched_detail(self, cve, advisory):
        """显示关联数据的详细信息"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"关联详情 - {cve.get('cve_id')}")
        detail_window.geometry("1000x800")

        # 详细信息文本
        text = scrolledtext.ScrolledText(
            detail_window,
            wrap=tk.WORD,
            width=110,
            height=40,
            font=("Consolas", 10)
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 格式化详细信息
        detail_text = f"""
{'=' * 90}
CVE 与 Dell 安全公告关联详情
{'=' * 90}

【NVD CVE 信息】
CVE 编号: {cve.get('cve_id', 'N/A')}
严重等级: {cve.get('cvss_severity', '未知')} | CVSS 评分: {cve.get('cvss_score', 'N/A')}
发布日期: {cve.get('published_date', 'N/A')}

CVE 描述:
{cve.get('description', '无描述')}

【Dell 安全公告信息】
公告 ID: {advisory.get('dell_security_advisory', 'N/A')}
标题: {advisory.get('title', 'N/A')}
发布日期: {advisory.get('published_date', 'N/A')}

相关 CVE: {', '.join(advisory.get('cve_ids', []))}

【Dell 受影响产品及型号】
"""
        # 添加受影响的产品详情
        products = advisory.get('affected_products', [])
        if products:
            for i, product in enumerate(products, 1):
                detail_text += f"\n  {i}. 产品: {product.get('name', 'N/A')}\n"
                if product.get('model'):
                    detail_text += f"     型号: {product.get('model', 'N/A')}\n"
                if product.get('version_range'):
                    detail_text += f"     受影响版本: {product.get('version_range', 'N/A')}\n"
        else:
            detail_text += "\n  详情请访问 Dell 安全公告链接\n"

        detail_text += f"\n【Dell 解决方案】\n"
        solution = advisory.get('solution', '')
        if solution:
            detail_text += f"{solution}\n"
        else:
            detail_text += "请访问 Dell 安全公告链接查看详细解决方案和操作步骤\n"

        detail_text += f"\n【参考链接】\n"
        detail_text += f"NVD: https://nvd.nist.gov/vuln/detail/{cve.get('cve_id')}\n"
        detail_text += f"Dell: {advisory.get('link', 'N/A')}\n"
        detail_text += f"\n{'=' * 90}\n"

        text.insert(tk.END, detail_text)
        text.config(state=tk.DISABLED)

    # ==================== 统计更新功能 ====================

    def update_stats(self):
        """更新统计信息（优化版，使用哈希表加速）"""
        # ✅ 修复：从数据库获取实际总数（而非内存列表）
        nvd_total = self.get_cve_count_from_db()
        dell_total = self.get_dell_count_from_db()

        # ✅ 修复：从数据库计算关联匹配数（不依赖内存中的cve_data）
        # 这样即使CVE数据未加载到内存，也能显示正确的关联数
        matched_count = self.get_matched_count_from_db()

        # 统计各严重等级
        severity_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for cve in self.cve_data:
            severity = cve.get("cvss_severity", "")
            if severity in severity_count:
                severity_count[severity] += 1

        # 更新统计卡片
        self.stats_cards["NVD CVE总数"].value_label.config(text=str(nvd_total))
        self.stats_cards["Dell公告数"].value_label.config(text=str(dell_total))
        self.stats_cards["关联匹配数"].value_label.config(text=str(matched_count))
        self.stats_cards["严重"].value_label.config(text=str(severity_count["CRITICAL"]))
        self.stats_cards["高危"].value_label.config(text=str(severity_count["HIGH"]))
        self.stats_cards["中危"].value_label.config(text=str(severity_count["MEDIUM"]))
        self.stats_cards["低危"].value_label.config(text=str(severity_count["LOW"]))

        # 更新底部状态栏
        self.cve_count_label.config(
            text=f"NVD CVE: {nvd_total} | Dell 公告: {dell_total} | 关联: {matched_count}"
        )

        # 生成详细统计报告
        stats_text = f"""
{'=' * 80}
CVE 漏洞监控系统 - 统计报告
{'=' * 80}

生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

【数据概览】
NVD CVE 总数: {nvd_total}
Dell 安全公告数: {dell_total}
关联匹配数: {matched_count}
匹配率: {(matched_count / nvd_total * 100) if nvd_total > 0 else 0:.2f}%

【严重等级分布】
CRITICAL (严重): {severity_count['CRITICAL']} 个 ({severity_count['CRITICAL'] / nvd_total * 100 if nvd_total > 0 else 0:.1f}%)
HIGH     (高危): {severity_count['HIGH']} 个 ({severity_count['HIGH'] / nvd_total * 100 if nvd_total > 0 else 0:.1f}%)
MEDIUM   (中危): {severity_count['MEDIUM']} 个 ({severity_count['MEDIUM'] / nvd_total * 100 if nvd_total > 0 else 0:.1f}%)
LOW      (低危): {severity_count['LOW']} 个 ({severity_count['LOW'] / nvd_total * 100 if nvd_total > 0 else 0:.1f}%)

【最新 CVE (前10个)】
"""

        for cve in self.cve_data[:10]:
            cve_id = cve.get('cve_id', 'N/A')
            severity = cve.get('cvss_severity', '未知')
            score = cve.get('cvss_score', 'N/A')

            # 检查是否有 Dell 公告
            has_dell = any(cve_id in advisory.get('cve_ids', []) for advisory in self.dell_advisories)
            dell_mark = "[Dell]" if has_dell else ""

            # 处理 None 值
            severity_str = str(severity) if severity else "N/A"
            score_str = str(score) if score is not None else "N/A"
            stats_text += f"  - {cve_id:20} | {severity_str:8} | 评分: {score_str} {dell_mark}\n"

        if self.dell_advisories:
            stats_text += f"\n【最新 Dell 安全公告 (前5个)】\n"
            for advisory in self.dell_advisories[:5]:
                advisory_id = advisory.get('dell_security_advisory', 'N/A')
                title = advisory.get('title', 'N/A')
                cve_count = len(advisory.get('cve_ids', []))
                stats_text += f"  - {advisory_id:20} | {title[:40]}... | {cve_count} CVE\n"

        stats_text += f"\n{'=' * 80}\n"

        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)

    # ==================== 队列检查和日志功能 ====================

    def check_queues(self):
        """检查队列中的数据（优化版：增量更新）"""
        # 检查 NVD 数据队列
        new_nvd_items = []  # 收集本次批量新增的数据
        need_clear_nvd_tree = False

        while not self.data_queue.empty():
            try:
                data_type, data = self.data_queue.get_nowait()

                # 支持元组命令格式
                if isinstance(data_type, str) and data_type == 'clear_nvd':
                    # 清空NVD树视图
                    need_clear_nvd_tree = True
                elif isinstance(data_type, str) and data_type == 'add_nvd':
                    # 添加NVD数据
                    if data:
                        cve_id = data.get('cve_id', '')
                        # 只添加不重复的数据
                        if cve_id and not any(cve.get('cve_id') == cve_id for cve in new_nvd_items):
                            new_nvd_items.append(data)
                elif data_type == 'nvd':
                    # ✅ 优化：直接添加到内存，无需重新加载数据库
                    # 检查是否已存在（避免重复）
                    cve_id = data.get('cve_id', '')
                    if cve_id and not any(cve.get('cve_id') == cve_id for cve in self.cve_data):
                        self.cve_data.append(data)
                        new_nvd_items.append(data)
            except queue.Empty:
                break

        # 执行清空操作
        if need_clear_nvd_tree:
            for item in self.nvd_tree.get_children():
                self.nvd_tree.delete(item)

        # ✅ 批量添加到树视图（减少 GUI 更新次数）with performance optimization
        if new_nvd_items:
            processed_count = 0
            for cve in new_nvd_items:
                self.add_nvd_to_tree(cve)
                processed_count += 1

                # Yield control periodically to prevent GUI freezing for large batches
                if processed_count % 50 == 0:
                    self.root.update_idletasks()  # Process pending GUI events

        # 检查 Dell 数据队列
        new_dell_items = []  # 收集新增的 Dell 数据
        need_refresh_database = False
        need_update_stats = False
        need_clear_dell_tree = False

        while not self.dell_queue.empty():
            try:
                data = self.dell_queue.get_nowait()
                # 检查是否是特殊命令
                if isinstance(data, tuple) and len(data) == 2:
                    command, payload = data
                    if command == 'refresh_database':
                        need_refresh_database = True
                    elif command == 'update_stats':
                        need_update_stats = True
                    elif command == 'clear':
                        # 清空Dell树视图
                        need_clear_dell_tree = True
                    elif command == 'add':
                        # 添加Dell数据
                        if payload:
                            dsa_id = payload.get('dell_security_advisory', '')
                            # 只添加不重复的数据
                            if dsa_id and not any(adv.get('dell_security_advisory') == dsa_id for adv in new_dell_items):
                                new_dell_items.append(payload)
                else:
                    # ✅ 优化：收集数据，稍后批量处理
                    # 检查是否已存在（避免重复）
                    dsa_id = data.get('dell_security_advisory', '')
                    if dsa_id and not any(adv.get('dell_security_advisory') == dsa_id for adv in self.dell_advisories):
                        self.dell_advisories.append(data)
                        new_dell_items.append(data)
            except queue.Empty:
                break

        # 执行清空操作
        if need_clear_dell_tree:
            for item in self.dell_tree.get_children():
                self.dell_tree.delete(item)

        # 执行特殊命令
        if need_refresh_database:
            self.load_dell_from_database()

        # ✅ 批量添加 Dell 数据到树视图 with performance optimization
        if new_dell_items:
            processed_count = 0
            for advisory in new_dell_items:
                self.add_dell_to_tree(advisory)
                processed_count += 1

                # Yield control periodically to prevent GUI freezing for large batches
                if processed_count % 20 == 0:
                    self.root.update_idletasks()  # Process pending GUI events

        # 检查日志队列
        while not self.log_queue.empty():
            try:
                message = self.log_queue.get_nowait()

                # Check if this is a progress update message
                if message.startswith("正在处理:") or message.startswith("Dell数据处理:"):
                    # Extract progress percentage if present
                    if " (" in message and "%" in message:
                        try:
                            percent_str = message.split("(")[-1].split("%")[0]
                            if percent_str.isdigit():
                                progress_val = int(percent_str)
                                self.root.after(0, self.update_progress, progress_val, message)
                        except:
                            pass  # If parsing fails, just log the message

                self.log(message)
            except queue.Empty:
                break

        # 检查关联树视图队列
        need_clear_matched_tree = False
        matched_items_to_add = []

        while not self.matched_tree_queue.empty():
            try:
                command, data = self.matched_tree_queue.get_nowait()
                if command == 'clear':
                    need_clear_matched_tree = True
                elif command == 'add':
                    matched_items_to_add.append(data)
            except queue.Empty:
                break

        # 执行清空操作
        if need_clear_matched_tree:
            for item in self.matched_tree.get_children():
                self.matched_tree.delete(item)

        # 批量添加关联数据 with performance optimization
        if matched_items_to_add:
            processed_count = 0
            for item_data in matched_items_to_add:
                self.matched_tree.insert(
                    "",
                    "end",
                    values=item_data["values"],
                    tags=(item_data["tag"],)
                )
                processed_count += 1

                # Yield control periodically to prevent GUI freezing for large batches
                if processed_count % 30 == 0:
                    self.root.update_idletasks()  # Process pending GUI events

        # ✅ 优化：只在有新数据或收到更新命令时才更新统计
        if new_nvd_items or new_dell_items or need_update_stats:
            self.update_stats()
            # 如果有新的 CVE 或 Dell 数据，刷新关联数据
            # Only refresh matched data if we have both types of data available
            if (new_nvd_items or new_dell_items) and self.cve_data and self.dell_advisories and len(self.cve_data) > 0 and len(self.dell_advisories) > 0:
                self.refresh_matched_data()

        # 继续检查
        self.root.after(100, self.check_queues)

    def close_database_connection(self):
        """关闭数据库连接（改进版，等待队列清空）"""
        # ✅ 修复 #1: 等待备份队列清空
        if hasattr(self, 'sqlite_backup_queue') and not self.sqlite_backup_queue.empty():
            try:
                print("等待数据备份完成...")
                # 等待队列清空，最多等待 10 秒
                import time
                start_time = time.time()
                while not self.sqlite_backup_queue.empty() and (time.time() - start_time) < 10:
                    time.sleep(0.1)

                if self.sqlite_backup_queue.empty():
                    print("✓ 数据备份完成")
                else:
                    print(f"⚠ 备份队列仍有 {self.sqlite_backup_queue.qsize()} 项未完成，强制关闭")
            except Exception as e:
                print(f"等待备份队列时出错: {e}")

        # 关闭 Redis 连接
        if hasattr(self, 'redis_manager') and self.redis_manager:
            try:
                self.redis_manager.close()
                print("Redis 连接已关闭")
            except Exception as e:
                print(f"关闭 Redis 连接时出错: {str(e)}")

        # 关闭 SQLite 连接
        if hasattr(self, 'conn') and self.conn:
            try:
                self.conn.close()
                print("SQLite 连接已关闭")
            except sqlite3.Error as e:
                print(f"关闭 SQLite 连接时出错: {str(e)}")

    def cleanup(self):
        """✅ 修复 #4: 统一的资源清理函数（防止重复清理）"""
        with self._cleanup_lock:
            if self._cleaned_up:
                return  # 已经清理过，直接返回

            try:
                print("\n正在清理资源...")
                self.close_database_connection()
                self._cleaned_up = True
                print("✓ 资源清理完成\n")
            except Exception as e:
                print(f"清理资源时出错: {e}")

    def _signal_handler(self, signum, frame):
        """✅ 修复 #4: 处理系统信号（Ctrl+C 等）"""
        print(f"\n收到信号 {signum}，正在安全退出...")
        try:
            self.cleanup()
        except Exception as e:
            print(f"信号处理出错: {e}")
        finally:
            sys.exit(0)

    def log(self, message):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"

        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)

    def clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)
        self.log("日志已清空")


class _StderrFilter:
    """过滤 libpng 等底层 C 库写入 stderr 的无害警告。"""
    _SUPPRESS = ('libpng warning: iCCP',)

    def __init__(self, real_stderr):
        self._real = real_stderr

    def write(self, msg):
        if not any(pat in msg for pat in self._SUPPRESS):
            self._real.write(msg)
        return len(msg)

    def flush(self):
        self._real.flush()

    def __getattr__(self, name):
        return getattr(self._real, name)


def main():
    """主函数"""
    # 过滤 Tk 初始化时 libpng 输出的 iCCP 警告（无害，来自 Tk 主题 PNG 资源）
    sys.stderr = _StderrFilter(sys.stderr)

    # 设置 Windows DPI 感知
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, OSError, AttributeError) as e:
        # 非Windows系统或Windows版本不支持DPI设置，忽略
        pass

    root = tk.Tk()
    app = CVEIntegratedGUI(root)

    # ✅ 修复 #1 & #4: 改进窗口关闭处理，使用统一的清理函数
    def on_closing():
        app.cleanup()  # 使用统一的清理函数
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()


if __name__ == "__main__":
    main()
