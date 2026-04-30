"""
智能知识管理平台
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
from datetime import datetime, timedelta, date as date_type
from pathlib import Path
import threading
import queue
import os
# 加载 .env 环境变量（Exa API Key 等）
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'), override=True)
except ImportError:
    pass
import atexit
import signal
import sys
import urllib.request
import urllib.parse
import urllib.error

# 日历组件（可选）
try:
    from tkcalendar import Calendar
    HAS_TKCALENDAR = True
except ImportError:
    HAS_TKCALENDAR = False

# 导入自定义模块
from collect_cves import CVECollector
from dell_security_scraper import DellSecurityScraper
from redis_manager import RedisDataManager
from config import COLORS, AI_CONFIG, get_api_key
from db_backup import backup_database, list_backups


def _extract_cvss_from_metrics(metrics: dict) -> tuple:
    """从 NVD metrics 中提取 CVSS 评分（优先级：v4.0 → v3.1 → v3.0 → v2.0）

    每一级遍历所有条目（NVD Primary + CNA Secondary），优先取 Primary，
    只有在 baseSeverity 有效（非 NONE/N/A/空）时才采用。

    Returns:
        (severity, score, vector) 元组，未找到时返回 ("", None, "")
    """
    for ver_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if ver_key in metrics and metrics[ver_key]:
            entries = sorted(metrics[ver_key],
                             key=lambda e: 0 if e.get("type") == "Primary" else 1)
            for entry in entries:
                cd = entry.get("cvssData", {})
                sev = cd.get("baseSeverity", "")
                score = cd.get("baseScore")
                if score is not None and sev and str(sev).upper() not in ("NONE", "N/A", ""):
                    return sev, score, cd.get("vectorString", "")

    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cd = metrics["cvssMetricV2"][0].get("cvssData", {})
        score = cd.get("baseScore")
        if score is not None:
            sev = "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
            return sev, score, cd.get("vectorString", "")

    return "", None, ""


def _make_qwen_client(timeout: int = 60):
    """统一创建 Qwen / DashScope 兼容客户端

    返回: (client, model) 元组；若未配置 API Key 则抛出 ValueError
    """
    from openai import OpenAI
    api_key = get_api_key("qwen")
    if not api_key:
        raise ValueError("未配置 QWEN_API_KEY/DASHSCOPE_API_KEY，请在 .env 中设置")
    client = OpenAI(
        api_key=api_key,
        base_url=AI_CONFIG["qwen_base_url"],
        timeout=timeout,
    )
    return client, AI_CONFIG["qwen_model"]


class CVEIntegratedGUI:
    """智能知识管理平台 - 整合界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("智能知识管理平台")
        self.root.geometry("1400x900")

        # 设置主题颜色（统一从 config.COLORS 读取，便于主题化）
        self.bg_color = "#f0f0f0"
        self.primary_color = COLORS["primary"]
        self.success_color = COLORS["success"]
        self.danger_color = COLORS["danger"]
        self.warning_color = COLORS["warning"]
        self.info_color = COLORS["info"]

        self.root.configure(bg=self.bg_color)

        # 数据队列（用于线程间通信）
        self.data_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.dell_queue = queue.Queue()
        self.matched_tree_queue = queue.Queue()  # 关联树视图队列

        # ✅ 修复 #2: 添加数据库访问锁（线程安全）
        self.db_lock = threading.Lock()

        # ✅ 修复 #4: 添加清理标志（防止重复清理）
        self._cleaned_up = False
        self._cleanup_lock = threading.Lock()

        # 数据存储
        self.cve_data = []
        self.dell_advisories = []
        self.matched_items_cache = []  # 关联数据缓存，用于搜索过滤
        self.is_collecting = False
        self.is_collecting_dell = False

        # IT新闻简报数据
        self.news_articles = []          # 采集到的新闻文章列表
        self.is_collecting_news = False  # 新闻采集状态标志
        self.news_brief_text = ""        # 当前生成的简报文本
        self._tts_process = None         # TTS 播放子进程句柄

        # 天气数据
        self._weather_config = {}        # 天气配置（城市等）
        self._weather_daily_cache = {}   # 日期→天气数据缓存
        self._weather_city_coords = None # 当前城市经纬度 (lat, lon, name)

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

        # SQLite 性能优化配置
        optimizations = [
            'PRAGMA journal_mode=WAL',           # WAL 模式，提升并发性能
            'PRAGMA cache_size=20000',           # 增加缓存大小（~80MB）for better performance
            'PRAGMA synchronous=NORMAL',         # 平衡性能和安全
            'PRAGMA temp_store=MEMORY',          # 临时数据存储在内存
            'PRAGMA mmap_size=268435456',         # 内存映射 I/O（256MB，匹配实际数据库规模）
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

            # IT新闻简报表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS news_briefs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    brief_date TEXT NOT NULL,
                    content TEXT NOT NULL,
                    articles_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 播客脚本表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS podcast_scripts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    script_date TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 学习对话记录表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learn_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    level TEXT,
                    source_type TEXT,
                    source_content TEXT,
                    conversation TEXT NOT NULL,
                    summary TEXT,
                    auto_summary TEXT,
                    key_topics TEXT,
                    suggested_questions TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 笔记本工作区表（Phase 2）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notebooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 笔记本资料源关联表（Phase 2）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notebook_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notebook_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_title TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (notebook_id) REFERENCES notebooks(id) ON DELETE CASCADE
                )
            ''')

            # Dell技术库文章表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dell_kb_articles (
                    article_id TEXT PRIMARY KEY,
                    title TEXT,
                    content TEXT,
                    solution TEXT,
                    url TEXT,
                    collected_date TEXT
                )
            ''')

            # 闪卡与知识问答表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flashcards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    question TEXT NOT NULL,
                    answer TEXT NOT NULL,
                    options TEXT,
                    correct_option INTEGER,
                    card_type TEXT DEFAULT 'flashcard',
                    difficulty INTEGER DEFAULT 1,
                    review_count INTEGER DEFAULT 0,
                    correct_count INTEGER DEFAULT 0,
                    next_review TEXT,
                    source_session_id INTEGER,
                    source_refs TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 学习产物表（Phase 3）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learn_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    topic TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source_refs TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES learn_sessions(id) ON DELETE SET NULL
                )
            ''')

            # Create indexes for better query performance
            # Index on published_date for date-based queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_last_modified ON cves(last_modified)")

            # Index for Dell advisories
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dell_published_date ON dell_advisories(published_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dell_cve_ids ON dell_advisories(cve_ids)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dell_title ON dell_advisories(title)")

            # Index for AI solutions
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_cve ON ai_solutions(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_advisory ON ai_solutions(dell_advisory_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_time ON ai_solutions(analysis_time)")

            # Index for news briefs and podcast scripts
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_news_briefs_date ON news_briefs(brief_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_podcast_scripts_date ON podcast_scripts(script_date)")

            # Index for learn sessions
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learn_sessions_topic ON learn_sessions(topic)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learn_sessions_created ON learn_sessions(created_at)")

            # Index for flashcards
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flashcards_topic ON flashcards(topic)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flashcards_type ON flashcards(card_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flashcards_next_review ON flashcards(next_review)")

            # Index for Dell KB articles
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dell_kb_collected_date ON dell_kb_articles(collected_date)")

            # Index for collection_history
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_collection_history_date ON collection_history(collected_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_collection_history_cve ON collection_history(cve_id)")

            # Index for notebooks / notebook_sources / learn_artifacts
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_notebooks_name ON notebooks(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_notebook_sources_nb ON notebook_sources(notebook_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learn_artifacts_session ON learn_artifacts(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learn_artifacts_topic ON learn_artifacts(topic)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_learn_artifacts_type ON learn_artifacts(artifact_type)")

            # ── FTS5 全文索引（加速 LIKE '%keyword%' 搜索）──
            cursor.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                    cve_id, data,
                    content=cves, content_rowid=rowid
                )
            ''')
            cursor.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS dell_fts USING fts5(
                    dsa_id, title, cve_ids, data,
                    content=dell_advisories, content_rowid=rowid
                )
            ''')

            # FTS 同步触发器 — 插入/删除/更新时自动维护索引
            cursor.executescript('''
                CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                    INSERT INTO cves_fts(rowid, cve_id, data)
                    VALUES (new.rowid, new.cve_id, new.data);
                END;
                CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
                    INSERT INTO cves_fts(cves_fts, rowid, cve_id, data)
                    VALUES ('delete', old.rowid, old.cve_id, old.data);
                END;
                CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
                    INSERT INTO cves_fts(cves_fts, rowid, cve_id, data)
                    VALUES ('delete', old.rowid, old.cve_id, old.data);
                    INSERT INTO cves_fts(rowid, cve_id, data)
                    VALUES (new.rowid, new.cve_id, new.data);
                END;

                CREATE TRIGGER IF NOT EXISTS dell_ai AFTER INSERT ON dell_advisories BEGIN
                    INSERT INTO dell_fts(rowid, dsa_id, title, cve_ids, data)
                    VALUES (new.rowid, new.dsa_id, new.title, new.cve_ids, new.data);
                END;
                CREATE TRIGGER IF NOT EXISTS dell_ad AFTER DELETE ON dell_advisories BEGIN
                    INSERT INTO dell_fts(dell_fts, rowid, dsa_id, title, cve_ids, data)
                    VALUES ('delete', old.rowid, old.dsa_id, old.title, old.cve_ids, old.data);
                END;
                CREATE TRIGGER IF NOT EXISTS dell_au AFTER UPDATE ON dell_advisories BEGIN
                    INSERT INTO dell_fts(dell_fts, rowid, dsa_id, title, cve_ids, data)
                    VALUES ('delete', old.rowid, old.dsa_id, old.title, old.cve_ids, old.data);
                    INSERT INTO dell_fts(rowid, dsa_id, title, cve_ids, data)
                    VALUES (new.rowid, new.dsa_id, new.title, new.cve_ids, new.data);
                END;
            ''')

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

            # ── 首次运行时填充 FTS5 索引 ──
            self._rebuild_fts_if_needed()

        except sqlite3.Error as e:
            self.log(f"更新数据库表结构失败: {str(e)}")

    def _rebuild_fts_if_needed(self):
        """首次运行或 FTS 索引为空时，从主表填充 FTS5 索引"""
        try:
            cursor = self.conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM cves")
            cve_total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM cves_fts")
            fts_cve = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM dell_advisories")
            dell_total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM dell_fts")
            fts_dell = cursor.fetchone()[0]

            if cve_total > 0 and fts_cve == 0:
                self.log(f"正在构建 CVE 全文索引（{cve_total} 条）...")
                cursor.execute("INSERT INTO cves_fts(rowid, cve_id, data) SELECT rowid, cve_id, data FROM cves")
                self.conn.commit()
                self.log(f"CVE 全文索引构建完成")

            if dell_total > 0 and fts_dell == 0:
                self.log(f"正在构建 Dell 全文索引（{dell_total} 条）...")
                cursor.execute("INSERT INTO dell_fts(rowid, dsa_id, title, cve_ids, data) SELECT rowid, dsa_id, title, cve_ids, data FROM dell_advisories")
                self.conn.commit()
                self.log(f"Dell 全文索引构建完成")

        except sqlite3.Error as e:
            self.log(f"FTS 索引构建失败（不影响正常使用）: {e}")

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
        """启动 Redis 缓存同步线程（启动时将 SQLite 增量同步到 Redis）"""
        if not self.use_redis:
            return

        def sync_worker():
            """将 SQLite 数据同步到 Redis（全量覆盖，SQLite 为权威源）"""
            try:
                # 同步 CVE 数据（增量补缺）
                redis_cve_ids = self.redis_manager.redis_client.smembers(self.redis_manager.CVE_SET)
                with self.db_lock:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT cve_id, data FROM cves")
                    rows = cursor.fetchall()

                missing_cves = []
                for cve_id, data_str in rows:
                    if cve_id not in redis_cve_ids:
                        try:
                            missing_cves.append(json.loads(data_str))
                        except (json.JSONDecodeError, TypeError):
                            continue

                if missing_cves:
                    synced = 0
                    for cve_data in missing_cves:
                        try:
                            self.redis_manager.store_cve(cve_data)
                            synced += 1
                        except Exception:
                            continue
                    self.log_queue.put(f"✓ Redis 同步: 补齐 {synced} 条 CVE")

                # 同步 Dell 数据（全量覆盖：以 SQLite 为准更新 Redis）
                with self.db_lock:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT dsa_id, data FROM dell_advisories")
                    dell_rows = cursor.fetchall()

                synced_dell = 0
                for dsa_id, data_str in dell_rows:
                    try:
                        dell_data = json.loads(data_str)
                        self.redis_manager.store_dell_advisory(dell_data)
                        synced_dell += 1
                    except Exception:
                        continue

                # 清理 Redis 中 SQLite 已删除的条目
                sqlite_dell_ids = {row[0] for row in dell_rows}
                redis_dell_ids = self.redis_manager.redis_client.smembers(self.redis_manager.DELL_SET)
                orphan_ids = redis_dell_ids - sqlite_dell_ids
                for orphan_id in orphan_ids:
                    self.redis_manager.delete_dell_advisory(orphan_id)

                if orphan_ids:
                    self.log_queue.put(f"✓ Redis 同步: Dell 覆盖 {synced_dell} 条, 清理孤立 {len(orphan_ids)} 条")
                elif not missing_cves:
                    self.log_queue.put("✓ Redis 缓存与 SQLite 数据一致")
                else:
                    self.log_queue.put(f"✓ Redis 同步: Dell {synced_dell} 条已同步")

            except Exception as e:
                self.log_queue.put(f"Redis 增量同步出错: {e}")

        sync_thread = threading.Thread(target=sync_worker, daemon=True)
        sync_thread.start()

    def store_cve_data(self, cve_data):
        """存储单个CVE数据（SQLite主存储，Redis缓存同步）"""
        # SQLite 先写（保证持久化）
        is_new = self._store_cve_to_sqlite(cve_data)

        # Redis 后写（缓存更新，失败不影响主流程）
        if self.use_redis:
            try:
                self.redis_manager.store_cve(cve_data)
            except Exception:
                pass

        return is_new

    def bulk_store_cve_data(self, cve_list):
        """批量存储CVE数据（SQLite批量写入，Redis缓存同步）"""
        if not cve_list:
            return 0

        # SQLite 批量写入（主存储）
        new_count = self._bulk_store_cve_to_sqlite(cve_list)

        # Redis 缓存更新（best-effort）
        if self.use_redis:
            try:
                for cve_data in cve_list:
                    self.redis_manager.store_cve(cve_data)
            except Exception:
                pass

        return new_count

    def _bulk_store_cve_to_sqlite(self, cve_list):
        """批量存储CVE数据到SQLite（事务处理，使用executemany提高性能）"""
        with self.db_lock:
            try:
                cursor = self.conn.cursor()

                # Start transaction for better performance
                cursor.execute("BEGIN TRANSACTION")

                # 预处理数据，准备批量插入
                cve_rows = []
                history_rows = []
                now_iso = datetime.now().isoformat()

                for cve_data in cve_list:
                    cve_id = cve_data.get('cve_id', '')
                    if not cve_id:
                        continue
                    data_str = json.dumps(cve_data) if cve_data else '{}'
                    cve_rows.append((
                        cve_id,
                        data_str,
                        cve_data.get('last_modified', '') or '',
                        cve_data.get('published_date', '') or ''
                    ))
                    history_rows.append((cve_id, now_iso))

                # 批量插入 CVE 数据
                cursor.executemany('''
                    INSERT OR REPLACE INTO cves (cve_id, data, last_modified, published_date)
                    VALUES (?, ?, ?, ?)
                ''', cve_rows)

                # 批量插入采集历史
                cursor.executemany('''
                    INSERT INTO collection_history (cve_id, collected_date)
                    VALUES (?, ?)
                ''', history_rows)

                self.conn.commit()
                return len(cve_rows)
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
        with self.db_lock:
            try:
                cursor = self.conn.cursor()

                cve_id = cve_data.get('cve_id', '')
                if not cve_id:
                    return False

                data_str = json.dumps(cve_data) if cve_data else '{}'

                # 检查是否已存在（用于返回值判断）
                cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
                is_new = cursor.fetchone() is None

                # INSERT OR REPLACE 一步完成插入/更新
                cursor.execute('''
                    INSERT OR REPLACE INTO cves (cve_id, data, last_modified, published_date)
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
                            # 回填缺失的 CVSS 评分（v4.0→v3.1→v3.0→v2.0，跳过 NONE）
                            sev = data.get("cvss_severity", "")
                            if not sev or str(sev).upper() in ("NONE", "N/A", ""):
                                metrics = data.get("metrics", {})
                                sev, score, vec = _extract_cvss_from_metrics(metrics)
                                if sev:
                                    data["cvss_severity"] = sev
                                    data["cvss_score"] = score
                                    data["cvss_vector"] = vec
                                elif data.get("vuln_status") in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
                                    data["cvss_severity"] = "AWAITING"
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
            cursor.execute("SELECT cve_id, data, last_modified, published_date FROM cves ORDER BY published_date DESC LIMIT ?", (int(limit),))

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
        """存储单个Dell安全公告（SQLite主存储，Redis缓存同步）"""
        # SQLite 先写（保证持久化）
        is_new = self._store_dell_to_sqlite(advisory_data)

        # Redis 后写（缓存更新，失败不影响主流程）
        if self.use_redis:
            try:
                self.redis_manager.store_dell_advisory(advisory_data)
            except Exception:
                pass

        return is_new

    def _store_dell_to_sqlite(self, advisory_data):
        """存储 Dell 数据到 SQLite（Upsert：有则更新，无则插入）"""
        with self.db_lock:
            try:
                cursor = self.conn.cursor()

                dsa_id = advisory_data.get('dell_security_advisory', '')
                if not dsa_id:
                    return False

                cve_ids_str = ','.join(advisory_data.get('cve_ids', []))
                data_str = json.dumps(advisory_data, ensure_ascii=False)

                # Upsert：新记录插入，已有记录用更完整的 data 覆盖
                cursor.execute('''
                    INSERT INTO dell_advisories
                    (dsa_id, title, cve_ids, data, published_date, collected_date, link)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(dsa_id) DO UPDATE SET
                        data = excluded.data,
                        title = excluded.title,
                        cve_ids = excluded.cve_ids,
                        published_date = excluded.published_date,
                        link = excluded.link
                ''', (
                    dsa_id,
                    advisory_data.get('title', ''),
                    cve_ids_str,
                    data_str,
                    advisory_data.get('published_date', ''),
                    datetime.now().isoformat(),
                    advisory_data.get('link', '')
                ))

                is_new = cursor.rowcount > 0
                self.conn.commit()
                return is_new
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
                except Exception:
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
            text="🛡️ 智能知识管理平台",
            font=("Microsoft YaHei", 24, "bold"),
            fg="white",
            bg=self.primary_color
        )
        title_label.pack(pady=20)

        # 主要内容区域（使用 Notebook 创建标签页）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 0. IT新闻简报标签页（放在最前面）
        self.news_frame = tk.Frame(self.notebook, bg="white")
        self.news_tab_id = self.notebook.add(self.news_frame, text="📰 IT新闻简报")

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

        # 5. Dell技术库标签页
        self.dell_kb_frame = tk.Frame(self.notebook, bg="white")
        self.dell_kb_tab_id = self.notebook.add(self.dell_kb_frame, text="📖 Dell技术库")

        # 6. 统计分析标签页
        self.stats_frame = tk.Frame(self.notebook, bg="white")
        self.stats_tab_id = self.notebook.add(self.stats_frame, text="📈 统计分析")

        # 7. 智能学习标签页
        self.learn_frame = tk.Frame(self.notebook, bg="white")
        self.learn_tab_id = self.notebook.add(self.learn_frame, text="🧠 智能学习")

        # 8. 日志标签页
        self.log_frame = tk.Frame(self.notebook, bg="white")
        self.log_tab_id = self.notebook.add(self.log_frame, text="📝 操作日志")

        # 创建各个标签页的内容
        self.create_news_view()
        self.create_nvd_view()
        self.create_dell_view()
        self.create_matched_view()
        self.create_solution_view()
        self.create_dell_kb_view()
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

    # ==================== IT新闻简报 ====================

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

    # 重点城市列表（含经纬度，免去地理编码请求）
    MAJOR_CITIES = [
        {"name": "北京", "lat": 39.9042, "lon": 116.4074},
        {"name": "上海", "lat": 31.2304, "lon": 121.4737},
        {"name": "广州", "lat": 23.1291, "lon": 113.2644},
        {"name": "深圳", "lat": 22.5431, "lon": 114.0579},
        {"name": "杭州", "lat": 30.2741, "lon": 120.1551},
        {"name": "成都", "lat": 30.5728, "lon": 104.0668},
        {"name": "武汉", "lat": 30.5928, "lon": 114.3055},
        {"name": "南京", "lat": 32.0603, "lon": 118.7969},
        {"name": "重庆", "lat": 29.4316, "lon": 106.9123},
        {"name": "西安", "lat": 34.3416, "lon": 108.9398},
        {"name": "天津", "lat": 39.3434, "lon": 117.3616},
        {"name": "苏州", "lat": 31.2990, "lon": 120.5853},
        {"name": "厦门", "lat": 24.4798, "lon": 118.0894},
        {"name": "长沙", "lat": 28.2282, "lon": 112.9388},
        {"name": "青岛", "lat": 36.0671, "lon": 120.3826},
        {"name": "大连", "lat": 38.9140, "lon": 121.6147},
        {"name": "郑州", "lat": 34.7466, "lon": 113.6253},
        {"name": "沈阳", "lat": 41.8057, "lon": 123.4315},
        {"name": "合肥", "lat": 31.8206, "lon": 117.2272},
        {"name": "昆明", "lat": 25.0389, "lon": 102.7183},
    ]

    # Open-Meteo 天气码 → 中文描述
    WEATHER_CODE_DESC = {
        0: '晴', 1: '晴间多云', 2: '多云', 3: '阴',
        45: '雾', 48: '雾霜',
        51: '小雨', 53: '中雨', 55: '大雨', 56: '小冻雨', 57: '大冻雨',
        61: '小雨', 63: '中雨', 65: '大雨', 66: '小冻雨', 67: '大冻雨',
        71: '小雪', 73: '中雪', 75: '大雪', 77: '霰',
        80: '小阵雨', 81: '阵雨', 82: '强阵雨',
        85: '小阵雪', 86: '大阵雪',
        95: '雷暴', 96: '雷暴伴冰雹', 99: '雷暴伴大冰雹',
    }

    # 天气码 → Emoji
    WEATHER_CODE_ICON = {
        0: '☀️', 1: '🌤️', 2: '⛅', 3: '☁️',
        45: '🌫️', 48: '🌫️',
        51: '🌧️', 53: '🌧️', 55: '🌧️', 56: '🌧️', 57: '🌧️',
        61: '🌧️', 63: '🌧️', 65: '🌧️', 66: '🌧️', 67: '🌧️',
        71: '❄️', 73: '❄️', 75: '❄️', 77: '❄️',
        80: '🌦️', 81: '🌦️', 82: '🌦️',
        85: '❄️', 86: '❄️',
        95: '⛈️', 96: '⛈️', 99: '⛈️',
    }

    def create_news_view(self):
        """创建 IT新闻简报 标签页内容（含天气、日历、数据库保存）"""
        # 加载天气配置
        self._load_weather_config()

        # ── 顶部控制栏 ──────────────────────────────────────────────
        ctrl = tk.Frame(self.news_frame, bg="white", pady=8)
        ctrl.pack(fill=tk.X, padx=10)

        tk.Label(
            ctrl,
            text="IT新闻简报 — 每日自动采集科技资讯，AI生成500字简报",
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
            btn_frame, text="🎙 生成播客", command=self.generate_podcast,
            bg=self.warning_color, fg="white", font=("Microsoft YaHei", 10, "bold"),
            padx=12, pady=4, relief=tk.FLAT, cursor="hand2",
        )
        self.news_podcast_btn.pack(side=tk.LEFT, padx=4)

        # ── 天气与穿衣建议栏 ────────────────────────────────────────
        weather_bar = tk.Frame(self.news_frame, bg="#e8f4fd", pady=6)
        weather_bar.pack(fill=tk.X, padx=10, pady=(0, 4))

        # 城市选择
        tk.Label(
            weather_bar, text="🌤️ 城市：", bg="#e8f4fd",
            font=("Microsoft YaHei", 10, "bold"), fg="#1a5276",
        ).pack(side=tk.LEFT, padx=(8, 2))

        city_names = [c["name"] for c in self.MAJOR_CITIES]
        self._weather_city_var = tk.StringVar()
        self._weather_city_combo = ttk.Combobox(
            weather_bar, textvariable=self._weather_city_var,
            values=city_names, width=8, font=("Microsoft YaHei", 9), state="readonly",
        )
        self._weather_city_combo.pack(side=tk.LEFT, padx=(0, 4))
        # 恢复上次保存的城市
        saved_city = self._weather_config.get("city", "上海")
        if saved_city in city_names:
            self._weather_city_combo.set(saved_city)
        else:
            self._weather_city_combo.set("上海")
        self._weather_city_combo.bind("<<ComboboxSelected>>", self._on_weather_city_changed)

        tk.Button(
            weather_bar, text="📍 自动定位", command=self._weather_autolocate,
            bg="#3498db", fg="white", font=("Microsoft YaHei", 9),
            padx=6, pady=1, relief=tk.FLAT, cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            weather_bar, text="🔄 刷新天气", command=self._weather_refresh,
            bg="#27ae60", fg="white", font=("Microsoft YaHei", 9),
            padx=6, pady=1, relief=tk.FLAT, cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 12))

        # 天气信息显示
        self._weather_info_label = tk.Label(
            weather_bar, text="点击「刷新天气」获取天气信息",
            bg="#e8f4fd", font=("Microsoft YaHei", 10), fg="#2c3e50", anchor="w",
        )
        self._weather_info_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        # ── 水平分割：左=日历+文章区  右=简报/播客 ──────────────────
        h_paned = tk.PanedWindow(
            self.news_frame, orient=tk.HORIZONTAL, bg="#d0d0d0", sashwidth=5, sashrelief=tk.RAISED
        )
        h_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 4))

        # ── 左侧：日历（上）+ 文章列表（中）+ 文章详情（下）──────────
        v_paned = tk.PanedWindow(
            h_paned, orient=tk.VERTICAL, bg="#d0d0d0", sashwidth=5, sashrelief=tk.RAISED
        )
        h_paned.add(v_paned, minsize=320, width=380)

        # 上：日历模块
        cal_frame = tk.Frame(v_paned, bg="white")
        v_paned.add(cal_frame, minsize=200)

        cal_header = tk.Frame(cal_frame, bg="white")
        cal_header.pack(fill=tk.X, padx=8, pady=(6, 2))
        tk.Label(
            cal_header, text="📅 日历 · 资讯存档",
            bg="white", font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color,
        ).pack(side=tk.LEFT)

        self._cal_info_label = tk.Label(
            cal_header, text="", bg="white", font=("Microsoft YaHei", 8), fg="#888",
        )
        self._cal_info_label.pack(side=tk.RIGHT, padx=4)

        if HAS_TKCALENDAR:
            self._calendar = Calendar(
                cal_frame, selectmode='day', locale='zh_CN',
                year=datetime.now().year, month=datetime.now().month,
                day=datetime.now().day,
                font=("Microsoft YaHei", 9),
                showweeknumbers=False,
                borderwidth=0,
                background='white', foreground='black',
                headersbackground='#3498db', headersforeground='white',
                selectbackground='#e74c3c', selectforeground='white',
                normalbackground='white', normalforeground='#333',
                weekendbackground='#fef9e7', weekendforeground='#c0392b',
                othermonthbackground='#f5f5f5', othermonthforeground='#bbb',
                othermonthwebackground='#f5f5f5', othermonthweforeground='#bbb',
            )
            self._calendar.pack(fill=tk.X, padx=8, pady=(0, 4))
            self._calendar.bind("<<CalendarSelected>>", self._on_calendar_date_selected)
            # 月份切换时刷新高亮
            self._calendar.bind("<<CalendarMonthChanged>>", self._on_calendar_month_changed)
        else:
            tk.Label(
                cal_frame, text="（需要安装 tkcalendar: pip install tkcalendar）",
                bg="white", fg="#999", font=("Microsoft YaHei", 9),
            ).pack(padx=8, pady=10)
            self._calendar = None

        # 中：文章列表
        list_frame = tk.Frame(v_paned, bg="white")
        v_paned.add(list_frame, minsize=120)

        list_header = tk.Frame(list_frame, bg="white")
        list_header.pack(fill=tk.X, padx=8, pady=(6, 2))

        tk.Label(
            list_header, text="今日文章列表",
            bg="white", font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color,
        ).pack(side=tk.LEFT)

        self.news_ai_analyze_btn = tk.Button(
            list_header, text="🤖 AI分析新闻", command=self._ai_analyze_selected_news,
            bg="#8e44ad", fg="white", font=("Microsoft YaHei", 9, "bold"),
            padx=10, pady=2, relief=tk.FLAT, cursor="hand2",
        )
        self.news_ai_analyze_btn.pack(side=tk.RIGHT, padx=4)

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

        # ── 右侧：简报 / 播客脚本 / 历史资讯 Notebook ──────────────
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

        self.tts_voice_var = tk.StringVar(value="默认声音")
        self.tts_voice_combo = ttk.Combobox(
            pod_tb, textvariable=self.tts_voice_var,
            state="readonly", width=28, font=("Microsoft YaHei", 9),
            values=["默认声音"],
        )
        self.tts_voice_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.tts_voice_combo.current(0)
        self._tts_voice_names = [""]

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

        # 保存脚本按钮
        tk.Button(
            pod_tb, text="💾 保存脚本", command=self._save_podcast_script,
            bg=self.primary_color, fg="white", font=("Microsoft YaHei", 9, "bold"),
            padx=10, pady=2, relief=tk.FLAT, cursor="hand2",
        ).pack(side=tk.RIGHT, padx=6)

        self.tts_status_label = tk.Label(
            pod_tb, text="", bg="#f5f0e0", font=("Microsoft YaHei", 8), fg="#666",
        )
        self.tts_status_label.pack(side=tk.LEFT, padx=8)

        self.news_podcast_area = scrolledtext.ScrolledText(
            podcast_sub, wrap=tk.WORD, font=("Microsoft YaHei", 10), bg="#fffdf0",
        )
        self.news_podcast_area.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ── 历史资讯子标签页 ─────────────────────────────────────────
        history_sub = tk.Frame(self.news_right_notebook, bg="#f0faf0")
        self.news_right_notebook.add(history_sub, text="📅 历史资讯")

        hist_tb = tk.Frame(history_sub, bg="#e0f0e0", pady=4)
        hist_tb.pack(fill=tk.X, padx=4, pady=(4, 0))

        self._history_date_label = tk.Label(
            hist_tb, text="请在日历中选择日期查看历史资讯",
            bg="#e0f0e0", font=("Microsoft YaHei", 9, "bold"), fg="#2c3e50",
        )
        self._history_date_label.pack(side=tk.LEFT, padx=8)

        self._history_area = scrolledtext.ScrolledText(
            history_sub, wrap=tk.WORD, font=("Microsoft YaHei", 10), bg="#f0faf0",
        )
        self._history_area.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ── 底部状态栏 ───────────────────────────────────────────────
        self.news_status_label = tk.Label(
            self.news_frame, text="就绪 — 点击「采集新闻」获取今日科技资讯",
            bg="white", fg="#666", font=("Microsoft YaHei", 9), anchor="w",
        )
        self.news_status_label.pack(fill=tk.X, padx=12, pady=(0, 4))

        # 异步加载可用 TTS 声音
        threading.Thread(target=self._load_sapi_voices, daemon=True).start()

        # 初始化：刷新日历高亮 + 自动查询天气
        self.root.after(500, self._refresh_calendar_tags)
        self.root.after(800, self._weather_refresh)

    def _load_sapi_voices(self):
        """后台查询 SAPI 声音列表：自动注册 OneCore 中文男声，过滤非中文声音"""
        try:
            import subprocess

            # ── 第一步：将 OneCore 中文声音（如 Kangkang）注册到 SAPI5 HKLM ──
            #   注册失败不应阻止第二步的声音列表查询
            try:
                reg_script = r"""
Add-Type -AssemblyName System.Speech
$srcBase = 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Voices\Tokens'
$dstBase = 'HKLM:\SOFTWARE\Microsoft\Speech\Voices\Tokens'
$voiceDataDir = 'C:\Windows\Speech_OneCore\Engines\TTS\zh-CN'

$targets = @{
    'MSTTS_V110_zhCN_KangkangM' = 'M2052Kangkang'
    'MSTTS_V110_zhCN_YaoyaoM'   = 'M2052Yaoyao'
}

foreach ($tokenName in $targets.Keys) {
    $src = "$srcBase\$tokenName"
    $dst = "$dstBase\$tokenName"
    if (-not (Test-Path $src)) { continue }
    if (Test-Path $dst) { continue }
    try {
        New-Item -Path $dst -Force | Out-Null
        $props = Get-ItemProperty $src
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            Set-ItemProperty -Path $dst -Name $_.Name -Value $_.Value
        }
        $correctPath = Join-Path $voiceDataDir $targets[$tokenName]
        Set-ItemProperty -Path $dst -Name 'VoicePath' -Value $correctPath
        Set-ItemProperty -Path $dst -Name '(default)' -Value (($props.'(default)') -replace ' - Chinese.*', ' Desktop - Chinese (Simplified)')

        $attrSrc = "$src\Attributes"
        $attrDst = "$dst\Attributes"
        if (Test-Path $attrSrc) {
            New-Item -Path $attrDst -Force | Out-Null
            $ap = Get-ItemProperty $attrSrc
            $ap.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                Set-ItemProperty -Path $attrDst -Name $_.Name -Value $_.Value
            }
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
            except Exception:
                pass  # 注册失败不影响下面的声音列表查询

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
                try:
                    labels = [v[0] for v in voices]
                    self.tts_voice_combo.configure(values=labels)
                    self._tts_voice_names = [v[1] for v in voices]
                    if labels:
                        self.tts_voice_var.set(labels[0])
                        self.tts_voice_combo.current(0)
                except Exception as update_error:
                    self.log(f"更新 TTS 声音下拉框失败: {update_error}")

            # 主线程更新下拉框；若事件循环尚未稳定，再补一次重试
            self._pending_tts_voices = voices
            for delay in (0, 500, 1500):
                try:
                    self.root.after(delay, _update)
                except RuntimeError:
                    continue

        except Exception as e:
            try:
                self.root.after(1000, self.log, f"加载 TTS 声音失败: {e}")
                self.root.after(1000, lambda: self.tts_voice_combo.configure(values=["默认声音"]))
                self.root.after(1000, lambda: self.tts_voice_var.set("默认声音"))
            except RuntimeError:
                pass
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

            model = os.getenv("QWEN_MODEL", "qwen3.6-plus")
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
        """保存简报到数据库和文件"""
        brief = self.news_brief_area.get(1.0, tk.END).strip()
        if not brief:
            messagebox.showwarning("提示", "简报内容为空，请先生成简报")
            return
        today = datetime.now().strftime("%Y-%m-%d")
        # 保存到数据库
        try:
            articles_json = json.dumps(
                [{"title": a.get("title", ""), "source": a.get("source", ""),
                  "url": a.get("url", "")} for a in self.news_articles],
                ensure_ascii=False,
            )
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO news_briefs (brief_date, content, articles_json) VALUES (?, ?, ?)",
                    (today, brief, articles_json),
                )
                self.conn.commit()
            self.log(f"简报已保存到数据库（{today}）")
        except Exception as e:
            self.log(f"简报保存到数据库失败: {e}")

        # 同时保存到文件
        save_dir = self.data_dir / "news_briefs"
        save_dir.mkdir(exist_ok=True)
        filename = save_dir / f"brief_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"IT新闻简报 — {datetime.now().strftime('%Y年%m月%d日 %H:%M')}\n")
                f.write("=" * 60 + "\n\n")
                f.write(brief)
                f.write("\n\n" + "=" * 60 + "\n")
                f.write("【原始采集文章列表】\n")
                for i, art in enumerate(self.news_articles, 1):
                    f.write(f"{i}. [{art['source']}] {art['title']}\n")
                    if art.get("url"):
                        f.write(f"   {art['url']}\n")
        except Exception as e:
            self.log(f"简报保存到文件失败: {e}")

        # 刷新日历高亮
        self._refresh_calendar_tags()
        messagebox.showinfo("保存成功", f"简报已保存至数据库和文件")

    # ==================== AI 分析新闻 ====================

    def _ai_analyze_selected_news(self):
        """AI深度分析选中的新闻文章"""
        sel = self.news_listbox.curselection()
        if not sel:
            messagebox.showwarning("提示", "请先在「今日文章列表」中选择一条新闻")
            return
        idx = sel[0]
        if idx >= len(self.news_articles):
            messagebox.showwarning("提示", "选择的文章索引无效，请重新选择")
            return

        art = self.news_articles[idx]
        title = art.get('title', '未知标题')
        self.news_ai_analyze_btn.config(state=tk.DISABLED, text="分析中...")
        self.news_status_label.config(text=f"AI 正在分析: {title[:40]}...")
        threading.Thread(
            target=self._ai_analyze_news_thread,
            args=(art,),
            daemon=True
        ).start()

    def _ai_analyze_news_thread(self, article):
        """后台线程：调用 AI 深度分析单条新闻"""
        try:
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                self.root.after(0, messagebox.showerror, "配置错误",
                                "未设置 QWEN_API_KEY 或 DASHSCOPE_API_KEY，无法调用 AI")
                return

            model = os.getenv("QWEN_MODEL", "qwen3.6-plus")
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

            title = article.get('title', '未知标题')
            source = article.get('source', '未知来源')
            url = article.get('url', '')
            summary = article.get('summary', '')
            published = article.get('published', '')
            today = datetime.now().strftime("%Y年%m月%d日")

            prompt = f"""今天是 {today}。请对以下 IT 科技新闻进行深度分析：

【标题】{title}
【来源】{source}
【发布时间】{published}
【链接】{url}
【摘要】{summary}

请提供以下维度的专业分析：
1. **新闻概述**：用 2-3 句话精炼概括新闻核心内容
2. **技术解读**：分析涉及的关键技术、产品或服务
3. **行业影响**：对相关行业/领域的影响和意义
4. **企业分析**：对涉及企业的战略影响（如适用）
5. **安全视角**：从信息安全角度分析潜在风险或启示（如适用）
6. **趋势展望**：这条新闻反映的技术或行业发展趋势
7. **关键要点**：3-5 个核心要点总结

请用中文撰写，语言专业简洁，总字数约 600-800 字。"""

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一位资深 IT 科技分析师，擅长对科技新闻进行深度解读和行业分析。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.6,
                max_tokens=2000,
            )
            analysis = response.choices[0].message.content.strip()

            # 在简报区域显示分析结果，带标题头
            header = (
                f"{'=' * 60}\n"
                f"🤖 AI 新闻深度分析\n"
                f"{'=' * 60}\n"
                f"📰 {title}\n"
                f"📡 来源: {source}  |  时间: {published}\n"
                f"🔗 {url}\n"
                f"{'─' * 60}\n\n"
            )
            full_text = header + analysis

            self.root.after(0, self._show_news_analysis, full_text, title)

        except Exception as e:
            self.root.after(0, self.log, f"AI分析新闻失败: {e}")
            self.root.after(0, messagebox.showerror, "错误", f"AI分析失败：{e}")
        finally:
            self.root.after(0, self.news_ai_analyze_btn.config,
                            {"state": tk.NORMAL, "text": "🤖 AI分析新闻"})

    def _show_news_analysis(self, analysis_text, title):
        """显示 AI 新闻分析结果到简报区域"""
        self.news_brief_area.delete(1.0, tk.END)
        self.news_brief_area.insert(tk.END, analysis_text)
        self.news_brief_text = analysis_text
        self.news_right_notebook.select(0)
        ts = datetime.now().strftime("%H:%M:%S")
        self.news_status_label.config(text=f"AI分析完成 — {ts}")
        self.news_brief_info.config(
            text=f"AI分析: {title[:30]}... | {datetime.now().strftime('%Y-%m-%d %H:%M')} | {len(analysis_text)} 字"
        )
        self.log(f"AI新闻分析完成: {title[:40]}")

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

            model = os.getenv("QWEN_MODEL", "qwen3.6-plus")
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
            self.root.after(0, self.news_podcast_btn.config, {"state": tk.NORMAL, "text": "🎙 生成播客"})

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

    # ==================== 天气功能 ====================

    def _load_weather_config(self):
        """加载天气配置（城市偏好）"""
        config_path = self.data_dir / "news_config.json"
        try:
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    self._weather_config = json.load(f)
            else:
                self._weather_config = {"city": "上海"}
        except Exception:
            self._weather_config = {"city": "上海"}

    def _save_weather_config(self):
        """保存天气配置"""
        config_path = self.data_dir / "news_config.json"
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(self._weather_config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log(f"保存天气配置失败: {e}")

    def _on_weather_city_changed(self, event=None):
        """城市选择变更回调"""
        city = self._weather_city_var.get()
        self._weather_config["city"] = city
        self._save_weather_config()
        # 清除坐标缓存，强制重新定位
        for c in self.MAJOR_CITIES:
            if c["name"] == city:
                self._weather_city_coords = (c["lat"], c["lon"], city)
                break
        self._weather_daily_cache.clear()
        self._weather_refresh()

    def _weather_autolocate(self):
        """通过 IP 自动定位当前城市"""
        self._weather_info_label.config(text="正在自动定位...")
        threading.Thread(target=self._autolocate_thread, daemon=True).start()

    def _autolocate_thread(self):
        """后台线程：IP 定位"""
        try:
            resp = urllib.request.urlopen("https://ipapi.co/json/", timeout=10)
            data = json.loads(resp.read().decode())
            city = data.get("city", "")
            lat = data.get("latitude")
            lon = data.get("longitude")
            if city and lat and lon:
                self._weather_city_coords = (float(lat), float(lon), city)
                self._weather_config["city"] = city
                self._weather_config["lat"] = float(lat)
                self._weather_config["lon"] = float(lon)

                def _update_ui():
                    # 尝试在下拉框中匹配城市
                    city_names = [c["name"] for c in self.MAJOR_CITIES]
                    if city in city_names:
                        self._weather_city_combo.set(city)
                    else:
                        # 非预置城市，添加到下拉框
                        current_values = list(self._weather_city_combo["values"])
                        if city not in current_values:
                            current_values.insert(0, city)
                            self._weather_city_combo["values"] = current_values
                        self._weather_city_combo.set(city)
                    self._save_weather_config()
                    self._weather_daily_cache.clear()
                    self._weather_refresh()

                self.root.after(0, _update_ui)
            else:
                self.root.after(0, self._weather_info_label.config, {"text": "定位失败，请手动选择城市"})
        except Exception as e:
            self.root.after(0, self._weather_info_label.config, {"text": f"定位失败: {e}"})

    def _weather_refresh(self):
        """刷新天气数据（当前选中日期或今天）"""
        target_date = datetime.now().strftime("%Y-%m-%d")
        if HAS_TKCALENDAR and self._calendar:
            try:
                sel = self._calendar.get_date()
                # tkcalendar 返回的日期格式依赖 locale，统一转换
                if isinstance(sel, str):
                    for fmt in ("%Y-%m-%d", "%m/%d/%y", "%Y/%m/%d", "%d/%m/%Y"):
                        try:
                            target_date = datetime.strptime(sel, fmt).strftime("%Y-%m-%d")
                            break
                        except ValueError:
                            continue
                elif isinstance(sel, (date_type, datetime)):
                    target_date = sel.strftime("%Y-%m-%d")
            except Exception:
                pass

        self._weather_info_label.config(text="正在获取天气...")
        threading.Thread(target=self._fetch_weather_thread, args=(target_date,), daemon=True).start()

    def _get_city_coords(self):
        """获取当前城市经纬度"""
        # 优先使用缓存
        if self._weather_city_coords:
            return self._weather_city_coords

        city = self._weather_city_var.get() if hasattr(self, '_weather_city_var') else self._weather_config.get("city", "上海")

        # 从预置列表查找
        for c in self.MAJOR_CITIES:
            if c["name"] == city:
                self._weather_city_coords = (c["lat"], c["lon"], city)
                return self._weather_city_coords

        # 从配置中读取自定义坐标
        if "lat" in self._weather_config and "lon" in self._weather_config:
            self._weather_city_coords = (
                self._weather_config["lat"],
                self._weather_config["lon"],
                city,
            )
            return self._weather_city_coords

        # 调用 Open-Meteo 地理编码
        try:
            geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={urllib.parse.quote(city)}&count=1&language=zh&format=json"
            resp = urllib.request.urlopen(geo_url, timeout=10)
            geo_data = json.loads(resp.read().decode())
            if geo_data.get("results"):
                loc = geo_data["results"][0]
                self._weather_city_coords = (loc["latitude"], loc["longitude"], loc.get("name", city))
                return self._weather_city_coords
        except Exception:
            pass

        # 默认上海
        self._weather_city_coords = (31.2304, 121.4737, "上海")
        return self._weather_city_coords

    def _fetch_weather_thread(self, target_date: str):
        """后台线程：获取天气数据（支持多日预报 + 历史）"""
        try:
            coords = self._get_city_coords()
            lat, lon, city_name = coords

            today = datetime.now().date()
            target = datetime.strptime(target_date, "%Y-%m-%d").date()
            diff = (target - today).days

            # Open-Meteo 支持 past_days≤92, forecast_days≤16
            if -92 <= diff <= 16:
                if diff <= 0:
                    past_days = min(abs(diff) + 1, 92)
                    forecast_days = 1
                else:
                    past_days = 1
                    forecast_days = min(diff + 1, 16)

                url = (
                    f"https://api.open-meteo.com/v1/forecast?"
                    f"latitude={lat}&longitude={lon}"
                    f"&daily=temperature_2m_max,temperature_2m_min,weather_code,precipitation_sum"
                    f"&current=temperature_2m,weather_code,relative_humidity_2m,wind_speed_10m"
                    f"&past_days={past_days}&forecast_days={forecast_days}"
                    f"&timezone=auto"
                )

                # 重试机制：最多3次，应对502等临时服务端错误
                data = None
                last_error = None
                for attempt in range(3):
                    try:
                        resp = urllib.request.urlopen(url, timeout=15)
                        data = json.loads(resp.read().decode())
                        break
                    except urllib.error.HTTPError as e:
                        last_error = e
                        if e.code in (502, 503, 504) and attempt < 2:
                            import time
                            time.sleep(2 * (attempt + 1))
                            continue
                        raise
                    except (urllib.error.URLError, OSError) as e:
                        last_error = e
                        if attempt < 2:
                            import time
                            time.sleep(2 * (attempt + 1))
                            continue
                        raise

                if data is None:
                    raise last_error or Exception("天气API请求失败")

                # 缓存每日数据
                daily = data.get("daily", {})
                dates = daily.get("time", [])
                t_max = daily.get("temperature_2m_max", [])
                t_min = daily.get("temperature_2m_min", [])
                w_codes = daily.get("weather_code", [])
                precip = daily.get("precipitation_sum", [])

                for i, d in enumerate(dates):
                    self._weather_daily_cache[d] = {
                        "temp_max": t_max[i] if i < len(t_max) else None,
                        "temp_min": t_min[i] if i < len(t_min) else None,
                        "weather_code": w_codes[i] if i < len(w_codes) else None,
                        "precipitation": precip[i] if i < len(precip) else None,
                    }

                # 构建显示文本
                if target_date in self._weather_daily_cache:
                    wd = self._weather_daily_cache[target_date]
                    wc = wd["weather_code"]
                    icon = self.WEATHER_CODE_ICON.get(wc, '🌈')
                    desc = self.WEATHER_CODE_DESC.get(wc, '未知')
                    tmax = wd["temp_max"]
                    tmin = wd["temp_min"]
                    avg_temp = round((tmax + tmin) / 2) if tmax is not None and tmin is not None else None
                    outfit = self._get_outfit_suggestion(avg_temp, desc) if avg_temp is not None else ""

                    # 如果是今天，使用实时数据
                    if diff == 0 and "current" in data:
                        cur = data["current"]
                        cur_temp = round(cur.get("temperature_2m", avg_temp or 0))
                        cur_wc = cur.get("weather_code", wc)
                        cur_hum = cur.get("relative_humidity_2m", "")
                        cur_wind = round(cur.get("wind_speed_10m", 0), 1)
                        icon = self.WEATHER_CODE_ICON.get(cur_wc, icon)
                        desc = self.WEATHER_CODE_DESC.get(cur_wc, desc)
                        outfit = self._get_outfit_suggestion(cur_temp, desc)
                        info_text = (
                            f"{icon} {city_name} · {cur_temp}°C · {desc} · "
                            f"湿度{cur_hum}% · 风速{cur_wind}km/h   |   "
                            f"穿搭建议：{outfit}"
                        )
                    else:
                        date_label = target_date
                        info_text = (
                            f"{icon} {city_name}（{date_label}）· {tmin}~{tmax}°C · {desc}   |   "
                            f"穿搭建议：{outfit}"
                        )
                    self.root.after(0, self._weather_info_label.config, {"text": info_text})
                else:
                    self.root.after(0, self._weather_info_label.config, {"text": f"暂无 {target_date} 天气数据"})
            else:
                self.root.after(0, self._weather_info_label.config, {"text": f"暂无 {target_date} 天气数据（超出预报范围）"})
        except Exception as e:
            # Open-Meteo 失败，尝试 wttr.in 备用源（仅支持当天实时天气）
            try:
                self._fetch_weather_fallback(city_name, target_date)
            except Exception:
                self.root.after(0, self._weather_info_label.config, {"text": f"获取天气失败: {e}"})

    def _fetch_weather_fallback(self, city_name: str, target_date: str):
        """备用天气源：wttr.in（当 Open-Meteo 不可用时）"""
        import time as _time

        # wttr.in 天气描述映射
        wttr_desc_map = {
            "Sunny": "晴", "Clear": "晴", "Partly cloudy": "多云",
            "Cloudy": "阴", "Overcast": "阴", "Mist": "薄雾",
            "Fog": "雾", "Light rain": "小雨", "Moderate rain": "中雨",
            "Heavy rain": "大雨", "Light snow": "小雪", "Moderate snow": "中雪",
            "Heavy snow": "大雪", "Thunderstorm": "雷暴", "Patchy rain possible": "可能有雨",
            "Light drizzle": "毛毛雨", "Patchy light rain": "零星小雨",
        }
        wttr_icon_map = {
            "晴": "☀️", "多云": "⛅", "阴": "☁️", "薄雾": "🌫️", "雾": "🌫️",
            "小雨": "🌦️", "中雨": "🌧️", "大雨": "🌧️", "小雪": "🌨️",
            "中雪": "🌨️", "大雪": "❄️", "雷暴": "⛈️",
        }

        last_error = None
        for attempt in range(2):
            try:
                wttr_url = f"https://wttr.in/{urllib.parse.quote(city_name)}?format=j1"
                req = urllib.request.Request(wttr_url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=15)
                wdata = json.loads(resp.read().decode())

                cur = wdata.get("current_condition", [{}])[0]
                temp = cur.get("temp_C", "?")
                humidity = cur.get("humidity", "?")
                wind = cur.get("windspeedKmph", "?")
                weather_en = cur.get("weatherDesc", [{}])[0].get("value", "")
                desc = wttr_desc_map.get(weather_en, weather_en)
                icon = wttr_icon_map.get(desc, "🌈")

                try:
                    avg_temp = int(temp)
                except (ValueError, TypeError):
                    avg_temp = None
                outfit = self._get_outfit_suggestion(avg_temp, desc) if avg_temp is not None else ""

                today_str = datetime.now().strftime("%Y-%m-%d")
                if target_date == today_str:
                    info_text = (
                        f"{icon} {city_name} · {temp}°C · {desc} · "
                        f"湿度{humidity}% · 风速{wind}km/h   |   "
                        f"穿搭建议：{outfit}"
                    )
                else:
                    info_text = (
                        f"{icon} {city_name}（仅实时）· {temp}°C · {desc}   |   "
                        f"穿搭建议：{outfit}"
                    )
                self.root.after(0, self._weather_info_label.config, {"text": info_text})
                return
            except Exception as e:
                last_error = e
                if attempt < 1:
                    _time.sleep(2)
                    continue

        raise last_error or Exception("备用天气API也失败")

    def _get_outfit_suggestion(self, temp, description):
        """根据温度和天气描述生成简短穿搭建议"""
        if temp is None:
            return ""
        if temp <= 0:
            base = "羽绒服、保暖内衣、围巾、手套、防滑靴"
        elif temp <= 10:
            base = "厚外套、毛衣、长裤、保暖鞋"
        elif temp <= 20:
            base = "风衣/夹克、长袖衬衫、薄毛衣"
        elif temp <= 28:
            base = "T恤、薄长裤/裙子、透气鞋"
        else:
            base = "短袖、短裤/连衣裙、防晒帽、太阳镜"
        # 天气附加建议
        extra = ""
        if '雨' in description:
            extra = " + 雨伞、防水鞋"
        elif '雪' in description:
            extra = " + 防滑靴、保暖外套"
        elif '晴' in description and temp > 25:
            extra = " + 防晒霜、遮阳帽"
        elif '风' in description:
            extra = " + 防风外套"
        return base + extra

    # ==================== 日历功能 ====================

    def _on_calendar_date_selected(self, event=None):
        """日历日期选中回调：更新天气 + 显示历史资讯"""
        if not HAS_TKCALENDAR or not self._calendar:
            return
        sel = self._calendar.get_date()
        if isinstance(sel, str):
            for fmt in ("%Y-%m-%d", "%m/%d/%y", "%Y/%m/%d", "%d/%m/%Y"):
                try:
                    selected_date = datetime.strptime(sel, fmt).strftime("%Y-%m-%d")
                    break
                except ValueError:
                    continue
            else:
                selected_date = sel
        elif isinstance(sel, (date_type, datetime)):
            selected_date = sel.strftime("%Y-%m-%d")
        else:
            selected_date = str(sel)

        # 更新天气
        self._weather_info_label.config(text=f"正在获取 {selected_date} 天气...")
        threading.Thread(target=self._fetch_weather_thread, args=(selected_date,), daemon=True).start()

        # 加载历史资讯
        self._load_history_for_date(selected_date)

    def _on_calendar_month_changed(self, event=None):
        """日历月份切换回调：刷新高亮"""
        self.root.after(100, self._refresh_calendar_tags)

    def _refresh_calendar_tags(self):
        """刷新日历中有数据日期的高亮标记"""
        if not HAS_TKCALENDAR or not self._calendar:
            return
        try:
            # 清除旧标记
            self._calendar.calevent_remove('all')

            # 查询所有有数据的日期
            with self.db_lock:
                cursor = self.conn.cursor()
                brief_dates = set()
                script_dates = set()
                cursor.execute("SELECT DISTINCT brief_date FROM news_briefs")
                for row in cursor.fetchall():
                    brief_dates.add(row[0])
                cursor.execute("SELECT DISTINCT script_date FROM podcast_scripts")
                for row in cursor.fetchall():
                    script_dates.add(row[0])

            all_dates = brief_dates | script_dates

            # 添加标记事件
            for d_str in all_dates:
                try:
                    d = datetime.strptime(d_str, "%Y-%m-%d").date()
                    if d_str in brief_dates and d_str in script_dates:
                        tag = "both"
                    elif d_str in brief_dates:
                        tag = "brief"
                    else:
                        tag = "script"
                    self._calendar.calevent_create(d, "有数据", tag)
                except ValueError:
                    continue

            # 设置标记样式
            self._calendar.tag_config("brief", background="#27ae60", foreground="white")
            self._calendar.tag_config("script", background="#f39c12", foreground="white")
            self._calendar.tag_config("both", background="#8e44ad", foreground="white")

            count = len(all_dates)
            self._cal_info_label.config(text=f"共 {count} 天有存档" if count else "")

        except Exception as e:
            self.log(f"刷新日历标记失败: {e}")

    def _load_history_for_date(self, date_str):
        """加载指定日期的历史资讯（简报+脚本），显示在历史标签页"""
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "SELECT content, articles_json, created_at FROM news_briefs WHERE brief_date = ? ORDER BY created_at DESC",
                    (date_str,),
                )
                briefs = cursor.fetchall()
                cursor.execute(
                    "SELECT content, created_at FROM podcast_scripts WHERE script_date = ? ORDER BY created_at DESC",
                    (date_str,),
                )
                scripts = cursor.fetchall()

            # 构建显示内容
            lines = []
            if briefs:
                for i, (content, articles_json, created_at) in enumerate(briefs, 1):
                    lines.append(f"{'='*50}")
                    lines.append(f"📰 简报 #{i}（保存于 {created_at}）")
                    lines.append(f"{'='*50}\n")
                    lines.append(content)
                    if articles_json:
                        try:
                            arts = json.loads(articles_json)
                            if arts:
                                lines.append(f"\n{'─'*40}")
                                lines.append("【原始文章来源】")
                                for j, a in enumerate(arts, 1):
                                    lines.append(f"  {j}. [{a.get('source','')}] {a.get('title','')}")
                                    if a.get('url'):
                                        lines.append(f"     {a['url']}")
                        except json.JSONDecodeError:
                            pass
                    lines.append("")
            if scripts:
                for i, (content, created_at) in enumerate(scripts, 1):
                    lines.append(f"{'='*50}")
                    lines.append(f"🎙️ 播客脚本 #{i}（保存于 {created_at}）")
                    lines.append(f"{'='*50}\n")
                    lines.append(content)
                    lines.append("")

            if not briefs and not scripts:
                lines.append(f"📅 {date_str} 暂无保存的资讯数据")
                lines.append("")
                lines.append("提示：生成简报或播客脚本后，点击「保存简报」或「保存脚本」即可存档。")

            self._history_area.delete(1.0, tk.END)
            self._history_area.insert(tk.END, "\n".join(lines))
            self._history_date_label.config(text=f"📅 {date_str} 的历史资讯")
            # 切换到历史标签页
            self.news_right_notebook.select(2)

        except Exception as e:
            self._history_area.delete(1.0, tk.END)
            self._history_area.insert(tk.END, f"加载历史数据失败: {e}")

    # ==================== 保存播客脚本 ====================

    def _save_podcast_script(self):
        """保存播客脚本到数据库"""
        script = self.news_podcast_area.get(1.0, tk.END).strip()
        if not script:
            messagebox.showwarning("提示", "播客脚本为空，请先生成播客脚本")
            return
        today = datetime.now().strftime("%Y-%m-%d")
        try:
            with self.db_lock:
                self.conn.execute(
                    "INSERT INTO podcast_scripts (script_date, content) VALUES (?, ?)",
                    (today, script),
                )
                self.conn.commit()
            self.log(f"播客脚本已保存到数据库（{today}）")
            self._refresh_calendar_tags()
            messagebox.showinfo("保存成功", "播客脚本已保存至数据库")
        except Exception as e:
            messagebox.showerror("保存失败", f"保存播客脚本失败: {e}")

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

        # AI解决方案按钮
        nvd_ai_btn = tk.Button(
            left_control,
            text="🤖 AI解决方案",
            command=self.nvd_ai_solution_click,
            bg="#9b59b6",
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        nvd_ai_btn.pack(side=tk.LEFT, padx=5)

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

        self.nvd_tree.column("CVE ID", width=150, minwidth=100, anchor="center")
        self.nvd_tree.column("严重等级", width=100, minwidth=80, anchor="center")
        self.nvd_tree.column("CVSS评分", width=100, minwidth=80, anchor="center")
        self.nvd_tree.column("发布日期", width=150, minwidth=100, anchor="center")
        self.nvd_tree.column("描述", width=500, minwidth=300, anchor="w")
        self.nvd_tree.column("来源", width=100, minwidth=80, anchor="center")

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

        # 历史 DSA 缝隙补全按钮
        self.dell_backfill_btn = tk.Button(
            left_control,
            text="🔧 历史缝隙补全",
            command=self.start_dell_backfill,
            bg=self.warning_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.dell_backfill_btn.pack(side=tk.LEFT, padx=5)

        # 修复发布日期按钮
        self.dell_fix_dates_btn = tk.Button(
            left_control,
            text="📅 修复发布日期",
            command=self.start_dell_fix_dates,
            bg="#6c757d",
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.dell_fix_dates_btn.pack(side=tk.LEFT, padx=5)

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
        columns = ("公告ID", "受影响产品", "公告影响等级", "标题", "CVE IDs", "发布日期")

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
        self.dell_tree.heading("受影响产品", text="受影响产品")
        self.dell_tree.heading("公告影响等级", text="影响等级")
        self.dell_tree.heading("标题", text="标题")
        self.dell_tree.heading("CVE IDs", text="相关 CVE")
        self.dell_tree.heading("发布日期", text="发布日期")

        self.dell_tree.column("公告ID", width=140, minwidth=100, anchor="center")
        self.dell_tree.column("受影响产品", width=280, minwidth=150, anchor="w")
        self.dell_tree.column("公告影响等级", width=90, minwidth=70, anchor="center")
        self.dell_tree.column("标题", width=500, minwidth=300, anchor="w")
        self.dell_tree.column("CVE IDs", width=300, minwidth=200, anchor="w")
        self.dell_tree.column("发布日期", width=150, minwidth=100, anchor="center")

        # 布局
        self.dell_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 0))
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # 按影响等级配色（与 NVD CVE 标签页一致）
        self.dell_tree.tag_configure("Critical", background="#ffebee", foreground="#b71c1c")
        self.dell_tree.tag_configure("High", background="#fff3e0", foreground="#e65100")
        self.dell_tree.tag_configure("Medium", background="#fff9c4", foreground="#f57f17")
        self.dell_tree.tag_configure("Low", background="#f1f8e9", foreground="#33691e")

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
            command=self.matched_ai_solution_click,
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

        # 搜索框
        search_frame = tk.Frame(data_container, bg="white")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="搜索：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.matched_search_var = tk.StringVar()
        matched_search_entry = tk.Entry(search_frame, textvariable=self.matched_search_var, width=35, font=("Microsoft YaHei", 10))
        matched_search_entry.pack(side=tk.LEFT, padx=(0, 5))

        search_btn = tk.Button(
            search_frame,
            text="🔍 搜索",
            command=self.filter_matched_data,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        search_btn.pack(side=tk.LEFT, padx=(0, 10))

        matched_delete_btn = tk.Button(
            search_frame,
            text="🗑 删除选中",
            command=self.delete_matched_selected,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        matched_delete_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(search_frame, text="(支持 CVE编号、Dell公告ID、受影响产品 搜索；Ctrl/Shift 多选后可删除)", bg="white", font=("Microsoft YaHei", 9), fg="gray").pack(side=tk.LEFT)

        # 创建 Treeview 来展示关联数据
        columns = ("CVE ID", "严重等级", "CVSS评分", "Dell公告", "影响等级", "受影响产品", "公告内容")

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
        self.matched_tree.heading("影响等级", text="影响等级")
        self.matched_tree.heading("受影响产品", text="受影响产品")
        self.matched_tree.heading("公告内容", text="公告内容")

        self.matched_tree.column("CVE ID", width=150, minwidth=100, anchor="center")
        self.matched_tree.column("严重等级", width=100, minwidth=80, anchor="center")
        self.matched_tree.column("CVSS评分", width=100, minwidth=80, anchor="center")
        self.matched_tree.column("Dell公告", width=150, minwidth=100, anchor="center")
        self.matched_tree.column("影响等级", width=100, minwidth=80, anchor="center")
        self.matched_tree.column("受影响产品", width=350, minwidth=200, anchor="w")
        self.matched_tree.column("公告内容", width=400, minwidth=250, anchor="w")

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
            text="🗑 清空历史记录",
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

        delete_selected_btn = tk.Button(
            info_frame,
            text="🗑 删除选中",
            command=self.delete_solution_selected,
            bg="#e67e22",
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        delete_selected_btn.pack(side=tk.RIGHT, padx=5)

        # 使用 PanedWindow 分割上下区域，用户可拖动调整大小
        paned = tk.PanedWindow(
            self.solution_frame, orient=tk.VERTICAL,
            bg="#cccccc", sashwidth=6, sashrelief=tk.RAISED
        )
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # --- 上方：历史记录列表 ---
        tree_wrapper = tk.Frame(paned, bg="white")

        columns = ("时间戳", "CVE ID", "Dell公告", "分析状态", "结果预览")

        tree_scroll_y = tk.Scrollbar(tree_wrapper, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(tree_wrapper, orient=tk.HORIZONTAL)

        self.solution_tree = ttk.Treeview(
            tree_wrapper,
            columns=columns,
            show="headings",
            selectmode="extended",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=6
        )

        tree_scroll_y.config(command=self.solution_tree.yview)
        tree_scroll_x.config(command=self.solution_tree.xview)

        self.solution_tree.heading("时间戳", text="分析时间")
        self.solution_tree.heading("CVE ID", text="方案编号")
        self.solution_tree.heading("Dell公告", text="Dell 公告 ID")
        self.solution_tree.heading("分析状态", text="分析状态")
        self.solution_tree.heading("结果预览", text="结果预览")

        self.solution_tree.column("时间戳", width=180, minwidth=150, anchor="center")
        self.solution_tree.column("CVE ID", width=150, minwidth=100, anchor="center")
        self.solution_tree.column("Dell公告", width=150, minwidth=100, anchor="center")
        self.solution_tree.column("分析状态", width=100, minwidth=80, anchor="center")
        self.solution_tree.column("结果预览", width=400, minwidth=300, anchor="w")

        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.solution_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 单击即可查看详情，双击也保留
        self.solution_tree.bind("<<TreeviewSelect>>", self.on_solution_item_double_click)
        self.solution_tree.bind("<Double-1>", self.on_solution_item_double_click)

        paned.add(tree_wrapper, minsize=120)

        # --- 下方：详细分析结果 ---
        detail_frame = tk.Frame(paned, bg="white")

        tk.Label(
            detail_frame,
            text="详细分析结果（选中上方记录自动显示）",
            bg="white",
            font=("Microsoft YaHei", 12, "bold")
        ).pack(anchor="w", pady=(8, 4))

        self.solution_detail_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            font=("Consolas", 13),
            bg="#f8f9fa",
            relief=tk.GROOVE,
            bd=2
        )
        self.solution_detail_text.pack(fill=tk.BOTH, expand=True)

        paned.add(detail_frame, minsize=200)

        # 默认分割比例：列表占 30%，详情占 70%
        self.solution_frame.update_idletasks()
        try:
            paned.sash_place(0, 0, 200)
        except Exception:
            pass

        # 初始化数据
        self.solution_history = []
        self.load_ai_solution_history()

    # ==================== Dell技术库标签页 ====================

    def create_dell_kb_view(self):
        """创建Dell技术库视图"""
        # 内存缓存
        self.dell_kb_data = []

        # 控制面板
        control_frame = tk.Frame(self.dell_kb_frame, bg="white", pady=10)
        control_frame.pack(fill=tk.X, padx=10)

        # 第一行：URL 输入 + 抓取
        url_row = tk.Frame(control_frame, bg="white")
        url_row.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            url_row, text="文章 URL:", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.kb_url_entry = tk.Entry(
            url_row, font=("Microsoft YaHei", 10),
            relief=tk.SOLID, bd=1
        )
        self.kb_url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.kb_url_entry.insert(0, "https://www.dell.com/support/kbdoc/zh-cn/...")
        self.kb_url_entry.bind("<FocusIn>", lambda e: self._kb_url_focus_in())
        self.kb_url_entry.config(fg="gray")

        self.kb_fetch_btn = tk.Button(
            url_row, text="📥 抓取文章", command=self.fetch_dell_kb_from_url,
            bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=15, pady=3, relief=tk.FLAT, cursor="hand2"
        )
        self.kb_fetch_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.kb_fetch_status = tk.Label(
            url_row, text="", bg="white",
            font=("Microsoft YaHei", 9), fg=self.info_color
        )
        self.kb_fetch_status.pack(side=tk.LEFT)

        # 第二行：搜索 + 操作按钮
        action_row = tk.Frame(control_frame, bg="white")
        action_row.pack(fill=tk.X)

        # 搜索
        tk.Label(
            action_row, text="搜索:", bg="white",
            font=("Microsoft YaHei", 10)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.kb_search_entry = tk.Entry(
            action_row, font=("Microsoft YaHei", 10),
            relief=tk.SOLID, bd=1, width=25
        )
        self.kb_search_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.kb_search_entry.bind("<Return>", lambda e: self.filter_dell_kb_data())

        tk.Button(
            action_row, text="🔍 搜索", command=self.filter_dell_kb_data,
            bg=self.info_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=10, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 10))

        # 从数据库加载
        tk.Button(
            action_row, text="📂 从数据库加载", command=self.load_dell_kb_from_database,
            bg=self.success_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=10, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 10))

        # AI解决方案
        tk.Button(
            action_row, text="🤖 AI解决方案", command=self.dell_kb_ai_solution_click,
            bg="#9b59b6", fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=10, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.RIGHT, padx=(10, 0))

        # 删除选中
        tk.Button(
            action_row, text="🗑 删除选中", command=self.delete_dell_kb_selected,
            bg=self.danger_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=10, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.RIGHT, padx=(10, 0))

        # 使用 PanedWindow 分割上下区域
        paned = tk.PanedWindow(self.dell_kb_frame, orient=tk.VERTICAL, bg="#dcdcdc", sashwidth=5)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # ── 上半部分：数据展示区 ──
        data_container = tk.Frame(paned, bg="white")

        columns = ("文章编号", "标题", "受影响产品", "解决方案", "采集时间")

        tree_scroll_y = tk.Scrollbar(data_container, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(data_container, orient=tk.HORIZONTAL)

        self.kb_tree = ttk.Treeview(
            data_container,
            columns=columns,
            show="headings",
            selectmode="extended",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=12
        )

        tree_scroll_y.config(command=self.kb_tree.yview)
        tree_scroll_x.config(command=self.kb_tree.xview)

        self.kb_tree.heading("文章编号", text="文章编号")
        self.kb_tree.heading("标题", text="标题")
        self.kb_tree.heading("受影响产品", text="受影响产品")
        self.kb_tree.heading("解决方案", text="解决方案")
        self.kb_tree.heading("采集时间", text="采集时间")

        self.kb_tree.column("文章编号", width=130, minwidth=100, anchor="center")
        self.kb_tree.column("标题", width=350, minwidth=200, anchor="w")
        self.kb_tree.column("受影响产品", width=280, minwidth=150, anchor="w")
        self.kb_tree.column("解决方案", width=280, minwidth=150, anchor="w")
        self.kb_tree.column("采集时间", width=140, minwidth=100, anchor="center")

        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.kb_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.kb_tree.bind("<Double-1>", self.on_dell_kb_item_double_click)

        paned.add(data_container, stretch="always")

        # ── 下半部分：数据导入导出面板 ──
        export_panel = tk.Frame(paned, bg="white", bd=1, relief=tk.GROOVE)

        # 标题栏
        title_bar = tk.Frame(export_panel, bg=self.primary_color, pady=6)
        title_bar.pack(fill=tk.X)
        tk.Label(
            title_bar, text="📦 数据导入 / 导出", bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 11, "bold")
        ).pack(side=tk.LEFT, padx=12)

        # 内容区
        body = tk.Frame(export_panel, bg="white", padx=15, pady=10)
        body.pack(fill=tk.BOTH, expand=True)

        # 第一行：数据源 + 导出格式
        row1 = tk.Frame(body, bg="white")
        row1.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            row1, text="数据源:", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.export_source_var = tk.StringVar(value="Dell技术库")
        source_options = [
            "IT新闻简报", "NVD CVE 数据", "Dell 安全公告",
            "CVE-Dell 关联", "AI解决方案", "Dell技术库",
            "学习对话记录", "学习产物", "闪卡知识库"
        ]
        self.export_source_combo = ttk.Combobox(
            row1, textvariable=self.export_source_var,
            values=source_options, state="readonly",
            font=("Microsoft YaHei", 10), width=18
        )
        self.export_source_combo.pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(
            row1, text="导出格式:", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.export_format_var = tk.StringVar(value="Markdown")
        for fmt in ("Markdown", "TXT", "HTML"):
            tk.Radiobutton(
                row1, text=fmt, variable=self.export_format_var, value=fmt,
                bg="white", font=("Microsoft YaHei", 10),
                activebackground="white"
            ).pack(side=tk.LEFT, padx=(0, 8))

        # 第二行：指定编号 + 数量
        row2 = tk.Frame(body, bg="white")
        row2.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            row2, text="指定编号:", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.export_id_entry = tk.Entry(
            row2, font=("Microsoft YaHei", 10),
            relief=tk.SOLID, bd=1, width=22
        )
        self.export_id_entry.pack(side=tk.LEFT, padx=(0, 6))
        self.export_id_entry.insert(0, "留空则按数量导出")
        self.export_id_entry.config(fg="gray")
        self.export_id_entry.bind("<FocusIn>", lambda e: self._export_id_focus_in())

        tk.Label(
            row2, text="导出数量:", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        ).pack(side=tk.LEFT, padx=(10, 6))

        self.export_limit_var = tk.StringVar(value="全部")
        ttk.Combobox(
            row2, textvariable=self.export_limit_var,
            values=["全部", "最近50条", "最近100条", "最近200条", "最近500条"],
            state="readonly", font=("Microsoft YaHei", 10), width=12
        ).pack(side=tk.LEFT, padx=(0, 6))

        # 第三行：操作按钮
        row3 = tk.Frame(body, bg="white")
        row3.pack(fill=tk.X, pady=(0, 8))

        tk.Button(
            row3, text="👁 预览", command=self._preview_export_data,
            bg="#8e44ad", fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=14, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            row3, text="📤 导出数据", command=self._do_export_data,
            bg=self.info_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=14, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            row3, text="📤 导出选中项", command=self._do_export_selected,
            bg="#e67e22", fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=14, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            row3, text="📥 导入数据", command=self._do_import_data,
            bg=self.success_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=14, pady=3, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.export_status_label = tk.Label(
            row3, text="", bg="white",
            font=("Microsoft YaHei", 9), fg=self.info_color
        )
        self.export_status_label.pack(side=tk.LEFT, padx=(10, 0))

        # 预览区
        preview_frame = tk.LabelFrame(
            body, text="导出预览", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color,
            padx=8, pady=5
        )
        preview_frame.pack(fill=tk.BOTH, expand=True)

        self.export_preview_text = scrolledtext.ScrolledText(
            preview_frame, font=("Consolas", 9), wrap=tk.WORD,
            height=5, state=tk.DISABLED, bg="#fafafa", relief=tk.FLAT
        )
        self.export_preview_text.pack(fill=tk.BOTH, expand=True)

        paned.add(export_panel, stretch="always")

        # 延迟加载，避免 log_text 尚未创建
        self.dell_kb_frame.after(500, self.load_dell_kb_from_database)

    def _kb_url_focus_in(self):
        """URL输入框获取焦点时清除占位符"""
        placeholder = "https://www.dell.com/support/kbdoc/zh-cn/..."
        if self.kb_url_entry.get() == placeholder:
            self.kb_url_entry.delete(0, tk.END)
            self.kb_url_entry.config(fg="black")

    # ==================== 数据导入导出功能 ====================

    def _export_id_focus_in(self):
        """指定编号输入框获取焦点时清除占位符"""
        placeholder = "留空则按数量导出"
        if self.export_id_entry.get() == placeholder:
            self.export_id_entry.delete(0, tk.END)
            self.export_id_entry.config(fg="black")

    def _get_export_limit(self):
        """解析导出数量限制"""
        val = self.export_limit_var.get()
        if val == "全部":
            return None
        import re as _re
        m = _re.search(r'\d+', val)
        return int(m.group()) if m else None

    def _get_export_id(self):
        """获取用户输入的指定编号，返回 None 或字符串"""
        val = self.export_id_entry.get().strip()
        if not val or val == "留空则按数量导出":
            return None
        return val

    def _fetch_export_rows(self, single_id=None):
        """根据选择的数据源从数据库查询完整数据，返回 (headers, rows)
        single_id: 可选，指定单条编号/ID 查询
        """
        source = self.export_source_var.get()
        if single_id is None:
            single_id = self._get_export_id()
        limit = self._get_export_limit()
        limit_sql = f" LIMIT {limit}" if (limit and not single_id) else ""

        try:
            with self.db_lock:
                cursor = self.conn.cursor()

                if source == "IT新闻简报":
                    if single_id:
                        cursor.execute("SELECT id, brief_date, content, articles_json, created_at FROM news_briefs WHERE id = ? OR brief_date LIKE ?", (single_id, f"%{single_id}%"))
                    else:
                        cursor.execute(f"SELECT id, brief_date, content, articles_json, created_at FROM news_briefs ORDER BY brief_date DESC{limit_sql}")
                    return ["ID", "日期", "简报内容", "文章数据(JSON)", "创建时间"], cursor.fetchall()

                elif source == "NVD CVE 数据":
                    if single_id:
                        cursor.execute("SELECT cve_id, published_date, last_modified, data FROM cves WHERE cve_id LIKE ?", (f"%{single_id}%",))
                    else:
                        cursor.execute(f"SELECT cve_id, published_date, last_modified, data FROM cves ORDER BY published_date DESC{limit_sql}")
                    raw_rows = cursor.fetchall()
                    rows = []
                    for r in raw_rows:
                        try:
                            d = json.loads(r[3]) if r[3] else {}
                            # 提取所有描述
                            descs = []
                            for dd in d.get("descriptions", []):
                                descs.append(f"[{dd.get('lang', '?')}] {dd.get('value', '')}")
                            desc_full = "\n".join(descs) if descs else ""
                            # 严重等级 + 评分
                            severity_parts = []
                            for m in d.get("metrics", {}).get("cvssMetricV40", []):
                                cd = m.get("cvssData", {})
                                severity_parts.append(f"V4.0 {cd.get('baseSeverity', '')} (评分: {cd.get('baseScore', '')})")
                            for m in d.get("metrics", {}).get("cvssMetricV31", []):
                                cd = m.get("cvssData", {})
                                severity_parts.append(f"V3.1 {cd.get('baseSeverity', '')} (评分: {cd.get('baseScore', '')})")
                            for m in d.get("metrics", {}).get("cvssMetricV2", []):
                                cd = m.get("cvssData", {})
                                severity_parts.append(f"V2评分: {cd.get('baseScore', '')}")
                            severity = "; ".join(severity_parts)
                            # 参考链接
                            refs = []
                            for ref in d.get("references", []):
                                refs.append(ref.get("url", ""))
                            refs_full = "\n".join(refs) if refs else ""
                            # 受影响配置
                            configs = json.dumps(d.get("configurations", []), ensure_ascii=False) if d.get("configurations") else ""
                        except Exception:
                            desc_full, severity, refs_full, configs = "", "", "", ""
                        rows.append((r[0], r[1], r[2], severity, desc_full, refs_full, configs))
                    return ["CVE ID", "发布日期", "最后修改", "严重等级", "完整描述", "参考链接", "受影响配置"], rows

                elif source == "Dell 安全公告":
                    if single_id:
                        cursor.execute("SELECT dsa_id, title, cve_ids, data, published_date, collected_date, link FROM dell_advisories WHERE dsa_id LIKE ?", (f"%{single_id}%",))
                    else:
                        cursor.execute(f"SELECT dsa_id, title, cve_ids, data, published_date, collected_date, link FROM dell_advisories ORDER BY published_date DESC{limit_sql}")
                    raw_rows = cursor.fetchall()
                    rows = []
                    for r in raw_rows:
                        # 解析 data JSON 提取完整内容
                        full_content = ""
                        try:
                            d = json.loads(r[3]) if r[3] else {}
                            parts = []
                            for key in ["description", "impact", "details", "remediation", "severity", "affected_products"]:
                                if d.get(key):
                                    parts.append(f"【{key}】\n{d[key]}")
                            full_content = "\n\n".join(parts) if parts else str(d)
                        except Exception:
                            full_content = str(r[3]) if r[3] else ""
                        rows.append((r[0], r[1], r[2], full_content, r[4], r[5], r[6]))
                    return ["DSA ID", "标题", "关联CVE", "详细内容", "发布日期", "采集日期", "链接"], rows

                elif source == "CVE-Dell 关联":
                    if single_id:
                        cursor.execute(f"""
                            SELECT c.cve_id, d.dsa_id, d.title, d.cve_ids, d.published_date, d.link
                            FROM cves c
                            JOIN dell_advisories d ON d.cve_ids LIKE '%' || c.cve_id || '%'
                            WHERE c.cve_id LIKE ? OR d.dsa_id LIKE ?
                            ORDER BY d.published_date DESC
                        """, (f"%{single_id}%", f"%{single_id}%"))
                    else:
                        cursor.execute(f"""
                            SELECT c.cve_id, d.dsa_id, d.title, d.cve_ids, d.published_date, d.link
                            FROM cves c
                            JOIN dell_advisories d ON d.cve_ids LIKE '%' || c.cve_id || '%'
                            ORDER BY d.published_date DESC{limit_sql}
                        """)
                    return ["CVE ID", "DSA ID", "Dell公告标题", "所有关联CVE", "发布日期", "链接"], cursor.fetchall()

                elif source == "AI解决方案":
                    if single_id:
                        cursor.execute("SELECT id, cve_id, dell_advisory_id, model_name, prompt, result, analysis_time, status FROM ai_solutions WHERE cve_id LIKE ? OR dell_advisory_id LIKE ? OR id = ?",
                                       (f"%{single_id}%", f"%{single_id}%", single_id))
                    else:
                        cursor.execute(f"SELECT id, cve_id, dell_advisory_id, model_name, prompt, result, analysis_time, status FROM ai_solutions ORDER BY analysis_time DESC{limit_sql}")
                    return ["ID", "CVE ID", "Dell公告ID", "模型", "提示词", "分析结果", "分析时间", "状态"], cursor.fetchall()

                elif source == "Dell技术库":
                    if single_id:
                        cursor.execute("SELECT article_id, title, content, solution, url, collected_date FROM dell_kb_articles WHERE article_id LIKE ? OR title LIKE ?",
                                       (f"%{single_id}%", f"%{single_id}%"))
                    else:
                        cursor.execute(f"SELECT article_id, title, content, solution, url, collected_date FROM dell_kb_articles ORDER BY collected_date DESC{limit_sql}")
                    return ["文章编号", "标题", "完整内容", "解决方案", "URL", "采集时间"], cursor.fetchall()

                elif source == "学习对话记录":
                    if single_id:
                        cursor.execute("SELECT id, topic, level, source_type, source_content, conversation, summary, created_at FROM learn_sessions WHERE id = ? OR topic LIKE ?",
                                       (single_id, f"%{single_id}%"))
                    else:
                        cursor.execute(f"SELECT id, topic, level, source_type, source_content, conversation, summary, created_at FROM learn_sessions ORDER BY created_at DESC{limit_sql}")
                    return ["ID", "主题", "级别", "来源类型", "来源内容", "完整对话", "摘要", "创建时间"], cursor.fetchall()

                elif source == "闪卡知识库":
                    if single_id:
                        cursor.execute("SELECT id, topic, question, answer, options, card_type, difficulty, review_count, correct_count, created_at FROM flashcards WHERE id = ? OR topic LIKE ?",
                                       (single_id, f"%{single_id}%"))
                    else:
                        cursor.execute(f"SELECT id, topic, question, answer, options, card_type, difficulty, review_count, correct_count, created_at FROM flashcards ORDER BY created_at DESC{limit_sql}")
                    return ["ID", "主题", "问题", "答案", "选项", "类型", "难度", "复习次数", "正确次数", "创建时间"], cursor.fetchall()

                elif source == "学习产物":
                    if single_id:
                        cursor.execute("SELECT id, session_id, topic, artifact_type, title, content, created_at FROM learn_artifacts WHERE id = ? OR topic LIKE ? OR title LIKE ?",
                                       (single_id, f"%{single_id}%", f"%{single_id}%"))
                    else:
                        cursor.execute(f"SELECT id, session_id, topic, artifact_type, title, content, created_at FROM learn_artifacts ORDER BY created_at DESC{limit_sql}")
                    return ["ID", "会话ID", "主题", "产物类型", "标题", "内容", "创建时间"], cursor.fetchall()

                else:
                    return [], []
        except Exception as e:
            self.log(f"导出查询失败: {e}")
            return [], []

    def _format_export_content(self, headers, rows, fmt, source=None):
        """将数据格式化为指定格式的文本（输出完整内容，不截断）"""
        if source is None:
            source = self.export_source_var.get()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if fmt == "Markdown":
            lines = [f"# {source} 数据导出", "", f"> 导出时间: {now}  |  共 {len(rows)} 条记录", ""]
            if not rows:
                lines.append("*暂无数据*")
                return "\n".join(lines)
            # 使用分条详情格式（适合长内容）
            for i, row in enumerate(rows, 1):
                lines.append(f"## 记录 {i}")
                lines.append("")
                for h, v in zip(headers, row):
                    val = str(v).strip() if v else ""
                    if "\n" in val or len(val) > 200:
                        # 长内容使用代码块
                        lines.append(f"**{h}:**")
                        lines.append("")
                        lines.append(val)
                        lines.append("")
                    else:
                        lines.append(f"- **{h}:** {val}")
                lines.append("")
                lines.append("---")
                lines.append("")
            return "\n".join(lines)

        elif fmt == "TXT":
            lines = [f"{'=' * 70}", f"  {source} 数据导出", f"  导出时间: {now}  |  共 {len(rows)} 条记录", f"{'=' * 70}", ""]
            if not rows:
                lines.append("暂无数据")
                return "\n".join(lines)
            for i, row in enumerate(rows, 1):
                lines.append(f"[{i}] " + "=" * 60)
                for h, v in zip(headers, row):
                    val = str(v).strip() if v else ""
                    lines.append(f"  {h}:")
                    if "\n" in val:
                        for vl in val.split("\n"):
                            lines.append(f"    {vl}")
                    else:
                        lines.append(f"    {val}")
                lines.append("")
            return "\n".join(lines)

        elif fmt == "HTML":
            import html as _html
            html_parts = [
                "<!DOCTYPE html>",
                '<html lang="zh-CN"><head><meta charset="UTF-8">',
                f"<title>{_html.escape(source)} 数据导出</title>",
                "<style>",
                "body{font-family:'Microsoft YaHei',sans-serif;margin:30px;background:#f8f9fa;color:#333;line-height:1.6}",
                "h1{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}",
                ".meta{color:#7f8c8d;margin-bottom:20px}",
                ".record{background:#fff;border-radius:8px;padding:20px;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,.08)}",
                ".record h3{color:#2c3e50;margin-top:0;border-left:4px solid #3498db;padding-left:10px}",
                ".field{margin-bottom:8px}",
                ".field-name{font-weight:bold;color:#2c3e50;display:inline-block;min-width:100px}",
                ".field-value{color:#333}",
                "pre{background:#f4f4f4;padding:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;font-size:13px}",
                "</style></head><body>",
                f"<h1>📦 {_html.escape(source)} 数据导出</h1>",
                f'<p class="meta">导出时间: {now} | 共 {len(rows)} 条记录</p>',
            ]
            if not rows:
                html_parts.append("<p>暂无数据</p>")
            else:
                for i, row in enumerate(rows, 1):
                    html_parts.append(f'<div class="record">')
                    html_parts.append(f"<h3>记录 {i}</h3>")
                    for h, v in zip(headers, row):
                        val = str(v).strip() if v else ""
                        escaped = _html.escape(val)
                        if "\n" in val or len(val) > 300:
                            html_parts.append(f'<div class="field"><span class="field-name">{_html.escape(h)}:</span><pre>{escaped}</pre></div>')
                        else:
                            html_parts.append(f'<div class="field"><span class="field-name">{_html.escape(h)}:</span> <span class="field-value">{escaped}</span></div>')
                    html_parts.append("</div>")
            html_parts.append("</body></html>")
            return "\n".join(html_parts)

        return ""

    def _preview_export_data(self):
        """预览导出数据"""
        headers, rows = self._fetch_export_rows()
        fmt = self.export_format_var.get()
        content = self._format_export_content(headers, rows, fmt)

        # 预览只显示前 5000 字符
        preview = content[:5000]
        if len(content) > 5000:
            preview += f"\n\n... (共 {len(content)} 字符，已截断预览)"

        self.export_preview_text.config(state=tk.NORMAL)
        self.export_preview_text.delete("1.0", tk.END)
        self.export_preview_text.insert(tk.END, preview)
        self.export_preview_text.config(state=tk.DISABLED)

        self.export_status_label.config(
            text=f"预览完成: {len(rows)} 条记录", fg=self.info_color
        )

    def _do_export_data(self):
        """导出数据到文件"""
        headers, rows = self._fetch_export_rows()
        if not rows:
            messagebox.showinfo("提示", "所选数据源暂无数据可导出")
            return
        self._save_export_file(headers, rows)

    def _do_export_selected(self):
        """导出 Dell技术库 TreeView 中选中的记录"""
        selected = self.kb_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先在上方列表中选中要导出的记录")
            return

        # 收集选中行的文章编号
        article_ids = []
        for item in selected:
            vals = self.kb_tree.item(item, "values")
            if vals:
                article_ids.append(vals[0])  # 第一列是文章编号

        if not article_ids:
            return

        # 查询选中记录的完整数据
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                placeholders = ",".join(["?"] * len(article_ids))
                cursor.execute(f"SELECT article_id, title, content, solution, url, collected_date FROM dell_kb_articles WHERE article_id IN ({placeholders})", article_ids)
                rows = cursor.fetchall()
        except Exception as e:
            messagebox.showerror("查询失败", f"查询选中记录失败: {e}")
            return

        if not rows:
            messagebox.showinfo("提示", "未找到选中记录的完整数据")
            return

        headers = ["文章编号", "标题", "完整内容", "解决方案", "URL", "采集时间"]
        self._save_export_file(headers, rows, source_name="Dell技术库(选中项)")

    def _save_export_file(self, headers, rows, source_name=None):
        """通用保存导出文件"""
        fmt = self.export_format_var.get()
        source = source_name or self.export_source_var.get()
        content = self._format_export_content(headers, rows, fmt, source=source)

        ext_map = {"Markdown": (".md", "Markdown 文件"), "TXT": (".txt", "文本文件"), "HTML": (".html", "HTML 文件")}
        ext, desc = ext_map.get(fmt, (".txt", "文本文件"))

        default_name = f"{source}_导出_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        filepath = filedialog.asksaveasfilename(
            title="导出数据",
            defaultextension=ext,
            initialfile=default_name,
            filetypes=[(desc, f"*{ext}"), ("所有文件", "*.*")]
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            self.export_status_label.config(
                text=f"✅ 已导出 {len(rows)} 条到 {Path(filepath).name}", fg=self.success_color
            )
            self.log(f"数据导出成功: {filepath} ({len(rows)} 条)")
        except Exception as e:
            messagebox.showerror("导出失败", f"写入文件失败: {e}")
            self.log(f"数据导出失败: {e}")

    def _do_import_data(self):
        """导入数据（仅支持 Dell技术库 的 Markdown/TXT 导入）"""
        source = self.export_source_var.get()
        if source != "Dell技术库":
            messagebox.showinfo("提示", "目前仅支持导入 Dell技术库 数据。\n请将数据源切换为「Dell技术库」后重试。")
            return

        filepath = filedialog.askopenfilename(
            title="导入数据",
            filetypes=[("Markdown 文件", "*.md"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if not filepath:
            return

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception as e:
            messagebox.showerror("导入失败", f"读取文件失败: {e}")
            return

        # 解析 Markdown 详情格式或 TXT 格式
        imported = 0
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                lines = text.strip().split("\n")

                # 解析分条详情格式（Markdown / TXT）
                current = {}
                field_map = {
                    "文章编号": "article_id", "标题": "title",
                    "完整内容": "content", "解决方案": "solution",
                    "URL": "url", "采集时间": "collected_date"
                }
                multiline_field = None
                multiline_buf = []

                def _flush_current():
                    nonlocal current, imported
                    if current.get("article_id"):
                        cursor.execute("""
                            INSERT OR REPLACE INTO dell_kb_articles
                            (article_id, title, content, solution, url, collected_date)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (current.get("article_id", ""), current.get("title", ""),
                              current.get("content", ""), current.get("solution", ""),
                              current.get("url", ""),
                              current.get("collected_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))
                        imported += 1
                    current = {}

                for line in lines:
                    stripped = line.strip()

                    # 检测新记录开始
                    if stripped.startswith("## 记录") or (stripped.startswith("[") and "]" in stripped and "=" * 5 in stripped):
                        # 保存多行缓冲
                        if multiline_field and multiline_buf:
                            current[multiline_field] = "\n".join(multiline_buf).strip()
                            multiline_field = None
                            multiline_buf = []
                        _flush_current()
                        continue

                    # 检测字段
                    matched_field = False
                    for label, key in field_map.items():
                        # Markdown 格式: - **字段:** 值 或 **字段:**
                        md_prefix = f"- **{label}:**"
                        md_prefix2 = f"**{label}:**"
                        # TXT 格式: 字段:
                        txt_prefix = f"{label}:"

                        if stripped.startswith(md_prefix):
                            if multiline_field and multiline_buf:
                                current[multiline_field] = "\n".join(multiline_buf).strip()
                                multiline_buf = []
                            val = stripped[len(md_prefix):].strip()
                            if val:
                                current[key] = val
                                multiline_field = None
                            else:
                                multiline_field = key
                            matched_field = True
                            break
                        elif stripped.startswith(md_prefix2):
                            if multiline_field and multiline_buf:
                                current[multiline_field] = "\n".join(multiline_buf).strip()
                                multiline_buf = []
                            val = stripped[len(md_prefix2):].strip()
                            if val:
                                current[key] = val
                                multiline_field = None
                            else:
                                multiline_field = key
                            matched_field = True
                            break
                        elif stripped.startswith(txt_prefix) and not stripped.startswith("http"):
                            if multiline_field and multiline_buf:
                                current[multiline_field] = "\n".join(multiline_buf).strip()
                                multiline_buf = []
                            val = stripped[len(txt_prefix):].strip()
                            if val:
                                current[key] = val
                                multiline_field = None
                            else:
                                multiline_field = key
                            matched_field = True
                            break

                    if not matched_field and multiline_field:
                        if stripped != "---":
                            multiline_buf.append(line.rstrip())

                # 最后一条
                if multiline_field and multiline_buf:
                    current[multiline_field] = "\n".join(multiline_buf).strip()
                _flush_current()

                self.conn.commit()

            if imported > 0:
                self.export_status_label.config(
                    text=f"✅ 成功导入 {imported} 条记录", fg=self.success_color
                )
                self.log(f"Dell技术库导入成功: {imported} 条 (来源: {filepath})")
                self.load_dell_kb_from_database()
            else:
                messagebox.showinfo("提示", "未能从文件中解析出有效数据。\n请确保文件格式与导出格式一致。")
        except Exception as e:
            messagebox.showerror("导入失败", f"导入数据失败: {e}")
            self.log(f"Dell技术库导入失败: {e}")

    def create_stats_view(self):
        """创建统计视图（数据可视化为主）"""
        # 顶部可滚动容器
        canvas = tk.Canvas(self.stats_frame, bg="white", highlightthickness=0)
        scrollbar = tk.Scrollbar(self.stats_frame, orient=tk.VERTICAL, command=canvas.yview)
        self.stats_scroll_frame = tk.Frame(canvas, bg="white")

        self.stats_scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        self._stats_canvas_win = canvas.create_window((0, 0), window=self.stats_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # 内容宽度跟随 canvas 宽度，避免超出屏幕
        def _on_canvas_resize(event):
            canvas.itemconfig(self._stats_canvas_win, width=event.width)
        canvas.bind("<Configure>", _on_canvas_resize)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 鼠标滚轮绑定
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        content = self.stats_scroll_frame

        # ── 第一行：统计卡片 ──
        cards_frame = tk.Frame(content, bg="white")
        cards_frame.pack(fill=tk.X, padx=15, pady=(15, 5))

        self.stats_cards = {}
        cards_info = [
            ("NVD CVE总数", "0", self.primary_color, "📊"),
            ("Dell公告数", "0", self.info_color, "🔔"),
            ("关联匹配数", "0", self.success_color, "🔗"),
            ("Dell 严重", "0", "#c0392b", "🔴"),
            ("Dell 高危", "0", "#e67e22", "🟠"),
            ("Dell 中危", "0", "#f1c40f", "🟡"),
            ("Dell 低危", "0", "#27ae60", "🟢"),
        ]

        for i, (title, value, color, icon) in enumerate(cards_info):
            card = self._create_stat_card(cards_frame, title, value, color, icon)
            card.grid(row=0, column=i, padx=6, pady=5, sticky="nsew")
            self.stats_cards[title] = card
        for i in range(len(cards_info)):
            cards_frame.columnconfigure(i, weight=1)

        # ── 第二行：严重等级分布饼图（2列）+ 数据汇聚图（1列）──
        pies_frame = tk.Frame(content, bg="white")
        pies_frame.pack(fill=tk.X, padx=15, pady=5)
        for i in range(3):
            pies_frame.columnconfigure(i, weight=1, uniform="chart_col")

        # 左：CVE严重等级饼图
        self.chart_cve_pie_frame = tk.LabelFrame(
            pies_frame, text="  CVE 严重等级分布  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        )
        self.chart_cve_pie_frame.grid(row=0, column=0, padx=4, pady=5, sticky="nsew")

        # 中：Dell公告影响等级饼图
        self.chart_dell_pie_frame = tk.LabelFrame(
            pies_frame, text="  Dell 公告影响等级分布  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.info_color
        )
        self.chart_dell_pie_frame.grid(row=0, column=1, padx=4, pady=5, sticky="nsew")

        # 右：数据汇聚匹配图
        self.chart_bar_frame = tk.LabelFrame(
            pies_frame, text="  数据汇聚与匹配关系  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.success_color
        )
        self.chart_bar_frame.grid(row=0, column=2, padx=4, pady=5, sticky="nsew")

        # ── 第三行：月度增长趋势图（3列）──
        trends_frame = tk.Frame(content, bg="white")
        trends_frame.pack(fill=tk.X, padx=15, pady=5)
        for i in range(3):
            trends_frame.columnconfigure(i, weight=1, uniform="chart_col")

        # 左：CVE 月度增长
        self.chart_cve_trend_frame = tk.LabelFrame(
            trends_frame, text="  CVE 月度增长趋势  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        )
        self.chart_cve_trend_frame.grid(row=0, column=0, padx=4, pady=5, sticky="nsew")

        # 中：Dell 公告月度增长
        self.chart_dell_trend_frame = tk.LabelFrame(
            trends_frame, text="  Dell 公告月度增长趋势  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.info_color
        )
        self.chart_dell_trend_frame.grid(row=0, column=1, padx=4, pady=5, sticky="nsew")

        # 右：关联月度增长
        self.chart_matched_trend_frame = tk.LabelFrame(
            trends_frame, text="  CVE-Dell 关联月度增长  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.success_color
        )
        self.chart_matched_trend_frame.grid(row=0, column=2, padx=4, pady=5, sticky="nsew")

        # ── 第四行：数据库信息 ──
        db_info_frame = tk.LabelFrame(
            content, text="  数据库信息  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg="#8e44ad"
        )
        db_info_frame.pack(fill=tk.X, padx=15, pady=5)

        self.db_info_container = tk.Frame(db_info_frame, bg="white")
        self.db_info_container.pack(fill=tk.X, padx=10, pady=8)

        # ── 第五行：最新 CVE 前10 ──
        cve_list_frame = tk.LabelFrame(
            content, text="  最新 CVE 漏洞 (前10)  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.primary_color
        )
        cve_list_frame.pack(fill=tk.X, padx=15, pady=5)

        cve_cols = ("CVE ID", "严重等级", "CVSS评分", "发布日期", "描述")
        self.stats_cve_tree = ttk.Treeview(cve_list_frame, columns=cve_cols, show="headings", height=10)
        for col in cve_cols:
            self.stats_cve_tree.heading(col, text=col)
        self.stats_cve_tree.column("CVE ID", width=150, minwidth=120, anchor="center")
        self.stats_cve_tree.column("严重等级", width=80, minwidth=60, anchor="center")
        self.stats_cve_tree.column("CVSS评分", width=80, minwidth=60, anchor="center")
        self.stats_cve_tree.column("发布日期", width=110, minwidth=90, anchor="center")
        self.stats_cve_tree.column("描述", width=500, minwidth=200, anchor="w")

        cve_scroll = tk.Scrollbar(cve_list_frame, orient=tk.VERTICAL, command=self.stats_cve_tree.yview)
        self.stats_cve_tree.configure(yscrollcommand=cve_scroll.set)
        self.stats_cve_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        cve_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        # 配色
        self.stats_cve_tree.tag_configure("CRITICAL", foreground="#c0392b")
        self.stats_cve_tree.tag_configure("HIGH", foreground="#e67e22")
        self.stats_cve_tree.tag_configure("MEDIUM", foreground="#f39c12")
        self.stats_cve_tree.tag_configure("LOW", foreground="#27ae60")

        # ── 第六行：最新 Dell 安全公告 前10 ──
        dell_list_frame = tk.LabelFrame(
            content, text="  最新 Dell 安全公告 (前10)  ", bg="white",
            font=("Microsoft YaHei", 10, "bold"), fg=self.info_color
        )
        dell_list_frame.pack(fill=tk.X, padx=15, pady=(5, 15))

        dell_cols = ("公告ID", "影响等级", "标题", "CVE数量", "发布日期")
        self.stats_dell_tree = ttk.Treeview(dell_list_frame, columns=dell_cols, show="headings", height=10)
        for col in dell_cols:
            self.stats_dell_tree.heading(col, text=col)
        self.stats_dell_tree.column("公告ID", width=140, minwidth=110, anchor="center")
        self.stats_dell_tree.column("影响等级", width=80, minwidth=60, anchor="center")
        self.stats_dell_tree.column("标题", width=450, minwidth=200, anchor="w")
        self.stats_dell_tree.column("CVE数量", width=80, minwidth=60, anchor="center")
        self.stats_dell_tree.column("发布日期", width=110, minwidth=90, anchor="center")

        dell_scroll = tk.Scrollbar(dell_list_frame, orient=tk.VERTICAL, command=self.stats_dell_tree.yview)
        self.stats_dell_tree.configure(yscrollcommand=dell_scroll.set)
        self.stats_dell_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        dell_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        self.stats_dell_tree.tag_configure("Critical", foreground="#c0392b")
        self.stats_dell_tree.tag_configure("High", foreground="#e67e22")
        self.stats_dell_tree.tag_configure("Medium", foreground="#f39c12")
        self.stats_dell_tree.tag_configure("Low", foreground="#27ae60")

    def _create_stat_card(self, parent, title, value, color, icon=""):
        """创建统计卡片（带图标和彩色左边框）"""
        card = tk.Frame(parent, bg="white", relief=tk.GROOVE, borderwidth=1)

        color_bar = tk.Frame(card, bg=color, width=5)
        color_bar.pack(side=tk.LEFT, fill=tk.Y)

        inner = tk.Frame(card, bg="white", padx=8, pady=6)
        inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(inner, text=f"{icon} {title}", bg="white", fg="#666",
                 font=("Microsoft YaHei", 9)).pack(anchor="w")

        value_label = tk.Label(inner, text=value, bg="white", fg=color,
                               font=("Microsoft YaHei", 22, "bold"))
        value_label.pack(anchor="w")

        card.value_label = value_label
        return card

    def _draw_pie_charts(self, cve_severity, dell_severity):
        """绘制 CVE 和 Dell 严重等级饼图（白色背景）"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure

            # 清空旧图表
            for w in self.chart_cve_pie_frame.winfo_children():
                w.destroy()
            for w in self.chart_dell_pie_frame.winfo_children():
                w.destroy()

            fig_w, fig_h, fig_dpi = 5.2, 2.6, 100

            # 原始严重等级颜色
            severity_colors = {
                "CRITICAL": "#c0392b", "Critical": "#c0392b",
                "HIGH": "#e67e22", "High": "#e67e22",
                "MEDIUM": "#f1c40f", "Medium": "#f1c40f",
                "LOW": "#27ae60", "Low": "#27ae60",
                "AWAITING": "#3498db",
                "N/A": "#95a5a6",
            }

            # ── CVE 严重等级饼图 ──
            fig_cve = Figure(figsize=(fig_w, fig_h), dpi=fig_dpi, facecolor='white')
            ax_cve = fig_cve.add_subplot(111)

            cve_labels, cve_sizes, cve_colors = [], [], []
            for lbl, key in [("Critical", "CRITICAL"), ("High", "HIGH"), ("Medium", "MEDIUM"),
                              ("Low", "LOW"), ("N/A", "N/A")]:
                cnt = cve_severity.get(key, 0)
                if key == "N/A":
                    cnt += cve_severity.get("AWAITING", 0)
                if cnt > 0:
                    cve_labels.append(f"{lbl}\n{cnt}")
                    cve_sizes.append(cnt)
                    cve_colors.append(severity_colors[key])

            if cve_sizes:
                wedges, texts, autotexts = ax_cve.pie(
                    cve_sizes, labels=cve_labels, colors=cve_colors, autopct='%1.0f%%',
                    startangle=140, pctdistance=0.72, labeldistance=1.15,
                    textprops={'fontsize': 9, 'fontfamily': 'Microsoft YaHei'}
                )
                for t in autotexts:
                    t.set_fontsize(8)
                    t.set_color('white')
                    t.set_fontweight('bold')
                ax_cve.set_title(f'CVE 总计: {sum(cve_sizes)}',
                                 fontsize=11, fontfamily='Microsoft YaHei', fontweight='bold', pad=8)
            else:
                ax_cve.text(0.5, 0.5, '暂无CVE数据', ha='center', va='center',
                            fontsize=13, fontfamily='Microsoft YaHei', color='#999')
                ax_cve.set_xlim(0, 1)
                ax_cve.set_ylim(0, 1)

            ax_cve.set_aspect('equal')
            fig_cve.tight_layout(pad=1.0)

            canvas_cve = FigureCanvasTkAgg(fig_cve, master=self.chart_cve_pie_frame)
            canvas_cve.draw()
            canvas_cve.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # ── Dell 公告影响等级饼图 ──
            fig_dell = Figure(figsize=(fig_w, fig_h), dpi=fig_dpi, facecolor='white')
            ax_dell = fig_dell.add_subplot(111)

            dell_labels, dell_sizes, dell_colors = [], [], []
            for lbl in ["Critical", "High", "Medium", "Low", "N/A"]:
                cnt = dell_severity.get(lbl, 0)
                if cnt > 0:
                    dell_labels.append(f"{lbl}\n{cnt}")
                    dell_sizes.append(cnt)
                    dell_colors.append(severity_colors[lbl])

            if dell_sizes:
                wedges, texts, autotexts = ax_dell.pie(
                    dell_sizes, labels=dell_labels, colors=dell_colors, autopct='%1.0f%%',
                    startangle=140, pctdistance=0.72, labeldistance=1.15,
                    textprops={'fontsize': 9, 'fontfamily': 'Microsoft YaHei'}
                )
                for t in autotexts:
                    t.set_fontsize(8)
                    t.set_color('white')
                    t.set_fontweight('bold')
                ax_dell.set_title(f'Dell公告 总计: {sum(dell_sizes)}',
                                  fontsize=11, fontfamily='Microsoft YaHei', fontweight='bold', pad=8)
            else:
                ax_dell.text(0.5, 0.5, '暂无Dell公告数据', ha='center', va='center',
                             fontsize=13, fontfamily='Microsoft YaHei', color='#999')
                ax_dell.set_xlim(0, 1)
                ax_dell.set_ylim(0, 1)

            ax_dell.set_aspect('equal')
            fig_dell.tight_layout(pad=1.0)

            canvas_dell = FigureCanvasTkAgg(fig_dell, master=self.chart_dell_pie_frame)
            canvas_dell.draw()
            canvas_dell.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        except ImportError:
            for frame in (self.chart_cve_pie_frame, self.chart_dell_pie_frame):
                tk.Label(frame, text="需要 matplotlib\npip install matplotlib",
                         bg="white", fg="#999", font=("Microsoft YaHei", 10)).pack(expand=True)
        except Exception as e:
            tk.Label(self.chart_cve_pie_frame, text=f"图表渲染失败:\n{e}",
                     bg="white", fg="#c0392b", font=("Microsoft YaHei", 9)).pack(expand=True)

    def _draw_monthly_trends(self, cve_monthly, dell_monthly, matched_monthly):
        """绘制 3 张月度增长趋势图（折线图 + 柱状图组合）"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure

            # 清空旧图表
            for w in self.chart_cve_trend_frame.winfo_children():
                w.destroy()
            for w in self.chart_dell_trend_frame.winfo_children():
                w.destroy()
            for w in self.chart_matched_trend_frame.winfo_children():
                w.destroy()

            fig_w, fig_h, fig_dpi = 5.2, 2.6, 100

            # ── CVE 月度趋势 ──
            fig_cve = Figure(figsize=(fig_w, fig_h), dpi=fig_dpi, facecolor='white')
            ax_cve = fig_cve.add_subplot(111)

            if cve_monthly:
                months = [m[0] for m in cve_monthly]
                counts = [m[1] for m in cve_monthly]

                bars = ax_cve.bar(range(len(months)), counts, color=self.primary_color, alpha=0.6, width=0.6)
                ax_cve.plot(range(len(months)), counts, color=self.primary_color, marker='o',
                            linewidth=2, markersize=6)

                for i, (bar, val) in enumerate(zip(bars, counts)):
                    if val > 0:
                        ax_cve.text(i, val + max(counts) * 0.03, str(val), ha='center', va='bottom',
                                    fontsize=9, fontfamily='Microsoft YaHei')

                ax_cve.set_xticks(range(len(months)))
                ax_cve.set_xticklabels(months, rotation=45, ha='right', fontsize=9, fontfamily='Microsoft YaHei')
                ax_cve.set_ylabel('数量', fontsize=10, fontfamily='Microsoft YaHei')
                ax_cve.set_title(f'CVE 月度增长 (最近{len(months)}个月)', fontsize=11,
                                 fontfamily='Microsoft YaHei', fontweight='bold', pad=8)
                ax_cve.grid(axis='y', alpha=0.3, linestyle='--')
                ax_cve.spines['top'].set_visible(False)
                ax_cve.spines['right'].set_visible(False)
            else:
                ax_cve.text(0.5, 0.5, '暂无月度数据', ha='center', va='center',
                            fontsize=12, fontfamily='Microsoft YaHei', color='#999')
                ax_cve.set_xlim(0, 1)
                ax_cve.set_ylim(0, 1)

            fig_cve.tight_layout()
            canvas_cve = FigureCanvasTkAgg(fig_cve, master=self.chart_cve_trend_frame)
            canvas_cve.draw()
            canvas_cve.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # ── Dell 月度趋势 ──
            fig_dell = Figure(figsize=(fig_w, fig_h), dpi=fig_dpi, facecolor='white')
            ax_dell = fig_dell.add_subplot(111)

            if dell_monthly:
                months = [m[0] for m in dell_monthly]
                counts = [m[1] for m in dell_monthly]

                bars = ax_dell.bar(range(len(months)), counts, color=self.info_color, alpha=0.6, width=0.6)
                ax_dell.plot(range(len(months)), counts, color=self.info_color, marker='o',
                             linewidth=2, markersize=6)

                for i, (bar, val) in enumerate(zip(bars, counts)):
                    if val > 0:
                        ax_dell.text(i, val + max(counts) * 0.03, str(val), ha='center', va='bottom',
                                     fontsize=9, fontfamily='Microsoft YaHei')

                ax_dell.set_xticks(range(len(months)))
                ax_dell.set_xticklabels(months, rotation=45, ha='right', fontsize=9, fontfamily='Microsoft YaHei')
                ax_dell.set_ylabel('数量', fontsize=10, fontfamily='Microsoft YaHei')
                ax_dell.set_title(f'Dell 公告月度增长 (最近{len(months)}个月)', fontsize=11,
                                  fontfamily='Microsoft YaHei', fontweight='bold', pad=8)
                ax_dell.grid(axis='y', alpha=0.3, linestyle='--')
                ax_dell.spines['top'].set_visible(False)
                ax_dell.spines['right'].set_visible(False)
            else:
                ax_dell.text(0.5, 0.5, '暂无月度数据', ha='center', va='center',
                             fontsize=12, fontfamily='Microsoft YaHei', color='#999')
                ax_dell.set_xlim(0, 1)
                ax_dell.set_ylim(0, 1)

            fig_dell.tight_layout()
            canvas_dell = FigureCanvasTkAgg(fig_dell, master=self.chart_dell_trend_frame)
            canvas_dell.draw()
            canvas_dell.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # ── 关联月度趋势 ──
            fig_matched = Figure(figsize=(fig_w, fig_h), dpi=fig_dpi, facecolor='white')
            ax_matched = fig_matched.add_subplot(111)

            if matched_monthly:
                months = [m[0] for m in matched_monthly]
                counts = [m[1] for m in matched_monthly]

                bars = ax_matched.bar(range(len(months)), counts, color=self.success_color, alpha=0.6, width=0.6)
                ax_matched.plot(range(len(months)), counts, color=self.success_color, marker='o',
                                linewidth=2, markersize=6)

                for i, (bar, val) in enumerate(zip(bars, counts)):
                    if val > 0:
                        ax_matched.text(i, val + max(counts) * 0.03, str(val), ha='center', va='bottom',
                                        fontsize=9, fontfamily='Microsoft YaHei')

                ax_matched.set_xticks(range(len(months)))
                ax_matched.set_xticklabels(months, rotation=45, ha='right', fontsize=9, fontfamily='Microsoft YaHei')
                ax_matched.set_ylabel('数量', fontsize=10, fontfamily='Microsoft YaHei')
                ax_matched.set_title(f'CVE-Dell 关联月度增长 (最近{len(months)}个月)', fontsize=11,
                                     fontfamily='Microsoft YaHei', fontweight='bold', pad=8)
                ax_matched.grid(axis='y', alpha=0.3, linestyle='--')
                ax_matched.spines['top'].set_visible(False)
                ax_matched.spines['right'].set_visible(False)
            else:
                ax_matched.text(0.5, 0.5, '暂无月度数据', ha='center', va='center',
                                fontsize=12, fontfamily='Microsoft YaHei', color='#999')
                ax_matched.set_xlim(0, 1)
                ax_matched.set_ylim(0, 1)

            fig_matched.tight_layout()
            canvas_matched = FigureCanvasTkAgg(fig_matched, master=self.chart_matched_trend_frame)
            canvas_matched.draw()
            canvas_matched.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        except ImportError:
            for frame in (self.chart_cve_trend_frame, self.chart_dell_trend_frame, self.chart_matched_trend_frame):
                tk.Label(frame, text="需要 matplotlib\npip install matplotlib",
                         bg="white", fg="#999", font=("Microsoft YaHei", 10)).pack(expand=True)
        except Exception as e:
            tk.Label(self.chart_cve_trend_frame, text=f"图表渲染失败:\n{e}",
                     bg="white", fg="#c0392b", font=("Microsoft YaHei", 9)).pack(expand=True)

    def _draw_overview_bar(self, nvd_total, dell_total, matched_count):
        """绘制数据汇聚匹配关系图（椭圆式展示）"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
            from matplotlib.patches import Ellipse, FancyArrowPatch
            import matplotlib.path as mpath

            # 清空旧图表
            for w in self.chart_bar_frame.winfo_children():
                w.destroy()

            fig = Figure(figsize=(5.2, 2.6), dpi=100, facecolor='white')
            ax = fig.add_subplot(111)
            ax.set_xlim(0, 10)
            ax.set_ylim(0, 10)
            ax.set_aspect('equal')
            ax.axis('off')

            # 顶部：CVE 椭圆
            cve_ellipse = Ellipse((2.5, 7.5), 4.2, 2.6,
                                   edgecolor=self.primary_color, facecolor=self.primary_color,
                                   alpha=0.12, linewidth=2.5)
            ax.add_patch(cve_ellipse)
            ax.text(2.5, 7.5, f'NVD CVE\n{nvd_total:,}', ha='center', va='center',
                    fontsize=12, fontweight='bold', fontfamily='Microsoft YaHei',
                    color=self.primary_color)

            # 顶部：Dell 椭圆
            dell_ellipse = Ellipse((7.5, 7.5), 4.2, 2.6,
                                    edgecolor=self.info_color, facecolor=self.info_color,
                                    alpha=0.12, linewidth=2.5)
            ax.add_patch(dell_ellipse)
            ax.text(7.5, 7.5, f'Dell 公告\n{dell_total:,}', ha='center', va='center',
                    fontsize=12, fontweight='bold', fontfamily='Microsoft YaHei',
                    color=self.info_color)

            # 中间：关联匹配椭圆（更大、更醒目）
            matched_ellipse = Ellipse((5, 3.2), 5.5, 3.2,
                                       edgecolor=self.success_color, facecolor=self.success_color,
                                       alpha=0.12, linewidth=3)
            ax.add_patch(matched_ellipse)
            ax.text(5, 3.2, f'关联匹配\n{matched_count:,}', ha='center', va='center',
                    fontsize=13, fontweight='bold', fontfamily='Microsoft YaHei',
                    color=self.success_color)

            # PPT 风格粗箭头：CVE → 关联
            arrow1 = FancyArrowPatch((2.5, 6.1), (4.1, 4.8),
                                      arrowstyle='fancy,head_length=8,head_width=6,tail_width=3',
                                      mutation_scale=1, linewidth=0,
                                      facecolor=self.primary_color, edgecolor=self.primary_color,
                                      alpha=0.35)
            ax.add_patch(arrow1)

            # PPT 风格粗箭头：Dell → 关联
            arrow2 = FancyArrowPatch((7.5, 6.1), (5.9, 4.8),
                                      arrowstyle='fancy,head_length=8,head_width=6,tail_width=3',
                                      mutation_scale=1, linewidth=0,
                                      facecolor=self.info_color, edgecolor=self.info_color,
                                      alpha=0.35)
            ax.add_patch(arrow2)

            # 底部：匹配系数说明
            if nvd_total > 0 and dell_total > 0:
                cve_coeff = matched_count / nvd_total
                dell_coeff = matched_count / dell_total
                ax.text(5, 1.2, f'CVE 匹配系数 {cve_coeff:.2f}  |  Dell 公告匹配系数 {dell_coeff:.2f}',
                        ha='center', va='center', fontsize=10, fontfamily='Microsoft YaHei',
                        color='#666')

            fig.tight_layout()

            canvas = FigureCanvasTkAgg(fig, master=self.chart_bar_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        except ImportError:
            tk.Label(self.chart_bar_frame, text="需要 matplotlib\npip install matplotlib",
                     bg="white", fg="#999", font=("Microsoft YaHei", 10)).pack(expand=True)
        except Exception as e:
            tk.Label(self.chart_bar_frame, text=f"图表渲染失败:\n{e}",
                     bg="white", fg="#c0392b", font=("Microsoft YaHei", 9)).pack(expand=True)

    def _get_monthly_cve_stats(self):
        """查询 CVE 最近 13 个月的统计数据"""
        try:
            with self.db_lock:
                rows = self.conn.execute("""
                    SELECT strftime('%Y-%m', published_date) as month, COUNT(*) as count
                    FROM cves
                    WHERE published_date IS NOT NULL AND published_date != ''
                    GROUP BY month
                    ORDER BY month DESC
                    LIMIT 13
                """).fetchall()
            result = [(row[0], row[1]) for row in reversed(rows)]
            return result
        except Exception as e:
            print(f"查询 CVE 月度统计失败: {e}")
            return []

    def _get_monthly_dell_stats(self):
        """查询 Dell 公告最近 13 个月的统计数据"""
        try:
            with self.db_lock:
                rows = self.conn.execute("""
                    SELECT strftime('%Y-%m', published_date) as month, COUNT(*) as count
                    FROM dell_advisories
                    WHERE published_date IS NOT NULL AND published_date != ''
                    GROUP BY month
                    ORDER BY month DESC
                    LIMIT 13
                """).fetchall()
            result = [(row[0], row[1]) for row in reversed(rows)]
            return result
        except Exception as e:
            print(f"查询 Dell 月度统���失败: {e}")
            return []

    def _get_monthly_matched_stats(self):
        """查询 CVE-Dell 关联最近 13 个月的统计数据（从 dell_advisories.cve_ids 解析）"""
        try:
            with self.db_lock:
                # 检查是否有 cve_dell_mapping 表
                has_mapping = self.conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='cve_dell_mapping'"
                ).fetchone()

                if has_mapping:
                    rows = self.conn.execute("""
                        SELECT strftime('%Y-%m', c.published_date) as month, COUNT(DISTINCT m.id) as count
                        FROM cve_dell_mapping m
                        JOIN cves c ON m.cve_id = c.cve_id
                        WHERE c.published_date IS NOT NULL AND c.published_date != ''
                        GROUP BY month
                        ORDER BY month DESC
                        LIMIT 13
                    """).fetchall()
                else:
                    # 从 dell_advisories.cve_ids 统计关联 CVE 数量（按 Dell 公告发布月份）
                    rows = self.conn.execute("""
                        SELECT strftime('%Y-%m', published_date) as month,
                               SUM(LENGTH(cve_ids) - LENGTH(REPLACE(cve_ids, ',', '')) + 1) as count
                        FROM dell_advisories
                        WHERE published_date IS NOT NULL AND published_date != ''
                          AND cve_ids IS NOT NULL AND cve_ids != ''
                        GROUP BY month
                        ORDER BY month DESC
                        LIMIT 13
                    """).fetchall()

            result = [(row[0], row[1]) for row in reversed(rows)]
            return result
        except Exception as e:
            print(f"查询关联月度统计失败: {e}")
            return []
            return []

    def _update_db_info(self):
        """更新数据库信息面板（版本、表条目数、占用空间）"""
        for w in self.db_info_container.winfo_children():
            w.destroy()

        info_font = ("Consolas", 10)
        label_font = ("Microsoft YaHei", 9, "bold")
        val_fg = "#2c3e50"

        # ── 顶栏：数据库引擎信息（水平紧凑布局） ──
        engine_row = tk.Frame(self.db_info_container, bg="#f8f8f8", relief=tk.GROOVE, borderwidth=1)
        engine_row.pack(fill=tk.X, pady=(0, 6))

        # SQLite 版本
        try:
            with self.db_lock:
                sqlite_ver = self.conn.execute("SELECT sqlite_version()").fetchone()[0]
        except Exception:
            sqlite_ver = "N/A"

        # 数据库文件大小
        try:
            db_size_bytes = self.db_path.stat().st_size
            if db_size_bytes >= 1048576:
                db_size_str = f"{db_size_bytes / 1048576:.1f} MB"
            else:
                db_size_str = f"{db_size_bytes / 1024:.0f} KB"
        except Exception:
            db_size_str = "N/A"
            db_size_bytes = 0

        # WAL 文件大小
        wal_size_str = ""
        try:
            wal_path = self.db_path.with_suffix('.db-wal')
            if wal_path.exists():
                wal_bytes = wal_path.stat().st_size
                if wal_bytes >= 1048576:
                    wal_size_str = f" + WAL {wal_bytes / 1048576:.1f} MB"
                else:
                    wal_size_str = f" + WAL {wal_bytes / 1024:.0f} KB"
        except Exception:
            pass

        # Redis 状态
        if self.use_redis:
            try:
                info = self.redis_manager.redis_client.info('server')
                redis_ver = info.get('redis_version', 'N/A')
                mem_info = self.redis_manager.redis_client.info('memory')
                used = mem_info.get('used_memory_human', 'N/A')
                redis_text = f"v{redis_ver} ({used})"
                redis_fg = "#27ae60"
            except Exception:
                redis_text = "连接异常"
                redis_fg = "#e74c3c"
        else:
            if "连接失败" in self.redis_init_message or "初始化失败" in self.redis_init_message:
                redis_text = "连接失败 (回退 SQLite)"
                redis_fg = "#e74c3c"
            elif "禁用" in self.redis_init_message:
                redis_text = "已禁用"
                redis_fg = "#95a5a6"
            else:
                redis_text = "未连接"
                redis_fg = "#95a5a6"

        # 水平排列引擎信息
        items = [
            ("SQLite", f"v{sqlite_ver}", "#2980b9"),
            ("数据库", f"{db_size_str}{wal_size_str}", val_fg),
            ("Redis", redis_text, redis_fg),
        ]
        for idx, (lbl, val, fg) in enumerate(items):
            tk.Label(engine_row, text=f" {lbl}: ", bg="#f8f8f8", fg="#666",
                     font=("Microsoft YaHei", 9)).pack(side=tk.LEFT, padx=(8 if idx == 0 else 0, 0), pady=4)
            tk.Label(engine_row, text=val, bg="#f8f8f8", fg=fg,
                     font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=(0, 12), pady=4)

        # ── 下方：各表数据条目数（全宽表格） ──
        table_frame = tk.Frame(self.db_info_container, bg="white")
        table_frame.pack(fill=tk.X)

        # 表头
        for ci, (h, w) in enumerate([("表名", 16), ("条目数", 10), ("估算大小", 10)]):
            tk.Label(table_frame, text=h, bg="#f0f0f0", fg="#333",
                     font=("Microsoft YaHei", 9, "bold"), width=w, padx=8, pady=2,
                     relief=tk.GROOVE, anchor="center").grid(row=0, column=ci, sticky="nsew")

        tables = [
            ("cves", "CVE 漏洞"),
            ("dell_advisories", "Dell 安全公告"),
            ("dell_kb_articles", "Dell 技术库"),
            ("ai_solutions", "AI 解决方案"),
            ("news_briefs", "新闻简报"),
            ("podcast_scripts", "播客脚本"),
            ("learn_sessions", "学习对话"),
        ]

        # 获取实际数据库文件大小作为合计基准
        try:
            actual_db_bytes = self.db_path.stat().st_size
        except Exception:
            actual_db_bytes = 0

        page_size = 4096
        try:
            with self.db_lock:
                page_size = self.conn.execute("PRAGMA page_size").fetchone()[0]
        except Exception:
            pass

        # 第一轮：收集每个表的 dbstat 原始页数
        raw_table_bytes = []
        total_rows = 0
        raw_total = 0

        for tbl, display_name in tables:
            try:
                with self.db_lock:
                    cnt = self.conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            except Exception:
                cnt = 0
            total_rows += cnt

            tbl_bytes = 0
            try:
                with self.db_lock:
                    pages = self.conn.execute(
                        "SELECT COUNT(*) FROM dbstat WHERE name = ?", (tbl,)
                    ).fetchone()[0]
                tbl_bytes = pages * page_size
            except Exception:
                tbl_bytes = max(cnt * 512, page_size) if cnt > 0 else page_size
            raw_total += tbl_bytes
            raw_table_bytes.append((display_name, cnt, tbl_bytes))

        # 第二轮：按比例缩放，使各表大小之和 = 实际数据库文件大小
        scale = actual_db_bytes / raw_total if raw_total > 0 else 1.0
        table_data = []
        scaled_total = 0
        for i, (display_name, cnt, raw_bytes) in enumerate(raw_table_bytes):
            if i < len(raw_table_bytes) - 1:
                scaled = int(raw_bytes * scale)
            else:
                # 最后一项用减法，确保精确相等
                scaled = actual_db_bytes - scaled_total
            scaled_total += scaled
            table_data.append((display_name, cnt, scaled))

        # 渲染表格行
        def _fmt_size(b):
            if b >= 1048576:
                return f"{b / 1048576:.1f} MB"
            elif b >= 1024:
                return f"{b / 1024:.0f} KB"
            return f"{b} B"

        for ri, (display_name, cnt, tbl_bytes) in enumerate(table_data):
            bg = "white" if ri % 2 == 0 else "#fafafa"
            tk.Label(table_frame, text=display_name, bg=bg, fg=val_fg,
                     font=("Microsoft YaHei", 9), padx=8, pady=1,
                     anchor="center").grid(row=ri + 1, column=0, sticky="nsew")
            tk.Label(table_frame, text=f"{cnt:,}", bg=bg, fg=val_fg,
                     font=info_font, padx=8, pady=1,
                     anchor="center").grid(row=ri + 1, column=1, sticky="nsew")
            tk.Label(table_frame, text=_fmt_size(tbl_bytes), bg=bg, fg="#888",
                     font=info_font, padx=8, pady=1,
                     anchor="center").grid(row=ri + 1, column=2, sticky="nsew")

        # 合计行（使用实际数据库文件大小）
        total_size_str = _fmt_size(actual_db_bytes)

        tk.Label(table_frame, text="合计", bg="#e8e8e8", fg="#333",
                 font=("Microsoft YaHei", 9, "bold"), padx=8, pady=2,
                 anchor="center").grid(row=len(tables) + 1, column=0, sticky="nsew")
        tk.Label(table_frame, text=f"{total_rows:,}", bg="#e8e8e8", fg="#333",
                 font=("Consolas", 10, "bold"), padx=8, pady=2,
                 anchor="center").grid(row=len(tables) + 1, column=1, sticky="nsew")
        tk.Label(table_frame, text=total_size_str, bg="#e8e8e8", fg="#333",
                 font=("Consolas", 10, "bold"), padx=8, pady=2,
                 anchor="center").grid(row=len(tables) + 1, column=2, sticky="nsew")

        for ci in range(3):
            table_frame.columnconfigure(ci, weight=1)

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
            bg="#d0d0d0", sashwidth=5, sashrelief=tk.RAISED
        )
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        # ── 左侧控制面板 ──────────────────────────────────────────────
        left_outer = tk.Frame(main_paned, bg="white")
        main_paned.add(left_outer, width=380, minsize=280)

        left_canvas = tk.Canvas(left_outer, bg="white", highlightthickness=0)
        left_scroll = tk.Scrollbar(left_outer, orient=tk.VERTICAL, command=left_canvas.yview)
        left_canvas.configure(yscrollcommand=left_scroll.set)
        left_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        left_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        left_panel = tk.Frame(left_canvas, bg="white")
        self._learn_left_canvas_win = left_canvas.create_window((0, 0), window=left_panel, anchor="nw")
        left_panel.bind(
            "<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        )
        # 拖动分隔线时，左侧内容宽度跟随 canvas 动态变化
        left_canvas.bind("<Configure>", lambda e: left_canvas.itemconfig(
            self._learn_left_canvas_win, width=e.width
        ))

        # 1. 学习内容来源
        data_frame = tk.LabelFrame(
            left_panel, text="📚 学习内容来源", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        data_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        self.learn_source_var = tk.StringVar(value="db")
        rb_db = tk.Radiobutton(
            data_frame, text="💾 从数据库选取", variable=self.learn_source_var,
            value="db", bg="white", font=("Microsoft YaHei", 9),
            command=self._on_learn_source_change, padx=0
        )
        rb_db.pack(anchor="w", padx=8, pady=2)
        rb_file = tk.Radiobutton(
            data_frame, text="📁 上传本地文件", variable=self.learn_source_var,
            value="file", bg="white", font=("Microsoft YaHei", 9),
            command=self._on_learn_source_change, padx=0
        )
        rb_file.pack(anchor="w", padx=8, pady=2)
        rb_url = tk.Radiobutton(
            data_frame, text="🌐 网页链接", variable=self.learn_source_var,
            value="url", bg="white", font=("Microsoft YaHei", 9),
            command=self._on_learn_source_change, padx=0
        )
        rb_url.pack(anchor="w", padx=8, pady=2)

        # 网页链接子选项 — URL 输入 + 抓取按钮
        self.learn_url_frame = tk.Frame(data_frame, bg="white")
        # 默认隐藏，选中 url radio 时显示
        tk.Label(
            self.learn_url_frame, text="URL:", bg="white",
            font=("Microsoft YaHei", 9)
        ).pack(side=tk.LEFT)
        self.learn_url_entry = tk.Entry(
            self.learn_url_frame, font=("Microsoft YaHei", 9),
            relief=tk.SOLID, bd=1, width=14
        )
        self.learn_url_entry.pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)
        self.learn_url_fetch_btn = tk.Button(
            self.learn_url_frame, text="抓取",
            command=self._fetch_learn_url,
            bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 8, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=6
        )
        self.learn_url_fetch_btn.pack(side=tk.RIGHT, padx=(2, 0))

        # 数据库子选项 — 数据源 + 下一级菜单
        self.learn_db_type_frame = tk.Frame(data_frame, bg="white")
        self.learn_db_type_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
        tk.Label(
            self.learn_db_type_frame, text="数据源:", bg="white",
            font=("Microsoft YaHei", 9)
        ).pack(side=tk.LEFT)
        self.learn_db_type_combo = ttk.Combobox(
            self.learn_db_type_frame,
            values=["IT新闻简报", "Dell安全公告", "Dell技术库", "CVE漏洞数据", "AI分析记录", "学习对话记录"],
            state="readonly", width=10, font=("Microsoft YaHei", 9)
        )
        self.learn_db_type_combo.current(0)
        self.learn_db_type_combo.pack(side=tk.LEFT, padx=4)
        self.learn_db_type_combo.bind("<<ComboboxSelected>>", self._on_learn_db_type_change)

        # 关键字搜索行
        self.learn_search_frame = tk.Frame(data_frame, bg="white")
        self.learn_search_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
        tk.Label(
            self.learn_search_frame, text="关键字:", bg="white",
            font=("Microsoft YaHei", 9)
        ).pack(side=tk.LEFT)
        self.learn_search_var = tk.StringVar()
        self.learn_search_entry = tk.Entry(
            self.learn_search_frame, textvariable=self.learn_search_var,
            font=("Microsoft YaHei", 9), width=20, relief=tk.SOLID, bd=1
        )
        self.learn_search_entry.pack(side=tk.LEFT, padx=4)
        self.learn_search_entry.bind("<Return>", lambda e: self._refresh_learn_sub_items())
        tk.Button(
            self.learn_search_frame, text="搜索", command=self._refresh_learn_sub_items,
            bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 8, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=6
        ).pack(side=tk.LEFT, padx=(2, 0))
        tk.Button(
            self.learn_search_frame, text="清除", command=self._clear_learn_search,
            bg="#95a5a6", fg="white",
            font=("Microsoft YaHei", 8),
            relief=tk.FLAT, cursor="hand2", padx=6
        ).pack(side=tk.LEFT, padx=(2, 0))

        # 下一级选择区域
        self.learn_sub_frame = tk.Frame(data_frame, bg="white")
        self.learn_sub_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
        tk.Label(
            self.learn_sub_frame, text="选择内容:", bg="white",
            font=("Microsoft YaHei", 9)
        ).pack(side=tk.LEFT)
        self.learn_sub_combo = ttk.Combobox(
            self.learn_sub_frame,
            state="readonly", width=24, font=("Microsoft YaHei", 9)
        )
        self.learn_sub_combo.pack(side=tk.LEFT, padx=4)
        # 初始化下一级菜单
        self._refresh_learn_sub_items()

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

        # 智能摘要区
        self.learn_summary_frame = tk.LabelFrame(
            left_panel, text="✨ 智能摘要", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        self.learn_summary_frame.pack(fill=tk.X, padx=8, pady=(4, 4))

        self.learn_summary_text = scrolledtext.ScrolledText(
            self.learn_summary_frame, height=8, wrap=tk.WORD,
            font=("Microsoft YaHei", 8), bg="#f8f9fa",
            relief=tk.FLAT, state=tk.DISABLED
        )
        self.learn_summary_text.pack(fill=tk.X, padx=8, pady=(4, 4))

        # 建议问题区
        tk.Label(
            self.learn_summary_frame, text="建议学习问题：", bg="white",
            font=("Microsoft YaHei", 8), fg="#666666"
        ).pack(anchor="w", padx=8)
        self.learn_questions_frame = tk.Frame(self.learn_summary_frame, bg="white")
        self.learn_questions_frame.pack(fill=tk.X, padx=8, pady=(0, 6))

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
            topic_frame, font=("Microsoft YaHei", 9),
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
            font=("Microsoft YaHei", 9, "bold"),
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
        self.learn_save_btn = tk.Button(
            btn_frame, text="💾 保存对话",
            command=self._save_learn_session,
            bg=self.info_color, fg="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_save_btn.pack(fill=tk.X, pady=(4, 0))

        # 5. 知识巩固区
        consolidate_frame = tk.LabelFrame(
            left_panel, text="🧩 知识巩固", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        consolidate_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        self.learn_gen_cards_btn = tk.Button(
            consolidate_frame, text="🃏 AI 生成闪卡",
            command=self._generate_flashcards,
            bg="#8e44ad", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_gen_cards_btn.pack(fill=tk.X, padx=8, pady=(6, 2))

        self.learn_quiz_btn = tk.Button(
            consolidate_frame, text="📝 知识问答",
            command=self._open_quiz_window,
            bg="#e67e22", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_quiz_btn.pack(fill=tk.X, padx=8, pady=2)

        self.learn_flashcard_btn = tk.Button(
            consolidate_frame, text="🔄 闪卡复习",
            command=self._open_flashcard_window,
            bg="#16a085", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_flashcard_btn.pack(fill=tk.X, padx=8, pady=(2, 6))

        # 6. 学习产物生成区（Phase 3）
        artifact_frame = tk.LabelFrame(
            left_panel, text="📦 学习产物", bg="white",
            font=("Microsoft YaHei", 9, "bold"), fg=self.primary_color
        )
        artifact_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        self.learn_timeline_btn = tk.Button(
            artifact_frame, text="📅 生成时间线",
            command=lambda: self._generate_artifact("timeline"),
            bg="#3498db", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_timeline_btn.pack(fill=tk.X, padx=8, pady=(6, 2))

        self.learn_mindmap_btn = tk.Button(
            artifact_frame, text="🧠 生成思维导图",
            command=lambda: self._generate_artifact("mindmap"),
            bg="#9b59b6", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_mindmap_btn.pack(fill=tk.X, padx=8, pady=2)

        self.learn_guide_btn = tk.Button(
            artifact_frame, text="📖 生成学习指南",
            command=lambda: self._generate_artifact("guide"),
            bg="#27ae60", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_guide_btn.pack(fill=tk.X, padx=8, pady=2)

        self.learn_faq_btn = tk.Button(
            artifact_frame, text="❓ 生成 FAQ",
            command=lambda: self._generate_artifact("faq"),
            bg="#f39c12", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_faq_btn.pack(fill=tk.X, padx=8, pady=2)

        self.learn_podcast_btn = tk.Button(
            artifact_frame, text="🎙 生成对话播客",
            command=lambda: self._generate_artifact("podcast"),
            bg="#e74c3c", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        self.learn_podcast_btn.pack(fill=tk.X, padx=8, pady=(2, 6))

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
        """数据来源单选切换时显示/隐藏子选项"""
        src = self.learn_source_var.get()
        if src == "db":
            self.learn_db_type_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
            self.learn_search_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
            self.learn_sub_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
            self.learn_url_frame.pack_forget()
            self._refresh_learn_sub_items()
        elif src == "url":
            self.learn_db_type_frame.pack_forget()
            self.learn_search_frame.pack_forget()
            self.learn_sub_frame.pack_forget()
            self.learn_url_frame.pack(fill=tk.X, padx=16, pady=(0, 4))
        else:
            self.learn_db_type_frame.pack_forget()
            self.learn_search_frame.pack_forget()
            self.learn_sub_frame.pack_forget()
            self.learn_url_frame.pack_forget()

    def _on_learn_db_type_change(self, event=None):
        """数据源下拉切换时清空搜索并刷新下一级菜单"""
        self.learn_search_var.set("")
        self._refresh_learn_sub_items()

    def _refresh_learn_sub_items(self):
        """根据当前数据源类型和关键字刷新下一级选择菜单"""
        db_type = self.learn_db_type_combo.get()
        keyword = self.learn_search_var.get().strip()
        items = []
        limit = 500 if keyword else 200
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                if db_type == "IT新闻简报":
                    if keyword:
                        cursor.execute(
                            "SELECT DISTINCT brief_date FROM news_briefs WHERE brief_date LIKE ? OR content LIKE ? ORDER BY brief_date DESC LIMIT ?",
                            (f"%{keyword}%", f"%{keyword}%", limit)
                        )
                    else:
                        cursor.execute(
                            "SELECT DISTINCT brief_date FROM news_briefs ORDER BY brief_date DESC LIMIT ?", (limit,)
                        )
                    for (d,) in cursor.fetchall():
                        items.append(d)
                elif db_type == "Dell安全公告":
                    if keyword:
                        cursor.execute(
                            "SELECT dsa_id, title FROM dell_advisories WHERE dsa_id LIKE ? OR title LIKE ? OR cve_ids LIKE ? ORDER BY published_date DESC LIMIT ?",
                            (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", limit)
                        )
                    else:
                        cursor.execute(
                            "SELECT dsa_id, title FROM dell_advisories ORDER BY published_date DESC LIMIT ?", (limit,)
                        )
                    for dsa_id, title in cursor.fetchall():
                        display = f"{dsa_id} - {(title or '')[:35]}"
                        items.append(display)
                elif db_type == "Dell技术库":
                    if keyword:
                        cursor.execute(
                            "SELECT article_id, title FROM dell_kb_articles WHERE article_id LIKE ? OR title LIKE ? ORDER BY collected_date DESC LIMIT ?",
                            (f"%{keyword}%", f"%{keyword}%", limit)
                        )
                    else:
                        cursor.execute(
                            "SELECT article_id, title FROM dell_kb_articles ORDER BY collected_date DESC LIMIT ?", (limit,)
                        )
                    for aid, title in cursor.fetchall():
                        display = f"{aid} - {(title or '')[:35]}"
                        items.append(display)
                elif db_type == "CVE漏洞数据":
                    if keyword:
                        cursor.execute(
                            "SELECT cve_id FROM cves WHERE cve_id LIKE ? ORDER BY published_date DESC LIMIT ?",
                            (f"%{keyword}%", limit)
                        )
                        for (cve_id,) in cursor.fetchall():
                            items.append(cve_id)
                    else:
                        cursor.execute(
                            "SELECT cve_id FROM cves ORDER BY published_date DESC LIMIT ?", (limit,)
                        )
                        for (cve_id,) in cursor.fetchall():
                            items.append(cve_id)
                elif db_type == "AI分析记录":
                    if keyword:
                        cursor.execute(
                            "SELECT cve_id, dell_advisory_id, analysis_time FROM ai_solutions "
                            "WHERE cve_id LIKE ? OR dell_advisory_id LIKE ? "
                            "ORDER BY analysis_time DESC LIMIT ?",
                            (f"%{keyword}%", f"%{keyword}%", limit)
                        )
                    else:
                        cursor.execute(
                            "SELECT cve_id, dell_advisory_id, analysis_time FROM ai_solutions "
                            "ORDER BY analysis_time DESC LIMIT ?", (limit,)
                        )
                    for cve_id, dsa_id, ts in cursor.fetchall():
                        ts_short = (ts or "")[:16]
                        items.append(f"{cve_id} / {dsa_id or 'N/A'} ({ts_short})")
                elif db_type == "学习对话记录":
                    if keyword:
                        cursor.execute(
                            "SELECT id, topic, level, created_at FROM learn_sessions "
                            "WHERE topic LIKE ? ORDER BY created_at DESC LIMIT ?",
                            (f"%{keyword}%", limit)
                        )
                    else:
                        cursor.execute(
                            "SELECT id, topic, level, created_at FROM learn_sessions "
                            "ORDER BY created_at DESC LIMIT ?", (limit,)
                        )
                    for sid, topic, level, ts in cursor.fetchall():
                        ts_short = (ts or "")[:16]
                        items.append(f"#{sid} {(topic or '')[:20]} [{level or ''}] ({ts_short})")
        except Exception as e:
            self.log(f"刷新学习子菜单失败: {e}")

        hint = f"(搜索 '{keyword}' 共 {len(items)} 条)" if keyword else "(暂无数据)"
        self.learn_sub_combo['values'] = items if items else [hint]
        if items:
            self.learn_sub_combo.current(0)
        else:
            self.learn_sub_combo.set(hint)

    def _clear_learn_search(self):
        """清除关键字搜索并刷新列表"""
        self.learn_search_var.set("")
        self._refresh_learn_sub_items()

    def _load_learn_content(self):
        """加载学习内容到预览框"""
        source = self.learn_source_var.get()
        if source == "db":
            self._load_learn_from_db()
        elif source == "url":
            self._fetch_learn_url()
        else:
            self._load_learn_from_file()

    def _load_learn_from_db(self):
        """从 SQLite 数据库加载选中的具体条目内容"""
        db_type = self.learn_db_type_combo.get()
        sub_val = self.learn_sub_combo.get()
        if not sub_val or sub_val == "(暂无数据)":
            self._learn_set_preview(f"请先选择要加载的{db_type}条目。\n如果列表为空，请先在对应标签页采集数据。")
            return

        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                content_lines = []
                topic_hint = ""

                if db_type == "IT新闻简报":
                    # sub_val 是日期字符串 如 "2026-03-07"
                    date_str = sub_val.strip()
                    cursor.execute(
                        "SELECT content, articles_json FROM news_briefs WHERE brief_date = ? ORDER BY created_at DESC LIMIT 1",
                        (date_str,)
                    )
                    row = cursor.fetchone()
                    if row:
                        content, articles_json = row
                        content_lines.append(f"【{date_str} IT新闻简报】\n")
                        content_lines.append(content or "")
                        if articles_json:
                            try:
                                arts = json.loads(articles_json)
                                if arts:
                                    content_lines.append(f"\n{'─'*40}\n【原始新闻来源 ({len(arts)} 篇)】")
                                    for i, a in enumerate(arts, 1):
                                        content_lines.append(
                                            f"  {i}. [{a.get('source','')}] {a.get('title','')}"
                                        )
                            except json.JSONDecodeError:
                                pass
                    else:
                        self._learn_set_preview(f"{date_str} 无新闻简报记录。")
                        return
                    topic_hint = f"IT新闻动态分析 ({date_str})"

                elif db_type == "Dell安全公告":
                    # sub_val 格式 "DSA-xxxx-xxx - title..."
                    dsa_id = sub_val.split(" - ")[0].strip()
                    cursor.execute(
                        "SELECT dsa_id, title, cve_ids, data, link FROM dell_advisories WHERE dsa_id = ?",
                        (dsa_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        dsa_id, title, cve_ids, data_str, link = row
                        content_lines.append(f"【Dell安全公告: {dsa_id}】")
                        content_lines.append(f"标题: {title or 'N/A'}")
                        content_lines.append(f"关联CVE: {cve_ids or '无'}")
                        content_lines.append(f"链接: {link or 'N/A'}")
                        if data_str:
                            try:
                                d = json.loads(data_str)
                                impact = d.get('impact', '')
                                summary = d.get('summary', '')
                                solution = d.get('solution', '')
                                products = d.get('affected_products', [])
                                if impact:
                                    content_lines.append(f"影响等级: {impact}")
                                if products:
                                    prod_strs = []
                                    for p in products[:10]:
                                        if isinstance(p, dict):
                                            prod_strs.append(p.get('name', p.get('product', str(p))))
                                        else:
                                            prod_strs.append(str(p))
                                    content_lines.append(f"受影响产品: {', '.join(prod_strs)}")
                                if summary:
                                    content_lines.append(f"\n【摘要】\n{summary[:3000]}")
                                if solution:
                                    content_lines.append(f"\n【解决方案】\n{solution[:3000]}")
                            except json.JSONDecodeError:
                                pass
                    else:
                        self._learn_set_preview(f"未找到公告 {dsa_id}。")
                        return
                    topic_hint = f"Dell安全公告分析 ({dsa_id})"

                elif db_type == "Dell技术库":
                    # sub_val 格式 "000261124 - 标题..."
                    article_id = sub_val.split(" - ")[0].strip()
                    cursor.execute(
                        "SELECT article_id, title, content, solution, url FROM dell_kb_articles WHERE article_id = ?",
                        (article_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        aid, title, content, solution, url = row
                        content_lines.append(f"【Dell技术库文章: {aid}】")
                        content_lines.append(f"标题: {title or 'N/A'}")
                        content_lines.append(f"链接: {url or 'N/A'}")
                        if content:
                            content_lines.append(f"\n【正文内容】\n{content[:8000]}")
                        if solution:
                            content_lines.append(f"\n【解决方案】\n{solution[:3000]}")
                    else:
                        self._learn_set_preview(f"未找到文章 {article_id}。")
                        return
                    topic_hint = f"Dell技术文档学习 ({article_id})"

                elif db_type == "CVE漏洞数据":
                    # sub_val 可能是 "CVE-2026-1234" 或 "CVE-2026-1234 - desc..."
                    cve_id = sub_val.split(" - ")[0].strip()
                    cursor.execute(
                        "SELECT data FROM cves WHERE cve_id = ?", (cve_id,)
                    )
                    row = cursor.fetchone()
                    if row and row[0]:
                        try:
                            d = json.loads(row[0])
                            # 兼容扁平格式（collect_cves 生成）和 NVD 原始嵌套格式
                            desc = d.get("description", "")
                            if not desc:
                                for item in d.get("descriptions", []):
                                    if isinstance(item, dict) and item.get("lang") == "en":
                                        desc = item.get("value", "")
                                        break
                            severity = d.get("cvss_severity", "")
                            score = d.get("cvss_score", "")
                            vector = d.get("cvss_vector", "")
                            if not severity:
                                metrics = d.get("metrics", {})
                                # 优先使用 CVSS v4.0
                                cvss = metrics.get("cvssMetricV40", [])
                                if not cvss:
                                    cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                                if cvss:
                                    cvss_data = cvss[0].get("cvssData", {})
                                    severity = cvss_data.get("baseSeverity", "")
                                    score = cvss_data.get("baseScore", "")
                                    vector = cvss_data.get("vectorString", "")
                                # 对于尚未评分的 CVE，根据漏洞状态标注
                                elif d.get("vuln_status", "") in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
                                    severity = "AWAITING"
                            weaknesses = []
                            for w in d.get("weaknesses", []):
                                if isinstance(w, str):
                                    weaknesses.append(w)
                                elif isinstance(w, dict):
                                    for wd in w.get("description", []):
                                        if isinstance(wd, dict) and wd.get("lang") == "en":
                                            weaknesses.append(wd.get("value", ""))
                            refs = d.get("references", [])

                            content_lines.append(f"【CVE漏洞: {cve_id}】")
                            content_lines.append(f"严重等级: {severity}  CVSS评分: {score}")
                            content_lines.append(f"CVSS向量: {vector}")
                            if weaknesses:
                                content_lines.append(f"CWE类型: {', '.join(weaknesses)}")
                            content_lines.append(f"\n【描述】\n{desc}")
                            if refs:
                                content_lines.append(f"\n【参考链接】")
                                for r in refs[:8]:
                                    content_lines.append(f"  - {r.get('url', '')}")
                        except json.JSONDecodeError:
                            content_lines.append(f"[{cve_id}] 数据解析失败")
                    else:
                        self._learn_set_preview(f"未找到 {cve_id} 的数据。")
                        return
                    topic_hint = f"CVE漏洞分析 ({cve_id})"

                elif db_type == "AI分析记录":
                    # sub_val 格式 "CVE-xxx / DSA-xxx (2026-03-07 19:00)"
                    parts = sub_val.split(" / ")
                    cve_id = parts[0].strip() if parts else ""
                    cursor.execute(
                        "SELECT cve_id, dell_advisory_id, result, analysis_time, model_name FROM ai_solutions "
                        "WHERE cve_id = ? ORDER BY analysis_time DESC LIMIT 1",
                        (cve_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        cve_id, dsa_id, result, ts, model = row
                        content_lines.append(f"【AI分析记录】")
                        content_lines.append(f"CVE: {cve_id}  Dell公告: {dsa_id or 'N/A'}")
                        content_lines.append(f"模型: {model or 'N/A'}  时间: {ts}")
                        content_lines.append(f"\n{'─'*40}\n{result or '无分析结果'}")
                    else:
                        self._learn_set_preview(f"未找到 {cve_id} 的AI分析记录。")
                        return
                    topic_hint = f"AI安全分析解读 ({cve_id})"

                elif db_type == "学习对话记录":
                    # sub_val 格式 "#123 主题名... [层次] (2026-03-07 19:00)"
                    import re
                    m = re.match(r'#(\d+)', sub_val)
                    if not m:
                        self._learn_set_preview("无法解析对话记录ID。")
                        return
                    session_id = int(m.group(1))
                    cursor.execute(
                        "SELECT topic, level, source_type, source_content, conversation, summary, created_at "
                        "FROM learn_sessions WHERE id = ?",
                        (session_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        topic, level, src_type, src_content, conv_json, summary, ts = row
                        content_lines.append(f"【费曼学习对话记录 #{session_id}】")
                        content_lines.append(f"主题: {topic or 'N/A'}")
                        content_lines.append(f"层次: {level or 'N/A'}  数据源: {src_type or 'N/A'}")
                        content_lines.append(f"时间: {ts}")
                        if summary:
                            content_lines.append(f"\n【学习摘要】\n{summary}")
                        if conv_json:
                            try:
                                msgs = json.loads(conv_json)
                                content_lines.append(f"\n{'─'*40}\n【对话内容 ({len(msgs)} 条消息)】")
                                for msg in msgs:
                                    role = msg.get('role', '')
                                    text = msg.get('content', '')
                                    if role == 'system':
                                        continue
                                    label = "👤 用户" if role == 'user' else "🤖 AI导师"
                                    content_lines.append(f"\n{label}:\n{text}")
                            except json.JSONDecodeError:
                                content_lines.append(conv_json)
                        if src_content:
                            content_lines.append(f"\n{'─'*40}\n【原始参考资料（节选）】\n{src_content[:2000]}")
                    else:
                        self._learn_set_preview(f"未找到对话记录 #{session_id}。")
                        return
                    topic_hint = f"复习: {topic or '学习对话'}"

                else:
                    return

            self.learn_source_content = "\n".join(content_lines)
            self._learn_set_preview(self.learn_source_content)
            # 自动填入建议主题
            current = self.learn_topic_entry.get().strip()
            if not current or current.startswith(("CVE漏洞分析", "Dell安全公告", "IT新闻", "AI安全", "复习:")):
                self.learn_topic_entry.delete(0, tk.END)
                self.learn_topic_entry.insert(0, topic_hint)
            self.learn_status_label.config(
                text=f"已加载: {db_type} — {sub_val[:40]}"
            )
            # 自动生成摘要（后台线程）
            threading.Thread(target=self._generate_content_summary, args=(self.learn_source_content, db_type), daemon=True).start()
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
            self.learn_source_content = content[:16000]  # 最多16000字符作为上下文
            preview = content[:600] + ("\n..." if len(content) > 600 else "")
            self._learn_set_preview(preview)
            # 用文件名作为主题提示
            fname = Path(path).stem
            self.learn_topic_entry.delete(0, tk.END)
            self.learn_topic_entry.insert(0, fname)
            self.learn_status_label.config(
                text=f"已加载文件: {Path(path).name}  ({len(content)} 字符)"
            )
            # 自动生成摘要（后台线程）
            threading.Thread(target=self._generate_content_summary, args=(content, "本地文件"), daemon=True).start()
        except Exception as e:
            self._learn_set_preview(f"文件读取失败: {e}")

    def _fetch_learn_url(self):
        """从网页 URL 抓取内容用于学习（Exa API 优先，HTTP 回退）"""
        url = self.learn_url_entry.get().strip()
        if not url:
            messagebox.showwarning("提示", "请输入网页 URL。")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.learn_url_entry.delete(0, tk.END)
            self.learn_url_entry.insert(0, url)

        self.learn_url_fetch_btn.config(state=tk.DISABLED, text="抓取中...")
        self.learn_status_label.config(text=f"正在抓取网页内容: {url[:60]}...")
        self._learn_set_preview("正在抓取网页内容，请稍候...")

        threading.Thread(
            target=self._fetch_learn_url_thread,
            args=(url,),
            daemon=True
        ).start()

    def _fetch_learn_url_thread(self, url: str):
        """后台线程：抓取网页内容"""
        content = ""
        source_label = ""

        # 1. 优先使用 Exa API
        exa_api_key = os.getenv("EXA_API_KEY")
        if exa_api_key:
            try:
                import requests as req
                response = req.post(
                    "https://api.exa.ai/contents",
                    headers={
                        "accept": "application/json",
                        "content-type": "application/json",
                        "x-api-key": exa_api_key,
                    },
                    json={"ids": [url], "text": True},
                    timeout=30,
                )
                if response.status_code == 200:
                    results = response.json().get("results", [])
                    if results:
                        content = results[0].get("text", "")
                        source_label = "Exa API"
            except Exception as e:
                self.root.after(0, self.log, f"Exa API 抓取失败，尝试 HTTP 回退: {e}")

        # 2. HTTP + BeautifulSoup 回退
        if not content:
            try:
                import requests as req
                from bs4 import BeautifulSoup
                resp = req.get(
                    url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    },
                    timeout=30,
                )
                resp.raise_for_status()
                soup = BeautifulSoup(resp.text, 'html.parser')
                # 提取页面标题
                title_tag = soup.find('title')
                page_title = title_tag.get_text(strip=True) if title_tag else ""
                # 清理噪声标签
                for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                    tag.decompose()
                content = soup.get_text(separator='\n', strip=True)
                if page_title and not content.startswith(page_title):
                    content = page_title + "\n\n" + content
                source_label = "HTTP"
            except Exception as e:
                self.root.after(
                    0, self._learn_fetch_url_done, "",
                    f"网页抓取失败: {e}", url
                )
                return

        self.root.after(0, self._learn_fetch_url_done, content, source_label, url)

    def _learn_fetch_url_done(self, content: str, info: str, url: str):
        """网页抓取完成回调（主线程）"""
        self.learn_url_fetch_btn.config(state=tk.NORMAL, text="抓取")

        if not content:
            self._learn_set_preview(f"未能获取网页内容。\n{info}")
            self.learn_status_label.config(text=f"抓取失败: {info}")
            return

        self.learn_source_content = content[:16000]
        char_count = len(content)
        preview = content[:800] + ("\n..." if char_count > 800 else "")
        self._learn_set_preview(preview)

        # 自动填入 URL 域名作为主题提示
        current = self.learn_topic_entry.get().strip()
        if not current or current in ("CVE漏洞分析",):
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                self.learn_topic_entry.delete(0, tk.END)
                self.learn_topic_entry.insert(0, f"网页学习: {domain}")
            except Exception:
                pass

        self.learn_status_label.config(
            text=f"已加载网页 ({info}): {url[:50]}  ({char_count} 字符)"
        )
        self.log(f"网页内容已加载用于学习: {url} ({char_count} 字符, {info})")

        # 自动生成摘要（后台线程）
        threading.Thread(target=self._generate_content_summary, args=(content, "网页"), daemon=True).start()

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

    def _generate_content_summary(self, content: str, source_type: str):
        """后台线程：生成资料的自动摘要、主题和建议问题"""
        try:
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                return

            model = os.getenv("QWEN_MODEL", "qwen3.6-plus")
            base_url = os.getenv(
                "QWEN_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1"
            )

            # 限制内容长度
            content_preview = content[:3000] if len(content) > 3000 else content

            prompt = f"""请分析以下{source_type}内容，生成结构化的学习辅助信息。

内容：
{content_preview}

请严格按以下 JSON 格式返回，不要添加任何其他文字或 markdown 标记：
{{
  "summary": "用 2-3 句话概括核心内容",
  "key_topics": ["提取 3-5 个核心主题或关键概念"],
  "suggested_questions": ["生成 5 个适合学习的问题，从浅到深"]
}}

要求：
1. 摘要要简洁准确，突出核心价值
2. 主题要具体明确，便于后续学习
3. 问题要有层次感，覆盖理解、应用、分析等不同层次
4. 仅返回 JSON，不要有任何其他内容"""

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一位专业的学习内容分析专家。仅返回纯 JSON，不要使用 markdown 代码块。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500,
            )
            reply = response.choices[0].message.content.strip()

            # 清理 markdown 代码块标记
            if reply.startswith("```"):
                lines = reply.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                reply = "\n".join(lines)

            result = json.loads(reply)

            # 在主线程更新 UI
            self.root.after(0, self._display_content_summary, result)

        except Exception as e:
            self.log(f"生成摘要失败: {e}")

    def _display_content_summary(self, result: dict):
        """在主线程显示摘要结果"""
        try:
            summary = result.get("summary", "")
            key_topics = result.get("key_topics", [])
            suggested_questions = result.get("suggested_questions", [])

            # 显示摘要和主题
            self.learn_summary_text.config(state=tk.NORMAL)
            self.learn_summary_text.delete("1.0", tk.END)

            if summary:
                self.learn_summary_text.insert(tk.END, "📝 核心摘要\n", "header")
                self.learn_summary_text.insert(tk.END, f"{summary}\n\n")

            if key_topics:
                self.learn_summary_text.insert(tk.END, "🔑 核心主题\n", "header")
                for i, topic in enumerate(key_topics, 1):
                    self.learn_summary_text.insert(tk.END, f"{i}. {topic}\n")

            self.learn_summary_text.tag_config("header", foreground=self.primary_color, font=("Microsoft YaHei", 9, "bold"))
            self.learn_summary_text.config(state=tk.DISABLED)

            # 显示建议问题（可点击）
            for widget in self.learn_questions_frame.winfo_children():
                widget.destroy()

            for i, question in enumerate(suggested_questions[:5], 1):
                btn = tk.Button(
                    self.learn_questions_frame,
                    text=f"{i}. {question}",
                    command=lambda q=question: self._fill_question(q),
                    bg="#e8f4fd", fg="#2c3e50",
                    font=("Microsoft YaHei", 8), anchor="w",
                    relief=tk.FLAT, cursor="hand2", padx=6, pady=3
                )
                btn.pack(fill=tk.X, pady=1)

            self.learn_status_label.config(text="✨ 智能摘要已生成")

        except Exception as e:
            self.log(f"显示摘要失败: {e}")

    def _fill_question(self, question: str):
        """将建议问题填入用户输入框"""
        self.learn_user_input.delete("1.0", tk.END)
        self.learn_user_input.insert("1.0", question)
        self.learn_user_input.focus_set()

    def _generate_artifact(self, artifact_type: str):
        """生成学习产物（时间线/思维导图/学习指南/FAQ/播客）"""
        if not self.learn_messages or len(self.learn_messages) < 3:
            messagebox.showwarning("提示", "请先进行至少一轮学习对话，再生成学习产物。")
            return

        # 禁用按钮
        buttons = {
            "timeline": self.learn_timeline_btn,
            "mindmap": self.learn_mindmap_btn,
            "guide": self.learn_guide_btn,
            "faq": self.learn_faq_btn,
            "podcast": self.learn_podcast_btn
        }
        btn = buttons.get(artifact_type)
        if btn:
            btn.config(state=tk.DISABLED, text="生成中...")

        self.learn_status_label.config(text=f"正在生成{self._get_artifact_name(artifact_type)}...")
        threading.Thread(
            target=self._generate_artifact_thread,
            args=(artifact_type,),
            daemon=True
        ).start()

    def _get_artifact_name(self, artifact_type: str) -> str:
        """获取产物类型的中文名称"""
        names = {
            "timeline": "学习时间线",
            "mindmap": "思维导图",
            "guide": "学习指南",
            "faq": "常见问题",
            "podcast": "对话播客"
        }
        return names.get(artifact_type, "学习产物")

    def _generate_artifact_thread(self, artifact_type: str):
        """后台线程：生成学习产物"""
        try:
            try:
                client, model = _make_qwen_client(timeout=120)
            except ValueError as e:
                self.root.after(0, messagebox.showerror, "配置错误", str(e))
                return

            # 提取对话内容
            conv_text = ""
            for m in self.learn_messages:
                if m.get("role") in ("user", "assistant"):
                    role_label = "学习者" if m["role"] == "user" else "导师"
                    conv_text += f"{role_label}: {m['content']}\n\n"
            conv_text = conv_text[:4000]  # 限制长度

            topic = getattr(self, 'learn_topic', '') or "未知主题"

            # 根据类型生成不同的 prompt
            prompts = self._get_artifact_prompts(topic, conv_text, artifact_type)
            prompt = prompts.get(artifact_type, prompts["guide"])

            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一位专业的学习内容组织专家，擅长将学习对话转化为结构化的学习资料。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=3000,
            )
            content = response.choices[0].message.content.strip()

            # 保存到数据库
            session_id = getattr(self, 'current_session_id', None)
            artifact_name = self._get_artifact_name(artifact_type)
            title = f"{artifact_name}：{topic}"

            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """INSERT INTO learn_artifacts
                       (session_id, topic, artifact_type, title, content, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (session_id, topic, artifact_type, title, content,
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                self.conn.commit()

            # 在主线程显示结果
            self.root.after(0, self._show_artifact_result, artifact_type, title, content)

        except Exception as e:
            err = f"生成{self._get_artifact_name(artifact_type)}失败: {e}"
            self.root.after(0, messagebox.showerror, "生成失败", err)
            self.root.after(0, self.learn_status_label.config, {"text": err})
        finally:
            # 恢复按钮状态
            buttons = {
                "timeline": (self.learn_timeline_btn, "📅 生成时间线"),
                "mindmap": (self.learn_mindmap_btn, "🧠 生成思维导图"),
                "guide": (self.learn_guide_btn, "📖 生成学习指南"),
                "faq": (self.learn_faq_btn, "❓ 生成 FAQ"),
                "podcast": (self.learn_podcast_btn, "🎙 生成对话播客")
            }
            btn_info = buttons.get(artifact_type)
            if btn_info:
                btn, text = btn_info
                self.root.after(0, btn.config, {"state": tk.NORMAL, "text": text})

    def _get_artifact_prompts(self, topic: str, conv_text: str, artifact_type: str) -> dict:
        """获取不同类型产物的生成提示词"""
        return {
            "timeline": f"""基于以下关于「{topic}」的学习对话，生成学习时间线。

对话内容：
{conv_text}

请生成一个 Markdown 格式的学习时间线，包含：
1. 学习的主要阶段（按时间顺序）
2. 每个阶段的关键理解和突破
3. 遇到的困难和解决方法
4. 知识点之间的递进关系

格式示例：
## 学习时间线：{topic}

### 阶段 1：初步理解（第 1-2 轮对话）
- 🎯 目标：理解基本概念
- 💡 关键突破：...
- 🤔 困惑点：...

### 阶段 2：深入探索（第 3-4 轮对话）
...

仅返回 Markdown 内容，不要有其他说明。""",

            "mindmap": f"""基于以下关于「{topic}」的学习对话，生成思维导图。

对话内容：
{conv_text}

请生成一个 Mermaid 格式的思维导图，展示：
1. 核心概念及其层次结构
2. 概念之间的关系
3. 关键知识点

**重要**：请严格按照以下格式返回，不要添加任何 markdown 代码块标记（不要用 ```mermaid）：

mindmap
  root(({topic}))
    核心概念1
      子概念1.1
      子概念1.2
    核心概念2
      子概念2.1
      子概念2.2

仅返回纯 Mermaid 代码，从 mindmap 开始，不要有任何其他说明或标记。""",

            "guide": f"""基于以下关于「{topic}」的学习对话，生成学习指南。

对话内容：
{conv_text}

请生成一个结构化的学习指南，包含：
1. 学习目标
2. 前置知识
3. 核心概念清单
4. 学习路径（分步骤）
5. 实践建议
6. 进阶方向

使用 Markdown 格式，清晰易读。仅返回内容，不要有其他说明。""",

            "faq": f"""基于以下关于「{topic}」的学习对话，生成常见问题解答（FAQ）。

对话内容：
{conv_text}

请生成 5-8 个常见问题及其解答，包含：
1. 基础概念问题
2. 常见误解
3. 实际应用问题
4. 进阶问题

格式示例：
## 常见问题解答：{topic}

### Q1: [问题]
**A:** [简洁的回答]

### Q2: [问题]
**A:** [简洁的回答]

仅返回 Markdown 内容，不要有其他说明。""",

            "podcast": f"""基于以下关于「{topic}」的学习对话，生成一段双人对话式播客脚本。

对话内容：
{conv_text}

要求：
1. 对话要自然流畅，像真实的播客节目
2. 主持人 A（提问者）和主持人 B（讲解者）
3. 时长约 3-5 分钟（约 800-1200 字）
4. 用通俗易懂的语言解释技术概念

格式示例：
主持人 A：大家好，欢迎来到今天的节目。今天我们要聊聊{topic}。

主持人 B：是的，这是一个很重要的话题。根据我们的学习...

仅返回对话脚本，不要有其他说明。"""
        }

    def _show_artifact_result(self, artifact_type: str, title: str, content: str):
        """在弹窗中显示生成的学习产物"""
        if artifact_type == "podcast":
            self.news_podcast_area.delete(1.0, tk.END)
            self.news_podcast_area.insert(tk.END, content)
            self.tts_status_label.config(text="学习播客脚本已生成，可点击播放")

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)

        # 添加窗口控制按钮
        self._add_window_controls(dialog)

        # 标题栏
        tk.Label(
            dialog, text=title,
            font=("Microsoft YaHei", 11, "bold"),
            bg="#2c3e50", fg="white", padx=10, pady=10
        ).pack(fill=tk.X)

        # 工具栏（按钮区域，紧贴标题栏下方，始终可见）
        btn_frame = tk.Frame(dialog, bg="#ecf0f1", pady=6)
        btn_frame.pack(fill=tk.X, padx=0)

        tk.Button(
            btn_frame, text="💾 保存到文件",
            command=lambda: self._save_artifact_to_file(artifact_type, title, content),
            bg=self.success_color, fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, text="💾 保存到数据库",
            command=lambda: self._save_artifact_to_db(artifact_type, title, content),
            bg="#8e44ad", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, text="📋 复制到剪贴板",
            command=lambda: self._copy_to_clipboard(content),
            bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=5)

        if artifact_type == "podcast":
            tk.Button(
                btn_frame, text="▶ 播放语音",
                command=lambda: self._play_artifact_tts(content),
                bg="#e67e22", fg="white",
                font=("Microsoft YaHei", 9, "bold"),
                relief=tk.FLAT, cursor="hand2", padx=12, pady=4
            ).pack(side=tk.LEFT, padx=5)

            tk.Button(
                btn_frame, text="⏹ 停止",
                command=self._stop_podcast_tts,
                bg="#c0392b", fg="white",
                font=("Microsoft YaHei", 9, "bold"),
                relief=tk.FLAT, cursor="hand2", padx=12, pady=4
            ).pack(side=tk.LEFT, padx=5)

        if artifact_type == "mindmap":
            tk.Button(
                btn_frame, text="🖼 保存思维导图图片",
                command=lambda: self._save_mindmap_image(content, title),
                bg="#16a085", fg="white",
                font=("Microsoft YaHei", 9, "bold"),
                relief=tk.FLAT, cursor="hand2", padx=12, pady=4
            ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, text="关闭", command=dialog.destroy,
            bg="#95a5a6", fg="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.RIGHT, padx=5)

        # 内容区域
        if artifact_type == "mindmap":
            # 思维导图专用布局：Canvas 占满主区域，源码折叠在底部
            self._render_mindmap_canvas_full(dialog, content)
        else:
            # 其他产物：纯文本展示
            text_frame = tk.Frame(dialog)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            text = scrolledtext.ScrolledText(
                text_frame, wrap=tk.WORD, font=("Consolas", 15), bg="#f8f9fa"
            )
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(tk.END, content)
            text.config(state=tk.DISABLED)

        self.learn_status_label.config(text=f"✅ {self._get_artifact_name(artifact_type)}已生成")

        # 统一尺寸并居中
        self._center_window(dialog, 1350, 1050)

    def _copy_to_clipboard(self, text: str):
        """复制文本到剪贴板"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("成功", "内容已复制到剪贴板")
        except Exception as e:
            messagebox.showerror("失败", f"复制失败: {e}")

    def _save_artifact_to_file(self, artifact_type: str, title: str, content: str):
        """保存学习产物到文件"""
        # 根据类型确定文件扩展名
        ext_map = {
            "mindmap": ".mmd",  # Mermaid 文件
            "timeline": ".md",
            "guide": ".md",
            "faq": ".md",
            "podcast": ".txt"
        }
        default_ext = ext_map.get(artifact_type, ".txt")

        # 生成默认文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
        default_filename = f"{safe_title}_{timestamp}{default_ext}"

        # 文件类型过滤器
        filetypes = [
            ("Markdown 文件", "*.md"),
            ("文本文件", "*.txt"),
            ("Mermaid 文件", "*.mmd"),
            ("所有文件", "*.*")
        ]

        filepath = filedialog.asksaveasfilename(
            title="保存学习产物",
            initialfile=default_filename,
            defaultextension=default_ext,
            filetypes=filetypes
        )

        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("成功", f"已保存到：\n{filepath}")
            self.log(f"学习产物已保存: {filepath}")
        except Exception as e:
            messagebox.showerror("失败", f"保存失败: {e}")

    def _save_artifact_to_db(self, artifact_type: str, title: str, content: str):
        """将学习产物保存到数据库 learn_artifacts 表（参考保存对话按钮）"""
        topic = getattr(self, 'learn_topic', '') or "未命名主题"
        session_id = getattr(self, 'current_session_id', None)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """INSERT INTO learn_artifacts
                       (session_id, topic, artifact_type, title, content, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (session_id, topic, artifact_type, title, content, ts)
                )
                self.conn.commit()
                artifact_id = cursor.lastrowid
            self.log(f"学习产物已保存到数据库: #{artifact_id} - {title}")
            messagebox.showinfo(
                "保存成功",
                f"学习产物已保存到数据库。\n\n"
                f"记录编号: #{artifact_id}\n"
                f"类型: {self._get_artifact_name(artifact_type)}\n"
                f"主题: {topic}\n\n"
                f"可在「Dell技术库」标签页选择数据源「学习产物」一并导出。"
            )
        except Exception as e:
            self.log(f"保存学习产物到数据库失败: {e}")
            messagebox.showerror("保存失败", f"保存到数据库时出错：\n{e}")

    def _play_artifact_tts(self, text: str):
        """播放学习产物（如播客脚本）的 TTS 语音"""
        if not text or not text.strip():
            messagebox.showwarning("提示", "内容为空，无法播放")
            return
        if self._tts_process and self._tts_process.poll() is None:
            messagebox.showinfo("提示", "正在播放中，请先点击停止")
            return

        # 获取选中的声音名称（复用新闻播客的声音设置）
        voice_name = ""
        try:
            idx = self.tts_voice_combo.current()
            voices = getattr(self, "_tts_voice_names", [""])
            if 0 <= idx < len(voices):
                voice_name = voices[idx]
        except Exception:
            pass

        try:
            self.tts_status_label.config(text="学习播客播放中...")
        except Exception:
            pass
        threading.Thread(target=self._tts_thread, args=(text, voice_name), daemon=True).start()

    # ============== 思维导图渲染 ==============

    def _parse_mindmap_text(self, content: str):
        """将 Mermaid mindmap 文本解析为缩进树结构。
        返回 root 节点 dict: {"label": str, "children": [...]}
        """
        # 去除可能的 ```mermaid 代码块包裹
        lines = content.replace("```mermaid", "").replace("```", "").splitlines()
        clean_lines = []
        for ln in lines:
            if not ln.strip():
                continue
            stripped = ln.strip().lower()
            if stripped.startswith("mindmap"):
                continue
            clean_lines.append(ln.rstrip())

        if not clean_lines:
            return {"label": getattr(self, 'learn_topic', '思维导图'), "children": []}

        def label_of(s: str) -> str:
            t = s.strip()
            # 清理 root((xxx)) / (xxx) / [xxx] 等包裹
            for pair in (("root((", "))"), ("((", "))"), ("(", ")"), ("[", "]"), ("{", "}")):
                if t.startswith(pair[0]) and t.endswith(pair[1]):
                    t = t[len(pair[0]):-len(pair[1])]
                    break
            if t.lower().startswith("root"):
                t = t[4:].lstrip("(").rstrip(")").strip()
            return t or "节点"

        def indent_of(s: str) -> int:
            return len(s) - len(s.lstrip(" \t"))

        # 第一行是 root；如果首行 indent 与后续相同，仍按最浅缩进作为根
        indents = [indent_of(ln) for ln in clean_lines]
        min_indent = min(indents)

        root = {"label": label_of(clean_lines[0]), "children": []}
        stack = [(min_indent, root)]

        for ln in clean_lines[1:]:
            ind = indent_of(ln)
            node = {"label": label_of(ln), "children": []}
            while stack and stack[-1][0] >= ind:
                stack.pop()
            if not stack:
                stack.append((min_indent, root))
            stack[-1][1]["children"].append(node)
            stack.append((ind, node))

        return root

    def _layout_mindmap(self, root):
        """计算每个节点的 (x, y, w, h) 坐标。返回 (节点列表, 连接列表, 总宽, 总高)"""
        H_GAP = 40   # 横向间距
        V_GAP = 12   # 纵向间距
        NODE_H = 32
        CHAR_W = 12  # 每个字符宽度（中文）
        PAD = 30

        # 计算每个节点的高度（子树纵向占用）
        def measure(node, depth=0):
            label = node["label"][:30]
            w = max(80, len(label) * CHAR_W + 20)
            node["_w"] = w
            node["_depth"] = depth
            if not node["children"]:
                node["_h"] = NODE_H
            else:
                ch = sum(measure(c, depth + 1) for c in node["children"])
                ch += V_GAP * (len(node["children"]) - 1)
                node["_h"] = max(NODE_H, ch)
            return node["_h"]

        measure(root)

        # 计算每个深度层的最大宽度（用于列对齐）
        col_w = {}
        def collect_w(node):
            d = node["_depth"]
            col_w[d] = max(col_w.get(d, 0), node["_w"])
            for c in node["children"]:
                collect_w(c)
        collect_w(root)

        # 计算每个深度的 x 起点
        col_x = {}
        cx = PAD
        for d in sorted(col_w.keys()):
            col_x[d] = cx
            cx += col_w[d] + H_GAP

        nodes = []
        edges = []

        def place(node, y_start):
            x = col_x[node["_depth"]]
            y = y_start + node["_h"] // 2 - NODE_H // 2
            node["_x"] = x
            node["_y"] = y
            nodes.append(node)
            # 子节点
            cy = y_start
            for c in node["children"]:
                place(c, cy)
                edges.append((node, c))
                cy += c["_h"] + V_GAP

        place(root, PAD)

        total_w = cx + PAD
        total_h = root["_h"] + 2 * PAD
        return nodes, edges, total_w, total_h

    def _render_mindmap_canvas_full(self, parent, content: str):
        """思维导图专用布局：Canvas 占满主区域，Mermaid 源码可折叠"""
        try:
            root_node = self._parse_mindmap_text(content)
            nodes, edges, total_w, total_h = self._layout_mindmap(root_node)
        except Exception as e:
            tk.Label(parent, text=f"思维导图渲染失败: {e}", fg="red").pack()
            return

        # 思维导图 Canvas 区域（占满剩余空间）
        canvas_container = tk.Frame(parent, bg="white", relief=tk.SOLID, bd=1)
        canvas_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 0))

        canvas = tk.Canvas(
            canvas_container, bg="white",
            scrollregion=(0, 0, total_w, total_h),
            highlightthickness=0
        )
        hscroll = tk.Scrollbar(canvas_container, orient=tk.HORIZONTAL, command=canvas.xview)
        vscroll = tk.Scrollbar(canvas_container, orient=tk.VERTICAL, command=canvas.yview)
        canvas.config(xscrollcommand=hscroll.set, yscrollcommand=vscroll.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        canvas_container.columnconfigure(0, weight=1)
        canvas_container.rowconfigure(0, weight=1)

        self._draw_mindmap_on_canvas(canvas, nodes, edges)
        self._last_mindmap_size = (total_w, total_h)
        self._last_mindmap_nodes = nodes
        self._last_mindmap_edges = edges

        # 鼠标滚轮缩放/滚动
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)

        # 可折叠的 Mermaid 源码区域
        source_frame = tk.Frame(parent, bg="#f8f9fa")
        source_frame.pack(fill=tk.X, padx=8, pady=(4, 8))

        is_expanded = [False]
        source_text = [None]

        def toggle_source():
            if is_expanded[0]:
                source_text[0].pack_forget()
                toggle_btn.config(text="▶ 显示 Mermaid 源码")
                is_expanded[0] = False
            else:
                if source_text[0] is None:
                    source_text[0] = scrolledtext.ScrolledText(
                        source_frame, wrap=tk.WORD,
                        font=("Consolas", 10), bg="#f8f9fa",
                        height=8
                    )
                    source_text[0].insert(tk.END, content)
                    source_text[0].config(state=tk.DISABLED)
                source_text[0].pack(fill=tk.X, padx=4, pady=(0, 4))
                toggle_btn.config(text="▼ 隐藏 Mermaid 源码")
                is_expanded[0] = True

        toggle_btn = tk.Button(
            source_frame, text="▶ 显示 Mermaid 源码",
            command=toggle_source,
            bg="#bdc3c7", fg="#2c3e50",
            font=("Microsoft YaHei", 8),
            relief=tk.FLAT, cursor="hand2", padx=8, pady=2
        )
        toggle_btn.pack(anchor="w", padx=4, pady=4)

    def _render_mindmap_canvas(self, parent, content: str):
        """在 parent 中渲染思维导图 Canvas（带滚动条）"""
        try:
            root_node = self._parse_mindmap_text(content)
            nodes, edges, total_w, total_h = self._layout_mindmap(root_node)
        except Exception as e:
            tk.Label(parent, text=f"思维导图渲染失败: {e}", fg="red").pack()
            return

        # 容器：固定高度 + 横纵向滚动条
        container = tk.Frame(parent, bg="white", relief=tk.SOLID, bd=1)
        container.pack(fill=tk.X, pady=(0, 8))

        canvas_h = min(420, max(200, total_h + 20))
        canvas = tk.Canvas(
            container, bg="white", height=canvas_h,
            scrollregion=(0, 0, total_w, total_h),
            highlightthickness=0
        )
        hscroll = tk.Scrollbar(container, orient=tk.HORIZONTAL, command=canvas.xview)
        vscroll = tk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        canvas.config(xscrollcommand=hscroll.set, yscrollcommand=vscroll.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        self._draw_mindmap_on_canvas(canvas, nodes, edges)
        # 保存绘图所需信息以便导出图片
        self._last_mindmap_size = (total_w, total_h)
        self._last_mindmap_nodes = nodes
        self._last_mindmap_edges = edges

    def _draw_mindmap_on_canvas(self, canvas, nodes, edges):
        """在 canvas 上绘制节点和连线"""
        # 不同深度使用不同颜色
        palette = [
            "#3498db", "#2ecc71", "#e67e22", "#9b59b6",
            "#1abc9c", "#e74c3c", "#34495e", "#f39c12"
        ]
        NODE_H = 32

        # 先画连线（贝塞尔曲线效果用直线近似）
        for parent, child in edges:
            x1 = parent["_x"] + parent["_w"]
            y1 = parent["_y"] + NODE_H // 2
            x2 = child["_x"]
            y2 = child["_y"] + NODE_H // 2
            mid = (x1 + x2) // 2
            canvas.create_line(
                x1, y1, mid, y1, mid, y2, x2, y2,
                fill="#7f8c8d", width=2, smooth=True
            )

        # 再画节点
        for node in nodes:
            x = node["_x"]
            y = node["_y"]
            w = node["_w"]
            depth = node["_depth"]
            color = palette[depth % len(palette)]
            label = node["label"][:30]
            # 圆角矩形（用矩形 + 椭圆模拟）
            canvas.create_rectangle(
                x, y, x + w, y + NODE_H,
                fill=color, outline=color, width=1
            )
            canvas.create_text(
                x + w // 2, y + NODE_H // 2,
                text=label, fill="white",
                font=("Microsoft YaHei", 10, "bold")
            )

    def _save_mindmap_image(self, content: str, title: str):
        """将思维导图保存为 PNG（需要 Pillow）或 PostScript 文件"""
        try:
            root_node = self._parse_mindmap_text(content)
            nodes, edges, total_w, total_h = self._layout_mindmap(root_node)
        except Exception as e:
            messagebox.showerror("失败", f"思维导图解析失败: {e}")
            return

        # 创建一个离屏 Canvas 来绘制
        offscreen = tk.Toplevel(self.root)
        offscreen.withdraw()  # 隐藏窗口
        canvas = tk.Canvas(
            offscreen, width=total_w, height=total_h,
            bg="white", highlightthickness=0
        )
        canvas.pack()
        self._draw_mindmap_on_canvas(canvas, nodes, edges)
        canvas.update()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()

        # 优先尝试 PNG（Pillow）
        try:
            from PIL import Image, ImageDraw, ImageFont
            has_pillow = True
        except ImportError:
            has_pillow = False

        if has_pillow:
            filetypes = [("PNG 图片", "*.png"), ("PostScript 文件", "*.ps"), ("所有文件", "*.*")]
            default_ext = ".png"
        else:
            filetypes = [("PostScript 文件", "*.ps"), ("所有文件", "*.*")]
            default_ext = ".ps"

        filepath = filedialog.asksaveasfilename(
            title="保存思维导图图片",
            initialfile=f"{safe_title}_{timestamp}{default_ext}",
            defaultextension=default_ext,
            filetypes=filetypes
        )

        if not filepath:
            offscreen.destroy()
            return

        try:
            if filepath.lower().endswith(".png") and has_pillow:
                # 直接用 Pillow 重新绘制为 PNG（更可靠）
                img = Image.new("RGB", (int(total_w), int(total_h)), "white")
                draw = ImageDraw.Draw(img)
                try:
                    font = ImageFont.truetype("msyh.ttc", 14)
                except Exception:
                    try:
                        font = ImageFont.truetype("simhei.ttf", 14)
                    except Exception:
                        font = ImageFont.load_default()

                palette = ["#3498db", "#2ecc71", "#e67e22", "#9b59b6",
                           "#1abc9c", "#e74c3c", "#34495e", "#f39c12"]
                NODE_H = 32

                for parent, child in edges:
                    x1 = parent["_x"] + parent["_w"]
                    y1 = parent["_y"] + NODE_H // 2
                    x2 = child["_x"]
                    y2 = child["_y"] + NODE_H // 2
                    mid = (x1 + x2) // 2
                    draw.line([(x1, y1), (mid, y1), (mid, y2), (x2, y2)], fill="#7f8c8d", width=2)

                for node in nodes:
                    x, y, w = node["_x"], node["_y"], node["_w"]
                    color = palette[node["_depth"] % len(palette)]
                    label = node["label"][:30]
                    draw.rectangle([x, y, x + w, y + NODE_H], fill=color, outline=color)
                    # 文本居中
                    try:
                        bbox = draw.textbbox((0, 0), label, font=font)
                        tw = bbox[2] - bbox[0]
                        th = bbox[3] - bbox[1]
                    except Exception:
                        tw, th = len(label) * 12, 14
                    draw.text((x + (w - tw) // 2, y + (NODE_H - th) // 2),
                              label, fill="white", font=font)
                img.save(filepath, "PNG")
            else:
                # PostScript 输出（tkinter 原生支持）
                canvas.postscript(file=filepath, colormode="color",
                                  width=total_w, height=total_h)
            messagebox.showinfo("成功", f"思维导图已保存到：\n{filepath}")
            self.log(f"思维导图图片已保存: {filepath}")
        except Exception as e:
            messagebox.showerror("失败", f"保存图片失败: {e}")
        finally:
            offscreen.destroy()


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
            snippet = self.learn_source_content[:6000]
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

            model = os.getenv("QWEN_MODEL", "qwen3.6-plus")
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
                max_tokens=2500,
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
        self.learn_save_btn.config(state=state)

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

    def _save_learn_session(self):
        """保存当前费曼学习对话到数据库"""
        if not self.learn_messages or len(self.learn_messages) < 2:
            messagebox.showwarning("提示", "当前没有可保存的对话内容。\n请先开始一次学习会话。")
            return

        topic = getattr(self, 'learn_topic', '') or self.learn_topic_entry.get().strip() or "未命名主题"
        level = self.learn_level_var.get()
        source_type = self.learn_db_type_combo.get() if self.learn_source_var.get() == "db" else "本地文件"
        source_content = getattr(self, 'learn_source_content', '') or ''

        # 过滤 system 消息，只保存用户和 AI 的对话
        save_msgs = [m for m in self.learn_messages if m.get('role') != 'system']
        if not save_msgs:
            messagebox.showwarning("提示", "对话内容为空，无法保存。")
            return

        # 生成摘要：取最后一条 AI 回复的前 200 字符
        summary = ""
        for m in reversed(self.learn_messages):
            if m.get('role') == 'assistant':
                summary = m.get('content', '')[:200]
                break

        conv_json = json.dumps(save_msgs, ensure_ascii=False)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "INSERT INTO learn_sessions (topic, level, source_type, source_content, conversation, summary, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (topic, level, source_type, source_content[:8000], conv_json, summary, ts)
                )
                self.conn.commit()
                session_id = cursor.lastrowid

            self.log(f"学习对话已保存: #{session_id} - {topic}")
            self.learn_status_label.config(text=f"对话已保存: #{session_id} — {topic}")
            messagebox.showinfo("保存成功", f"学习对话已保存到数据库。\n\n记录编号: #{session_id}\n主题: {topic}\n对话轮数: {len(save_msgs)} 条\n\n可在数据源「学习对话记录」中重新加载。")
        except Exception as e:
            self.log(f"保存学习对话失败: {e}")
            messagebox.showerror("保存失败", f"保存对话时出错：\n{e}")

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

        base_prompt = prompts.get(level, prompts["入门"])

        # 增强提示词：添加来源引用与防幻觉约束
        citation_instruction = """

【重要约束】
1. 你的回答必须严格基于用户提供的学习资料，不要引入资料之外的信息
2. 当引用资料中的具体信息时，在句子末尾添加 [📚] 标记
3. 如果用户的问题无法从资料中找到答案，明确告知"资料中未提及此内容"
4. 保持回答的准确性和可追溯性，这是费曼学习法的核心要求"""

        return base_prompt + citation_instruction

    # ==================== 知识巩固：闪卡 & 问答 ====================

    def _generate_flashcards(self):
        """基于当前学习对话，让 AI 生成闪卡和选择题"""
        if not self.learn_messages or len(self.learn_messages) < 3:
            messagebox.showwarning("提示", "请先进行至少一轮学习对话，再生成闪卡。")
            return

        self.learn_gen_cards_btn.config(state=tk.DISABLED, text="正在生成...")
        self.learn_status_label.config(text="AI 正在生成闪卡和选择题...")
        threading.Thread(
            target=self._generate_flashcards_thread, daemon=True
        ).start()

    def _generate_flashcards_thread(self):
        """后台线程：调用 AI 生成闪卡和选择题"""
        try:
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            if not api_key:
                self.root.after(0, messagebox.showerror, "配置错误",
                                "未设置 QWEN_API_KEY，无法调用 AI")
                return

            model = os.getenv("QWEN_MODEL", "qwen3.6-plus")
            base_url = os.getenv(
                "QWEN_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1"
            )

            # 提取对话内容摘要
            conv_text = ""
            for m in self.learn_messages:
                if m["role"] in ("user", "assistant"):
                    conv_text += f"{m['content']}\n\n"
            conv_text = conv_text[:4000]  # 限制长度

            topic = getattr(self, 'learn_topic', '') or "未知主题"

            prompt = (
                f"基于以下关于「{topic}」的学习对话内容，生成学习卡片。\n\n"
                f"对话内容：\n{conv_text}\n\n"
                "请严格按以下 JSON 格式返回，不要添加任何其他文字、markdown标记或代码块标记：\n"
                '{"flashcards": [\n'
                '  {"question": "概念问题", "answer": "简明解释"}\n'
                '],\n'
                '"quizzes": [\n'
                '  {"question": "题目", "options": ["A. 选项1", "B. 选项2", "C. 选项3", "D. 选项4"], '
                '"correct": 0, "explanation": "解析"}\n'
                ']}\n\n'
                "要求：\n"
                "1. 生成 3-5 张闪卡（概念→解释），覆盖对话中的核心知识点\n"
                "2. 生成 3-5 道四选一选择题，correct 为正确选项索引(0-3)\n"
                "3. 题目应覆盖不同难度和知识点\n"
                "4. 仅返回 JSON，不要有任何其他内容"
            )

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一位教育专家，擅长将学习内容转化为闪卡和选择题。仅返回纯JSON，不要使用markdown代码块。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=3000,
            )
            reply = response.choices[0].message.content.strip()

            # 清理 markdown 代码块标记
            if reply.startswith("```"):
                lines = reply.split("\n")
                # 移除首尾的 ``` 行
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                reply = "\n".join(lines)

            data = json.loads(reply)
            flashcards = data.get("flashcards", [])
            quizzes = data.get("quizzes", [])

            saved_count = 0
            with self.db_lock:
                cursor = self.conn.cursor()
                for card in flashcards:
                    cursor.execute(
                        """INSERT INTO flashcards (topic, question, answer, card_type, difficulty)
                           VALUES (?, ?, ?, 'flashcard', 1)""",
                        (topic, card["question"], card["answer"])
                    )
                    saved_count += 1

                for quiz in quizzes:
                    options_json = json.dumps(quiz["options"], ensure_ascii=False)
                    explanation = quiz.get("explanation", "")
                    cursor.execute(
                        """INSERT INTO flashcards
                           (topic, question, answer, options, correct_option, card_type, difficulty)
                           VALUES (?, ?, ?, ?, ?, 'quiz', 2)""",
                        (topic, quiz["question"], explanation,
                         options_json, quiz["correct"])
                    )
                    saved_count += 1
                self.conn.commit()

            msg = f"已生成 {len(flashcards)} 张闪卡 + {len(quizzes)} 道选择题，共 {saved_count} 条"
            self.root.after(0, self._learn_append_message,
                            f"【知识巩固】{msg}\n可点击「知识问答」或「闪卡复习」进行练习。",
                            "system")
            self.root.after(0, self.learn_status_label.config, {"text": msg})
            self.root.after(0, messagebox.showinfo, "生成完成", msg)

        except json.JSONDecodeError as e:
            err = f"AI 返回格式解析失败: {e}"
            self.root.after(0, self._learn_append_message, err, "system")
            self.root.after(0, self.learn_status_label.config, {"text": err})
        except Exception as e:
            err = f"生成闪卡失败: {e}"
            self.root.after(0, self._learn_append_message, err, "system")
            self.root.after(0, self.learn_status_label.config, {"text": err})
        finally:
            self.root.after(0, self.learn_gen_cards_btn.config,
                            {"state": tk.NORMAL, "text": "🃏 AI 生成闪卡"})

    def _open_quiz_window(self):
        """打开知识问答窗口（选择题模式）"""
        topic = getattr(self, 'learn_topic', '') or self.learn_topic_entry.get().strip()

        # 从数据库获取该主题的选择题
        quizzes = []
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                if topic:
                    cursor.execute(
                        "SELECT id, question, answer, options, correct_option "
                        "FROM flashcards WHERE card_type='quiz' AND topic=? "
                        "ORDER BY RANDOM()", (topic,))
                else:
                    cursor.execute(
                        "SELECT id, question, answer, options, correct_option "
                        "FROM flashcards WHERE card_type='quiz' "
                        "ORDER BY RANDOM() LIMIT 20")
                quizzes = cursor.fetchall()
        except Exception as e:
            messagebox.showerror("错误", f"加载题目失败: {e}")
            return

        if not quizzes:
            messagebox.showinfo("提示",
                                "当前主题暂无选择题。\n请先进行学习对话，然后点击「AI 生成闪卡」。")
            return

        # 创建问答窗口
        quiz_win = tk.Toplevel(self.root)
        quiz_win.title(f"知识问答 — {topic or '全部主题'}")
        quiz_win.configure(bg="white")
        quiz_win.transient(self.root)
        quiz_win.grab_set()

        # 添加窗口控制按钮
        self._add_window_controls(quiz_win)

        # 状态变量
        quiz_state = {
            "index": 0,
            "score": 0,
            "total": len(quizzes),
            "answered": False,
        }

        # 顶部进度条
        progress_frame = tk.Frame(quiz_win, bg="#f0f0f0")
        progress_frame.pack(fill=tk.X, padx=15, pady=(12, 0))
        progress_label = tk.Label(
            progress_frame, text=f"第 1/{len(quizzes)} 题",
            bg="#f0f0f0", font=("Microsoft YaHei", 10, "bold"),
            fg=self.primary_color
        )
        progress_label.pack(side=tk.LEFT, padx=5)
        score_label = tk.Label(
            progress_frame, text="得分: 0",
            bg="#f0f0f0", font=("Microsoft YaHei", 10, "bold"),
            fg=self.success_color
        )
        score_label.pack(side=tk.RIGHT, padx=5)

        # 题目区域
        question_frame = tk.Frame(quiz_win, bg="white")
        question_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        question_label = tk.Label(
            question_frame, text="", bg="white",
            font=("Microsoft YaHei", 13), wraplength=580,
            justify=tk.LEFT, anchor="nw"
        )
        question_label.pack(fill=tk.X, pady=(5, 15))

        # 选项按钮容器
        options_frame = tk.Frame(question_frame, bg="white")
        options_frame.pack(fill=tk.X)
        option_buttons = []

        # 解析区域
        explain_label = tk.Label(
            question_frame, text="", bg="#f8f9fa",
            font=("Microsoft YaHei", 11), wraplength=580,
            justify=tk.LEFT, anchor="nw", padx=10, pady=8
        )

        def load_question(idx):
            """加载指定索引的题目"""
            if idx >= len(quizzes):
                show_result()
                return

            quiz_state["answered"] = False
            qid, question, explanation, options_json, correct = quizzes[idx]

            progress_label.config(text=f"第 {idx + 1}/{len(quizzes)} 题")
            question_label.config(text=question)
            explain_label.pack_forget()
            explain_label.config(text="")

            try:
                options = json.loads(options_json)
            except Exception:
                options = ["A. ?", "B. ?", "C. ?", "D. ?"]

            # 清除旧按钮
            for btn in option_buttons:
                btn.destroy()
            option_buttons.clear()

            for i, opt_text in enumerate(options):
                btn = tk.Button(
                    options_frame, text=opt_text,
                    font=("Microsoft YaHei", 11), bg="#f5f5f5",
                    fg="#333", anchor="w", padx=15, pady=8,
                    relief=tk.GROOVE, cursor="hand2",
                    command=lambda ci=i: on_answer(ci, correct, explanation)
                )
                btn.pack(fill=tk.X, pady=3)
                option_buttons.append(btn)

            next_btn.config(state=tk.DISABLED)

        def on_answer(chosen, correct, explanation):
            """用户选择答案"""
            if quiz_state["answered"]:
                return
            quiz_state["answered"] = True

            is_correct = (chosen == correct)
            if is_correct:
                quiz_state["score"] += 1

            score_label.config(text=f"得分: {quiz_state['score']}")

            # 高亮显示
            for i, btn in enumerate(option_buttons):
                if i == correct:
                    btn.config(bg="#27ae60", fg="white")
                elif i == chosen and not is_correct:
                    btn.config(bg="#e74c3c", fg="white")
                btn.config(state=tk.DISABLED)

            # 显示解析
            result_text = "正确! " if is_correct else "错误! "
            if explanation:
                result_text += f"\n解析: {explanation}"
            explain_label.config(
                text=result_text,
                bg="#e8f8f5" if is_correct else "#fdf2e9"
            )
            explain_label.pack(fill=tk.X, pady=(10, 0))

            # 更新数据库统计
            try:
                qid = quizzes[quiz_state["index"]][0]
                with self.db_lock:
                    cursor = self.conn.cursor()
                    cursor.execute(
                        "UPDATE flashcards SET review_count = review_count + 1"
                        + (", correct_count = correct_count + 1" if is_correct else "")
                        + " WHERE id = ?", (qid,))
                    self.conn.commit()
            except Exception:
                pass

            next_btn.config(state=tk.NORMAL)

        def next_question():
            """下一题"""
            quiz_state["index"] += 1
            load_question(quiz_state["index"])

        def show_result():
            """显示最终结果"""
            for btn in option_buttons:
                btn.destroy()
            option_buttons.clear()

            total = quiz_state["total"]
            score = quiz_state["score"]
            pct = round(score / total * 100) if total > 0 else 0

            if pct >= 80:
                emoji, comment = "🎉", "优秀！知识掌握扎实！"
            elif pct >= 60:
                emoji, comment = "👍", "不错！还有提升空间。"
            else:
                emoji, comment = "💪", "继续加油！建议复习闪卡。"

            question_label.config(
                text=f"\n{emoji} 答题完成！\n\n"
                     f"总题数: {total}\n"
                     f"正确数: {score}\n"
                     f"正确率: {pct}%\n\n"
                     f"{comment}",
                font=("Microsoft YaHei", 14), anchor="center"
            )
            explain_label.pack_forget()
            next_btn.config(state=tk.DISABLED)

        # 底部按钮栏
        bottom_frame = tk.Frame(quiz_win, bg="white")
        bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 12))

        next_btn = tk.Button(
            bottom_frame, text="下一题 →",
            command=next_question,
            bg=self.primary_color, fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=20, pady=6
        )
        next_btn.pack(side=tk.RIGHT)

        tk.Button(
            bottom_frame, text="关闭",
            command=quiz_win.destroy,
            bg="#95a5a6", fg="white",
            font=("Microsoft YaHei", 10),
            relief=tk.FLAT, cursor="hand2", padx=20, pady=6
        ).pack(side=tk.LEFT)

        # 加载第一题
        load_question(0)

        # 居中显示
        self._center_window(quiz_win, 650, 520)

    def _open_flashcard_window(self):
        """打开闪卡复习窗口（卡片翻转模式）"""
        topic = getattr(self, 'learn_topic', '') or self.learn_topic_entry.get().strip()

        # 从数据库获取闪卡
        cards = []
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                if topic:
                    cursor.execute(
                        "SELECT id, question, answer, review_count, correct_count "
                        "FROM flashcards WHERE card_type='flashcard' AND topic=? "
                        "ORDER BY RANDOM()", (topic,))
                else:
                    cursor.execute(
                        "SELECT id, question, answer, review_count, correct_count "
                        "FROM flashcards WHERE card_type='flashcard' "
                        "ORDER BY RANDOM() LIMIT 30")
                cards = cursor.fetchall()
        except Exception as e:
            messagebox.showerror("错误", f"加载闪卡失败: {e}")
            return

        if not cards:
            messagebox.showinfo("提示",
                                "当前主题暂无闪卡。\n请先进行学习对话，然后点击「AI 生成闪卡」。")
            return

        # 创建闪卡窗口
        fc_win = tk.Toplevel(self.root)
        fc_win.title(f"闪卡复习 — {topic or '全部主题'}")
        fc_win.configure(bg="#f0f4f8")
        fc_win.transient(self.root)
        fc_win.grab_set()

        # 添加窗口控制按钮
        self._add_window_controls(fc_win)

        fc_state = {
            "index": 0,
            "flipped": False,
            "stats": {"know": 0, "fuzzy": 0, "unknown": 0},
        }

        # 顶部进度
        top_frame = tk.Frame(fc_win, bg="#f0f4f8")
        top_frame.pack(fill=tk.X, padx=15, pady=(12, 0))
        fc_progress = tk.Label(
            top_frame, text=f"第 1/{len(cards)} 张",
            bg="#f0f4f8", font=("Microsoft YaHei", 10, "bold"),
            fg=self.primary_color
        )
        fc_progress.pack(side=tk.LEFT)
        fc_stats_label = tk.Label(
            top_frame, text="",
            bg="#f0f4f8", font=("Microsoft YaHei", 9), fg="#666"
        )
        fc_stats_label.pack(side=tk.RIGHT)

        # 卡片区域
        card_frame = tk.Frame(
            fc_win, bg="white", relief=tk.RAISED, bd=2,
            padx=30, pady=25
        )
        card_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=15)

        card_side_label = tk.Label(
            card_frame, text="问题", bg="white",
            font=("Microsoft YaHei", 9), fg="#999"
        )
        card_side_label.pack(anchor="nw")

        card_content = tk.Label(
            card_frame, text="", bg="white",
            font=("Microsoft YaHei", 14), wraplength=480,
            justify=tk.LEFT, anchor="nw"
        )
        card_content.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # 翻转按钮
        flip_btn = tk.Button(
            card_frame, text="点击翻转查看答案",
            font=("Microsoft YaHei", 9), bg="#ecf0f1", fg="#666",
            relief=tk.FLAT, cursor="hand2", pady=4
        )
        flip_btn.pack(fill=tk.X, pady=(10, 0))

        def load_card(idx):
            if idx >= len(cards):
                show_summary()
                return

            fc_state["flipped"] = False
            cid, question, answer, rev_cnt, cor_cnt = cards[idx]

            fc_progress.config(text=f"第 {idx + 1}/{len(cards)} 张")
            card_side_label.config(text="问题", fg="#3498db")
            card_content.config(text=question, fg="#2c3e50")
            flip_btn.config(text="点击翻转查看答案", state=tk.NORMAL)

            for btn in rating_buttons:
                btn.config(state=tk.DISABLED)

        def flip_card():
            if fc_state["flipped"]:
                return
            fc_state["flipped"] = True

            cid, question, answer, rev_cnt, cor_cnt = cards[fc_state["index"]]
            card_side_label.config(text="答案", fg="#27ae60")
            card_content.config(text=answer, fg="#2c3e50")
            flip_btn.config(text="已翻转", state=tk.DISABLED)

            for btn in rating_buttons:
                btn.config(state=tk.NORMAL)

        flip_btn.config(command=flip_card)

        def rate_card(rating):
            """评分并进入下一张"""
            cid = cards[fc_state["index"]][0]
            fc_state["stats"][rating] += 1

            is_correct = rating == "know"

            # 更新数据库
            try:
                with self.db_lock:
                    cursor = self.conn.cursor()
                    # 根据评分设置下次复习间隔
                    if rating == "know":
                        interval_days = 7
                    elif rating == "fuzzy":
                        interval_days = 2
                    else:
                        interval_days = 0  # 明天复习

                    next_review = (datetime.now() + timedelta(days=interval_days)).isoformat()
                    cursor.execute(
                        "UPDATE flashcards SET review_count = review_count + 1"
                        + (", correct_count = correct_count + 1" if is_correct else "")
                        + ", next_review = ? WHERE id = ?",
                        (next_review, cid))
                    self.conn.commit()
            except Exception:
                pass

            # 更新统计显示
            s = fc_state["stats"]
            fc_stats_label.config(
                text=f"掌握:{s['know']}  模糊:{s['fuzzy']}  不熟:{s['unknown']}"
            )

            fc_state["index"] += 1
            load_card(fc_state["index"])

        def show_summary():
            card_side_label.config(text="复习完成", fg="#8e44ad")
            s = fc_state["stats"]
            total = s["know"] + s["fuzzy"] + s["unknown"]
            pct = round(s["know"] / total * 100) if total > 0 else 0

            card_content.config(
                text=f"共复习 {total} 张闪卡\n\n"
                     f"掌握: {s['know']}  ({pct}%)\n"
                     f"模糊: {s['fuzzy']}\n"
                     f"不熟: {s['unknown']}\n\n"
                     f"{'很好！继续保持！' if pct >= 70 else '建议重新复习不熟的卡片。'}",
                font=("Microsoft YaHei", 13)
            )
            flip_btn.pack_forget()
            for btn in rating_buttons:
                btn.config(state=tk.DISABLED)

        # 底部评分按钮
        bottom_frame = tk.Frame(fc_win, bg="#f0f4f8")
        bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 12))

        rating_buttons = []
        ratings = [
            ("不熟", "unknown", "#e74c3c"),
            ("模糊", "fuzzy", "#f39c12"),
            ("掌握", "know", "#27ae60"),
        ]
        for text, key, color in ratings:
            btn = tk.Button(
                bottom_frame, text=text,
                command=lambda k=key: rate_card(k),
                bg=color, fg="white",
                font=("Microsoft YaHei", 10, "bold"),
                relief=tk.FLAT, cursor="hand2", padx=15, pady=6,
                state=tk.DISABLED
            )
            btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)
            rating_buttons.append(btn)

        tk.Button(
            bottom_frame, text="关闭",
            command=fc_win.destroy,
            bg="#95a5a6", fg="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT, cursor="hand2", padx=10, pady=6
        ).pack(side=tk.RIGHT, padx=(8, 0))

        # 加载第一张
        load_card(0)

        # 居中显示
        self._center_window(fc_win, 580, 450)

    # ==================== 操作日志 ====================

    def create_log_view(self):
        """创建日志视图"""
        # 顶部工具栏
        toolbar = tk.Frame(self.log_frame, bg="#f0f0f0", pady=6)
        toolbar.pack(fill=tk.X, padx=10, pady=(10, 0))

        tk.Button(
            toolbar, text="💾 备份数据库",
            command=self._backup_database_ui,
            bg=self.success_color, fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="📋 查看备份",
            command=self._show_backups_ui,
            bg=self.info_color, fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="🔄 批量回填 CVSS",
            command=self._backfill_cvss_ui,
            bg="#8e44ad", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="🌐 重查 AWAITING CVE",
            command=self._requery_awaiting_cvss_ui,
            bg="#2980b9", fg="white",
            font=("Microsoft YaHei", 9, "bold"),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="🗑 清空日志",
            command=self.clear_log,
            bg=self.warning_color, fg="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT, cursor="hand2", padx=12, pady=4
        ).pack(side=tk.RIGHT)

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
                                # SQLite 批量写入（主存储）
                                self._bulk_store_cve_to_sqlite(cves_to_store)

                                # Redis 缓存更新（best-effort）
                                if self.use_redis:
                                    try:
                                        for cve_to_store in cves_to_store:
                                            self.redis_manager.store_cve(cve_to_store)
                                    except Exception:
                                        pass

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
            self._last_fetched_html = ""
            exa_api_key = os.getenv("EXA_API_KEY")
            # 1. 优先使用Exa API
            if exa_api_key:
                self.log_queue.put("使用Exa API获取页面内容...")
                content = self._fetch_with_exa(url, exa_api_key)
            # 2. Fallback：直接HTTP请求 + BeautifulSoup（同时保存HTML）
            if not content:
                self.log_queue.put("回退：使用直接HTTP请求获取页面...")
                content = self._fetch_with_requests(url)
            # 3. Fallback：Selenium 浏览器渲染（绕过反爬虫）
            if not content:
                self.log_queue.put("回退：使用Selenium浏览器获取页面...")
                content = self._fetch_with_selenium(url)
            if not content:
                self.root.after(0, self._fetch_done, None,
                                "❌ 无法获取页面内容，请检查URL是否有效或网络连接")
                return
            # 如果 Exa 成功但没有 HTML，额外获取 HTML 用于表格解析
            if not self._last_fetched_html:
                try:
                    import requests as req
                    resp = req.get(url, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    }, timeout=30)
                    if resp.status_code == 200:
                        self._last_fetched_html = resp.text
                except Exception:
                    pass
            # 3. 解析内容构建advisory结构
            advisory = self._parse_dell_page_content(url, content, self._last_fetched_html)
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
        """直接HTTP请求 + BeautifulSoup 提取正文文本（同时保存原始HTML用于表格解析）"""
        import requests as req
        from bs4 import BeautifulSoup
        try:
            # 创建 session 以保持 cookies
            session = req.Session()

            # 增强的请求头，模拟真实浏览器
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Cache-Control': 'max-age=0',
                'DNT': '1',
            }

            # 如果是 Dell 域名，先访问主页获取 cookies
            if 'dell.com' in url:
                try:
                    session.get('https://www.dell.com', headers=headers, timeout=10)
                except Exception:
                    pass  # 忽略主页访问失败

            response = session.get(url, headers=headers, timeout=30, allow_redirects=True)
            response.raise_for_status()
            self._last_fetched_html = response.text  # 保存原始HTML用于表格解析
            soup = BeautifulSoup(response.text, 'html.parser')
            for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
                tag.decompose()
            return soup.get_text(separator='\n', strip=True)
        except Exception as e:
            self.log_queue.put(f"直接HTTP抓取失败: {e}")
        return ""

    def _fetch_with_selenium(self, url: str) -> str:
        """使用Selenium浏览器获取页面内容（绕过反爬虫检测）"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC

            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
            options.add_experimental_option('excludeSwitches', ['enable-automation'])

            driver = webdriver.Chrome(options=options)
            try:
                driver.get(url)
                WebDriverWait(driver, 20).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                import time
                time.sleep(2)
                self._last_fetched_html = driver.page_source
                text = driver.find_element(By.TAG_NAME, "body").text
                if text and len(text) > 500:
                    self.log_queue.put(f"Selenium成功获取页面内容（{len(text)} 字符）")
                    return text
                else:
                    self.log_queue.put(f"Selenium获取内容过短（{len(text)} 字符），可能被拦截")
            finally:
                driver.quit()
        except ImportError:
            self.log_queue.put("Selenium未安装，跳过浏览器回退策略")
        except Exception as e:
            self.log_queue.put(f"Selenium抓取失败: {e}")
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

    def _parse_dell_page_content(self, url: str, content: str, html: str = "") -> dict:
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
        # 发布日期（仅日期，不含时分）
        published_date = datetime.now().strftime('%Y-%m-%d')
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
                        published_date = datetime.strptime(m.group(1), fmt).strftime('%Y-%m-%d')
                        break
                    except ValueError:
                        continue
                break
        # 影响级别：调用 scraper 统一方法（支持文本/HTML/CVSS分数多策略提取）
        impact = scraper._extract_impact(content, html)
        # 摘要：提取 "Summary" 区域内容
        summary = scraper._extract_summary_section(content)
        # 产品和解决方案：从 "Affected Products & Remediation" 表格提取
        products, solution = scraper._extract_remediation(content, html)
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

    # ==================== Dell技术库 抓取功能 ====================

    def fetch_dell_kb_from_url(self):
        """从URL抓取Dell技术库文章"""
        url = self.kb_url_entry.get().strip()
        placeholder = "https://www.dell.com/support/kbdoc/zh-cn/..."
        if not url or url == placeholder:
            messagebox.showwarning("请输入URL", "请先输入Dell技术库文章的URL")
            return
        if not url.startswith("http"):
            messagebox.showwarning("URL格式错误", "请输入有效的HTTP/HTTPS URL")
            return
        self.kb_fetch_btn.config(state=tk.DISABLED)
        self.kb_fetch_status.config(text="⏳ 正在抓取文章内容...", fg=self.info_color)
        self.log(f"开始抓取Dell技术库文章: {url}")
        threading.Thread(
            target=self._fetch_kb_article_thread, args=(url,), daemon=True
        ).start()

    def _fetch_kb_article_thread(self, url: str):
        """后台线程：抓取Dell技术库文章"""
        try:
            content = ""
            exa_api_key = os.getenv("EXA_API_KEY")
            if exa_api_key:
                self.log_queue.put("使用Exa API获取技术文章...")
                content = self._fetch_with_exa(url, exa_api_key)
            if not content:
                self.log_queue.put("使用HTTP请求获取技术文章...")
                content = self._fetch_with_requests(url)
            if not content:
                self.root.after(0, self._kb_fetch_done, None,
                                "❌ 无法获取页面内容，请检查URL是否有效")
                return

            # 提取文章编号
            article_id = self._extract_kb_article_id(url)
            if not article_id:
                self.root.after(0, self._kb_fetch_done, None,
                                "⚠️ 未能从URL提取文章编号")
                return

            # 解析标题和解决方案
            title, solution = self._parse_kb_article_content(content, article_id)

            article = {
                'article_id': article_id,
                'title': title,
                'content': content,
                'solution': solution,
                'url': url,
                'collected_date': datetime.now().isoformat()
            }

            is_new = self._store_kb_article_to_sqlite(article)
            if is_new:
                msg = f"✅ 文章已入库：{article_id}"
            else:
                msg = f"ℹ️ 文章已更新：{article_id}"
            self.root.after(0, self._kb_fetch_done, article, msg)

        except Exception as e:
            import traceback
            self.log_queue.put(f"技术库文章抓取异常: {traceback.format_exc()}")
            self.root.after(0, self._kb_fetch_done, None, f"❌ 抓取失败: {str(e)}")

    def _extract_kb_article_id(self, url: str) -> str:
        """从URL中提取Dell技术库文章编号"""
        # 匹配 /000261124/ 或 /000261124- 格式
        match = re.search(r'/(\d{6,12})(?:[/-]|$)', url)
        if match:
            return match.group(1)
        return ""

    def _parse_kb_article_content(self, content: str, article_id: str) -> tuple:
        """解析技术库文章内容，提取标题和解决方案"""
        lines = content.strip().split('\n')

        # 提取标题：查找包含文章编号或前几行中最有意义的标题
        title = ""
        for line in lines[:15]:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # 优先匹配包含文章编号的行
            if article_id in line_stripped:
                title = line_stripped
                break
            # 或者找到较长的非导航行作为标题
            if len(line_stripped) > 10 and not title:
                # 跳过导航链接、面包屑等
                if any(kw in line_stripped.lower() for kw in ['dell', 'support', 'kbdoc', 'powerstore',
                                                               'poweredge', 'powerflex', 'idrac',
                                                               'unity', 'vxrail', 'avamar',
                                                               'networker', 'recoverpoint']):
                    title = line_stripped
                    break
        if not title and lines:
            # 回退：使用第一行非空内容
            for line in lines[:5]:
                if line.strip():
                    title = line.strip()[:200]
                    break

        # 提取解决方案：搜索关键词分段
        solution = ""
        solution_keywords = ['解决方案', '解决办法', '解决步骤', '修复方法',
                             'Resolution', 'Solution', 'Workaround', 'Fix',
                             'resolution', 'solution', 'workaround', 'fix']
        content_lower = content.lower()
        best_pos = -1
        for kw in solution_keywords:
            pos = content_lower.find(kw.lower())
            if pos != -1 and (best_pos == -1 or pos < best_pos):
                best_pos = pos

        if best_pos != -1:
            # 从关键词位置开始提取内容
            solution = content[best_pos:best_pos + 3000].strip()
        else:
            # 没有明确的解决方案段落，取后半部分内容
            half = len(content) // 2
            solution = content[half:half + 2000].strip() if len(content) > 500 else ""

        return title[:500], solution[:5000]

    def _store_kb_article_to_sqlite(self, article: dict) -> bool:
        """存储技术库文章到SQLite（Upsert）"""
        with self.db_lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO dell_kb_articles
                    (article_id, title, content, solution, url, collected_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(article_id) DO UPDATE SET
                        title = excluded.title,
                        content = excluded.content,
                        solution = excluded.solution,
                        url = excluded.url,
                        collected_date = excluded.collected_date
                ''', (
                    article['article_id'],
                    article.get('title', ''),
                    article.get('content', ''),
                    article.get('solution', ''),
                    article.get('url', ''),
                    article.get('collected_date', '')
                ))
                is_new = cursor.rowcount > 0
                self.conn.commit()
                return is_new
            except sqlite3.Error as e:
                self.log(f"存储技术库文章失败: {e}")
                return False

    def _kb_fetch_done(self, article, message: str):
        """抓取完成后更新UI"""
        self.kb_fetch_btn.config(state=tk.NORMAL)
        if article:
            self.kb_fetch_status.config(text=message, fg=self.success_color)
            self.log(message)
            # 刷新列表
            self.load_dell_kb_from_database()
        else:
            self.kb_fetch_status.config(text=message, fg=self.danger_color)
            self.log(f"技术库抓取: {message}")

    def load_dell_kb_from_database(self):
        """从数据库加载Dell技术库文章到TreeView"""
        # 清空TreeView
        for item in self.kb_tree.get_children():
            self.kb_tree.delete(item)
        self.dell_kb_data = []

        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "SELECT article_id, title, content, solution, url, collected_date "
                    "FROM dell_kb_articles ORDER BY collected_date DESC LIMIT 500"
                )
                rows = cursor.fetchall()

            for row in rows:
                article_id, title, content, solution, url, collected_date = row
                # 格式化时间
                time_str = collected_date
                try:
                    dt = datetime.fromisoformat(collected_date)
                    time_str = dt.strftime('%Y-%m-%d %H:%M')
                except (ValueError, TypeError):
                    pass

                # 从 content 中提取受影响产品型号
                affected_products_str = self._extract_kb_affected_products(content or "")

                # 解决方案预览
                sol_preview = self._extract_kb_solution(content or "", solution or "")

                self.kb_tree.insert(
                    "", tk.END,
                    values=(article_id, (title or "")[:100], affected_products_str, sol_preview, time_str)
                )
                self.dell_kb_data.append({
                    'article_id': article_id,
                    'title': title or '',
                    'content': content or '',
                    'solution': solution or '',
                    'url': url or '',
                    'collected_date': collected_date or ''
                })

            self.log(f"Dell技术库已加载 {len(rows)} 条文章")
        except Exception as e:
            self.log(f"加载Dell技术库失败: {e}")

    def _extract_kb_affected_products(self, content: str) -> str:
        """从Dell技术库文章内容中提取受影响产品型号

        Args:
            content: 文章内容文本

        Returns:
            产品型号字符串（逗号分隔）
        """
        if not content:
            return "N/A"

        # 支持多种产品标题格式：#### 产品 / #### 受影响的产品 / #### Affected Products
        patterns = [
            r'#{2,4}\s*产品\s*\n+([^\n#]+(?:\n(?!#{2,5})[^\n]+)*)',
            r'#{2,4}\s*受影响的产品\s*\n+([^\n#]+(?:\n(?!#{2,5})[^\n]+)*)',
            r'#{2,4}\s*(?:Affected|Impacted)\s+Products?\s*\n+([^\n#]+(?:\n(?!#{2,5})[^\n]+)*)',
        ]

        # 遍历所有模式和所有匹配，取第一个有效的产品列表
        for pattern in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            for match in matches:
                products_text = match.group(1).strip()
                # 清理文本：移除多余空白、换行和 Markdown 格式符号
                products_text = re.sub(r'\s+', ' ', products_text)
                products_text = re.sub(r'[*_`]', '', products_text)

                # 过滤无效内容
                if not products_text:
                    continue
                if products_text in ("NA", "N/A"):
                    continue
                if "Provide Feedback" in products_text or "提供反馈" in products_text:
                    continue

                # 截断过长内容
                if len(products_text) > 200:
                    products_text = products_text[:200] + "..."
                return products_text

        # 回退：从文档底部向上查找纯文本格式的"受影响的产品"（无markdown标题）
        plain_patterns = [
            r'受影响的产品\s*\n+([^\n]+)',
            r'受影响产品\s*\n+([^\n]+)',
            r'(?:Affected|Impacted)\s+Products?\s*\n+([^\n]+)',
        ]

        for pattern in plain_patterns:
            # 从后向前查找最后一次出现（文档底部通常是最终版本）
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            if matches:
                # 取最后一个匹配
                match = matches[-1]
                products_text = match.group(1).strip()
                # 清理文本
                products_text = re.sub(r'\s+', ' ', products_text)
                products_text = re.sub(r'[*_`]', '', products_text)

                # 过滤无效内容
                if not products_text:
                    continue
                if products_text in ("NA", "N/A"):
                    continue
                if "Provide Feedback" in products_text or "提供反馈" in products_text:
                    continue
                # 过滤乱码文本（包含大量非ASCII字符）
                if len([c for c in products_text if ord(c) > 127]) > len(products_text) * 0.5:
                    continue

                # 截断过长内容
                if len(products_text) > 200:
                    products_text = products_text[:200] + "..."
                return products_text

        return "N/A"

    def _extract_kb_solution(self, content: str, solution_field: str = "") -> str:
        """从Dell技术库文章内容中提取解决方案摘要

        优先从 content 正文中提取"解决方案"段落，回退到 solution 字段。
        """
        if content:
            # 策略1: 纯文本格式 — 找正文中最后一个"解决方案"段落（跳过目录中的短标题）
            for marker in ['解决方案', 'Resolution', 'Solution']:
                positions = [m.start() for m in re.finditer(r'\n' + re.escape(marker) + r'\n', content)]
                for pos in reversed(positions):
                    after = content[pos + len(marker) + 2:]
                    end_idx = len(after)
                    for em in ['受影响的产品', 'Affected Product', '提供反馈', 'Provide Feedback',
                               '文章属性', 'Article Properties', '其它信息', 'Additional Info',
                               'DTA 信息', '法律免责声明', 'Legal Disclaimer']:
                        eidx = after.find(em)
                        if 0 < eidx < end_idx:
                            end_idx = eidx
                    sol = after[:end_idx].strip()
                    if len(sol) > 30:
                        sol = re.sub(r'\s+', ' ', sol)
                        return sol[:300]

            # 策略2: Markdown 格式 — ## 解决方案 / ## Resolution
            md_patterns = [
                r'#{2,4}\s*解决方案\s*\n+(.*?)(?=\n#{2,4}\s|\n受影响的产品|\n提供反馈|$)',
                r'#{2,4}\s*(?:Resolution|Solution)\s*\n+(.*?)(?=\n#{2,4}\s|\nAffected Product|\nProvide Feedback|$)',
            ]
            for pattern in md_patterns:
                matches = list(re.finditer(pattern, content, re.DOTALL | re.IGNORECASE))
                for match in reversed(matches):
                    sol = match.group(1).strip()
                    sol = re.sub(r'[*_`]', '', sol)
                    if len(sol) > 30:
                        sol = re.sub(r'\s+', ' ', sol)
                        return sol[:300]

        # 策略3: 从 solution 字段中提取有效内容（过滤掉目录标题和乱码前缀）
        if solution_field:
            lines = solution_field.split('\n')
            real_lines = []
            skip_toc = True
            toc_keywords = {'解决方案', 'Resolution', 'Solution', '受影响的产品', '提供反馈',
                            'Affected Products', 'Provide Feedback', '其它信息', 'DTA 信息',
                            '法律免责声明', 'Additional Info', 'Legal Disclaimer'}
            for line in lines:
                stripped = line.strip()
                if skip_toc and (stripped in toc_keywords or stripped.startswith('##')):
                    continue
                if stripped.startswith('摘要:') or stripped.startswith('Summary:'):
                    continue
                if len(stripped) > 20:
                    skip_toc = False
                    real_lines.append(stripped)
                elif not skip_toc and stripped:
                    real_lines.append(stripped)
            clean = ' '.join(real_lines).strip()
            if len(clean) > 30:
                return clean[:300]

        return ""

    def filter_dell_kb_data(self):
        """搜索Dell技术库文章"""
        search_term = self.kb_search_entry.get().strip()
        if not search_term:
            self.load_dell_kb_from_database()
            return

        search_upper = search_term.upper()

        # 清空TreeView
        for item in self.kb_tree.get_children():
            self.kb_tree.delete(item)

        # 阶段1：内存搜索
        results = []
        for article in self.dell_kb_data:
            if (search_upper in (article.get('article_id', '') or '').upper() or
                search_upper in (article.get('title', '') or '').upper() or
                search_upper in (article.get('content', '') or '').upper() or
                search_upper in (article.get('solution', '') or '').upper()):
                results.append(article)

        if results:
            for article in results[:500]:
                time_str = article.get('collected_date', '')
                try:
                    dt = datetime.fromisoformat(time_str)
                    time_str = dt.strftime('%Y-%m-%d %H:%M')
                except (ValueError, TypeError):
                    pass
                content = article.get('content', '') or ''
                affected_products_str = self._extract_kb_affected_products(content)
                sol_preview = self._extract_kb_solution(content, article.get('solution', ''))
                self.kb_tree.insert(
                    "", tk.END,
                    values=(article['article_id'], (article.get('title', '') or '')[:100],
                            affected_products_str, sol_preview, time_str)
                )
            self.log(f"Dell技术库搜索到 {len(results)} 条匹配记录")
            return

        # 阶段2：数据库搜索
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                like_term = f'%{search_term}%'
                cursor.execute(
                    "SELECT article_id, title, content, solution, url, collected_date "
                    "FROM dell_kb_articles "
                    "WHERE article_id LIKE ? OR title LIKE ? OR content LIKE ? OR solution LIKE ? "
                    "ORDER BY collected_date DESC LIMIT 200",
                    (like_term, like_term, like_term, like_term)
                )
                rows = cursor.fetchall()

            for row in rows:
                article_id, title, content, solution, url, collected_date = row
                time_str = collected_date
                try:
                    dt = datetime.fromisoformat(collected_date)
                    time_str = dt.strftime('%Y-%m-%d %H:%M')
                except (ValueError, TypeError):
                    pass
                affected_products_str = self._extract_kb_affected_products(content or "")
                sol_preview = self._extract_kb_solution(content or "", solution or "")
                self.kb_tree.insert(
                    "", tk.END,
                    values=(article_id, (title or "")[:100], affected_products_str, sol_preview, time_str)
                )
            if rows:
                self.log(f"数据库搜索到 {len(rows)} 条Dell技术库匹配记录")
            else:
                self.log(f"未找到匹配 '{search_term}' 的Dell技术库文章")
                messagebox.showinfo("搜索结果", f"未找到匹配 '{search_term}' 的Dell技术库文章")
        except Exception as e:
            self.log(f"数据库搜索Dell技术库失败: {e}")

    def delete_dell_kb_selected(self):
        """删除选中的Dell技术库文章（支持多选）"""
        selected = self.kb_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的文章（支持 Ctrl/Shift 多选）")
            return

        count = len(selected)
        if not messagebox.askyesno(
            "确认删除",
            f"确定要永久删除选中的 {count} 篇技术库文章吗？\n此操作不可撤销。"
        ):
            return

        ids_to_delete = []
        for iid in selected:
            values = self.kb_tree.item(iid, 'values')
            if values:
                ids_to_delete.append(values[0])

        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.executemany(
                    "DELETE FROM dell_kb_articles WHERE article_id = ?",
                    [(aid,) for aid in ids_to_delete]
                )
                self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("删除失败", f"数据库操作失败：{e}")
            return

        # 更新内存
        id_set = set(ids_to_delete)
        self.dell_kb_data = [a for a in self.dell_kb_data if a.get('article_id') not in id_set]

        # 从TreeView删除
        for iid in selected:
            self.kb_tree.delete(iid)

        preview = ', '.join(ids_to_delete[:5])
        suffix = '...' if count > 5 else ''
        self.log(f"已删除 {count} 篇技术库文章：{preview}{suffix}")

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

    def start_dell_backfill(self):
        """启动 Dell 历史 DSA 缝隙补全"""
        if self.is_collecting_dell:
            messagebox.showwarning("提示", "正在采集中，请稍后再试")
            return

        # 确认对话框
        result = messagebox.askyesno(
            "历史 DSA 缝隙补全",
            "此功能将分析数据库中已有的 DSA ID，找出缺失的编号并尝试补全。\n\n"
            "范围：2019-2026 年\n"
            "预计耗时：5-15 分钟\n\n"
            "是否继续？"
        )
        if not result:
            return

        self.is_collecting_dell = True
        self.dell_backfill_btn.config(state=tk.DISABLED)
        self.dell_collect_btn.config(state=tk.DISABLED)
        self.dell_stop_btn.config(state=tk.NORMAL)

        # 在新线程中运行补全
        thread = threading.Thread(target=self.run_dell_backfill)
        thread.daemon = True
        thread.start()

        self.log("开始 Dell 历史 DSA 缝隙补全...")

    def run_dell_backfill(self):
        """在线程中运行 Dell 缝隙补全"""
        try:
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.run(self.backfill_dell_advisories_async())
        except Exception as e:
            self.log_queue.put(f"Dell 缝隙补全出错: {str(e)}")
        finally:
            self.is_collecting_dell = False
            self.root.after(0, self._finish_dell_backfill)

    def _finish_dell_backfill(self):
        """完成 Dell 缝隙补全的 UI 更新（主线程）"""
        self.dell_backfill_btn.config(state=tk.NORMAL)
        self.dell_collect_btn.config(state=tk.NORMAL)
        self.dell_stop_btn.config(state=tk.DISABLED)
        self.hide_progress()

    def start_dell_fix_dates(self):
        """启动 Dell 安全公告发布日期修复"""
        if self.is_collecting_dell:
            messagebox.showwarning("提示", "正在采集中，请稍后再试")
            return

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT dsa_id, published_date, link FROM dell_advisories
            WHERE published_date LIKE '2026-%'
              AND dsa_id NOT LIKE 'DSA-2026-%'
        """)
        wrong_rows = cursor.fetchall()

        if not wrong_rows:
            messagebox.showinfo("提示", "没有需要修复的日期记录")
            return

        result = messagebox.askyesno(
            "修复发布日期",
            f"发现 {len(wrong_rows)} 条日期异常记录（DSA 年份 < 2026 但日期为 2026）。\n\n"
            "将尝试重新获取正确的 Last Modified 日期。\n"
            "预计耗时：2-5 分钟\n\n是否继续？"
        )
        if not result:
            return

        self.is_collecting_dell = True
        self.dell_fix_dates_btn.config(state=tk.DISABLED)
        self.dell_collect_btn.config(state=tk.DISABLED)

        thread = threading.Thread(
            target=self._run_dell_fix_dates, args=(wrong_rows,))
        thread.daemon = True
        thread.start()

        self.log(f"开始修复 {len(wrong_rows)} 条 Dell 公告发布日期...")

    def _run_dell_fix_dates(self, wrong_rows):
        """在线程中运行日期修复"""
        try:
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.run(self._fix_dell_dates_async(wrong_rows))
        except Exception as e:
            self.log_queue.put(f"日期修复出错: {str(e)}")
        finally:
            self.is_collecting_dell = False
            self.root.after(0, self._finish_dell_fix_dates)

    def _finish_dell_fix_dates(self):
        """完成日期修复的 UI 更新"""
        self.dell_fix_dates_btn.config(state=tk.NORMAL)
        self.dell_collect_btn.config(state=tk.NORMAL)
        self.hide_progress()
        # 刷新 Dell 树视图以显示更新后的日期
        self.root.after(100, lambda: self.filter_dell_data())

    async def _fix_dell_dates_async(self, wrong_rows):
        """异步执行日期修复"""
        scraper = DellSecurityScraper()
        advisories = [
            {'dsa_id': r[0], 'published_date': r[1], 'link': r[2] or ''}
            for r in wrong_rows
        ]

        updated = await scraper.requery_published_dates(
            advisories,
            log_callback=lambda msg: self.log_queue.put(msg),
        )

        if updated:
            cursor = self.conn.cursor()
            for item in updated:
                cursor.execute(
                    "UPDATE dell_advisories SET published_date = ? WHERE dsa_id = ?",
                    (item['new_date'], item['dsa_id'])
                )
                # 同步更新 data JSON 中的 published_date
                cursor.execute(
                    "SELECT data FROM dell_advisories WHERE dsa_id = ?",
                    (item['dsa_id'],)
                )
                row = cursor.fetchone()
                if row:
                    import json as _json
                    try:
                        data = _json.loads(row[0])
                        data['published_date'] = item['new_date']
                        cursor.execute(
                            "UPDATE dell_advisories SET data = ? WHERE dsa_id = ?",
                            (_json.dumps(data, ensure_ascii=False), item['dsa_id'])
                        )
                    except Exception:
                        pass
            self.conn.commit()
            self.log_queue.put(f"✅ 成功修复 {len(updated)} 条发布日期")
        else:
            self.log_queue.put("未找到可修复的日期记录")

    async def backfill_dell_advisories_async(self):
        """异步执行 Dell 历史 DSA 缝隙补全"""
        scraper = DellSecurityScraper()
        try:
            # 获取数据库中已存在的 DSA IDs
            existing_dsa_ids = self.get_existing_dell_ids()
            self.log_queue.put(f"数据库中已有 {len(existing_dsa_ids)} 条 Dell 安全公告")

            # 执行缝隙补全
            items = await scraper.backfill_missing_dsa_ids(
                existing_dsa_ids=existing_dsa_ids,
                year_range=(2019, 2026),
                log_callback=lambda msg: self.log_queue.put(msg),
            )

            if items:
                self.log_queue.put(f"✓ 成功补全 {len(items)} 条历史 Dell 安全公告")

                # 存储到数据库
                new_count = 0
                for i, item in enumerate(items):
                    if not self.is_collecting_dell:
                        self.log_queue.put(f"补全被用户中断，已处理 {i}/{len(items)} 条数据")
                        break

                    item = self.enhance_dell_advisory(item)
                    is_new = self.store_dell_advisory(item)
                    if is_new:
                        new_count += 1

                    if i % 5 == 0 and i > 0:
                        progress_percent = int((i / len(items)) * 100)
                        self.log_queue.put(f"Dell 补全数据处理: {i}/{len(items)} ({progress_percent}%)")
                        await asyncio.sleep(0.01)

                self.log_queue.put(f"✓ Dell 历史缝隙补全完成，新增 {new_count} 条公告")

                # 重新加载数据
                self.root.after(0, self.load_dell_from_database)
            else:
                self.log_queue.put("未发现需要补全的 DSA ID")

        except Exception as e:
            self.log_queue.put(f"Dell 缝隙补全失败: {str(e)}")
            import traceback
            self.log_queue.put(traceback.format_exc())

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

            # 获取数据库中已存在的 DSA IDs，传给爬虫跳过已有公告
            existing_dsa_ids = self.get_existing_dell_ids()
            self.log_queue.put(f"数据库中已有 {len(existing_dsa_ids)} 条 Dell 安全公告")
            self.log_queue.put(f"正在从 Dell 官网采集最近 {days} 天的新安全公告...")

            # 使用 Exa / HTTP / Selenium 多策略采集，自动跳过已有公告
            items = await scraper.fetch_security_advisories(
                days=days,
                existing_dsa_ids=existing_dsa_ids,
                log_callback=lambda msg: self.log_queue.put(msg),
            )

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
                    with self.db_lock:
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

                    # 批量添加数据（后台预处理，减少主线程负担）
                    for cve in self.cve_data:
                        preprocessed = self._preprocess_nvd_row(cve)
                        self.data_queue.put(('add_nvd', preprocessed))

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

            # 批量添加数据（后台预处理，减少主线程负担）
            for cve in self.cve_data:
                preprocessed = self._preprocess_nvd_row(cve)
                self.data_queue.put(('add_nvd', preprocessed))

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

            # 打开CSV文件并创建新的reader（多编码回退）
            detected_encoding = None
            for encoding in ('gbk', 'gb2312', 'utf-8-sig', 'utf-8', 'latin-1'):
                try:
                    # 尝试用该编码打开并读取整个文件
                    with open(csv_file, 'r', encoding=encoding) as test_f:
                        test_f.read()
                    detected_encoding = encoding
                    break
                except (UnicodeDecodeError, UnicodeError, LookupError):
                    continue

            if not detected_encoding:
                detected_encoding = 'latin-1'  # latin-1 永远不会失败

            self.log_queue.put(f"CSV 文件编码: {detected_encoding}")
            f = open(csv_file, 'r', encoding=detected_encoding)
            reader = csv.DictReader(f)

            try:

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

                    # 从标题中提取受影响产品（CSV 不含产品详情）
                    affected_products = self._extract_products_from_dell_title(title)

                    # 构建Dell advisory数据
                    advisory = {
                        'dell_security_advisory': dsa_id,
                        'title': title,
                        'cve_ids': cve_ids,
                        'published_date': published_date,
                        'link': f'https://www.dell.com/support/kbdoc/en-us/{dsa_id.lower().replace("dsa-", "")}',
                        'summary': f'{impact} severity security update.',
                        'description': title,
                        'affected_products': affected_products,
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
            finally:
                f.close()

            # 发送日志到队列
            self.log_queue.put(f"✓ 成功加载Dell CSV数据: {Path(csv_file).name}")
            self.log_queue.put(f"  总计: {len(dell_data)} 条DSA")
            if new_count > 0:
                self.log_queue.put(f"  新增: {new_count} 条Dell安全公告到数据库")
            if existing_count > 0:
                self.log_queue.put(f"  跳过: {existing_count} 条已存在的公告")

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

    def _extract_products_from_dell_title(self, title: str) -> list:
        """从 Dell 安全公告标题中提取受影响产品名称

        Args:
            title: Dell 安全公告标题

        Returns:
            产品列表，格式: [{'name': 产品名, 'model': 产品名, 'version_range': ''}]
        """
        if not title:
            return []

        products = []

        # 模式A: "Security Update for [产品名] for/Multiple..."
        # 示例: "Security Update for Dell PowerScale OneFS Multiple Vulnerabilities"
        pattern_a = r'Security Update for\s+(.+?)\s+(?:for|Multiple|Vulnerabilit)'
        match = re.search(pattern_a, title, re.IGNORECASE)
        if match:
            product_text = match.group(1).strip()
            # 处理 "and" 连接的多个产品
            if ' and ' in product_text:
                for p in product_text.split(' and '):
                    p = p.strip()
                    if p:
                        products.append({'name': p, 'model': p, 'version_range': ''})
            else:
                products.append({'name': product_text, 'model': product_text, 'version_range': ''})
            return products

        # 模式B: "[产品1], [产品2], ... Security Update"
        # 示例: "Dell PowerMaxOS, Dell PowerMax EEM, ... Security Update for Multiple Vulnerabilities"
        pattern_b = r'^(.+?)\s+Security Update'
        match = re.search(pattern_b, title, re.IGNORECASE)
        if match:
            product_text = match.group(1).strip()
            # 按逗号分隔产品列表
            if ',' in product_text:
                for p in product_text.split(','):
                    p = p.strip()
                    if p and len(p) > 3:  # 过滤过短的片段
                        products.append({'name': p, 'model': p, 'version_range': ''})
                return products
            else:
                products.append({'name': product_text, 'model': product_text, 'version_range': ''})
                return products

        # 回退：如果标题中包含 "Dell" 关键词，提取整个标题作为产品名
        if 'Dell' in title:
            # 截取到第一个 "for" 或 "Security" 之前
            for keyword in [' for ', ' Security', ' Multiple']:
                if keyword in title:
                    product_text = title.split(keyword)[0].strip()
                    if product_text:
                        products.append({'name': product_text, 'model': product_text, 'version_range': ''})
                        return products

        # 最终回退：返回空列表
        return []

    def _is_invalid_product_name(self, name: str) -> bool:
        """判断产品名称是否无效（需要过滤）

        Args:
            name: 产品名称

        Returns:
            True 表示无效，应该过滤掉
        """
        if not name or len(name) < 2:
            return True

        # 过滤占位符
        if name in ("如标题", "详见公告", "NA", "N/A"):
            return True

        # 过滤包含特定关键词的无效内容
        invalid_keywords = [
            "Provide Feedback",
            "提供反馈",
            "Summary:",
            "Link to",
            "Customers can",
            "The following",
            "Multiple components",
            "Affected products:",
            "Registered Dell",
            "[Dell Vulnerability",
            "Product Security Information",
            "This article applies",
            "View More View Less",
        ]
        for keyword in invalid_keywords:
            if keyword in name:
                return True

        # 过滤过长的文本（超过150字符，可能是描述性文本而非产品名）
        if len(name) > 150:
            return True

        return False

    def _extract_dell_advisory_products(self, advisory: dict) -> str:
        """从 Dell 安全公告数据中提取受影响产品字符串（通用方法）"""
        affected_products = []
        products_data = advisory.get("affected_products", [])
        for prod in products_data:
            if isinstance(prod, dict):
                model = prod.get("product", "") or prod.get("name", "") or prod.get("model", "")
            elif isinstance(prod, str):
                model = prod
            else:
                continue
            model = model.strip()
            if not model or self._is_invalid_product_name(model):
                continue
            affected_products.append(model)

        if not affected_products:
            title_products = self._extract_products_from_dell_title(advisory.get("title", ""))
            for tp in title_products:
                name = tp.get("name", "")
                if name:
                    affected_products.append(name)

        result = "; ".join(affected_products) if affected_products else "N/A"
        if len(result) > 300:
            result = result[:300] + "..."
        return result


    def parse_dell_date(self, date_str):
        """解析Dell日期格式 (例如: OCT 29 2025) 为ISO格式"""
        if not date_str:
            return datetime.now().isoformat()

        try:
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

    def _preprocess_nvd_row(self, cve_data):
        """预处理 NVD 数据为 Treeview 行格式（在后台线程调用）"""
        severity = cve_data.get("cvss_severity", "未知")
        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else ""

        # 格式化发布日期
        published = cve_data.get("published_date", "")
        if published:
            try:
                dt = datetime.fromisoformat(published.replace("Z", ""))
                published = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                pass

        # 截断描述
        description = cve_data.get("description", "")
        if len(description) > 150:
            description = description[:150] + "..."

        return (
            cve_data.get("cve_id", ""),
            severity,
            cve_data.get("cvss_score", "N/A"),
            published,
            description,
            cve_data.get("source", "NVD")
        ), tag

    def add_nvd_to_tree(self, cve_data):
        """添加 NVD CVE 数据到树视图"""
        # 如果传入的是预处理的 tuple，直接插入
        if isinstance(cve_data, tuple) and len(cve_data) == 2:
            values, tag = cve_data
            self.nvd_tree.insert("", "end", values=values, tags=(tag,))
        else:
            # 兼容旧逻辑：实时处理
            values, tag = self._preprocess_nvd_row(cve_data)
            self.nvd_tree.insert("", "end", values=values, tags=(tag,))

    def add_dell_to_tree(self, advisory):
        """添加 Dell 安全公告到树视图"""
        # 格式化 CVE IDs
        cve_ids = advisory.get("cve_ids", [])
        cve_ids_str = ", ".join(cve_ids) if cve_ids else "无"

        # 格式化发布日期（仅显示日期，不含时分）
        published = advisory.get("published_date", "")
        if published:
            try:
                # 尝试解析日期
                from dateutil import parser
                dt = parser.parse(published)
                published = dt.strftime("%Y-%m-%d")
            except (ValueError, TypeError, ImportError) as e:
                # 日期解析失败或dateutil未安装，保持原样
                pass

        # 提取公告影响等级：优先 impact 字段，回退从 summary 中解析
        severity_level = advisory.get("impact", "")
        if not severity_level:
            summary = advisory.get("summary", "")
            match = re.search(r'\b(Critical|High|Medium|Low)\b', summary, re.IGNORECASE)
            if match:
                severity_level = match.group(1).capitalize()
            else:
                severity_level = "N/A"

        # 提取受影响产品
        affected_products_str = self._extract_dell_advisory_products(advisory)

        self.dell_tree.insert(
            "",
            "end",
            values=(
                advisory.get("dell_security_advisory", "N/A"),
                affected_products_str,
                severity_level,
                advisory.get("title", ""),
                cve_ids_str,
                published,
            ),
            tags=(severity_level,)
        )

    def _refresh_matched_data_background(self):
        """在后台线程中刷新关联数据（避免UI阻塞）"""
        try:
            # 始终从数据库加载全量Dell数据，避免内存limit导致遗漏
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
                records = cursor.fetchall()
            dell_advisories = []
            for record in records:
                try:
                    if record[0]:
                        data = json.loads(record[0])
                        dell_advisories.append(data)
                except Exception:
                    continue

            if not dell_advisories:
                self.log_queue.put("无法刷新关联数据：数据库中无Dell数据")
                return

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
            with self.db_lock:
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
                except Exception:
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

                        # 提取影响等级（来自 Dell 公告的 impact 字段）
                        impact = advisory.get("impact", "")
                        if not impact:
                            summary = advisory.get("summary", "")
                            impact_match = re.search(r'\b(Critical|High|Medium|Low)\b', summary, re.IGNORECASE)
                            impact = impact_match.group(1).capitalize() if impact_match else "N/A"

                        # 提取受影响产品型号
                        affected_products = []
                        products_data = advisory.get("affected_products", [])
                        for prod in products_data:
                            if isinstance(prod, dict):
                                model = prod.get("product", "") or prod.get("name", "") or prod.get("model", "")
                            elif isinstance(prod, str):
                                model = prod
                            else:
                                continue
                            model = model.strip()
                            if not model or self._is_invalid_product_name(model):
                                continue
                            affected_products.append(model)

                        # 回退：从标题中提取产品名
                        if not affected_products:
                            title_products = self._extract_products_from_dell_title(advisory.get("title", ""))
                            for tp in title_products:
                                name = tp.get("name", "")
                                if name:
                                    affected_products.append(name)

                        affected_products_str = "; ".join(affected_products) if affected_products else "N/A"
                        if len(affected_products_str) > 300:
                            affected_products_str = affected_products_str[:300] + "..."

                        # 公告内容（Dell 公告的标题）
                        dell_title = advisory.get("title", "")
                        if len(dell_title) > 150:
                            dell_title = dell_title[:150] + "..."
                        if not dell_title:
                            dell_title = "详见公告详情"

                        severity = cve.get("cvss_severity", "未知")
                        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else ""

                        matched_items.append({
                            "values": (
                                cve_id,
                                severity,
                                cve.get("cvss_score", "N/A"),
                                advisory.get("dell_security_advisory", "N/A"),
                                impact,
                                affected_products_str,
                                dell_title
                            ),
                            "tag": tag
                        })
                        matched_count += 1

            # 缓存所有匹配项用于搜索过滤
            self.matched_items_cache = matched_items

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

        # 始终从数据库加载全量Dell数据，避免内存limit导致遗漏
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC")
                records = cursor.fetchall()
            dell_advisories = []
            for record in records:
                try:
                    if record[0]:
                        data = json.loads(record[0])
                        dell_advisories.append(data)
                except Exception:
                    continue

            if not dell_advisories:
                self.log("无法刷新关联数据：数据库中无Dell数据")
                return

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
            with self.db_lock:
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
                except Exception:
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

                        # 提取影响等级（来自 Dell 公告的 impact 字段）
                        impact = advisory.get("impact", "")
                        if not impact:
                            summary = advisory.get("summary", "")
                            impact_match = re.search(r'\b(Critical|High|Medium|Low)\b', summary, re.IGNORECASE)
                            impact = impact_match.group(1).capitalize() if impact_match else "N/A"

                        # 提取受影响产品型号
                        affected_products = []
                        products_data = advisory.get("affected_products", [])
                        for prod in products_data:
                            if isinstance(prod, dict):
                                model = prod.get("product", "") or prod.get("name", "") or prod.get("model", "")
                            elif isinstance(prod, str):
                                model = prod
                            else:
                                continue
                            model = model.strip()
                            if not model or self._is_invalid_product_name(model):
                                continue
                            affected_products.append(model)

                        # 回退：从标题中提取产品名
                        if not affected_products:
                            title_products = self._extract_products_from_dell_title(advisory.get("title", ""))
                            for tp in title_products:
                                name = tp.get("name", "")
                                if name:
                                    affected_products.append(name)

                        affected_products_str = "; ".join(affected_products) if affected_products else "N/A"
                        if len(affected_products_str) > 300:
                            affected_products_str = affected_products_str[:300] + "..."

                        # 公告内容（Dell 公告的标题）
                        dell_title = advisory.get("title", "")
                        if len(dell_title) > 150:
                            dell_title = dell_title[:150] + "..."
                        if not dell_title:
                            dell_title = "详见公告详情"

                        severity = cve.get("cvss_severity", "未知")
                        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else ""

                        matched_items.append({
                            "values": (
                                cve_id,
                                severity,
                                cve.get("cvss_score", "N/A"),
                                advisory.get("dell_security_advisory", "N/A"),
                                impact,
                                affected_products_str,
                                dell_title
                            ),
                            "tag": tag
                        })
                        matched_count += 1

            # 缓存所有匹配项用于搜索过滤
            self.matched_items_cache = matched_items

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

    def filter_matched_data(self, *args):
        """过滤关联数据（支持 CVE编号、Dell公告ID、受影响产品 搜索）"""
        search_term = self.matched_search_var.get().strip()
        search_upper = search_term.upper()

        # 清空树视图
        for item in self.matched_tree.get_children():
            self.matched_tree.delete(item)

        # 如果搜索框为空，显示所有缓存数据
        if not search_term:
            for item_data in self.matched_items_cache:
                self.matched_tree.insert("", "end", values=item_data["values"], tags=(item_data["tag"],))
            return

        # 在缓存中搜索（CVE ID 在 index 0，Dell公告 在 index 3，受影响产品 在 index 5）
        matched = []
        for item_data in self.matched_items_cache:
            values = item_data["values"]
            cve_id = str(values[0]).upper() if values[0] else ""
            dell_id = str(values[3]).upper() if len(values) > 3 and values[3] else ""
            products = str(values[5]).upper() if len(values) > 5 and values[5] else ""
            if search_upper in cve_id or search_upper in dell_id or search_upper in products:
                matched.append(item_data)

        for item_data in matched:
            self.matched_tree.insert("", "end", values=item_data["values"], tags=(item_data["tag"],))

        if matched:
            self.log(f"关联数据搜索 '{search_term}'：找到 {len(matched)} 条匹配记录")
        else:
            self.log(f"未找到匹配 '{search_term}' 的关联数据")
            messagebox.showinfo("搜索结果", f"未找到匹配 '{search_term}' 的关联数据")

    def delete_matched_selected(self):
        """删除关联列表中选中的记录（从 Dell 公告中移除对应 CVE 关联）"""
        selected = self.matched_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的记录（支持 Ctrl/Shift 多选）")
            return

        count = len(selected)
        if not messagebox.askyesno(
            "确认删除",
            f"确定要删除选中的 {count} 条关联记录吗？\n"
            f"注意：这将从对应的 Dell 安全公告中移除关联的 CVE ID。"
        ):
            return

        # 收集要删除的 (cve_id, dell_id) 对
        pairs_to_delete = []
        for iid in selected:
            values = self.matched_tree.item(iid, 'values')
            if values:
                pairs_to_delete.append((str(values[0]), str(values[3])))

        # 从数据库的 Dell 公告中移除 CVE 关联
        try:
            cursor = self.conn.cursor()
            for cve_id, dell_id in pairs_to_delete:
                cursor.execute("SELECT data FROM dell_advisories WHERE dsa_id = ?", (dell_id,))
                row = cursor.fetchone()
                if row and row[0]:
                    data = json.loads(row[0])
                    cve_ids = data.get("cve_ids", [])
                    if cve_id in cve_ids:
                        cve_ids.remove(cve_id)
                        data["cve_ids"] = cve_ids
                        new_cve_str = ", ".join(cve_ids)
                        cursor.execute(
                            "UPDATE dell_advisories SET cve_ids = ?, data = ? WHERE dsa_id = ?",
                            (new_cve_str, json.dumps(data, ensure_ascii=False), dell_id)
                        )
            self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("删除失败", f"数据库操作失败：{e}")
            return

        # 同步更新内存中的 dell_advisories
        pairs_set = set(pairs_to_delete)
        for advisory in self.dell_advisories:
            dsa_id = advisory.get("dell_security_advisory", "")
            cve_ids = advisory.get("cve_ids", [])
            for cve_id, dell_id in pairs_set:
                if dsa_id == dell_id and cve_id in cve_ids:
                    cve_ids.remove(cve_id)

        # 从缓存中移除
        self.matched_items_cache = [
            item for item in self.matched_items_cache
            if (str(item["values"][0]), str(item["values"][3])) not in pairs_set
        ]

        # 从树视图中移除
        for iid in selected:
            self.matched_tree.delete(iid)

        preview = ', '.join(f"{p[0]}-{p[1]}" for p in pairs_to_delete[:3])
        suffix = '...' if count > 3 else ''
        self.log(f"已删除 {count} 条关联记录：{preview}{suffix}")
        self.update_stats()

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
        """从数据库搜索NVD数据（后台线程，分级搜索策略）"""
        try:
            search_upper = search_term.upper()
            cursor = self.conn.cursor()

            # 第一级：精确/前缀匹配 cve_id（走索引，最快）
            cursor.execute(
                "SELECT data FROM cves WHERE cve_id = ? LIMIT 1",
                (search_upper,)
            )
            records = cursor.fetchall()

            # 第二级：cve_id 模糊匹配（主键列，仍然较快）
            if not records:
                cursor.execute("""
                    SELECT data FROM cves
                    WHERE UPPER(cve_id) LIKE ?
                    ORDER BY published_date DESC
                    LIMIT 500
                """, (f'%{search_upper}%',))
                records = cursor.fetchall()

            # 第三级：FTS5 全文搜索（替代 data LIKE，速度提升 100x+）
            if not records:
                self.log_queue.put(f"CVE ID 无匹配，正在全文搜索...")
                fts_term = search_term.replace('"', '""')
                try:
                    cursor.execute("""
                        SELECT c.data FROM cves_fts f
                        JOIN cves c ON c.rowid = f.rowid
                        WHERE cves_fts MATCH ?
                        LIMIT 200
                    """, (f'"{fts_term}"',))
                    records = cursor.fetchall()
                except sqlite3.OperationalError:
                    pass

            # 第四级：LIKE 回退（FTS 无结果或不可用时）
            if not records:
                cursor.execute("""
                    SELECT data FROM cves
                    WHERE data LIKE ?
                    ORDER BY published_date DESC
                    LIMIT 200
                """, (f'%{search_upper}%',))
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
                # 使用默认参数捕获当前值，避免闭包问题
                self.root.after(0, lambda term=search_term: messagebox.showinfo("搜索结果", f"未找到匹配 '{term}' 的NVD CVE数据"))

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
            # 同步删除 Redis 缓存
            if self.use_redis:
                try:
                    for cid in cve_ids_to_delete:
                        self.redis_manager.delete_cve(cid)
                except Exception:
                    pass
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
        """从数据库搜索Dell公告（后台线程，分级搜索策略）"""
        try:
            search_upper = f"%{search_term.upper()}%"
            cursor = self.conn.cursor()

            # 第一级：仅搜索索引列和短文本列（dsa_id, title, cve_ids）
            cursor.execute("""
                SELECT data FROM dell_advisories
                WHERE UPPER(dsa_id)   LIKE ?
                   OR UPPER(title)    LIKE ?
                   OR UPPER(cve_ids)  LIKE ?
                ORDER BY published_date DESC
                LIMIT 200
            """, (search_upper, search_upper, search_upper))

            results = []
            for (raw,) in cursor.fetchall():
                try:
                    if raw:
                        results.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

            # 第二级：FTS5 全文搜索（替代 data LIKE）
            if not results:
                self.log_queue.put(f"在主要字段中未找到匹配，正在全文搜索...")
                fts_term = search_term.replace('"', '""')
                try:
                    cursor.execute("""
                        SELECT d.data FROM dell_fts f
                        JOIN dell_advisories d ON d.rowid = f.rowid
                        WHERE dell_fts MATCH ?
                        LIMIT 100
                    """, (f'"{fts_term}"',))
                    for (raw,) in cursor.fetchall():
                        try:
                            if raw:
                                results.append(json.loads(raw))
                        except json.JSONDecodeError:
                            continue
                except sqlite3.OperationalError:
                    pass

            # 第三级：LIKE 回退（FTS 无结果或不可用时）
            if not results:
                cursor.execute("""
                    SELECT data FROM dell_advisories
                    WHERE data LIKE ?
                    ORDER BY published_date DESC
                    LIMIT 100
                """, (search_upper,))
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
                # 将数据库搜索结果合并到内存列表，确保双击能找到
                existing_ids = {a.get('dell_security_advisory', '') for a in self.dell_advisories}
                for advisory in results:
                    if advisory.get('dell_security_advisory', '') not in existing_ids:
                        self.dell_advisories.append(advisory)
                self.log_queue.put(f"✓ 数据库中找到 {len(results)} 条匹配 '{search_term}' 的记录")
            else:
                self.log_queue.put(f"未找到匹配 '{search_term}' 的Dell公告（已搜索全部数据库）")
                # 使用默认参数捕获当前值，避免闭包问题
                self.root.after(0, lambda term=search_term: messagebox.showinfo("搜索结果", f"未找到匹配 '{term}' 的Dell公告"))

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

            # 先在内存中查找
            for cve in self.cve_data:
                if cve.get('cve_id') == cve_id:
                    self.show_nvd_detail(cve)
                    return

            # 内存中没有，从数据库查询
            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,))
                record = cursor.fetchone()
                if record and record[0]:
                    cve = json.loads(record[0])
                    self.show_nvd_detail(cve)
                else:
                    messagebox.showwarning("提示", f"未找到 {cve_id} 的详细数据")
            except Exception as e:
                messagebox.showerror("错误", f"加载详细数据失败: {e}")

    def show_nvd_detail(self, cve):
        """显示 NVD CVE 详细信息"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"CVE 详细信息 - {cve.get('cve_id')}")
        detail_window.transient(self.root)

        # 添加窗口控制按钮
        self._add_window_controls(detail_window)

        # 详细信息文本
        text = scrolledtext.ScrolledText(
            detail_window,
            wrap=tk.WORD,
            font=("Consolas", 15)
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

        # 统一尺寸并居中
        self._center_window(detail_window, 1350, 1050)

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
        detail_window.transient(self.root)

        # 添加窗口控制按钮
        self._add_window_controls(detail_window)

        # 详细信息文本
        text = scrolledtext.ScrolledText(
            detail_window,
            wrap=tk.WORD,
            font=("Consolas", 15)
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

        # 统一尺寸并居中
        self._center_window(detail_window, 1350, 1050)

    # ==================== AI解决方案功能 ====================

    def dell_kb_ai_solution_click(self):
        """Dell技术库 AI解决方案按钮点击事件"""
        selection = self.kb_tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择要分析的技术库文章")
            return

        item = self.kb_tree.item(selection[0])
        article_id_raw = str(item['values'][0])

        # 从内存中查找（兼容 TreeView 去掉前导零的情况）
        article = None
        for a in self.dell_kb_data:
            stored_id = a.get('article_id', '')
            if stored_id == article_id_raw or stored_id.lstrip('0') == article_id_raw.lstrip('0'):
                article = a
                break

        # 内存中未找到，从数据库查询（精确 + 模糊）
        if not article:
            try:
                with self.db_lock:
                    cursor = self.conn.cursor()
                    # 先精确匹配
                    cursor.execute(
                        "SELECT article_id, title, content, solution, url FROM dell_kb_articles WHERE article_id = ?",
                        (article_id_raw,)
                    )
                    row = cursor.fetchone()
                    # 回退：LIKE 模糊匹配（处理前导零差异）
                    if not row:
                        cursor.execute(
                            "SELECT article_id, title, content, solution, url FROM dell_kb_articles WHERE article_id LIKE ?",
                            (f'%{article_id_raw}%',)
                        )
                        row = cursor.fetchone()
                    if row:
                        article = {
                            'article_id': row[0], 'title': row[1],
                            'content': row[2], 'solution': row[3], 'url': row[4]
                        }
            except Exception as e:
                self.log(f"查询技术库文章失败: {e}")

        if not article:
            messagebox.showerror("错误", f"无法找到文章 {article_id_raw} 的详细数据")
            return

        self.log(f"正在调用AI分析技术库文章: {article_id_raw}...")
        threading.Thread(
            target=self._call_dell_kb_ai_solution_thread,
            args=(article,), daemon=True
        ).start()

    def _call_dell_kb_ai_solution_thread(self, article):
        """后台线程调用AI分析Dell技术库文章"""
        try:
            model_name = os.getenv("QWEN_MODEL", "qwen3.6-plus")
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

            if not api_key:
                raise ValueError("Qwen API密钥未设置。请在 .env 文件中设置 QWEN_API_KEY 或 DASHSCOPE_API_KEY。")

            article_id = article.get('article_id', 'N/A')
            title = article.get('title', '无标题')
            content = article.get('content', '')
            solution = article.get('solution', '')
            url = article.get('url', '')

            # 截断避免超长
            if len(content) > 3000:
                content = content[:3000] + "..."
            if len(solution) > 2000:
                solution = solution[:2000] + "..."

            prompt = f"""请对以下Dell技术文档进行专业分析，提供深入的技术理解和操作建议：

【文章信息】
- 文章编号: {article_id}
- 标题: {title}
- 原文链接: {url}

【文章内容】
{content}

【文档中的解决方案】
{solution if solution else '文档未提供明确的解决方案段落'}

【分析要求】
请提供以下内容：
1. 问题概述：简要说明该技术文档描述的问题或场景
2. 根因分析：分析问题产生的根本原因
3. 解决方案详解：对文档中的解决方案进行详细解读和补充
4. 操作步骤建议：给出清晰的操作步骤
5. 注意事项：执行过程中需要注意的风险和前提条件
6. 相关知识扩展：与该问题相关的技术背景知识

请以专业、结构清晰的格式组织答案。"""

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url, timeout=120)
            analysis_date = datetime.now().strftime("%Y年%m月%d日 %H:%M")
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": f"你是一个Dell企业级产品技术专家，精通Dell服务器、存储、网络等产品线的技术支持。当前分析日期: {analysis_date}。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )

            result = response.choices[0].message.content

            # 构造兼容 _show_ai_solution_result 的数据结构
            cve_data = {'cve_id': f"KB-{article.get('article_id', 'N/A')}"}
            dell_data = {'dell_security_advisory': 'Dell技术库', 'dsa_id': 'Dell技术库'}
            self.root.after(0, self._show_ai_solution_result, result, cve_data, dell_data)

        except ImportError:
            err = "openai库未安装。请运行: pip install openai"
            self.root.after(0, self.log, err)
            self.root.after(0, messagebox.showerror, "错误", err)
        except Exception as e:
            error_msg = f"AI分析技术库文章失败: {str(e)}"
            self.root.after(0, self.log, error_msg)
            self.root.after(0, messagebox.showerror, "错误", error_msg)

    def on_dell_kb_item_double_click(self, event):
        """双击查看Dell技术库文章详情"""
        selection = self.kb_tree.selection()
        if not selection:
            return

        item = self.kb_tree.item(selection[0])
        article_id = str(item['values'][0])

        # 从内存中查找（兼容前导零差异）
        article = None
        for a in self.dell_kb_data:
            stored_id = a.get('article_id', '')
            if stored_id == article_id or stored_id.lstrip('0') == article_id.lstrip('0'):
                article = a
                break

        if not article:
            try:
                with self.db_lock:
                    cursor = self.conn.cursor()
                    cursor.execute(
                        "SELECT article_id, title, content, solution, url, collected_date "
                        "FROM dell_kb_articles WHERE article_id = ?",
                        (article_id,)
                    )
                    row = cursor.fetchone()
                    if not row:
                        cursor.execute(
                            "SELECT article_id, title, content, solution, url, collected_date "
                            "FROM dell_kb_articles WHERE article_id LIKE ?",
                            (f'%{article_id}%',)
                        )
                        row = cursor.fetchone()
                    if row:
                        article = {
                            'article_id': row[0], 'title': row[1],
                            'content': row[2], 'solution': row[3],
                            'url': row[4], 'collected_date': row[5]
                        }
            except Exception as e:
                self.log(f"查询技术库文章详情失败: {e}")

        if not article:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Dell技术库 - {article_id}")
        dialog.transient(self.root)

        # 添加窗口控制按钮
        self._add_window_controls(dialog)

        # 标题栏
        header = f"文章编号: {article_id}  |  {article.get('title', '')}"
        tk.Label(
            dialog, text=header,
            font=("Microsoft YaHei", 12, "bold"),
            bg="#2c3e50", fg="white", padx=10, pady=10
        ).pack(fill=tk.X)

        # 内容区域
        text_frame = tk.Frame(dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD, font=("Consolas", 15), bg="#f8f9fa"
        )
        text.pack(fill=tk.BOTH, expand=True)

        text.insert(tk.END, f"【文章编号】{article_id}\n")
        text.insert(tk.END, f"【标题】{article.get('title', '')}\n")
        text.insert(tk.END, f"【URL】{article.get('url', '')}\n")
        text.insert(tk.END, f"【采集时间】{article.get('collected_date', '')}\n")
        text.insert(tk.END, f"\n{'=' * 60}\n【正文内容】\n{'=' * 60}\n\n")
        text.insert(tk.END, article.get('content', '无内容'))
        if article.get('solution'):
            text.insert(tk.END, f"\n\n{'=' * 60}\n【解决方案】\n{'=' * 60}\n\n")
            text.insert(tk.END, article['solution'])
        text.config(state=tk.DISABLED)

        # 关闭按钮
        tk.Button(
            dialog, text="关闭", command=dialog.destroy,
            bg="#95a5a6", fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=20, pady=5, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=10)

        # 统一尺寸并居中
        self._center_window(dialog, 1350, 1050)

    def nvd_ai_solution_click(self):
        """NVD标签页 AI解决方案按钮点击事件"""
        try:
            selection = self.nvd_tree.selection()
            if not selection:
                messagebox.showwarning("提示", "请先选择要分析的 CVE 数据")
                return

            # 获取选中的 CVE ID
            item = self.nvd_tree.item(selection[0])
            cve_id = item['values'][0]

            # 从内存中查找详细数据
            cve_detail = None
            for cve in self.cve_data:
                if cve.get('cve_id') == cve_id:
                    cve_detail = cve
                    break

            # 内存中未找到，从数据库查询
            if not cve_detail:
                try:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,))
                    row = cursor.fetchone()
                    if row and row[0]:
                        cve_detail = json.loads(row[0])
                except Exception as e:
                    self.log(f"从数据库查询CVE数据失败: {str(e)}")

            if not cve_detail:
                messagebox.showerror("错误", f"无法找到 {cve_id} 的详细数据")
                return

            self.log(f"正在调用AI分析: {cve_id}...")
            threading.Thread(
                target=self._call_nvd_ai_solution_thread,
                args=(cve_detail,),
                daemon=True
            ).start()

        except Exception as e:
            error_msg = f"AI解决方案处理失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def matched_ai_solution_click(self):
        """CVE-Dell关联标签页 AI解决方案按钮点击事件"""
        try:
            selection = self.matched_tree.selection()
            if not selection:
                messagebox.showwarning("提示", "请先选择要分析的关联数据")
                return

            # matched_tree 列: CVE ID, 严重等级, CVSS, Dell公告ID, 影响等级, 受影响产品, 公告内容
            item = self.matched_tree.item(selection[0])
            cve_id = item['values'][0]
            advisory_id = item['values'][3] if len(item['values']) > 3 else None

            # 从内存中查找CVE详细数据
            cve_detail = None
            for cve in self.cve_data:
                if cve.get('cve_id') == cve_id:
                    cve_detail = cve
                    break

            # 内存中未找到，从数据库查询
            if not cve_detail:
                try:
                    with self.db_lock:
                        cursor = self.conn.cursor()
                        cursor.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,))
                        row = cursor.fetchone()
                        if row and row[0]:
                            cve_detail = json.loads(row[0])
                except Exception as e:
                    self.log(f"从数据库查询CVE数据失败: {str(e)}")

            if not cve_detail:
                messagebox.showerror("错误", f"无法找到 {cve_id} 的详细数据")
                return

            # 查找Dell公告详细数据
            dell_detail = None
            if advisory_id and advisory_id not in ("N/A", "NA"):
                for advisory in self.dell_advisories:
                    if advisory.get('dell_security_advisory') == advisory_id:
                        dell_detail = advisory
                        break
                if not dell_detail:
                    try:
                        with self.db_lock:
                            cursor = self.conn.cursor()
                            cursor.execute("SELECT data FROM dell_advisories WHERE dsa_id = ?", (advisory_id,))
                            row = cursor.fetchone()
                            if row and row[0]:
                                dell_detail = json.loads(row[0])
                    except Exception as e:
                        self.log(f"从数据库查询Dell公告数据失败: {str(e)}")

            if dell_detail:
                # 有Dell公告数据，使用CVE+Dell联合分析
                self.log(f"正在调用AI分析（关联数据）: {cve_id} - {advisory_id}...")
                threading.Thread(
                    target=self._call_ai_solution_thread,
                    args=(cve_detail, dell_detail),
                    daemon=True
                ).start()
            else:
                # 无Dell公告数据，仅分析CVE
                self.log(f"正在调用AI分析（仅CVE）: {cve_id}...")
                threading.Thread(
                    target=self._call_nvd_ai_solution_thread,
                    args=(cve_detail,),
                    daemon=True
                ).start()

        except Exception as e:
            error_msg = f"AI解决方案处理失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def _call_nvd_ai_solution_thread(self, cve_data):
        """在后台线程中调用AI分析CVE数据（无需Dell公告）"""
        try:
            model_name = os.getenv("QWEN_MODEL", "qwen3.6-plus")
            api_key = os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

            if not api_key:
                raise ValueError(
                    "Qwen API密钥未设置。\n"
                    "请在 .env 文件中设置 QWEN_API_KEY 或 DASHSCOPE_API_KEY。"
                )

            # 构建CVE专用提示词
            description = cve_data.get('description', '无详细描述')
            if len(description) > 800:
                description = description[:800] + "..."

            references = cve_data.get('references', [])
            ref_urls = "\n".join([f"  - {r.get('url', '')}" for r in references[:5]]) if references else "  无"

            weaknesses = cve_data.get('weaknesses', [])
            weakness_str = ", ".join(weaknesses) if weaknesses else "未知"

            products = cve_data.get('affected_products', [])
            products_list = []
            for p in products[:10]:
                vendor = p.get('vendor', '')
                product = p.get('product', '')
                version = p.get('version', '*')
                if vendor and product:
                    products_list.append(f"  - {vendor} / {product} (版本: {version})")
            products_str = "\n".join(products_list) if products_list else "  未列出"

            prompt = f"""请为以下CVE漏洞提供专业的安全解决方案分析：

【CVE信息】
- CVE编号: {cve_data.get('cve_id', 'N/A')}
- 严重等级: {cve_data.get('cvss_severity', '未知')}
- CVSS评分: {cve_data.get('cvss_score', 'N/A')}
- CVSS向量: {cve_data.get('cvss_vector', 'N/A')}
- 发布日期: {cve_data.get('published_date', 'N/A')}
- 漏洞状态: {cve_data.get('vuln_status', 'N/A')}
- CWE类型: {weakness_str}

【漏洞描述】
{description}

【受影响产品】
{products_str}

【参考链接】
{ref_urls}

【分析要求】
请提供以下内容：
1. 漏洞详细分析：漏洞原理、攻击向量、利用条件和影响范围
2. 受影响产品和版本范围的详细说明
3. 推荐的修复方案（补丁、升级版本等）
4. 临时缓解措施（在补丁未就绪时的应急方案）
5. 网络层面的监控和检测建议
6. 相关参考资源

请以专业、结构清晰的格式组织答案。"""

            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url, timeout=120)
            analysis_date = datetime.now().strftime("%Y年%m月%d日 %H:%M")
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": f"你是一个企业级安全顾问，专业提供CVE漏洞分析和解决方案建议。当前分析日期: {analysis_date}。请在报告中使用此日期作为分析日期。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )

            solution_result = response.choices[0].message.content

            # 构造空的 dell_advisory_data 以复用显示逻辑
            empty_dell = {"dell_security_advisory": "NVD CVE数据", "title": ""}
            self.root.after(0, self._show_ai_solution_result, solution_result, cve_data, empty_dell)

        except ImportError:
            err = "openai库未安装。请运行: pip install openai"
            self.root.after(0, self.log, err)
            self.root.after(0, messagebox.showerror, "错误", err)
        except Exception as e:
            error_msg = f"AI解决方案分析失败: {str(e)}"
            self.root.after(0, self.log, error_msg)
            self.root.after(0, messagebox.showerror, "错误", error_msg)

    def _call_ai_solution_thread(self, cve_data, dell_advisory_data):
        """在后台线程中调用AI分析"""
        try:
            # 读取环境变量配置
            # 模型名称：从QWEN_MODEL环境变量读取，默认为qwen3.6-plus
            model_name = os.getenv("QWEN_MODEL", "qwen3.6-plus")

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

                analysis_date = datetime.now().strftime("%Y年%m月%d日 %H:%M")
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": f"你是一个企业级安全顾问，专业提供CVE漏洞分析和解决方案建议。当前分析日期: {analysis_date}。请在报告中使用此日期作为分析日期。"
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

        # 处理 affected_products（可能是 dict 列表或 str 列表）
        raw_products = dell_advisory_data.get('affected_products', [])
        prod_names = []
        for p in raw_products:
            if isinstance(p, dict):
                prod_names.append(p.get('name', p.get('product', str(p))))
            else:
                prod_names.append(str(p))

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
- 影响产品: {', '.join(prod_names)}

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
        """弹框显示AI分析结果，用户可选择保存到解决方案标签页"""
        try:
            cve_id = cve_data.get('cve_id', 'N/A')
            advisory_id = dell_advisory_data.get('dell_security_advisory') or dell_advisory_data.get('dsa_id') or 'N/A'

            # 创建弹框
            dialog = tk.Toplevel(self.root)
            dialog.title(f"AI解决方案 - {cve_id}")
            dialog.transient(self.root)
            dialog.grab_set()

            # 添加窗口控制按钮
            self._add_window_controls(dialog)

            # 标题
            header_text = f"CVE编号: {cve_id}"
            if advisory_id and advisory_id not in ("N/A", "NA"):
                if advisory_id == "NVD CVE数据":
                    header_text += f"  |  来源: NVD CVE数据"
                else:
                    header_text += f"  |  Dell公告: {advisory_id}"
            header_text += f"  |  分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

            tk.Label(
                dialog, text=header_text,
                font=("Microsoft YaHei", 10, "bold"),
                bg="#f0f0f0", padx=10, pady=8
            ).pack(fill=tk.X)

            # 结果文本区域
            text_frame = tk.Frame(dialog)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            result_text = scrolledtext.ScrolledText(
                text_frame, wrap=tk.WORD, font=("Consolas", 15), bg="#f8f9fa"
            )
            result_text.pack(fill=tk.BOTH, expand=True)
            result_text.insert(tk.END, result)
            result_text.config(state=tk.DISABLED)

            # 底部按钮区域
            btn_frame = tk.Frame(dialog, bg="white", pady=10)
            btn_frame.pack(fill=tk.X, padx=10)

            def save_and_close():
                self.save_ai_solution_to_db(cve_data, dell_advisory_data, result, "成功")
                self.load_ai_solution_history()
                # 在详细结果区域也显示
                if hasattr(self, 'solution_detail_text'):
                    self.solution_detail_text.config(state=tk.NORMAL)
                    self.solution_detail_text.delete(1.0, tk.END)
                    self.solution_detail_text.insert(tk.END, f"【AI解决方案分析】\n{header_text}\n{'=' * 80}\n\n")
                    self.solution_detail_text.insert(tk.END, result)
                    self.solution_detail_text.config(state=tk.DISABLED)
                self.log(f"AI分析结果已保存: {cve_id}")
                dialog.destroy()
                self.notebook.select(self.solution_tab_id)

            save_btn = tk.Button(
                btn_frame, text="💾 保存到解决方案", command=save_and_close,
                bg=self.success_color, fg="white",
                font=("Microsoft YaHei", 11, "bold"),
                padx=20, pady=6, relief=tk.FLAT, cursor="hand2"
            )
            save_btn.pack(side=tk.LEFT, padx=(0, 10))

            close_btn = tk.Button(
                btn_frame, text="关闭", command=dialog.destroy,
                bg="#95a5a6", fg="white",
                font=("Microsoft YaHei", 11, "bold"),
                padx=20, pady=6, relief=tk.FLAT, cursor="hand2"
            )
            close_btn.pack(side=tk.LEFT)

            # 统一尺寸并居中
            self._center_window(dialog, 1350, 1050)

            self.log(f"AI分析完成: {cve_id}")

        except Exception as e:
            error_msg = f"显示分析结果失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def save_ai_solution_to_db(self, cve_data, dell_advisory_data, result, status="成功"):
        """保存AI分析结果到数据库"""
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
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
                        os.getenv("QWEN_MODEL", "qwen3.6-plus"),
                        "",  # 提示词可选
                        result[:10000],  # 限制长度
                        status
                    )
                )
                self.conn.commit()
        except sqlite3.OperationalError as e:
            # 表可能不存在，尝试创建
            self.log(f"数据库操作失败，尝试创建ai_solutions表: {str(e)}")
            try:
                with self.db_lock:
                    cursor = self.conn.cursor()
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
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_cve ON ai_solutions(cve_id)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_advisory ON ai_solutions(dell_advisory_id)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_solutions_time ON ai_solutions(analysis_time)")
                    self.conn.commit()
                    self.log("ai_solutions表创建成功，重试插入数据")

                    # 重试插入
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
                            os.getenv("QWEN_MODEL", "qwen3.6-plus"),
                            "",
                            result[:10000],
                            status
                        )
                    )
                    self.conn.commit()
                    self.log("AI分析结果保存成功")
            except Exception as retry_error:
                self.log(f"创建表并重试插入失败: {str(retry_error)}")

    def load_ai_solution_history(self):
        """从数据库加载历史记录"""
        try:
            # 清空TreeView
            for item in self.solution_tree.get_children():
                self.solution_tree.delete(item)

            with self.db_lock:
                cursor = self.conn.cursor()
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

                    # 规范化空值显示（保留 "NVD CVE数据"）
                    if not advisory_id or advisory_id == "NA":
                        advisory_id = "NVD CVE数据"
                    status = status if status else "N/A"

                    # 格式化时间戳
                    try:
                        dt = datetime.fromisoformat(analysis_time)
                        time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
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

                    # 根据来源显示不同标签
                    if advisory_id and advisory_id not in ("N/A", "NA", "NVD CVE数据"):
                        source_info = f"公告ID: {advisory_id}"
                    else:
                        source_info = f"数据来源: NVD CVE数据"

                    header = f"""
【AI解决方案详情】
CVE编号: {cve_id} | {source_info}
分析时间: {history['time']} | 状态: {history['status']}
{'=' * 80}

"""
                    self.solution_detail_text.insert(tk.END, header)
                    self.solution_detail_text.insert(tk.END, history['result'])
                    self.solution_detail_text.config(state=tk.DISABLED)
                    break

    def export_solution_history(self):
        """导出解决方案历史记录（支持导出全部或选中条目）"""
        try:
            # 判断是否有选中条目
            selected_iids = self.solution_tree.selection()
            if selected_iids:
                choice = messagebox.askyesnocancel(
                    "导出范围",
                    f"当前选中了 {len(selected_iids)} 条记录。\n\n"
                    f"• 点击「是」— 仅导出选中的 {len(selected_iids)} 条\n"
                    f"• 点击「否」— 导出全部 {len(self.solution_history)} 条\n"
                    f"• 点击「取消」— 取消导出"
                )
                if choice is None:
                    return
                if choice:
                    # 根据选中行的索引获取对应的 solution_history 条目
                    all_iids = self.solution_tree.get_children()
                    selected_indices = set()
                    for iid in selected_iids:
                        try:
                            selected_indices.add(all_iids.index(iid))
                        except ValueError:
                            pass
                    export_data = [self.solution_history[i] for i in sorted(selected_indices)
                                   if i < len(self.solution_history)]
                else:
                    export_data = self.solution_history
            else:
                export_data = self.solution_history

            if not export_data:
                messagebox.showwarning("提示", "没有可导出的记录")
                return

            filepath = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML文件", "*.html"), ("文本文件", "*.txt"), ("CSV文件", "*.csv"), ("所有文件", "*.*")]
            )

            if not filepath:
                return

            with open(filepath, 'w', encoding='utf-8') as f:
                if filepath.endswith('.html'):
                    self._export_solution_as_html(f, export_data)
                elif filepath.endswith('.csv'):
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(['分析时间', 'CVE编号', '公告编号', '分析状态', '结果'])
                    for history in export_data:
                        writer.writerow([
                            history['time'],
                            history['cve_id'],
                            history['advisory_id'],
                            history['status'],
                            history['result'][:200]
                        ])
                else:
                    for history in export_data:
                        f.write(f"\n{'=' * 80}\n")
                        f.write(f"CVE编号: {history['cve_id']}\n")
                        f.write(f"公告编号: {history['advisory_id']}\n")
                        f.write(f"分析时间: {history['time']}\n")
                        f.write(f"状态: {history['status']}\n")
                        f.write(f"\n{history['result']}\n")

            count_msg = f"{len(export_data)} 条记录"
            self.log(f"解决方案历史记录已导出 ({count_msg}): {filepath}")
            messagebox.showinfo("成功", f"已导出 {count_msg} 到:\n{filepath}")

        except Exception as e:
            error_msg = f"导出历史记录失败: {str(e)}"
            self.log(error_msg)
            messagebox.showerror("错误", error_msg)

    def _export_solution_as_html(self, f, export_data):
        """将解决方案历史记录导出为 HTML 格式"""
        import html as html_module
        from datetime import datetime

        export_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = len(export_data)
        success_count = sum(1 for h in export_data if h['status'] == '成功')
        fail_count = total - success_count

        f.write(f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI 解决方案历史记录</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: "Microsoft YaHei", "Segoe UI", sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; padding: 20px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px; border-radius: 10px; margin-bottom: 25px; }}
  .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
  .header .meta {{ font-size: 13px; opacity: 0.85; }}
  .stats {{ display: flex; gap: 15px; margin-bottom: 25px; }}
  .stat-card {{ flex: 1; background: white; border-radius: 8px; padding: 18px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .stat-card .num {{ font-size: 28px; font-weight: bold; }}
  .stat-card .label {{ font-size: 13px; color: #888; margin-top: 4px; }}
  .stat-card.total .num {{ color: #3498db; }}
  .stat-card.success .num {{ color: #27ae60; }}
  .stat-card.fail .num {{ color: #e74c3c; }}
  .card {{ background: white; border-radius: 8px; margin-bottom: 18px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }}
  .card-header {{ display: flex; justify-content: space-between; align-items: center; padding: 15px 20px; border-bottom: 1px solid #eee; }}
  .card-header .ids {{ font-weight: bold; font-size: 15px; }}
  .card-header .cve {{ color: #e74c3c; }}
  .card-header .advisory {{ color: #8e44ad; margin-left: 12px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
  .badge.success {{ background: #e8f8f0; color: #27ae60; }}
  .badge.fail {{ background: #fdecea; color: #e74c3c; }}
  .card-meta {{ padding: 10px 20px; font-size: 13px; color: #888; background: #fafbfc; }}
  .card-body {{ padding: 20px; white-space: pre-wrap; word-wrap: break-word; font-size: 14px; line-height: 1.8; }}
  .footer {{ text-align: center; margin-top: 30px; padding: 15px; color: #aaa; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>AI 解决方案历史记录</h1>
    <div class="meta">导出时间：{export_time} | 智能知识管理平台</div>
  </div>
  <div class="stats">
    <div class="stat-card total"><div class="num">{total}</div><div class="label">总记录数</div></div>
    <div class="stat-card success"><div class="num">{success_count}</div><div class="label">分析成功</div></div>
    <div class="stat-card fail"><div class="num">{fail_count}</div><div class="label">分析失败</div></div>
  </div>
""")

        for i, history in enumerate(export_data, 1):
            cve_id = html_module.escape(history['cve_id'])
            advisory_id = html_module.escape(history['advisory_id'])
            time_str = html_module.escape(history['time'])
            status = history['status']
            result = html_module.escape(history['result'])
            badge_cls = "success" if status == "成功" else "fail"

            f.write(f"""  <div class="card">
    <div class="card-header">
      <div class="ids">
        <span class="cve">{cve_id}</span>
        <span class="advisory">{advisory_id}</span>
      </div>
      <span class="badge {badge_cls}">{html_module.escape(status)}</span>
    </div>
    <div class="card-meta">分析时间：{time_str}</div>
    <div class="card-body">{result}</div>
  </div>
""")

        f.write("""  <div class="footer">由智能知识管理平台生成</div>
</div>
</body>
</html>
""")

    def clear_solution_history(self):
        """清空解决方案历史记录"""
        if not messagebox.askyesno("确认", "确定要清空所有AI解决方案历史记录吗？"):
            return

        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM ai_solutions")
                self.conn.commit()

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

    def delete_solution_selected(self):
        """删除解决方案列表中选中的记录（支持多选）"""
        selected = self.solution_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的记录（支持 Ctrl/Shift 多选）")
            return

        count = len(selected)
        if not messagebox.askyesno(
            "确认删除",
            f"确定要删除选中的 {count} 条AI解决方案记录吗？"
        ):
            return

        # 收集要删除的记录（优先使用数据库 id）
        items_to_delete = []
        db_ids = []
        for iid in selected:
            values = self.solution_tree.item(iid, 'values')
            if values:
                item_info = {
                    'time': str(values[0]),
                    'cve_id': str(values[1]),
                    'advisory_id': str(values[2])
                }
                items_to_delete.append(item_info)
                # 从 solution_history 中查找对应的数据库 id
                for h in self.solution_history:
                    if (h['cve_id'] == item_info['cve_id'] and
                        h.get('advisory_id', '') == item_info['advisory_id'] and
                        h.get('time', '') == item_info['time'] and
                        'id' in h):
                        db_ids.append((h['id'],))
                        break

        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                if db_ids:
                    # 使用精确 id 删除（走主键索引，快速且精确）
                    cursor.executemany(
                        "DELETE FROM ai_solutions WHERE id = ?",
                        db_ids
                    )
                else:
                    # 回退：使用精确匹配（非 LIKE）
                    for item in items_to_delete:
                        cursor.execute(
                            "DELETE FROM ai_solutions WHERE cve_id = ? AND dell_advisory_id = ? AND analysis_time = ?",
                            (item['cve_id'], item['advisory_id'], item['time'])
                        )
                self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("删除失败", f"数据库操作失败：{e}")
            return

        # 从内存中移除
        delete_keys = {(d['cve_id'], d['advisory_id'], d['time']) for d in items_to_delete}
        self.solution_history = [
            h for h in self.solution_history
            if (h['cve_id'], h.get('advisory_id', ''), h.get('time', '')) not in delete_keys
        ]

        # 从树视图中移除
        for iid in selected:
            self.solution_tree.delete(iid)

        preview = ', '.join(d['cve_id'] for d in items_to_delete[:5])
        suffix = '...' if count > 5 else ''
        self.log(f"已删除 {count} 条AI解决方案记录：{preview}{suffix}")

    def on_matched_item_double_click(self, event):
        """处理关联项目双击事件"""
        selection = self.matched_tree.selection()
        if not selection:
            return
        item = self.matched_tree.item(selection[0])
        cve_id = str(item['values'][0]).strip()
        advisory_id = str(item['values'][3]).strip()

        # 优先从内存查找，找不到则从数据库加载
        cve_detail = None
        dell_detail = None

        for cve in self.cve_data:
            if cve.get('cve_id') == cve_id:
                cve_detail = cve
                break

        for advisory in self.dell_advisories:
            if advisory.get('dell_security_advisory') == advisory_id or advisory.get('dsa_id') == advisory_id:
                dell_detail = advisory
                break

        # 从数据库加载缺失的数据
        try:
            with self.db_lock:
                if not cve_detail:
                    row = self.conn.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
                    if row and row[0]:
                        cve_detail = json.loads(row[0])

                if not dell_detail:
                    row = self.conn.execute("SELECT data FROM dell_advisories WHERE dsa_id = ?", (advisory_id,)).fetchone()
                    if row and row[0]:
                        dell_detail = json.loads(row[0])
        except Exception as e:
            self.log(f"加载关联详情失败: {e}")

        if cve_detail and dell_detail:
            self.show_matched_detail(cve_detail, dell_detail)
        elif cve_detail:
            # 只有 CVE 数据，也显示
            self.show_matched_detail(cve_detail, {"dell_security_advisory": advisory_id, "title": str(item['values'][5]), "cve_ids": [cve_id]})
        else:
            messagebox.showinfo("提示", f"未找到 {cve_id} / {advisory_id} 的详细数据。\n请先刷新关联数据。")

    def show_matched_detail(self, cve, advisory):
        """显示关联数据的详细信息"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"关联详情 - {cve.get('cve_id')}")
        detail_window.transient(self.root)

        # 添加窗口控制按钮
        self._add_window_controls(detail_window)

        # 详细信息文本
        text = scrolledtext.ScrolledText(
            detail_window,
            wrap=tk.WORD,
            font=("Consolas", 15)
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

        # 统一尺寸并居中
        self._center_window(detail_window, 1350, 1050)

    # ==================== 统计更新功能 ====================

    def update_stats(self):
        """更新统计信息（图表 + 详情列表 + 数据库信息）"""
        nvd_total = self.get_cve_count_from_db()
        dell_total = self.get_dell_count_from_db()
        matched_count = self.get_matched_count_from_db()

        # ── CVE 严重等级统计（全量数据库，含未分级） ──
        cve_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "AWAITING": 0, "N/A": 0}
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM cves")
                cve_rows = cursor.fetchall()
            for (raw,) in cve_rows:
                try:
                    d = json.loads(raw)
                    s = d.get("cvss_severity", "")
                    if not s or str(s).upper() in ("NONE", "N/A", ""):
                        # 优先从 metrics 中回填（v4.0→v3.1→v3.0→v2.0，跳过 NONE）
                        sev, _, _ = _extract_cvss_from_metrics(d.get("metrics", {}))
                        s = sev
                        if not s and d.get("vuln_status") in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
                            s = "AWAITING"
                    s = str(s).upper() if s else ""
                    if s in cve_severity:
                        cve_severity[s] += 1
                    else:
                        cve_severity["N/A"] += 1
                except Exception:
                    cve_severity["N/A"] += 1
        except Exception:
            pass

        # ── Dell 公告影响等级统计（全量数据库，含未分级） ──
        dell_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "N/A": 0}
        try:
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT data FROM dell_advisories")
                dell_rows = cursor.fetchall()
            for (raw,) in dell_rows:
                try:
                    d = json.loads(raw)
                    impact = d.get('impact', '')
                    if not impact:
                        summary = d.get('summary', '')
                        m = re.search(r'\b(Critical|High|Medium|Low)\b', summary, re.IGNORECASE)
                        impact = m.group(1).capitalize() if m else ''
                    if impact in ("Critical", "High", "Medium", "Low"):
                        dell_severity[impact] += 1
                    else:
                        dell_severity["N/A"] += 1
                except Exception:
                    dell_severity["N/A"] += 1
        except Exception:
            pass

        # 更新卡片数值（严重/高危/中危/低危 = Dell 影响等级）
        self.stats_cards["NVD CVE总数"].value_label.config(text=str(nvd_total))
        self.stats_cards["Dell公告数"].value_label.config(text=str(dell_total))
        self.stats_cards["关联匹配数"].value_label.config(text=str(matched_count))
        self.stats_cards["Dell 严重"].value_label.config(text=str(dell_severity["Critical"]))
        self.stats_cards["Dell 高危"].value_label.config(text=str(dell_severity["High"]))
        self.stats_cards["Dell 中危"].value_label.config(text=str(dell_severity["Medium"]))
        self.stats_cards["Dell 低危"].value_label.config(text=str(dell_severity["Low"]))

        # 更新底部状态栏
        self.cve_count_label.config(
            text=f"NVD CVE: {nvd_total} | Dell 公告: {dell_total} | 关联: {matched_count}"
        )

        # 查询月度趋势数据
        cve_monthly = self._get_monthly_cve_stats()
        dell_monthly = self._get_monthly_dell_stats()
        matched_monthly = self._get_monthly_matched_stats()

        # 绘制月度趋势图
        self._draw_monthly_trends(cve_monthly, dell_monthly, matched_monthly)

        # 绘制数据概览柱状图
        self._draw_overview_bar(nvd_total, dell_total, matched_count)

        # 绘制饼图
        self._draw_pie_charts(cve_severity, dell_severity)

        # ── 更新数据库信息 ──
        self._update_db_info()

        # ── 填充最新 CVE 前10 ──
        for item in self.stats_cve_tree.get_children():
            self.stats_cve_tree.delete(item)

        top_cves = []
        if self.cve_data:
            top_cves = self.cve_data[:10]
        else:
            try:
                with self.db_lock:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT data FROM cves ORDER BY published_date DESC LIMIT 10")
                    rows = cursor.fetchall()
                for (raw,) in rows:
                    try:
                        top_cves.append(json.loads(raw))
                    except Exception:
                        continue
            except Exception:
                pass

        for cve in top_cves:
            cve_id = cve.get('cve_id', 'N/A')
            severity = cve.get('cvss_severity', 'N/A') or 'N/A'
            score = cve.get('cvss_score', 'N/A')
            score_str = str(score) if score is not None else 'N/A'
            pub_date = cve.get('published_date', 'N/A') or 'N/A'
            if pub_date and len(pub_date) > 10:
                pub_date = pub_date[:10]
            desc = (cve.get('description', '') or '')[:120]
            tag = severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else ""
            self.stats_cve_tree.insert("", tk.END,
                values=(cve_id, severity, score_str, pub_date, desc), tags=(tag,))

        # ── 填充最新 Dell 安全公告 前10 ──
        for item in self.stats_dell_tree.get_children():
            self.stats_dell_tree.delete(item)

        top_dells = []
        if self.dell_advisories:
            top_dells = self.dell_advisories[:10]
        else:
            try:
                with self.db_lock:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT data FROM dell_advisories ORDER BY published_date DESC LIMIT 10")
                    rows = cursor.fetchall()
                for (raw,) in rows:
                    try:
                        top_dells.append(json.loads(raw))
                    except Exception:
                        continue
            except Exception:
                pass

        for adv in top_dells:
            dsa_id = adv.get('dell_security_advisory', 'N/A')
            impact = adv.get('impact', '')
            if not impact:
                summary = adv.get('summary', '')
                m = re.search(r'\b(Critical|High|Medium|Low)\b', summary, re.IGNORECASE)
                impact = m.group(1).capitalize() if m else 'N/A'
            title = adv.get('title', 'N/A') or 'N/A'
            cve_count = len(adv.get('cve_ids', []))
            pub_date = adv.get('published_date', 'N/A') or 'N/A'
            if pub_date and len(pub_date) > 10:
                pub_date = pub_date[:10]
            tag = impact if impact in ("Critical", "High", "Medium", "Low") else ""
            self.stats_dell_tree.insert("", tk.END,
                values=(dsa_id, impact, title, cve_count, pub_date), tags=(tag,))

    # ==================== 队列检查和日志功能 ====================

    def check_queues(self):
        """检查队列中的数据（优化版：增量更新）"""
        # 检查 NVD 数据队列
        new_nvd_items = []  # 收集本次批量新增的数据
        new_nvd_ids = set()  # 用 set 去重，O(1) 查找
        need_clear_nvd_tree = False

        while not self.data_queue.empty():
            try:
                data_type, data = self.data_queue.get_nowait()

                # 支持元组命令格式
                if isinstance(data_type, str) and data_type == 'clear_nvd':
                    # 清空NVD树视图
                    need_clear_nvd_tree = True
                    new_nvd_items.clear()
                    new_nvd_ids.clear()
                elif isinstance(data_type, str) and data_type == 'add_nvd':
                    # 添加NVD数据（支持预处理的 tuple 和原始 dict）
                    if data:
                        # 预处理后的数据是 ((values_tuple), tag)
                        if isinstance(data, tuple) and len(data) == 2:
                            values, tag = data
                            cve_id = values[0]  # CVE ID 是第一列
                        else:
                            # 原始 dict 格式（兼容旧代码）
                            cve_id = data.get('cve_id', '')

                        # 只添加不重复的数据
                        if cve_id and cve_id not in new_nvd_ids:
                            new_nvd_ids.add(cve_id)
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

        # ✅ 批量添加到树视图（每次最多处理500条，剩余放回队列下次处理）
        if new_nvd_items:
            batch, remaining = new_nvd_items[:500], new_nvd_items[500:]

            # 临时禁用滚动条回调，减少重绘开销
            original_yscroll = self.nvd_tree.cget('yscrollcommand')
            self.nvd_tree.config(yscrollcommand='')

            # 批量插入
            for cve in batch:
                self.add_nvd_to_tree(cve)

            # 恢复滚动条回调
            self.nvd_tree.config(yscrollcommand=original_yscroll)

            # 剩余数据重新入队，下次 check_queues 继续处理
            for cve in remaining:
                self.data_queue.put(('add_nvd', cve))

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
                        except Exception:
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
        """关闭数据库连接"""
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

    def _add_window_controls(self, window):
        """为弹窗启用系统原生的最小化、最大化、关闭按钮

        Args:
            window: Toplevel 窗口对象
        """
        # 在 Windows 上，Toplevel 窗口默认已经有系统原生的标题栏按钮
        # 但如果设置了 transient，可能会隐藏最小化/最大化按钮
        # 使用 ctypes 修改窗口样式，确保显示完整的标题栏按钮
        try:
            import ctypes
            from ctypes import wintypes

            # 等待窗口创建完成
            window.update_idletasks()

            # 获取窗口句柄
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            if not hwnd:
                hwnd = window.winfo_id()

            # 获取当前窗口样式
            GWL_STYLE = -16
            WS_MINIMIZEBOX = 0x00020000
            WS_MAXIMIZEBOX = 0x00010000
            WS_SYSMENU = 0x00080000

            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)

            # 添加最小化、最大化、系统菜单按钮
            new_style = style | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU

            # 设置新样式
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, new_style)

            # 刷新窗口框架以应用新样式
            SWP_FRAMECHANGED = 0x0020
            SWP_NOMOVE = 0x0002
            SWP_NOSIZE = 0x0001
            SWP_NOZORDER = 0x0004
            ctypes.windll.user32.SetWindowPos(
                hwnd, 0, 0, 0, 0, 0,
                SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER
            )

        except Exception as e:
            # 如果修改窗口样式失败，记录日志但不影响窗口显示
            self.log(f"启用窗口控制按钮失败（可忽略）: {e}")

    def _center_window(self, window, width=None, height=None):
        """将弹窗居中显示在主窗口中央

        Args:
            window: Toplevel 窗口对象
            width: 窗口宽度（可选，不指定则使用当前宽度）
            height: 窗口高度（可选，不指定则使用当前高度）
        """
        window.update_idletasks()

        # 获取窗口尺寸
        if width is None or height is None:
            window_width = window.winfo_width()
            window_height = window.winfo_height()
        else:
            window_width = width
            window_height = height

        # 获取主窗口位置和尺寸
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        # 计算居中位置
        x = root_x + (root_width - window_width) // 2
        y = root_y + (root_height - window_height) // 2

        # 确保窗口不会超出屏幕
        x = max(0, x)
        y = max(0, y)

        window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    def log(self, message):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"

        if hasattr(self, 'log_text') and self.log_text:
            self.log_text.insert(tk.END, log_message)
            self.log_text.see(tk.END)
        else:
            # 控件尚未创建，写入队列
            if hasattr(self, 'log_queue'):
                self.log_queue.put(message)

    def clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)
        self.log("日志已清空")

    def _backup_database_ui(self):
        """一键备份数据库"""
        self.log("正在备份数据库...")
        try:
            db_path = str(self.data_dir / "cve_database.db")
            result = backup_database(db_path)
            if result:
                size_mb = round(Path(result).stat().st_size / 1024 / 1024, 1)
                msg = f"数据库备份成功！\n\n路径：{result}\n大小：{size_mb} MB"
                messagebox.showinfo("备份成功", msg)
                self.log(f"数据库备份完成: {result} ({size_mb} MB)")
            else:
                messagebox.showerror("备份失败", "数据库备份失败，请检查磁盘空间。")
        except Exception as e:
            messagebox.showerror("备份失败", f"备份出错：{e}")
            self.log(f"数据库备份失败: {e}")

    def _show_backups_ui(self):
        """查看备份列表"""
        try:
            backups = list_backups()
        except Exception as e:
            messagebox.showerror("错误", f"读取备份列表失败: {e}")
            return

        if not backups:
            messagebox.showinfo("备份列表", "暂无备份文件。\n点击「💾 备份数据库」创建第一个备份。")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("数据库备份列表")
        dialog.transient(self.root)

        # 添加窗口控制按钮
        self._add_window_controls(dialog)

        tk.Label(
            dialog, text=f"共 {len(backups)} 个备份",
            font=("Microsoft YaHei", 11, "bold"),
            bg="#2c3e50", fg="white", padx=10, pady=8
        ).pack(fill=tk.X)

        cols = ("name", "size", "created")
        tree = ttk.Treeview(dialog, columns=cols, show="headings", height=15)
        tree.heading("name", text="文件名")
        tree.heading("size", text="大小 (MB)")
        tree.heading("created", text="创建时间")
        tree.column("name", width=280)
        tree.column("size", width=80, anchor="center")
        tree.column("created", width=160, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for b in backups:
            tree.insert("", tk.END, values=(b["name"], b["size_mb"], b["created_at"]))

        tk.Button(
            dialog, text="关闭", command=dialog.destroy,
            bg="#95a5a6", fg="white", font=("Microsoft YaHei", 9),
            relief=tk.FLAT, cursor="hand2", padx=15, pady=5
        ).pack(pady=(0, 10))

        # 居中显示
        self._center_window(dialog, 600, 400)

    def _backfill_cvss_ui(self):
        """批量回填数据库中缺失的 CVSS 评分/严重等级"""
        if not messagebox.askyesno(
            "确认回填",
            "将批量扫描数据库中所有严重等级/评分缺失的 NVD CVE 数据，\n"
            "优先从已存储的 metrics(JSON) 中回填 CVSS v4.0/v3.1/v3.0/v2.0 信息。\n\n"
            "该操作不会访问外网，只会更新本地数据库。是否继续？"
        ):
            return

        self.log("开始批量回填 CVSS 数据...")
        self.show_progress("正在扫描缺失的 CVSS 数据...")
        threading.Thread(target=self._backfill_cvss_thread, daemon=True).start()

    def _backfill_cvss_thread(self):
        """后台线程：批量回填 CVSS 评分/严重等级"""
        try:
            updated = 0
            awaiting = 0
            total_missing = 0

            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT cve_id, data FROM cves")
                rows = cursor.fetchall()

                total = len(rows)
                for idx, (cve_id, data_str) in enumerate(rows, 1):
                    try:
                        data = json.loads(data_str) if data_str else {}
                    except Exception:
                        continue

                    # 跳过已有有效 severity 且非 NONE 的记录
                    existing_sev = str(data.get("cvss_severity", "")).upper()
                    if existing_sev and existing_sev not in ("NONE", "N/A", "", "AWAITING") and data.get("cvss_score") not in (None, ""):
                        continue

                    total_missing += 1
                    metrics = data.get("metrics", {})
                    filled = False

                    sev, score, vec = _extract_cvss_from_metrics(metrics)
                    if sev:
                        data["cvss_severity"] = sev
                        data["cvss_score"] = score
                        data["cvss_vector"] = vec
                        filled = True

                    if not filled and data.get("vuln_status") in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
                        data["cvss_severity"] = "AWAITING"
                        awaiting += 1
                        filled = True

                    if filled:
                        cursor.execute(
                            "UPDATE cves SET data = ?, last_modified = ? WHERE cve_id = ?",
                            (json.dumps(data, ensure_ascii=False), data.get("last_modified", "") or "", cve_id)
                        )
                        updated += 1

                    if idx % 500 == 0 or idx == total:
                        pct = int(idx * 100 / max(total, 1))
                        self.root.after(0, self.update_progress, pct, f"已扫描 {idx}/{total} 条，已更新 {updated} 条")

                self.conn.commit()

            self.root.after(0, self.hide_progress)
            self.root.after(0, self.load_nvd_from_database)
            self.root.after(0, self.update_stats)
            self.root.after(
                0,
                messagebox.showinfo,
                "回填完成",
                f"扫描缺失记录: {total_missing} 条\n"
                f"成功回填: {updated} 条\n"
                f"其中标记 AWAITING: {awaiting} 条"
            )
            self.log(f"批量回填完成：扫描缺失 {total_missing} 条，更新 {updated} 条，AWAITING {awaiting} 条")

        except Exception as e:
            self.root.after(0, self.hide_progress)
            self.root.after(0, messagebox.showerror, "回填失败", f"批量回填 CVSS 失败: {e}")
            self.log(f"批量回填 CVSS 失败: {e}")

    def _requery_awaiting_cvss_ui(self):
        """从 NVD API 重新查询 AWAITING/N/A CVE 的 CVSS 评分"""
        # 先统计数量
        count = 0
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT cve_id, data FROM cves")
            for cve_id, data_str in cursor.fetchall():
                try:
                    d = json.loads(data_str) if data_str else {}
                    sev = str(d.get("cvss_severity", "")).upper()
                    if not sev or sev in ("AWAITING", "NONE", "N/A", ""):
                        count += 1
                except Exception:
                    pass

        if count == 0:
            messagebox.showinfo("提示", "没有需要重查的 AWAITING/N/A CVE")
            return

        if not messagebox.askyesno(
            "重查 AWAITING CVE",
            f"将从 NVD API 重新查询 {count} 条 AWAITING/N/A CVE 的最新 CVSS 评分。\n\n"
            f"需要访问外网（NVD API），预计耗时 {max(1, count // 100)} - {max(2, count // 50)} 分钟。\n\n"
            "是否继续？"
        ):
            return

        self.log(f"开始从 NVD API 重查 {count} 条 AWAITING/N/A CVE...")
        self.show_progress("正在从 NVD API 重查 AWAITING CVE...")
        threading.Thread(target=self._requery_awaiting_thread, daemon=True).start()

    def _requery_awaiting_thread(self):
        """后台线程：从 NVD API 重新查询 AWAITING/N/A CVE"""
        import aiohttp

        async def _do_requery():
            api_key = os.getenv("NVD_API_KEY")
            headers = {}
            if api_key:
                headers["apiKey"] = api_key

            # 收集需要重查的 CVE ID
            targets = []
            with self.db_lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT cve_id, data FROM cves")
                for cve_id, data_str in cursor.fetchall():
                    try:
                        d = json.loads(data_str) if data_str else {}
                        sev = str(d.get("cvss_severity", "")).upper()
                        if not sev or sev in ("AWAITING", "NONE", "N/A", ""):
                            targets.append((cve_id, d))
                    except Exception:
                        pass

            total = len(targets)
            self.log_queue.put(f"需要重查 {total} 条 CVE")
            updated = 0
            still_awaiting = 0
            errors = 0

            timeout = aiohttp.ClientTimeout(total=20)
            delay = 0.6 if api_key else 6

            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                for idx, (cve_id, data) in enumerate(targets, 1):
                    try:
                        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                result = await resp.json()
                                vulns = result.get("vulnerabilities", [])
                                if vulns:
                                    cve_obj = vulns[0].get("cve", {})
                                    metrics = cve_obj.get("metrics", {})

                                    sev, score, vec = _extract_cvss_from_metrics(metrics)
                                    if sev:
                                        data["cvss_severity"] = sev
                                        data["cvss_score"] = score
                                        data["cvss_vector"] = vec
                                        data["metrics"] = metrics
                                        updated += 1
                                    else:
                                        vuln_status = cve_obj.get("vulnStatus", "")
                                        if vuln_status in ("Awaiting Analysis", "Received", "Undergoing Analysis"):
                                            data["cvss_severity"] = "AWAITING"
                                        data["metrics"] = metrics
                                        still_awaiting += 1

                                    with self.db_lock:
                                        cursor = self.conn.cursor()
                                        cursor.execute(
                                            "UPDATE cves SET data = ? WHERE cve_id = ?",
                                            (json.dumps(data, ensure_ascii=False), cve_id)
                                        )
                                        if idx % 50 == 0:
                                            self.conn.commit()
                            elif resp.status == 403:
                                self.log_queue.put("NVD API 限流，等待 30 秒...")
                                await asyncio.sleep(30)
                                errors += 1
                            else:
                                errors += 1
                    except Exception as e:
                        errors += 1

                    if idx % 50 == 0 or idx == total:
                        pct = int(idx * 100 / max(total, 1))
                        self.root.after(0, self.update_progress, pct,
                                        f"已查询 {idx}/{total}，更新 {updated}，仍 AWAITING {still_awaiting}")
                        self.log_queue.put(f"进度: {idx}/{total}，已更新 {updated} 条")

                    await asyncio.sleep(delay)

            with self.db_lock:
                self.conn.commit()

            return updated, still_awaiting, errors, total

        try:
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            updated, still_awaiting, errors, total = asyncio.run(_do_requery())

            self.root.after(0, self.hide_progress)
            self.root.after(0, self.load_nvd_from_database)
            self.root.after(0, self.update_stats)
            self.root.after(
                0, messagebox.showinfo, "重查完成",
                f"总计重查: {total} 条\n"
                f"成功更新评分: {updated} 条\n"
                f"仍为 AWAITING: {still_awaiting} 条\n"
                f"查询失败: {errors} 条"
            )
            self.log(f"NVD 重查完成：总计 {total}，更新 {updated}，仍 AWAITING {still_awaiting}，失败 {errors}")

        except Exception as e:
            self.root.after(0, self.hide_progress)
            self.root.after(0, messagebox.showerror, "重查失败", f"NVD API 重查失败: {e}")
            self.log(f"NVD API 重查失败: {e}")


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
