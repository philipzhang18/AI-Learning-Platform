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

        # 数据存储
        self.cve_data = []
        self.dell_advisories = []
        self.is_collecting = False
        self.is_collecting_dell = False

        # 数据目录
        self.data_dir = Path("cve_data")
        self.data_dir.mkdir(exist_ok=True)

        # 初始化 Redis 数据管理器（优先使用）
        self.use_redis = False
        self.redis_init_message = ""
        try:
            self.redis_manager = RedisDataManager(
                password=os.getenv('REDIS_PASSWORD', 'defaultpassword')
            )
            if self.redis_manager.ping():
                self.use_redis = True
                self.redis_init_message = "Redis 已连接 - 使用高性能缓存模式"
            else:
                self.redis_init_message = "Redis 连接失败 - 回退到 SQLite 模式"
        except Exception as e:
            self.redis_init_message = f"Redis 初始化失败: {e} - 回退到 SQLite 模式"

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

        # 加载本地数据
        self.load_local_data()

    def init_database(self):
        """初始化本地数据库"""
        self.db_path = self.data_dir / "cve_database.db"
        # 确保使用 WAL 模式以提高并发性
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')
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
            cursor.execute("SELECT cve_id FROM cves")
            existing_ids = [row[0] for row in cursor.fetchall()]
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

    def _store_cve_to_sqlite(self, cve_data):
        """存储 CVE 数据到 SQLite（内部方法）"""
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
            
            records = cursor.fetchall()
            cve_data = []
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
        """存储 Dell 数据到 SQLite（内部方法）"""
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

    def load_dell_from_database(self):
        """从数据库加载Dell安全公告（优先使用 Redis）"""
        # 优先从 Redis 加载
        if self.use_redis:
            try:
                self.dell_advisories = self.redis_manager.get_all_dell_advisories()

                # 清空树形视图
                for item in self.dell_tree.get_children():
                    self.dell_tree.delete(item)

                # 显示数据
                for advisory in self.dell_advisories:
                    self.add_dell_to_tree(advisory)

                self.log(f"从 Redis 加载 {len(self.dell_advisories)} 条 Dell 安全公告")

                # 更新关联数据
                self.refresh_matched_data()
                return

            except Exception as e:
                self.log(f"Redis 加载 Dell 数据失败: {e}, 回退到 SQLite")
                # 继续使用 SQLite

        # 从 SQLite 加载（回退方案）
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

            # 清空树形视图
            for item in self.dell_tree.get_children():
                self.dell_tree.delete(item)

            # 显示数据
            for advisory in self.dell_advisories:
                self.add_dell_to_tree(advisory)

            self.log(f"从 SQLite 加载 {len(self.dell_advisories)} 条 Dell 安全公告")

            # 更新关联数据
            self.refresh_matched_data()

        except sqlite3.Error as e:
            self.log(f"从数据库加载Dell数据失败: {str(e)}")

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

        # 1. NVD CVE 数据标签页
        self.nvd_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.nvd_frame, text="📊 NVD CVE 数据")

        # 2. Dell 安全公告标签页
        self.dell_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.dell_frame, text="🏢 Dell 安全公告")

        # 3. 关联数据标签页
        self.matched_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.matched_frame, text="🔗 CVE-Dell 关联")

        # 4. 统计分析标签页
        self.stats_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.stats_frame, text="📈 统计分析")

        # 5. 日志标签页
        self.log_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.log_frame, text="📝 操作日志")

        # 创建各个标签页的内容
        self.create_nvd_view()
        self.create_dell_view()
        self.create_matched_view()
        self.create_stats_view()
        self.create_log_view()

        # 底部状态栏
        status_bar = tk.Frame(self.root, bg=self.primary_color, height=35)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)

        self.bottom_status = tk.Label(
            status_bar,
            text="准备就绪 | 支持离线数据查看",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 9)
        )
        self.bottom_status.pack(side=tk.LEFT, padx=10, pady=5)

        self.cve_count_label = tk.Label(
            status_bar,
            text="NVD CVE: 0 | Dell 公告: 0 | 关联: 0",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 9, "bold")
        )
        self.cve_count_label.pack(side=tk.RIGHT, padx=10, pady=5)

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

        # 加载本地数据按钮
        load_btn = tk.Button(
            left_control,
            text="📁 加载本地数据",
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

        tk.Label(search_frame, text="(支持 CVE ID、描述、严重等级搜索)", bg="white", font=("Microsoft YaHei", 9), fg="gray").pack(side=tk.LEFT)

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

        # 数据展示区域
        data_container = tk.Frame(self.dell_frame, bg="white")
        data_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # 搜索框
        search_frame = tk.Frame(data_container, bg="white")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="公告ID：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))
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

        tk.Label(search_frame, text="(支持 CVE ID、标题、产品搜索)", bg="white", font=("Microsoft YaHei", 9), fg="gray").pack(side=tk.LEFT)

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

    # ==================== NVD CVE 采集功能 ====================

    def start_nvd_collection(self):
        """开始采集 NVD CVE 数据"""
        if self.is_collecting:
            return

        self.is_collecting = True
        self.nvd_collect_btn.config(state=tk.DISABLED)
        self.nvd_stop_btn.config(state=tk.NORMAL)

        # 清空现有数据
        for item in self.nvd_tree.get_children():
            self.nvd_tree.delete(item)

        self.cve_data = []

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
            self.nvd_collect_btn.config(state=tk.NORMAL)
            self.nvd_stop_btn.config(state=tk.DISABLED)

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
                    new_cves = []  # 收集新增的 CVE

                    for raw_cve in all_raw_cves:
                        if not self.is_collecting:
                            break

                        parsed = collector.parse_cve(raw_cve)
                        cve_id = parsed.get("cve_id", "")

                        if cve_id:
                            # 存储到数据库（增量）
                            is_new = cve_id not in existing_cve_ids
                            self.store_cve_data(parsed)

                            if is_new:
                                new_cves.append(parsed)
                                new_cves_count += 1
                                # 添加到已存在列表
                                existing_cve_ids.add(cve_id)
                            else:
                                updated_count += 1

                    # 优化：只将新增的 CVE 添加到内存和 GUI（不重新加载全部数据）
                    if new_cves:
                        self.log_queue.put(f"正在显示 {len(new_cves)} 条新增 CVE...")

                        # 批量添加到内存
                        self.cve_data.extend(new_cves)

                        # 批量添加到 GUI（通过队列）
                        for cve in new_cves:
                            self.data_queue.put(('nvd', cve))

                    # 显示统计
                    total_in_db = len(existing_cve_ids)
                    self.log_queue.put(f"✓ NVD CVE 数据采集完成！")
                    self.log_queue.put(f"  新增: {new_cves_count} 条")
                    if updated_count > 0:
                        self.log_queue.put(f"  更新: {updated_count} 条")
                    self.log_queue.put(f"  数据库总计: {total_in_db} 条")
                else:
                    # 从数据库加载现有数据
                    all_cves = self.load_cve_data_from_db()
                    self.cve_data = all_cves
                    self.log_queue.put(f"未获取到新的 CVE 数据，从数据库加载 {len(all_cves)} 条记录")

            except Exception as e:
                self.log_queue.put(f"采集过程出错: {str(e)}")
                import traceback
                self.log_queue.put(f"详细错误: {traceback.format_exc()}")

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

        # 清空现有数据
        for item in self.dell_tree.get_children():
            self.dell_tree.delete(item)

        self.dell_advisories = []

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
            self.dell_collect_btn.config(state=tk.NORMAL)
            self.dell_stop_btn.config(state=tk.DISABLED)

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

                for item in items:
                    if not self.is_collecting_dell:
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

                # 优化：批量添加到 GUI（只添加新数据）
                if new_advisories:
                    self.log_queue.put(f"正在显示 {len(new_advisories)} 条新增公告...")

                    # 批量添加到内存
                    self.dell_advisories.extend(new_advisories)

                    # 批量发送到队列
                    for advisory in new_advisories:
                        self.dell_queue.put(advisory)

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
            else:
                self.log_queue.put("未获取到任何数据")

        except Exception as e:
            self.log_queue.put(f"采集数据出错: {str(e)}")
            import traceback
            self.log_queue.put(f"详细错误: {traceback.format_exc()}")

    # ==================== 数据加载和显示功能 ====================

    def load_local_data(self):
        """加载本地数据"""
        # 加载数据库中的CVE数据
        try:
            self.cve_data = self.load_cve_data_from_db()
            
            # 从GUI中清除旧的NVD数据
            for item in self.nvd_tree.get_children():
                self.nvd_tree.delete(item)
                
            # 添加数据库中的数据到GUI
            for cve in self.cve_data:
                self.add_nvd_to_tree(cve)
                
            self.log(f"已从数据库加载 NVD 数据: {len(self.cve_data)} 条")

            # 加载 Dell 数据（优先从 Redis）
            if self.use_redis:
                try:
                    self.dell_advisories = self.redis_manager.get_all_dell_advisories()
                    for advisory in self.dell_advisories:
                        self.add_dell_to_tree(advisory)
                    self.log(f"从 Redis 加载 Dell 数据: {len(self.dell_advisories)} 条")
                except Exception as e:
                    self.log(f"从 Redis 加载 Dell 数据失败: {e}, 尝试从文件加载")
                    # 回退到文件加载
                    dell_files = list(self.data_dir.glob("dell_advisories_*.json"))
                    if dell_files:
                        latest_dell = max(dell_files, key=lambda x: x.stat().st_mtime)
                        with open(latest_dell, "r", encoding="utf-8") as f:
                            self.dell_advisories = json.load(f)
                        for advisory in self.dell_advisories:
                            self.add_dell_to_tree(advisory)
                        self.log(f"已加载本地 Dell 数据: {latest_dell.name} ({len(self.dell_advisories)} 条)")
            else:
                # SQLite 模式：从文件加载
                dell_files = list(self.data_dir.glob("dell_advisories_*.json"))
                if dell_files:
                    latest_dell = max(dell_files, key=lambda x: x.stat().st_mtime)
                    with open(latest_dell, "r", encoding="utf-8") as f:
                        self.dell_advisories = json.load(f)
                    for advisory in self.dell_advisories:
                        self.add_dell_to_tree(advisory)
                    self.log(f"已加载本地 Dell 数据: {latest_dell.name} ({len(self.dell_advisories)} 条)")

            # 刷新关联数据
            if self.cve_data and self.dell_advisories:
                self.refresh_matched_data()

            # 更新统计
            self.update_stats()

        except Exception as e:
            self.log(f"加载本地数据出错: {str(e)}")

    def load_local_nvd_data(self):
        """手动加载本地 NVD 数据"""
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

                # 从数据库重新加载所有数据
                self.cve_data = self.load_cve_data_from_db()

                # 清空并重新加载树视图
                for item in self.nvd_tree.get_children():
                    self.nvd_tree.delete(item)

                for cve in self.cve_data:
                    self.add_nvd_to_tree(cve)

                self.log(f"成功加载 NVD 数据: {Path(filename).name} ({len(loaded_cves)} 条)，现在数据库中共有 {len(self.cve_data)} 条")
                self.update_stats()

                # 刷新关联数据
                if self.dell_advisories:
                    self.refresh_matched_data()

            except Exception as e:
                messagebox.showerror("加载失败", f"加载文件失败：{str(e)}")
                self.log(f"加载文件失败: {str(e)}")

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
            self.dell_queue.put(('refresh_database', None))

            self.log_queue.put(f"✓ Dell CSV加载完成")

            # 通知主线程更新统计和关联数据
            self.dell_queue.put(('update_stats', None))

        except Exception as e:
            self.log_queue.put(f"加载Dell CSV失败: {str(e)}")
            import traceback
            self.log_queue.put(f"详细错误信息: {traceback.format_exc()}")

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

    def refresh_matched_data(self):
        """刷新关联数据（优化版，使用哈希表加速）"""
        # 清空关联树视图
        for item in self.matched_tree.get_children():
            self.matched_tree.delete(item)

        if not self.cve_data or not self.dell_advisories:
            self.log("无法刷新关联数据：缺少 NVD 或 Dell 数据")
            return

        # 优化：构建 CVE ID 到 CVE 数据的映射
        cve_dict = {cve.get("cve_id", ""): cve for cve in self.cve_data}

        # 匹配 CVE ID（优化：遍历 Dell 公告，查找对应的 CVE）
        matched_count = 0
        matched_items = []  # 先收集所有匹配项

        for advisory in self.dell_advisories:
            advisory_cve_ids = advisory.get("cve_ids", [])

            for cve_id in advisory_cve_ids:
                if cve_id in cve_dict:
                    cve = cve_dict[cve_id]

                    # 提取产品型号
                    products = advisory.get("affected_products", [])
                    product_names = [p.get("name", "") for p in products[:3]]  # 最多显示3个
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

        for item_data in items_to_display:
            self.matched_tree.insert(
                "",
                "end",
                values=item_data["values"],
                tags=(item_data["tag"],)
            )

        if matched_count > max_display:
            self.log(f"关联匹配完成：找到 {matched_count} 条匹配数据，显示前 {max_display} 条（性能优化）")
        else:
            self.log(f"关联匹配完成：找到 {matched_count} 条匹配的 CVE-Dell 数据")

        self.update_stats()

    # ==================== 搜索过滤功能 ====================

    def filter_nvd_data(self, *args):
        """过滤 NVD 数据"""
        search_term = self.nvd_search_var.get().upper()

        # 清空树视图
        for item in self.nvd_tree.get_children():
            self.nvd_tree.delete(item)

        # 重新添加符合条件的数据
        for cve in self.cve_data:
            cve_id = cve.get("cve_id", "") or ""
            description = cve.get("description", "") or ""
            severity = cve.get("cvss_severity", "") or ""
            
            if (search_term in cve_id.upper() or
                search_term in description.upper() or
                search_term in severity.upper()):
                self.add_nvd_to_tree(cve)

    def filter_dell_data(self, *args):
        """过滤 Dell 数据"""
        search_term = self.dell_search_var.get().upper()

        # 清空树视图
        for item in self.dell_tree.get_children():
            self.dell_tree.delete(item)

        # 重新添加符合条件的数据
        for advisory in self.dell_advisories:
            cve_ids = advisory.get("cve_ids", [])
            cve_ids_str = ", ".join(cve_ids).upper() if cve_ids else ""
            
            title = advisory.get("title", "") or ""
            title = title.upper()
            
            product_names = [p.get("name", "") for p in advisory.get("affected_products", [])]
            products = ", ".join(product_names).upper() if product_names else ""

            if (search_term in cve_ids_str or
                search_term in title or
                search_term in products):
                self.add_dell_to_tree(advisory)

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

        # 优化：使用集合加速关联匹配
        # 将所有 CVE ID 放入集合
        cve_ids_set = {cve.get("cve_id", "") for cve in self.cve_data}

        # 统计关联匹配数（优化：只遍历 Dell 公告，使用 set 查找）
        matched_cves = set()
        for advisory in self.dell_advisories:
            advisory_cve_ids = advisory.get("cve_ids", [])
            for cve_id in advisory_cve_ids:
                if cve_id in cve_ids_set:
                    matched_cves.add(cve_id)

        matched_count = len(matched_cves)

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

        while not self.data_queue.empty():
            try:
                data_type, data = self.data_queue.get_nowait()
                if data_type == 'nvd':
                    # ✅ 优化：直接添加到内存，无需重新加载数据库
                    # 检查是否已存在（避免重复）
                    cve_id = data.get('cve_id', '')
                    if cve_id and not any(cve.get('cve_id') == cve_id for cve in self.cve_data):
                        self.cve_data.append(data)
                        new_nvd_items.append(data)
            except queue.Empty:
                break

        # ✅ 批量添加到树视图（减少 GUI 更新次数）
        if new_nvd_items:
            for cve in new_nvd_items:
                self.add_nvd_to_tree(cve)

        # 检查 Dell 数据队列
        new_dell_items = []  # 收集新增的 Dell 数据
        need_refresh_database = False
        need_update_stats = False

        while not self.dell_queue.empty():
            try:
                data = self.dell_queue.get_nowait()
                # 检查是否是特殊命令
                if isinstance(data, tuple) and len(data) == 2:
                    command, _ = data
                    if command == 'refresh_database':
                        need_refresh_database = True
                    elif command == 'update_stats':
                        need_update_stats = True
                else:
                    # ✅ 优化：收集数据，稍后批量处理
                    # 检查是否已存在（避免重复）
                    dsa_id = data.get('dell_security_advisory', '')
                    if dsa_id and not any(adv.get('dell_security_advisory') == dsa_id for adv in self.dell_advisories):
                        self.dell_advisories.append(data)
                        new_dell_items.append(data)
            except queue.Empty:
                break

        # 执行特殊命令
        if need_refresh_database:
            self.load_dell_from_database()

        # ✅ 批量添加 Dell 数据到树视图
        if new_dell_items:
            for advisory in new_dell_items:
                self.add_dell_to_tree(advisory)

        # 检查日志队列
        while not self.log_queue.empty():
            try:
                message = self.log_queue.get_nowait()
                self.log(message)
            except queue.Empty:
                break

        # ✅ 优化：只在有新数据或收到更新命令时才更新统计
        if new_nvd_items or new_dell_items or need_update_stats:
            self.update_stats()
            # 如果有新的 CVE 或 Dell 数据，刷新关联数据
            if (new_nvd_items or new_dell_items) and self.cve_data and self.dell_advisories:
                self.refresh_matched_data()

        # 继续检查
        self.root.after(100, self.check_queues)

    def close_database_connection(self):
        """关闭数据库连接"""
        # 关闭 Redis 连接
        if hasattr(self, 'redis_manager') and self.redis_manager:
            try:
                self.redis_manager.close()
                self.log("Redis 连接已关闭")
            except Exception as e:
                self.log(f"关闭 Redis 连接时出错: {str(e)}")

        # 关闭 SQLite 连接
        if hasattr(self, 'conn') and self.conn:
            try:
                self.conn.close()
                self.log("SQLite 连接已关闭")
            except sqlite3.Error as e:
                self.log(f"关闭 SQLite 连接时出错: {str(e)}")

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


def main():
    """主函数"""
    # 设置 Windows DPI 感知
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, OSError, AttributeError) as e:
        # 非Windows系统或Windows版本不支持DPI设置，忽略
        pass

    root = tk.Tk()
    app = CVEIntegratedGUI(root)
    
    # 添加协议处理程序，在窗口关闭时关闭数据库连接
    def on_closing():
        app.close_database_connection()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    root.mainloop()


if __name__ == "__main__":
    main()
