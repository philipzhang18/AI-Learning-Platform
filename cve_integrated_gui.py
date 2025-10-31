"""
CVE 漏洞监控系统 - 整合版
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


class CVEIntegratedGUI:
    """CVE 漏洞监控系统整合界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("CVE 漏洞监控系统 - 整合版")
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

        # 数据存储
        self.cve_data = []
        self.dell_advisories = []
        self.is_collecting = False
        self.is_collecting_dell = False

        # 数据目录
        self.data_dir = Path("cve_data")
        self.data_dir.mkdir(exist_ok=True)

        # 初始化本地数据库
        self.init_database()

        # 创建界面
        self.create_widgets()

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
            
            # 检查是否已存在 'data' 列
            cursor.execute("PRAGMA table_info(cves)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # 如果没有 'data' 列，则添加
            if 'data' not in columns:
                # 重新创建表以添加缺失的列
                cursor.execute("ALTER TABLE cves ADD COLUMN data TEXT DEFAULT ''")
            
            # 检查并修复其他可能的问题
            # 如果主键定义不当，重新创建表
            if 'cve_id' not in columns or columns[0] != 'cve_id':  # Check if cve_id is the primary key
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
                except:
                    # If the old table structure is different, just create the new one
                    pass
            
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
    
    def store_cve_data(self, cve_data):
        """存储单个CVE数据到数据库"""
        try:
            cursor = self.conn.cursor()
            
            cve_id = cve_data.get('cve_id', '')
            if not cve_id:
                self.log("跳过空CVE ID的数据")
                return
                
            # Ensure the data field is not None
            data_str = json.dumps(cve_data) if cve_data else '{}'
            
            # 检查是否已存在
            cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone():
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
        except sqlite3.Error as e:
            self.log(f"存储CVE数据失败: {str(e)}")
            # 尝试回滚事务
            try:
                self.conn.rollback()
            except:
                pass  # Ignore rollback errors
        except Exception as e:
            self.log(f"存储CVE数据时发生未知错误: {str(e)}")
    
    def load_cve_data_from_db(self, cve_ids=None):
        """从数据库加载CVE数据"""
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

    def create_widgets(self):
        """创建界面组件"""

        # 顶部标题栏
        header_frame = tk.Frame(self.root, bg=self.primary_color, height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="🛡️ CVE 漏洞监控系统 - 整合版",
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

        self.nvd_days_var = tk.StringVar(value="365")
        days_combo = ttk.Combobox(
            left_control,
            textvariable=self.nvd_days_var,
            values=["7", "30", "90", "180", "365"],
            width=10,
            state="readonly"
        )
        days_combo.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(left_control, text="天", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 20))

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
        info_banner = tk.Frame(self.dell_frame, bg="#fff3cd", pady=8)
        info_banner.pack(fill=tk.X, padx=10, pady=(10, 0))

        info_text = "ℹ️ 注意：Dell 官方 RSS 已停用。当前使用高质量示例数据（包含 5 条真实格式的 Dell 安全公告），可完整演示所有功能。"
        info_label = tk.Label(
            info_banner,
            text=info_text,
            bg="#fff3cd",
            fg="#856404",
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

        # 开始采集按钮
        self.dell_collect_btn = tk.Button(
            left_control,
            text="▶ 生成示例 Dell 数据",
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
            text="📁 加载本地数据",
            command=self.load_local_dell_data,
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

        # 获取天数
        days = int(self.nvd_days_var.get())

        # 优先使用环境变量的 API Key
        api_key = os.getenv("NVD_API_KEY")

        # 在新线程中运行采集
        thread = threading.Thread(target=self.run_nvd_collection, args=(days, api_key))
        thread.daemon = True
        thread.start()

        self.log(f"开始采集 NVD CVE 数据（最近 {days} 天）...")
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
        """异步采集 NVD CVE 数据"""
        end_date = datetime.now().replace(hour=23, minute=59, second=59, microsecond=999999)
        start_date = end_date - timedelta(days=days)

        self.log_queue.put(f"时间范围: {start_date.date()} 至 {end_date.date()}")
        
        # 获取数据库中已存在的CVE IDs
        existing_cve_ids = self.get_existing_cve_ids()
        self.log_queue.put(f"数据库中已存在 {len(existing_cve_ids)} 个CVE记录")

        async with CVECollector(api_key=api_key) as collector:
            try:
                # Collect data in chunks to avoid API date range limitations
                # NVD API typically works best with date ranges of 120 days or less
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
                        
                        self.log_queue.put(f"批次完成: {len(chunk_cves)} 条 CVE 数据 (日期: {current_start.date()} 到 {current_end.date()})")
                        
                        # Move to next chunk
                        current_start = current_end
                        
                        # Brief pause between chunks to be respectful to the API
                        await asyncio.sleep(0.5)
                        
                    except Exception as chunk_error:
                        self.log_queue.put(f"批次采集错误 ({current_start.date()} to {current_end.date()}) : {str(chunk_error)}")
                        # Continue to next chunk instead of failing completely
                        current_start = current_end
                        continue

                if all_raw_cves:
                    new_cves_count = 0
                    self.log_queue.put(f"成功获取总计 {len(all_raw_cves)} 条 CVE 数据，正在解析...")
                    
                    # 解析数据
                    for raw_cve in all_raw_cves:
                        if not self.is_collecting:
                            break

                        parsed = collector.parse_cve(raw_cve)
                        cve_id = parsed.get("cve_id", "")
                        
                        # 只保存新数据到数据库
                        if cve_id and cve_id not in existing_cve_ids:
                            # 存储到数据库
                            self.store_cve_data(parsed)
                            
                            # 发送到队列以更新UI
                            self.data_queue.put(('nvd', parsed))
                            new_cves_count += 1
                        else:
                            # 如果已经存在，也更新以保持数据最新
                            self.store_cve_data(parsed)  # 更新现有数据

                    # 从数据库加载所有相关数据用于显示
                    all_cves = self.load_cve_data_from_db()
                    self.cve_data = all_cves
                    
                    # Clear the tree view and reload all data
                    for item in self.nvd_tree.get_children():
                        self.nvd_tree.delete(item)
                    
                    for cve in self.cve_data:
                        self.add_nvd_to_tree(cve)
                    
                    self.log_queue.put(f"NVD CVE 数据采集完成！新增 {new_cves_count} 条记录，总计 {len(all_cves)} 条")
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

        self.is_collecting_dell = True
        self.dell_collect_btn.config(state=tk.DISABLED)
        self.dell_stop_btn.config(state=tk.NORMAL)

        # 清空现有数据
        for item in self.dell_tree.get_children():
            self.dell_tree.delete(item)

        self.dell_advisories = []

        # 在新线程中运行采集
        thread = threading.Thread(target=self.run_dell_collection)
        thread.daemon = True
        thread.start()

        self.log("开始生成 Dell 安全公告示例数据...")
        self.log("注意：Dell RSS 已停用，使用高质量示例数据")

    def stop_dell_collection(self):
        """停止采集 Dell 数据"""
        self.is_collecting_dell = False
        self.dell_collect_btn.config(state=tk.NORMAL)
        self.dell_stop_btn.config(state=tk.DISABLED)
        self.log("Dell 安全公告采集已停止")

    def run_dell_collection(self):
        """在线程中运行 Dell 采集"""
        try:
            # 运行异步采集
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.run(self.collect_dell_advisories_async())
        except Exception as e:
            self.log_queue.put(f"Dell 采集出错: {str(e)}")
        finally:
            self.is_collecting_dell = False
            self.dell_collect_btn.config(state=tk.NORMAL)
            self.dell_stop_btn.config(state=tk.DISABLED)

    async def collect_dell_advisories_async(self):
        """异步采集 Dell 安全公告"""
        scraper = DellSecurityScraper()
        try:
            # 注意：由于 Dell RSS 已停用，这里会使用示例数据
            self.log_queue.put("正在生成示例数据...")
            items = await scraper.fetch_security_advisories()

            if items:
                self.log_queue.put(f"✓ 成功生成 {len(items)} 条 Dell 安全公告示例数据")

                for item in items:
                    if not self.is_collecting_dell:
                        break

                    self.dell_queue.put(item)

                # 保存到文件
                if self.dell_advisories:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = self.data_dir / f"dell_advisories_{timestamp}.json"
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(self.dell_advisories, f, ensure_ascii=False, indent=2)
                    self.log_queue.put(f"数据已保存到: {filename}")

                self.log_queue.put("Dell 安全公告示例数据生成完成！")
                self.log_queue.put("说明：示例数据采用真实格式，包含完整的产品型号和解决方案")
            else:
                self.log_queue.put("未生成任何数据")

        except Exception as e:
            self.log_queue.put(f"生成数据出错: {str(e)}")

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

            # 加载 Dell 数据（如果有的话）
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
        # 从环境变量或配置文件读取预定义的 CSV 路径
        # 支持环境变量: CVE_CSV_FILE
        predefined_file = os.getenv("CVE_CSV_FILE", "")

        # 如果环境变量未设置，尝试在几个常用位置查找示例文件
        if not predefined_file:
            possible_locations = [
                Path("d:/download/sample_2025_10_30.csv"),
                Path.home() / "Downloads" / "sample_2025_10_30.csv",
                self.data_dir / "sample_2025_10_30.csv",
                Path("sample_2025_10_30.csv")  # 当前目录
            ]

            for location in possible_locations:
                if location.exists():
                    predefined_file = str(location)
                    break

        # 尝试加载预定义的 CSV 文件
        if predefined_file and Path(predefined_file).exists():
            result = messagebox.askyesno(
                "加载确认",
                f"找到CSV文件: {predefined_file}\n是否直接加载此文件？\n\n点击\"否\"可选择其他CSV文件"
            )
            if result:
                csv_file = predefined_file
            else:
                csv_file = filedialog.askopenfilename(
                    title="选择 CSV 数据文件",
                    initialdir=str(Path(predefined_file).parent),
                    filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")]
                )
        else:
            # 默认打开文件选择对话框
            initial_dir = str(Path.home() / "Downloads")
            csv_file = filedialog.askopenfilename(
                title="选择 CSV 数据文件",
                initialdir=initial_dir,
                filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")]
            )

        if csv_file:
            try:
                import csv
                with open(csv_file, 'r', encoding='utf-8') as f:
                    # 首先尝试使用默认的逗号分隔符
                    try:
                        f.seek(0)
                        reader = csv.DictReader(f)
                        fieldnames = reader.fieldnames
                    except:
                        # 如果失败，尝试识别分隔符
                        f.seek(0)
                        sample = f.read(1024)
                        f.seek(0)
                        sniffer = csv.Sniffer()
                        delimiter = sniffer.sniff(sample).delimiter
                        reader = csv.DictReader(f, delimiter=delimiter)
                        fieldnames = reader.fieldnames
                    
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
                            
                            # 解析受影响的产品 - 处理可能有多列的情况
                            # 首先检查 'products' 列
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
                            else:
                                # 如果没有 'products' 列，检查是否有其他潜在的产品相关列
                                # 或检查是否有多个连续的空值不为空的列（可能是产品列表）
                                for field_name, field_value in row.items():
                                    if field_name not in [cve_field, 'description', 'cvss_score', 'cvss_severity', 
                                                          'published_date', 'last_modified', 'references']:
                                        if field_value and field_value.strip():
                                            # 假设这些是产品信息
                                            product = field_value.strip()
                                            if product and product not in ['None', 'N/A', '']:
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
                messagebox.showerror("加载失败", f"加载CSV文件失败：{str(e)}")
                self.log(f"加载CSV文件失败: {str(e)}")
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
            except:
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
            except:
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
        """刷新关联数据"""
        # 清空关联树视图
        for item in self.matched_tree.get_children():
            self.matched_tree.delete(item)

        if not self.cve_data or not self.dell_advisories:
            self.log("无法刷新关联数据：缺少 NVD 或 Dell 数据")
            return

        # 匹配 CVE ID
        matched_count = 0
        for cve in self.cve_data:
            cve_id = cve.get("cve_id", "")

            # 查找匹配的 Dell 公告
            for advisory in self.dell_advisories:
                if cve_id in advisory.get("cve_ids", []):
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

                    self.matched_tree.insert(
                        "",
                        "end",
                        values=(
                            cve_id,
                            severity,
                            cve.get("cvss_score", "N/A"),
                            advisory.get("dell_security_advisory", "N/A"),
                            products_str,
                            solution
                        ),
                        tags=(tag,)
                    )
                    matched_count += 1
                    break

        self.log(f"关联匹配完成：找到 {matched_count} 条匹配的 CVE-Dell 数据（包含CSV加载的数据）")
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
        """更新统计信息"""
        # 统计 NVD CVE 数据
        nvd_total = len(self.cve_data)
        dell_total = len(self.dell_advisories)

        # 统计关联匹配数
        matched_count = 0
        for cve in self.cve_data:
            cve_id = cve.get("cve_id", "")
            for advisory in self.dell_advisories:
                if cve_id in advisory.get("cve_ids", []):
                    matched_count += 1
                    break

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

            stats_text += f"  - {cve_id:20} | {severity:8} | 评分: {score} {dell_mark}\n"

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
        """检查队列中的数据"""
        # 检查 NVD 数据队列
        while not self.data_queue.empty():
            try:
                data_type, data = self.data_queue.get_nowait()
                if data_type == 'nvd':
                    # 存储到数据库
                    self.store_cve_data(data)
                    
                    # 从数据库重新加载所有数据 to ensure consistency
                    self.cve_data = self.load_cve_data_from_db()
                    
                    # Clear the tree view and reload all data
                    for item in self.nvd_tree.get_children():
                        self.nvd_tree.delete(item)
                    
                    for cve in self.cve_data:
                        self.add_nvd_to_tree(cve)
            except queue.Empty:
                break

        # 检查 Dell 数据队列
        while not self.dell_queue.empty():
            try:
                data = self.dell_queue.get_nowait()
                self.add_dell_to_tree(data)
                self.dell_advisories.append(data)
            except queue.Empty:
                break

        # 检查日志队列
        while not self.log_queue.empty():
            try:
                message = self.log_queue.get_nowait()
                self.log(message)
            except queue.Empty:
                break

        # 更新统计信息
        if self.cve_data or self.dell_advisories:
            self.update_stats()

        # 继续检查
        self.root.after(100, self.check_queues)

    def close_database_connection(self):
        """关闭数据库连接"""
        if hasattr(self, 'conn') and self.conn:
            try:
                self.conn.close()
                self.log("数据库连接已关闭")
            except sqlite3.Error as e:
                self.log(f"关闭数据库连接时出错: {str(e)}")

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
    except:
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
