"""
CVE 数据收集与可视化图形界面 V2
增强版：包含搜索功能和解决方案
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from pathlib import Path
import threading
import queue
import os
import re

class CVECollectorGUI:
    """CVE 数据收集图形界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("CVE 漏洞监控系统 V2 - 实时数据采集与分析")
        self.root.geometry("1400x850")

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

        # CVE 数据存储
        self.cve_data = []
        self.filtered_data = []  # 过滤后的数据
        self.is_collecting = False

        # 创建界面
        self.create_widgets()

        # 启动队列检查
        self.check_queues()

    def create_widgets(self):
        """创建界面组件"""

        # 顶部标题栏
        header_frame = tk.Frame(self.root, bg=self.primary_color, height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="🛡️ CVE 漏洞监控系统 V2.0",
            font=("Microsoft YaHei", 24, "bold"),
            fg="white",
            bg=self.primary_color
        )
        title_label.pack(pady=20)

        # 控制面板
        control_frame = tk.Frame(self.root, bg="white", pady=10)
        control_frame.pack(fill=tk.X, padx=10, pady=(10, 0))

        # 左侧控制按钮
        left_control = tk.Frame(control_frame, bg="white")
        left_control.pack(side=tk.LEFT, padx=20)

        # 天数选择
        tk.Label(left_control, text="采集天数范围：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))

        self.days_var = tk.StringVar(value="7")
        days_combo = ttk.Combobox(
            left_control,
            textvariable=self.days_var,
            values=["1", "3", "7", "14", "30"],
            width=10,
            state="readonly"
        )
        days_combo.pack(side=tk.LEFT, padx=(0, 20))

        # 开始采集按钮
        self.collect_btn = tk.Button(
            left_control,
            text="▶ 开始采集",
            command=self.start_collection,
            bg=self.success_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.collect_btn.pack(side=tk.LEFT, padx=5)

        # 停止按钮
        self.stop_btn = tk.Button(
            left_control,
            text="■ 停止",
            command=self.stop_collection,
            bg=self.danger_color,
            fg="white",
            font=("Microsoft YaHei", 10, "bold"),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 右侧状态信息
        right_control = tk.Frame(control_frame, bg="white")
        right_control.pack(side=tk.RIGHT, padx=20)

        self.status_label = tk.Label(
            right_control,
            text="⚪ 就绪",
            bg="white",
            font=("Microsoft YaHei", 10, "bold")
        )
        self.status_label.pack()

        # 搜索栏
        search_frame = tk.Frame(self.root, bg="white", pady=10)
        search_frame.pack(fill=tk.X, padx=10)

        # 搜索类型选择
        tk.Label(search_frame, text="搜索类型：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(20, 5))

        self.search_type_var = tk.StringVar(value="all")
        search_type_combo = ttk.Combobox(
            search_frame,
            textvariable=self.search_type_var,
            values=["all", "cve_id", "severity", "description", "solution"],
            width=15,
            state="readonly"
        )
        search_type_combo.pack(side=tk.LEFT, padx=(0, 10))

        # 映射显示文字
        search_type_combo.set("全部字段")
        search_type_combo['values'] = ["全部字段", "CVE编号", "严重等级", "描述", "解决方案"]

        # 搜索输入框
        tk.Label(search_frame, text="关键字：", bg="white", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(10, 5))

        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=("Microsoft YaHei", 10),
            width=30
        )
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))

        # 绑定实时搜索
        self.search_var.trace('w', self.on_search_change)

        # 搜索按钮
        search_btn = tk.Button(
            search_frame,
            text="🔍 搜索",
            command=self.search_cves,
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2"
        )
        search_btn.pack(side=tk.LEFT, padx=5)

        # 清空搜索按钮
        clear_search_btn = tk.Button(
            search_frame,
            text="清空",
            command=self.clear_search,
            bg="#95a5a6",
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2"
        )
        clear_search_btn.pack(side=tk.LEFT, padx=5)

        # 搜索结果标签
        self.search_result_label = tk.Label(
            search_frame,
            text="",
            bg="white",
            fg=self.info_color,
            font=("Microsoft YaHei", 9)
        )
        self.search_result_label.pack(side=tk.LEFT, padx=20)

        # 主要内容区域（使用 Notebook 创建标签页）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 数据展示标签页
        self.data_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.data_frame, text="📊 CVE 数据")

        # 统计信息标签页
        self.stats_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.stats_frame, text="📈 统计分析")

        # 日志标签页
        self.log_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.log_frame, text="📝 采集日志")

        # 创建数据展示区域
        self.create_data_view()

        # 创建统计展示区域
        self.create_stats_view()

        # 创建日志展示区域
        self.create_log_view()

        # 底部状态栏
        status_bar = tk.Frame(self.root, bg=self.primary_color, height=30)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)

        self.bottom_status = tk.Label(
            status_bar,
            text="准备就绪",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 9)
        )
        self.bottom_status.pack(side=tk.LEFT, padx=10, pady=5)

        self.cve_count_label = tk.Label(
            status_bar,
            text="CVE 总数: 0",
            bg=self.primary_color,
            fg="white",
            font=("Microsoft YaHei", 9)
        )
        self.cve_count_label.pack(side=tk.RIGHT, padx=10, pady=5)

    def create_data_view(self):
        """创建数据展示视图"""
        # 创建 Treeview 来展示 CVE 数据（增加解决方案列）
        columns = ("CVE ID", "严重等级", "CVSS评分", "发布日期", "描述", "解决方案")

        # 创建滚动条
        tree_scroll_y = tk.Scrollbar(self.data_frame, orient=tk.VERTICAL)
        tree_scroll_x = tk.Scrollbar(self.data_frame, orient=tk.HORIZONTAL)

        self.tree = ttk.Treeview(
            self.data_frame,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            height=20
        )

        # 配置滚动条
        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_x.config(command=self.tree.xview)

        # 设置列标题和宽度
        self.tree.heading("CVE ID", text="CVE 编号")
        self.tree.heading("严重等级", text="严重等级")
        self.tree.heading("CVSS评分", text="CVSS 评分")
        self.tree.heading("发布日期", text="发布日期")
        self.tree.heading("描述", text="描述")
        self.tree.heading("解决方案", text="解决方案")

        self.tree.column("CVE ID", width=120, minwidth=100)
        self.tree.column("严重等级", width=80, minwidth=60)
        self.tree.column("CVSS评分", width=80, minwidth=60)
        self.tree.column("发布日期", width=120, minwidth=100)
        self.tree.column("描述", width=400, minwidth=200)
        self.tree.column("解决方案", width=400, minwidth=200)

        # 布局
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X, padx=10)

        # 添加标签样式
        self.tree.tag_configure("CRITICAL", background="#ffebee", foreground="#b71c1c")
        self.tree.tag_configure("HIGH", background="#fff3e0", foreground="#e65100")
        self.tree.tag_configure("MEDIUM", background="#fff9c4", foreground="#f57f17")
        self.tree.tag_configure("LOW", background="#f1f8e9", foreground="#33691e")
        self.tree.tag_configure("INFO", background="#e3f2fd", foreground="#1565c0")

        # 绑定双击事件
        self.tree.bind("<Double-1>", self.on_item_double_click)

    def create_stats_view(self):
        """创建统计视图"""
        # 统计信息容器
        stats_container = tk.Frame(self.stats_frame, bg="white")
        stats_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 统计卡片
        self.stats_cards = {}

        # 创建统计卡片
        cards_info = [
            ("总计", "0", self.primary_color),
            ("严重", "0", "#b71c1c"),
            ("高危", "0", "#e65100"),
            ("中危", "0", "#f57f17"),
            ("低危", "0", "#33691e"),
            ("已解决", "0", self.success_color)
        ]

        for i, (title, value, color) in enumerate(cards_info):
            card = self.create_stats_card(stats_container, title, value, color)
            row = i // 3
            col = i % 3
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            self.stats_cards[title] = card

        # 配置列权重
        for i in range(3):
            stats_container.columnconfigure(i, weight=1)

        # 详细统计文本区域
        detail_frame = tk.Frame(self.stats_frame, bg="white")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        tk.Label(
            detail_frame,
            text="详细统计信息",
            bg="white",
            font=("Microsoft YaHei", 12, "bold")
        ).pack(anchor="w", pady=(10, 5))

        self.stats_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            width=80,
            height=12,
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

    def generate_solution(self, cve_data):
        """生成CVE解决方案"""
        severity = cve_data.get("severity", "")
        description = cve_data.get("description", "").lower()
        cve_id = cve_data.get("cve_id", "")

        # 基础解决方案
        solution = []

        # 根据严重等级给出建议
        if severity in ["CRITICAL", "HIGH"]:
            solution.append("【紧急】立即采取行动")
        elif severity == "MEDIUM":
            solution.append("【重要】计划修复")
        else:
            solution.append("【常规】定期更新")

        # 根据描述内容判断漏洞类型并给出针对性建议
        if "remote code execution" in description or "rce" in description:
            solution.append("1.立即应用官方补丁")
            solution.append("2.限制网络访问")
            solution.append("3.启用防火墙规则")
        elif "sql injection" in description:
            solution.append("1.使用参数化查询")
            solution.append("2.输入验证过滤")
            solution.append("3.最小权限原则")
        elif "cross-site scripting" in description or "xss" in description:
            solution.append("1.编码用户输入")
            solution.append("2.实施CSP策略")
            solution.append("3.使用安全框架")
        elif "buffer overflow" in description:
            solution.append("1.更新到最新版本")
            solution.append("2.启用ASLR/DEP")
            solution.append("3.代码审查")
        elif "denial of service" in description or "dos" in description:
            solution.append("1.配置速率限制")
            solution.append("2.使用DDoS防护")
            solution.append("3.资源监控")
        elif "privilege escalation" in description:
            solution.append("1.更新系统补丁")
            solution.append("2.限制用户权限")
            solution.append("3.审计日志监控")
        elif "authentication" in description or "authorization" in description:
            solution.append("1.强化认证机制")
            solution.append("2.多因素认证")
            solution.append("3.定期更换凭证")
        elif "information disclosure" in description:
            solution.append("1.配置安全头")
            solution.append("2.错误信息脱敏")
            solution.append("3.访问控制加固")
        else:
            # 通用建议
            solution.append("1.查看官方公告")
            solution.append("2.评估影响范围")
            solution.append("3.制定修复计划")

        # 添加通用建议
        if severity in ["CRITICAL", "HIGH"]:
            solution.append("4.监控异常活动")
            solution.append("5.备份重要数据")

        return " | ".join(solution)

    def search_cves(self):
        """搜索CVE数据"""
        search_type = self.search_type_var.get()
        keyword = self.search_var.get().strip().lower()

        if not keyword:
            self.filtered_data = self.cve_data
            self.refresh_tree_view()
            self.search_result_label.config(text="")
            return

        # 映射搜索类型
        type_map = {
            "全部字段": "all",
            "CVE编号": "cve_id",
            "严重等级": "severity",
            "描述": "description",
            "解决方案": "solution"
        }

        search_field = type_map.get(search_type, "all")

        # 执行搜索
        self.filtered_data = []
        for cve in self.cve_data:
            match = False

            if search_field == "all":
                # 搜索所有字段
                for key, value in cve.items():
                    if keyword in str(value).lower():
                        match = True
                        break
            elif search_field in cve:
                # 搜索特定字段
                if keyword in str(cve[search_field]).lower():
                    match = True

            if match:
                self.filtered_data.append(cve)

        # 更新显示
        self.refresh_tree_view()

        # 显示搜索结果
        result_text = f"找到 {len(self.filtered_data)} 条匹配结果"
        self.search_result_label.config(text=result_text)

        if len(self.filtered_data) == 0:
            self.log(f"搜索 '{keyword}' 无结果")
        else:
            self.log(f"搜索 '{keyword}' 找到 {len(self.filtered_data)} 条结果")

    def clear_search(self):
        """清空搜索"""
        self.search_var.set("")
        self.filtered_data = self.cve_data
        self.refresh_tree_view()
        self.search_result_label.config(text="")
        self.log("已清空搜索条件")

    def on_search_change(self, *args):
        """搜索框内容改变时触发"""
        # 如果搜索框为空，自动清空搜索
        if not self.search_var.get().strip():
            self.clear_search()

    def refresh_tree_view(self):
        """刷新树形视图显示"""
        # 清空现有数据
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 显示过滤后的数据
        data_to_show = self.filtered_data if self.filtered_data else self.cve_data

        for cve in data_to_show:
            self.add_cve_to_tree(cve, refresh=False)

        # 更新计数
        self.cve_count_label.config(text=f"显示: {len(data_to_show)} / 总计: {len(self.cve_data)}")

    def start_collection(self):
        """开始采集数据"""
        if self.is_collecting:
            return

        self.is_collecting = True
        self.collect_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="🔴 采集中...", fg=self.danger_color)

        # 清空现有数据
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.cve_data = []
        self.filtered_data = []

        # 获取天数
        days = int(self.days_var.get())

        # 在新线程中运行采集
        thread = threading.Thread(target=self.run_collection, args=(days,))
        thread.daemon = True
        thread.start()

        self.log("开始采集 CVE 数据...")
        self.log(f"采集范围：最近 {days} 天")

    def stop_collection(self):
        """停止采集"""
        self.is_collecting = False
        self.collect_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="⚪ 就绪", fg="black")
        self.log("采集已停止")

    def run_collection(self, days):
        """在线程中运行采集"""
        try:
            # 运行异步采集
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.run(self.collect_cves_async(days))
        except Exception as e:
            self.log_queue.put(f"采集出错: {str(e)}")
        finally:
            self.is_collecting = False

    async def collect_cves_async(self, days):
        """异步采集 CVE 数据"""
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # 计算时间范围
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        self.log_queue.put(f"时间范围: {start_str} 至 {end_str}")

        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            start_index = 0
            results_per_page = 50

            while self.is_collecting:
                params = {
                    "pubStartDate": start_str,
                    "pubEndDate": end_str,
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page
                }

                try:
                    async with session.get(base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            vulnerabilities = data.get("vulnerabilities", [])
                            total_results = data.get("totalResults", 0)

                            self.log_queue.put(
                                f"获取第 {start_index + 1}-{start_index + len(vulnerabilities)} 条，"
                                f"共 {total_results} 条"
                            )

                            if not vulnerabilities:
                                break

                            # 处理每个 CVE
                            for vuln in vulnerabilities:
                                if not self.is_collecting:
                                    break

                                cve_data = self.parse_cve(vuln)
                                # 生成解决方案
                                cve_data["solution"] = self.generate_solution(cve_data)
                                self.data_queue.put(cve_data)

                            # 检查是否还有更多数据
                            if start_index + len(vulnerabilities) >= total_results:
                                break

                            start_index += results_per_page

                            # 避免请求过快
                            await asyncio.sleep(6)
                        else:
                            self.log_queue.put(f"API 请求失败: HTTP {response.status}")
                            break

                except Exception as e:
                    self.log_queue.put(f"请求出错: {str(e)}")
                    break

        self.log_queue.put("采集完成！")

        # 保存数据到文件
        if self.cve_data:
            self.save_data()

    def parse_cve(self, raw_cve):
        """解析 CVE 数据"""
        cve = raw_cve.get("cve", {})

        # 提取基本信息
        cve_id = cve.get("id", "")

        # 提取描述
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # 限制描述长度
        full_description = description
        if len(description) > 200:
            description = description[:200] + "..."

        # 提取 CVSS 评分
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = None

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")

        # 发布日期
        published_date = cve.get("published", "")
        if published_date:
            try:
                dt = datetime.fromisoformat(published_date.replace("Z", ""))
                published_date = dt.strftime("%Y-%m-%d %H:%M")
            except:
                pass

        return {
            "cve_id": cve_id,
            "severity": cvss_severity or "未知",
            "score": cvss_score or "N/A",
            "published": published_date,
            "description": description,
            "full_description": full_description
        }

    def save_data(self):
        """保存数据到文件"""
        # 创建数据目录
        data_dir = Path("cve_data")
        data_dir.mkdir(exist_ok=True)

        # 生成文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = data_dir / f"cves_{timestamp}.json"

        # 保存数据
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.cve_data, f, ensure_ascii=False, indent=2)

        self.log_queue.put(f"数据已保存到: {filename}")

    def check_queues(self):
        """检查队列中的数据"""
        # 检查数据队列
        while not self.data_queue.empty():
            try:
                cve_data = self.data_queue.get_nowait()
                self.add_cve_to_tree(cve_data)
                self.cve_data.append(cve_data)
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
        if self.cve_data:
            self.update_stats()

        # 继续检查
        self.root.after(100, self.check_queues)

    def add_cve_to_tree(self, cve_data, refresh=True):
        """添加 CVE 数据到树形视图"""
        severity = cve_data["severity"]
        tag = severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "INFO"

        self.tree.insert(
            "",
            "end",
            values=(
                cve_data["cve_id"],
                cve_data["severity"],
                cve_data["score"],
                cve_data["published"],
                cve_data["description"],
                cve_data.get("solution", "查看详情")
            ),
            tags=(tag,)
        )

        if refresh:
            # 更新计数
            self.cve_count_label.config(text=f"CVE 总数: {len(self.cve_data)}")
            self.bottom_status.config(text=f"最新: {cve_data['cve_id']}")

    def update_stats(self):
        """更新统计信息"""
        total = len(self.cve_data)

        # 统计各严重等级
        severity_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "其他": 0
        }

        has_solution_count = 0

        for cve in self.cve_data:
            severity = cve["severity"]
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count["其他"] += 1

            # 统计有解决方案的
            if "solution" in cve and cve["solution"]:
                has_solution_count += 1

        # 更新统计卡片
        self.stats_cards["总计"].value_label.config(text=str(total))
        self.stats_cards["严重"].value_label.config(text=str(severity_count["CRITICAL"]))
        self.stats_cards["高危"].value_label.config(text=str(severity_count["HIGH"]))
        self.stats_cards["中危"].value_label.config(text=str(severity_count["MEDIUM"]))
        self.stats_cards["低危"].value_label.config(text=str(severity_count["LOW"]))
        self.stats_cards["已解决"].value_label.config(text=str(has_solution_count))

        # 生成详细统计报告
        stats_text = f"""
======================== 统计报告 ========================

采集时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
CVE 总数: {total}
已生成解决方案: {has_solution_count}

严重等级分布:
  CRITICAL (严重): {severity_count['CRITICAL']} 个
  HIGH     (高危): {severity_count['HIGH']} 个
  MEDIUM   (中危): {severity_count['MEDIUM']} 个
  LOW      (低危): {severity_count['LOW']} 个
  其他           : {severity_count['其他']} 个

最新 CVE (前10个):
"""

        for cve in self.cve_data[:10]:
            stats_text += f"  - {cve['cve_id']:20} | {cve['severity']:8} | 评分: {cve['score']}\n"

        stats_text += "\n" + "=" * 58

        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)

    def on_item_double_click(self, event):
        """处理双击事件"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            cve_id = item['values'][0]

            # 显示详细信息
            for cve in self.cve_data:
                if cve['cve_id'] == cve_id:
                    self.show_cve_detail(cve)
                    break

    def show_cve_detail(self, cve):
        """显示 CVE 详细信息"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"CVE 详细信息 - {cve['cve_id']}")
        detail_window.geometry("800x600")

        # 创建滚动文本框
        text_frame = tk.Frame(detail_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        text = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            width=90,
            height=30,
            font=("Consolas", 10)
        )
        text.pack(fill=tk.BOTH, expand=True)

        # 使用完整描述
        full_desc = cve.get('full_description', cve.get('description', ''))

        detail_text = f"""
{'='*70}
CVE 详细信息
{'='*70}

CVE 编号: {cve['cve_id']}
严重等级: {cve['severity']}
CVSS 评分: {cve['score']}
发布日期: {cve['published']}

描述:
{full_desc}

解决方案:
{cve.get('solution', '暂无解决方案')}

参考链接:
- NVD: https://nvd.nist.gov/vuln/detail/{cve['cve_id']}
- MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve['cve_id']}

{'='*70}
"""

        text.insert(tk.END, detail_text)
        text.config(state=tk.DISABLED)

        # 添加复制按钮
        button_frame = tk.Frame(detail_window)
        button_frame.pack(pady=(0, 10))

        copy_btn = tk.Button(
            button_frame,
            text="复制信息",
            command=lambda: self.copy_to_clipboard(detail_text),
            bg=self.info_color,
            fg="white",
            font=("Microsoft YaHei", 9),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        copy_btn.pack(side=tk.LEFT, padx=5)

        close_btn = tk.Button(
            button_frame,
            text="关闭",
            command=detail_window.destroy,
            bg="#95a5a6",
            fg="white",
            font=("Microsoft YaHei", 9),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        close_btn.pack(side=tk.LEFT, padx=5)

    def copy_to_clipboard(self, text):
        """复制文本到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("复制成功", "信息已复制到剪贴板")

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
    app = CVECollectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()