"""
CVE 监控系统测试程序 - 展示新功能
包含：详细解决方案、本地数据库、离线查询
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
from datetime import datetime
from pathlib import Path
import sys

# 导入本地模块
try:
    from solution_knowledge_base import SolutionKnowledgeBase
    from local_database import CVELocalDatabase
except ImportError:
    print("请确保 solution_knowledge_base.py 和 local_database.py 在同一目录")
    sys.exit(1)


class CVETestApp:
    """CVE 测试应用程序"""

    def __init__(self, root):
        self.root = root
        self.root.title("CVE 监控系统 - 新功能测试")
        self.root.geometry("1200x700")

        # 初始化组件
        self.solution_kb = SolutionKnowledgeBase()
        self.local_db = CVELocalDatabase()

        # 测试数据
        self.test_data = []

        # 创建界面
        self.create_widgets()

        # 加载本地数据
        self.load_local_data()

    def create_widgets(self):
        """创建界面组件"""

        # 顶部控制栏
        control_frame = tk.Frame(self.root, bg="#f0f0f0", pady=10)
        control_frame.pack(fill=tk.X)

        tk.Label(
            control_frame,
            text="CVE 监控系统 - 功能演示",
            font=("Microsoft YaHei", 16, "bold"),
            bg="#f0f0f0"
        ).pack()

        # 按钮栏
        button_frame = tk.Frame(self.root, bg="white", pady=10)
        button_frame.pack(fill=tk.X, padx=10)

        # 功能按钮
        tk.Button(
            button_frame,
            text="生成测试数据",
            command=self.generate_test_data,
            bg="#3498db",
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="保存到本地数据库",
            command=self.save_to_database,
            bg="#27ae60",
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="离线搜索测试",
            command=self.test_offline_search,
            bg="#e74c3c",
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="查看详细解决方案",
            command=self.show_detailed_solution,
            bg="#9b59b6",
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="数据库统计",
            command=self.show_db_stats,
            bg="#f39c12",
            fg="white",
            font=("Microsoft YaHei", 10),
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=5)

        # 主要内容区域
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左侧：数据列表
        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(
            left_frame,
            text="CVE 数据列表",
            font=("Microsoft YaHei", 12, "bold")
        ).pack()

        # 创建树形视图
        columns = ("CVE ID", "严重等级", "类型", "解决方案")
        self.tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        self.tree.pack(fill=tk.BOTH, expand=True, pady=5)

        # 右侧：详细信息
        right_frame = tk.Frame(main_frame, width=500)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))
        right_frame.pack_propagate(False)

        tk.Label(
            right_frame,
            text="详细信息",
            font=("Microsoft YaHei", 12, "bold")
        ).pack()

        self.detail_text = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            width=50,
            height=25,
            font=("Consolas", 9)
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # 底部状态栏
        self.status_label = tk.Label(
            self.root,
            text="就绪",
            bg="#34495e",
            fg="white",
            font=("Microsoft YaHei", 9),
            anchor="w"
        )
        self.status_label.pack(fill=tk.X)

    def generate_test_data(self):
        """生成测试数据"""
        self.test_data = [
            {
                "cve_id": "CVE-2024-10001",
                "severity": "CRITICAL",
                "score": 9.8,
                "published": "2024-10-28",
                "description": "A remote code execution vulnerability in Apache Struts allows attackers to execute arbitrary code",
                "type": "RCE"
            },
            {
                "cve_id": "CVE-2024-10002",
                "severity": "HIGH",
                "score": 8.5,
                "published": "2024-10-27",
                "description": "SQL injection vulnerability in WordPress plugin allows database access",
                "type": "SQL Injection"
            },
            {
                "cve_id": "CVE-2024-10003",
                "severity": "MEDIUM",
                "score": 6.5,
                "published": "2024-10-26",
                "description": "Cross-site scripting vulnerability in popular web framework",
                "type": "XSS"
            },
            {
                "cve_id": "CVE-2024-10004",
                "severity": "HIGH",
                "score": 7.8,
                "published": "2024-10-25",
                "description": "Buffer overflow in network service could lead to denial of service",
                "type": "Buffer Overflow"
            },
            {
                "cve_id": "CVE-2024-10005",
                "severity": "CRITICAL",
                "score": 9.0,
                "published": "2024-10-24",
                "description": "Authentication bypass vulnerability allows unauthorized access",
                "type": "Auth Bypass"
            }
        ]

        # 清空树形视图
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 添加到树形视图
        for cve in self.test_data:
            # 生成简短解决方案
            solution = self.solution_kb.get_brief_solution(cve)

            self.tree.insert("", "end", values=(
                cve["cve_id"],
                cve["severity"],
                cve.get("type", "Unknown"),
                solution[:50] + "..."
            ))

        self.update_status(f"已生成 {len(self.test_data)} 条测试数据")

        # 显示第一条的详细信息
        if self.test_data:
            self.show_cve_detail(self.test_data[0])

    def save_to_database(self):
        """保存到本地数据库"""
        if not self.test_data:
            messagebox.showwarning("提示", "请先生成测试数据")
            return

        saved = 0
        for cve in self.test_data:
            # 生成解决方案
            brief = self.solution_kb.get_brief_solution(cve)
            detailed = self.solution_kb.get_detailed_solution(cve)

            # 保存到数据库
            if self.local_db.save_cve(cve, brief, detailed):
                saved += 1

        self.update_status(f"已保存 {saved} 条数据到本地数据库")
        messagebox.showinfo("成功", f"成功保存 {saved} 条数据到本地数据库")

    def test_offline_search(self):
        """测试离线搜索"""
        # 创建搜索对话框
        search_window = tk.Toplevel(self.root)
        search_window.title("离线搜索测试")
        search_window.geometry("600x400")

        # 搜索控件
        search_frame = tk.Frame(search_window)
        search_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(search_frame, text="搜索类型:").pack(side=tk.LEFT, padx=5)

        search_type_var = tk.StringVar(value="all")
        search_type_combo = ttk.Combobox(
            search_frame,
            textvariable=search_type_var,
            values=["all", "cve_id", "severity", "description", "solution"],
            width=15
        )
        search_type_combo.pack(side=tk.LEFT, padx=5)

        tk.Label(search_frame, text="关键字:").pack(side=tk.LEFT, padx=5)

        keyword_var = tk.StringVar()
        keyword_entry = tk.Entry(search_frame, textvariable=keyword_var, width=20)
        keyword_entry.pack(side=tk.LEFT, padx=5)

        def perform_search():
            search_type = search_type_var.get()
            keyword = keyword_var.get()

            # 执行离线搜索
            results = self.local_db.search_offline(search_type, keyword)

            # 显示结果
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"搜索结果：找到 {len(results)} 条记录\n")
            result_text.insert(tk.END, "=" * 50 + "\n\n")

            for cve in results[:10]:  # 最多显示10条
                result_text.insert(tk.END, f"CVE ID: {cve['cve_id']}\n")
                result_text.insert(tk.END, f"严重等级: {cve['severity']}\n")
                result_text.insert(tk.END, f"描述: {cve['description'][:100]}...\n")
                result_text.insert(tk.END, f"解决方案: {cve.get('solution', 'N/A')[:100]}...\n")
                result_text.insert(tk.END, "-" * 40 + "\n")

        tk.Button(
            search_frame,
            text="搜索",
            command=perform_search,
            bg="#3498db",
            fg="white"
        ).pack(side=tk.LEFT, padx=10)

        # 结果显示
        result_text = scrolledtext.ScrolledText(search_window, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def show_detailed_solution(self):
        """显示详细解决方案"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一个CVE")
            return

        # 获取选中的CVE
        item = self.tree.item(selection[0])
        cve_id = item['values'][0]

        # 查找对应的CVE数据
        cve_data = None
        for cve in self.test_data:
            if cve['cve_id'] == cve_id:
                cve_data = cve
                break

        if not cve_data:
            return

        # 生成详细解决方案
        detailed_solution = self.solution_kb.get_detailed_solution(cve_data)

        # 创建解决方案窗口
        solution_window = tk.Toplevel(self.root)
        solution_window.title(f"详细解决方案 - {cve_id}")
        solution_window.geometry("800x600")

        # 标题
        title_label = tk.Label(
            solution_window,
            text=f"CVE: {cve_id} - {cve_data['severity']} 级漏洞",
            font=("Microsoft YaHei", 14, "bold"),
            fg="#e74c3c" if cve_data['severity'] == "CRITICAL" else "#f39c12"
        )
        title_label.pack(pady=10)

        # 解决方案文本
        solution_text = scrolledtext.ScrolledText(
            solution_window,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#f8f9fa"
        )
        solution_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 插入详细解决方案
        solution_text.insert(tk.END, detailed_solution)
        solution_text.config(state=tk.DISABLED)

        # 操作按钮
        button_frame = tk.Frame(solution_window)
        button_frame.pack(pady=10)

        def save_solution():
            # 保存解决方案到文件
            filename = f"cve_data/solution_{cve_id}.txt"
            Path("cve_data").mkdir(exist_ok=True)

            with open(filename, "w", encoding="utf-8") as f:
                f.write(detailed_solution)

            messagebox.showinfo("成功", f"解决方案已保存到 {filename}")

        tk.Button(
            button_frame,
            text="保存到文件",
            command=save_solution,
            bg="#27ae60",
            fg="white",
            padx=15,
            pady=5
        ).pack(side=tk.LEFT, padx=5)

    def show_db_stats(self):
        """显示数据库统计"""
        stats = self.local_db.get_statistics()

        stats_window = tk.Toplevel(self.root)
        stats_window.title("数据库统计信息")
        stats_window.geometry("400x300")

        # 显示统计信息
        stats_text = tk.Text(stats_window, font=("Consolas", 10))
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        stats_info = f"""
数据库统计信息
{'=' * 40}

总记录数: {stats.get('total', 0)}

严重等级分布:
  CRITICAL: {stats.get('critical', 0)}
  HIGH: {stats.get('high', 0)}
  MEDIUM: {stats.get('medium', 0)}
  LOW: {stats.get('low', 0)}

有解决方案的记录: {stats.get('with_solution', 0)}

数据日期范围:
  开始: {stats['date_range']['start']}
  结束: {stats['date_range']['end']}

最后更新: {stats.get('last_update', 'N/A')}

{'=' * 40}
"""

        stats_text.insert(tk.END, stats_info)
        stats_text.config(state=tk.DISABLED)

    def show_cve_detail(self, cve_data):
        """显示CVE详细信息"""
        self.detail_text.delete(1.0, tk.END)

        # 生成详细解决方案
        detailed_solution = self.solution_kb.get_detailed_solution(cve_data)

        detail = f"""
CVE 详细信息
{'=' * 50}

CVE ID: {cve_data['cve_id']}
严重等级: {cve_data['severity']}
CVSS 评分: {cve_data['score']}
发布日期: {cve_data['published']}

描述:
{cve_data['description']}

详细解决方案:
{'-' * 50}
{detailed_solution}

{'=' * 50}
"""

        self.detail_text.insert(tk.END, detail)

    def load_local_data(self):
        """加载本地数据"""
        # 检查数据库是否有数据
        stats = self.local_db.get_statistics()

        if stats['total'] > 0:
            self.update_status(f"已加载本地数据库，共 {stats['total']} 条记录")

            # 加载最新的10条
            results = self.local_db.search_offline(keyword="", date_range=None)

            for cve in results[:10]:
                self.tree.insert("", "end", values=(
                    cve['cve_id'],
                    cve['severity'],
                    "已存储",
                    (cve.get('solution', 'N/A')[:50] + "...") if cve.get('solution') else "N/A"
                ))
        else:
            self.update_status("本地数据库为空，请生成测试数据")

    def update_status(self, message):
        """更新状态栏"""
        self.status_label.config(text=f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def on_closing(self):
        """关闭时清理"""
        self.local_db.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = CVETestApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()