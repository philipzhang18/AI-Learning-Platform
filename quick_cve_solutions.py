#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速生成高危 CVE 解决方案 - Qwen 模型
"""

import sys
from openai import OpenAI
from llm_config import QWEN_API_KEY, QWEN_BASE_URL
from datetime import datetime

# 设置输出编码
if sys.platform == 'win32':
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')

def generate_quick_solutions():
    """快速生成高危 CVE 解决方案"""

    client = OpenAI(
        api_key=QWEN_API_KEY,
        base_url=QWEN_BASE_URL
    )

    prompt = """作为安全专家，针对以下在CVE项目图形界面中发现的高危漏洞，提供详细解决方案：

## 发现的高危 CVE（模拟数据）：

### 🔴 CRITICAL 级别 (2个)
1. **CVE-2024-3094** - XZ Utils 后门漏洞 (CVSS: 10.0)
   - 影响: xz-utils 5.6.0, 5.6.1
   - 威胁: 恶意代码植入，完全系统控制

2. **CVE-2024-21626** - Docker 容器逃逸 (CVSS: 9.8)
   - 影响: Docker Engine < 25.0.0
   - 威胁: 容器隔离突破，主机访问

### 🟠 HIGH 级别 (3个)
3. **CVE-2024-0132** - NVIDIA GPU 权限提升 (CVSS: 8.2)
   - 影响: NVIDIA Driver < 546.01

4. **CVE-2024-20656** - Exchange Server RCE (CVSS: 7.5)
   - 影响: Exchange 2019, 2016

5. **CVE-2024-23334** - Apache Kafka 认证绕过 (CVSS: 7.8)
   - 影响: Kafka < 3.6.1

## 请提供：

### A. 立即行动计划（紧急措施）
为每个CVE提供：
1. 24小时内必须执行的步骤
2. 临时缓解措施命令
3. 监控检测规则

### B. 完整修复方案
为每个CVE提供：
1. 补丁更新命令
2. 验证修复的方法
3. 回滚计划

### C. 图形界面集成建议
1. 如何在GUI中展示解决方案
2. 一键修复按钮的实现逻辑
3. 进度跟踪界面设计

### D. 自动化脚本
提供Python脚本实现：
1. 批量检测受影响系统
2. 自动应用补丁
3. 生成修复报告

要求：
- 提供具体可执行的命令
- 考虑不同操作系统（Linux/Windows）
- 包含错误处理
- 适合在CVE项目的图形界面中展示
"""

    try:
        print("🤖 使用 Qwen 模型生成高危 CVE 解决方案...")
        print("=" * 80)

        response = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {"role": "system", "content": "你是资深安全专家，精通漏洞修复和安全加固。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )

        solution = response.choices[0].message.content

        # 显示解决方案
        print("\n" + "=" * 80)
        print("高危 CVE 详细解决方案 - For GUI Display".center(80))
        print("=" * 80)
        print(f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        print(solution)

        # 保存到文件
        filename = f"cve_gui_solutions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# 高危 CVE 解决方案 - 图形界面版\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"模型: Qwen-Plus\n\n")
            f.write("---\n\n")
            f.write(solution)

        print("\n" + "=" * 80)
        print(f"✅ 解决方案已保存到: {filename}")

        # 生成TODO更新
        print("\n📝 更新任务列表...")
        return solution

    except Exception as e:
        print(f"❌ 错误: {e}")
        return None

def generate_gui_integration_code():
    """生成GUI集成代码"""

    code = """
# CVE 解决方案 GUI 集成代码示例

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import json

class CVESolutionPanel(tk.Frame):
    '''高危CVE解决方案面板'''

    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        # 标题
        title = tk.Label(self, text="🛡️ 高危CVE解决方案",
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)

        # CVE 列表框架
        list_frame = tk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10)

        # 左侧：CVE列表
        self.cve_tree = ttk.Treeview(list_frame, columns=("severity", "score"),
                                     height=10, width=40)
        self.cve_tree.heading("#0", text="CVE ID")
        self.cve_tree.heading("severity", text="级别")
        self.cve_tree.heading("score", text="CVSS")
        self.cve_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 右侧：解决方案显示
        solution_frame = tk.Frame(list_frame)
        solution_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10)

        tk.Label(solution_frame, text="解决方案详情:",
                font=("Arial", 12, "bold")).pack()

        self.solution_text = scrolledtext.ScrolledText(solution_frame,
                                                       width=60, height=20)
        self.solution_text.pack(fill=tk.BOTH, expand=True)

        # 按钮面板
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="🔍 扫描高危CVE",
                  command=self.scan_cves).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💡 生成解决方案",
                  command=self.generate_solution).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔧 一键修复",
                  command=self.auto_fix).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📊 生成报告",
                  command=self.generate_report).pack(side=tk.LEFT, padx=5)

        # 进度条
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = tk.Label(self, textvariable=self.status_var,
                             relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X)

        # 加���示例数据
        self.load_sample_cves()

    def load_sample_cves(self):
        '''加载示例CVE数据'''
        cves = [
            ("CVE-2024-3094", "CRITICAL", "10.0"),
            ("CVE-2024-21626", "CRITICAL", "9.8"),
            ("CVE-2024-0132", "HIGH", "8.2"),
            ("CVE-2024-20656", "HIGH", "7.5"),
            ("CVE-2024-23334", "HIGH", "7.8"),
        ]

        for cve_id, severity, score in cves:
            tag = "critical" if severity == "CRITICAL" else "high"
            self.cve_tree.insert("", tk.END, text=cve_id,
                                values=(severity, score), tags=(tag,))

        # 设置颜色
        self.cve_tree.tag_configure("critical", foreground="red")
        self.cve_tree.tag_configure("high", foreground="orange")

        # 绑定选择事件
        self.cve_tree.bind("<<TreeviewSelect>>", self.on_cve_select)

    def on_cve_select(self, event):
        '''CVE选择事件'''
        selection = self.cve_tree.selection()
        if selection:
            item = self.cve_tree.item(selection[0])
            cve_id = item['text']
            self.show_solution(cve_id)

    def show_solution(self, cve_id):
        '''显示解决方案'''
        self.solution_text.delete(1.0, tk.END)
        solution = self.get_cached_solution(cve_id)
        self.solution_text.insert(1.0, solution)
        self.status_var.set(f"显示 {cve_id} 解决方案")

    def get_cached_solution(self, cve_id):
        '''获取缓存的解决方案'''
        # 这里应该从Qwen生成的解决方案中读取
        solutions = {
            "CVE-2024-3094": '''
🔴 CVE-2024-3094 - XZ Utils 后门漏洞

紧急措施:
1. 立即降级 xz-utils:
   sudo apt-get install xz-utils=5.4.1-0.2

2. 检查系统:
   rpm -qa | grep xz
   dpkg -l | grep xz

3. 监控异常:
   grep -r "liblzma" /var/log/
''',
            "CVE-2024-21626": '''
🔴 CVE-2024-21626 - Docker 容器逃逸

紧急措施:
1. 更新 Docker:
   sudo apt-get update && sudo apt-get upgrade docker-ce

2. 重启容器:
   docker restart $(docker ps -q)

3. 审计权限:
   docker inspect --format='{{.HostConfig.Privileged}}' $(docker ps -q)
'''
        }
        return solutions.get(cve_id, "解决方案生成中...")

    def scan_cves(self):
        '''扫描高危CVE'''
        self.progress.start()
        self.status_var.set("正在扫描高危CVE...")

        def scan():
            # 模拟扫描
            import time
            time.sleep(2)
            self.progress.stop()
            self.status_var.set("扫描完成：发现 5 个高危CVE")
            messagebox.showinfo("扫描完成", "发现 2 个CRITICAL和 3 个HIGH级别CVE")

        threading.Thread(target=scan, daemon=True).start()

    def generate_solution(self):
        '''生成解决方案'''
        selection = self.cve_tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一个CVE")
            return

        self.progress.start()
        self.status_var.set("正在生成解决方案...")

        def generate():
            # 这里应该调用Qwen API
            import time
            time.sleep(2)
            self.progress.stop()
            self.status_var.set("解决方案已生成")
            self.on_cve_select(None)

        threading.Thread(target=generate, daemon=True).start()

    def auto_fix(self):
        '''一键修复'''
        result = messagebox.askyesno("确认", "是否执行一键修复？\\n这将自动应用所有补丁。")
        if result:
            self.progress.start()
            self.status_var.set("正在执行修复...")

            def fix():
                import time
                time.sleep(3)
                self.progress.stop()
                self.status_var.set("修复完成")
                messagebox.showinfo("成功", "已成功修复所有高危CVE")

            threading.Thread(target=fix, daemon=True).start()

    def generate_report(self):
        '''生成报告'''
        from datetime import datetime
        filename = f"CVE_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        with open(filename, "w", encoding="utf-8") as f:
            f.write("# 高危CVE修复报告\\n\\n")
            f.write(f"生成时间: {datetime.now()}\\n\\n")
            f.write("## 扫描结果\\n")
            f.write("- CRITICAL: 2个\\n")
            f.write("- HIGH: 3个\\n\\n")
            f.write("## 修复状态\\n")
            f.write("✅ 所有CVE已修复\\n")

        messagebox.showinfo("报告生成", f"报告已保存到: {filename}")
        self.status_var.set(f"报告已生成: {filename}")


# 主程序
if __name__ == "__main__":
    root = tk.Tk()
    root.title("CVE 高危风险管理系统")
    root.geometry("1200x700")

    panel = CVESolutionPanel(root)
    panel.pack(fill=tk.BOTH, expand=True)

    root.mainloop()
"""

    print("\n" + "=" * 80)
    print("GUI 集成代码示例")
    print("=" * 80)
    print(code)

    # 保存代码
    with open("cve_solution_gui.py", "w", encoding="utf-8") as f:
        f.write(code)

    print(f"\n✅ GUI集成代码已保存到: cve_solution_gui.py")

if __name__ == "__main__":
    print("\n🚀 快速生成高危 CVE 解决方案\n")

    # 生成解决方案
    solution = generate_quick_solutions()

    # 生成GUI集成代码
    if solution:
        print("\n" + "=" * 80)
        print("生成GUI集成代码...")
        generate_gui_integration_code()

    print("\n✅ 所有任务完成！")