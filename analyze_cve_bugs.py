#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用 Qwen 模型分析 CVE 项目代码中的 Bug
"""

import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Tuple
from openai import OpenAI

# 设置输出编码
if sys.platform == 'win32':
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')

# 导入配置
from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL


class CVEBugAnalyzer:
    """CVE 项目 Bug 分析器"""

    def __init__(self):
        """初始化分析器"""
        # Initialize OpenAI client with explicit http_client to avoid proxy issues
        import httpx
        http_client = httpx.Client(
            base_url=QWEN_BASE_URL,
            follow_redirects=True,
            timeout=30.0
        )
        
        self.client = OpenAI(
            api_key=QWEN_API_KEY,
            http_client=http_client
        )
        self.model = QWEN_MODEL  # 使用配置中的模型
        self.bugs_found = []
        self.files_to_analyze = [
            "collect_cves.py",
            "cve_gui.py",
            "cve_gui_v2.py",
            "local_database.py",
            "solution_knowledge_base.py",
            "main.py",
            "run.py",
            "demo_v2.py"
        ]

    def read_file_safely(self, filepath: str) -> str:
        """安全读取文件内容"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                # 限制文件大小，避免 token 超限
                if len(content) > 10000:
                    return content[:10000] + "\n... (文件过大，已截断)"
                return content
        except Exception as e:
            return f"无法读取文件: {e}"

    def analyze_code_for_bugs(self, code: str, filename: str) -> Dict:
        """使用 Qwen 分析代码中的 bug"""
        prompt = f"""作为一个资深的代码审查专家，请分析以下 Python 代码文件 '{filename}' 中的潜在问题。

请特别关注：
1. 安全漏洞（SQL注入、XSS、路径遍历等）
2. 异常处理不当
3. 资源泄露（文件、数据库连接等）
4. 逻辑错误
5. 性能问题
6. 代码质量问题

代码内容：
```python
{code[:5000]}  # 限制长度避免 token 超限
```

请提供分析结果，包括：
- 发现的严重问题
- 中等严重度问题
- 轻微问题或代码改进建议
- 每个问题请说明大概在哪里、是什么问题、如何修复
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个专业的代码安全审计专家，精通Python编程和安全最佳实践。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )

            result = response.choices[0].message.content
            return {"raw_analysis": result}

        except Exception as e:
            return {"error": str(e)}

    def analyze_security_issues(self) -> List[Dict]:
        """专门分析安全问题"""
        security_checks = {
            "collect_cves.py": [
                "API密钥是否硬编码",
                "是否有请求频率限制",
                "错误信息是否会泄露敏感信息"
            ],
            "local_database.py": [
                "SQL注入风险",
                "数据库连接是否正确关闭",
                "敏感数据是否加密存储"
            ],
            "cve_gui.py": [
                "用户输入是否验证",
                "是否有XSS风险",
                "文件操作是否安全"
            ]
        }

        security_issues = []

        for filename, checks in security_checks.items():
            if not os.path.exists(filename):
                continue

            code = self.read_file_safely(filename)

            prompt = f"""分析文件 {filename} 的安全性，重点检查：
{chr(10).join(f'- {check}' for check in checks)}

代码片段：
```python
{code[:3000]}
```

请列出发现的具体安全问题和修复建议。
"""

            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=1000
                )

                security_issues.append({
                    "file": filename,
                    "analysis": response.choices[0].message.content
                })

            except Exception as e:
                security_issues.append({
                    "file": filename,
                    "error": str(e)
                })

        return security_issues

    def analyze_project_structure(self) -> Dict:
        """分析项目结构问题"""
        prompt = """基于以下 CVE 安全漏洞监控项目的文件列表，分析项目结构和架构问题：

主要文件：
- collect_cves.py: CVE数据收集
- cve_gui.py / cve_gui_v2.py: 图形界面
- cve_web_interface.html: Web界面
- local_database.py: 数据库管理
- solution_knowledge_base.py: 解决方案知识库
- main.py / run.py: 主程序入口
- demo_v2.py: 演示程序

请分析：
1. 项目结构是否合理
2. 是否存在代码重复
3. 模块间耦合度问题
4. 缺少哪些关键组件
5. 架构改进建议
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=1500
            )

            return {
                "architecture_analysis": response.choices[0].message.content
            }

        except Exception as e:
            return {"error": str(e)}

    def quick_scan_common_issues(self) -> List[str]:
        """快速扫描常见问题"""
        issues = []

        # 检查常见的 Python bug 模式
        patterns_to_check = [
            ("except:", "裸露的 except 语句，应该指定异常类型"),
            ("eval(", "使用了危险的 eval 函数"),
            ("exec(", "使用了危险的 exec 函数"),
            ("pickle.loads", "pickle 反序列化可能存在安全风险"),
            ("os.system", "使用 os.system 可能有命令注入风险"),
            ("shell=True", "subprocess 使用 shell=True 有安全风险"),
            ("password =", "密码可能硬编码在代码中"),
            ("api_key =", "API密钥可能硬编码"),
            ("TODO", "存在未完成的 TODO 项"),
            ("FIXME", "存在需要修复的 FIXME 标记")
        ]

        for filename in self.files_to_analyze:
            if not os.path.exists(filename):
                continue

            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for line_num, line in enumerate(content.split('\n'), 1):
                        for pattern, description in patterns_to_check:
                            if pattern in line:
                                issues.append(
                                    f"{filename}:{line_num} - {description}\n"
                                    f"  代码: {line.strip()[:80]}"
                                )
            except Exception as e:
                issues.append(f"{filename}: 读取错误 - {e}")

        return issues

    def generate_report(self):
        """生成完整的分析报告"""
        print("=" * 80)
        print("CVE 项目 Bug 分析报告 - Powered by Qwen".center(80))
        print("=" * 80)

        # 1. 快速扫描
        print("\n📊 快速扫描结果")
        print("-" * 80)
        quick_issues = self.quick_scan_common_issues()
        if quick_issues:
            for issue in quick_issues[:10]:  # 只显示前10个
                print(f"⚠️  {issue}")
            if len(quick_issues) > 10:
                print(f"\n... 还有 {len(quick_issues) - 10} 个问题")
        else:
            print("✅ 快速扫描未发现明显问题")

        # 2. 深度代码分析
        print("\n🔍 深度代码分析")
        print("-" * 80)

        critical_files = ["collect_cves.py", "local_database.py", "main.py"]

        for filename in critical_files:
            if not os.path.exists(filename):
                continue

            print(f"\n分析文件: {filename}")
            code = self.read_file_safely(filename)

            if len(code) > 50:
                analysis = self.analyze_code_for_bugs(code, filename)

                if "error" in analysis:
                    print(f"  ❌ 分析错误: {analysis['error']}")
                elif "raw_analysis" in analysis:
                    # 打印分析结果的前 1000 个字符
                    result = analysis['raw_analysis']
                    if len(result) > 1000:
                        result = result[:1000] + "\n... (结果过长，已截断)"
                    print(f"\n{result}")

        # 3. 安全性分析
        print("\n🔒 安全性专项分析")
        print("-" * 80)
        security_issues = self.analyze_security_issues()

        for item in security_issues[:3]:  # 显示前3个文件的分析
            if "error" not in item:
                print(f"\n文件: {item['file']}")
                analysis_text = item['analysis']
                if len(analysis_text) > 800:
                    analysis_text = analysis_text[:800] + "\n... (已截断)"
                print(analysis_text)

        # 4. 架构分析
        print("\n🏗️  项目架构分析")
        print("-" * 80)
        arch_analysis = self.analyze_project_structure()

        if "error" not in arch_analysis:
            arch_text = arch_analysis['architecture_analysis']
            if len(arch_text) > 1200:
                arch_text = arch_text[:1200] + "\n... (已截断)"
            print(arch_text)
        else:
            print(f"架构分析失败: {arch_analysis['error']}")

        # 5. 总结
        print("\n" + "=" * 80)
        print("📋 分析总结")
        print("=" * 80)
        print(f"""
✅ 分析完成
- 快速扫描发现 {len(quick_issues)} 个潜在问题
- 深度分析了 {len(critical_files)} 个关键文件
- 完成安全性专项检查
- 提供了架构改进建议

⚠️ 重要建议：
1. 优先修复安全相关问题
2. 改进异常处理机制
3. 加强输入验证
4. 考虑代码重构以降低耦合度
        """)

        # 保存详细问题列表
        self.save_detailed_report(quick_issues, security_issues)

    def save_detailed_report(self, quick_issues, security_issues):
        """保存详细报告到文件"""
        report_content = """# CVE 项目 Bug 分析详细报告

## 快速扫描问题列表

"""
        for issue in quick_issues:
            report_content += f"- {issue}\n"

        report_content += "\n## 安全性分析\n\n"

        for item in security_issues:
            if "error" not in item:
                report_content += f"### {item['file']}\n\n"
                report_content += item['analysis'] + "\n\n"

        report_content += """
## 建议优先级

1. **高优先级**：修复所有裸露的 except 语句
2. **高优先级**：移除硬编码的 API 密钥
3. **中优先级**：改进错误处理
4. **低优先级**：代码重构和性能优化
"""

        with open("bug_analysis_report.md", "w", encoding="utf-8") as f:
            f.write(report_content)

        print("\n📝 详细报告已保存到: bug_analysis_report.md")


def main():
    """主函数"""
    print("\n🤖 使用 Qwen 模型分析 CVE 项目 Bug\n")

    # 检查当前目录
    if not os.path.exists("collect_cves.py"):
        print("❌ 错误：请在 CVE 项目根目录运行此脚本")
        return

    # 创建分析器
    analyzer = CVEBugAnalyzer()

    # 生成报告
    analyzer.generate_report()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n分析被中断")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()