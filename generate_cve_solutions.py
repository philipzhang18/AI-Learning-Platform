#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用 Qwen 模型为高危 CVE 生成详细解决方案
专注于图形界面中展示的 High 和 Critical 级别漏洞
"""

import sys
import json
import sqlite3
from datetime import datetime
from openai import OpenAI
from pathlib import Path
from llm_config import QWEN_API_KEY, QWEN_BASE_URL

# 设置输出编码
if sys.platform == 'win32':
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')


class CVEHighRiskSolutionGenerator:
    """高危 CVE 解决方案生成器"""

    def __init__(self):
        self.client = OpenAI(
            api_key=QWEN_API_KEY,
            base_url=QWEN_BASE_URL
        )
        self.model = "qwen-plus"  # 使用更强大的模型进行安全分析

    def get_high_risk_cves(self):
        """模拟获取高危 CVE 数据"""
        # 这里模拟一些常见的高危 CVE
        return [
            {
                "cve_id": "CVE-2024-3094",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "description": "XZ Utils 后门漏洞，恶意代码被植入到 liblzma 库中",
                "affected": "xz-utils 5.6.0, 5.6.1",
                "published": "2024-03-29"
            },
            {
                "cve_id": "CVE-2024-21626",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "description": "Docker Engine 容器逃逸漏洞，允许攻击者突破容器隔离",
                "affected": "Docker Engine < 25.0.0",
                "published": "2024-02-01"
            },
            {
                "cve_id": "CVE-2024-0132",
                "severity": "HIGH",
                "cvss_score": 8.2,
                "description": "NVIDIA GPU 驱动程序权限提升漏洞",
                "affected": "NVIDIA GPU Display Driver < 546.01",
                "published": "2024-01-15"
            },
            {
                "cve_id": "CVE-2024-20656",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": "Microsoft Exchange Server 远程代码执行漏洞",
                "affected": "Exchange Server 2019, 2016",
                "published": "2024-02-13"
            },
            {
                "cve_id": "CVE-2024-23334",
                "severity": "HIGH",
                "cvss_score": 7.8,
                "description": "Apache Kafka 认证绕过漏洞",
                "affected": "Apache Kafka < 3.6.1",
                "published": "2024-03-05"
            }
        ]

    def generate_detailed_solution(self, cve: dict) -> dict:
        """为单个 CVE 生成详细解决方案"""

        prompt = f"""
作为资深安全专家，请为以下 CVE 漏洞生成详细的解决方案：

CVE 信息：
- CVE ID: {cve['cve_id']}
- 严重级别: {cve['severity']}
- CVSS 评分: {cve['cvss_score']}
- 描述: {cve['description']}
- 影响版本: {cve['affected']}
- 发布日期: {cve['published']}

请提供以下内容：

## 1. 漏洞详细分析
- 漏洞原理
- 攻击向量
- 潜在影响
- 实际风险评估

## 2. 立即缓解措施（24小时内）
- 临时防护措施
- 配置调整建议
- 监控规则设置
- 应急隔离方案

## 3. 永久修复方案
- 补丁更新步骤
- 版本升级路径
- 配置加固建议
- 验证测试方法

## 4. 检测方法
- 如何检测系统是否受影响
- 如何验证是否已被利用
- 日志审计要点
- 自动化检测脚本

## 5. 预防措施
- 长期安全策略
- 类似漏洞防护
- 安全基线配置
- 持续监控方案

请提供具体可执行的命令和配置示例。
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一位资深的网络安全专家，精通漏洞分析和安全加固。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=3000
            )

            solution = response.choices[0].message.content

            return {
                "cve_id": cve['cve_id'],
                "severity": cve['severity'],
                "solution": solution,
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            return {
                "cve_id": cve['cve_id'],
                "error": str(e)
            }

    def generate_batch_solutions(self):
        """批量生成高危 CVE 解决方案"""
        high_risk_cves = self.get_high_risk_cves()
        solutions = []

        print("=" * 80)
        print("高危 CVE 详细解决方案生成器 - Powered by Qwen".center(80))
        print("=" * 80)

        # 分类统计
        critical_cves = [cve for cve in high_risk_cves if cve['severity'] == 'CRITICAL']
        high_cves = [cve for cve in high_risk_cves if cve['severity'] == 'HIGH']

        print(f"\n📊 风险统计：")
        print(f"   🔴 CRITICAL 级别: {len(critical_cves)} 个")
        print(f"   🟠 HIGH 级别: {len(high_cves)} 个")
        print(f"   📅 分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "-" * 80)

        # 首先处理 CRITICAL 级别
        if critical_cves:
            print("\n🔴 CRITICAL 级别 CVE 解决方案")
            print("=" * 80)
            for cve in critical_cves:
                print(f"\n分析 {cve['cve_id']} (CVSS: {cve['cvss_score']})...")
                solution = self.generate_detailed_solution(cve)
                solutions.append(solution)

                if "error" not in solution:
                    print(f"✅ {cve['cve_id']} 解决方案已生成")
                    # 打印部分解决方案
                    print("\n" + solution['solution'][:500] + "...\n")
                else:
                    print(f"❌ {cve['cve_id']} 生成失败: {solution['error']}")

        # 然后处理 HIGH 级别
        if high_cves:
            print("\n🟠 HIGH 级别 CVE 解决方案")
            print("=" * 80)
            for cve in high_cves:
                print(f"\n分析 {cve['cve_id']} (CVSS: {cve['cvss_score']})...")
                solution = self.generate_detailed_solution(cve)
                solutions.append(solution)

                if "error" not in solution:
                    print(f"✅ {cve['cve_id']} 解决方案已生成")
                    # 打印部分解决方案
                    print("\n" + solution['solution'][:500] + "...\n")
                else:
                    print(f"❌ {cve['cve_id']} 生成失败: {solution['error']}")

        return solutions

    def generate_emergency_response_plan(self):
        """生成应急响应计划"""
        prompt = """
基于已识别的高危 CVE 漏洞，请制定一个完整的应急响应计划：

## 需要包含：

1. **应急响应团队组织**
   - 角色定义
   - 职责分工
   - 通信机制

2. **优先级评估矩阵**
   - 基于 CVSS 评分
   - 基于业务影响
   - 基于资产价值

3. **响应时间线**
   - Critical: 4小时内
   - High: 24小时内
   - Medium: 72小时内

4. **标准操作流程 (SOP)**
   - 发现阶段
   - 评估阶段
   - 缓解阶段
   - 修复阶段
   - 验证阶段
   - 复盘阶段

5. **通信模板**
   - 内部通知
   - 管理层汇报
   - 外部披露（如需要）

6. **工具和资源清单**

7. **回滚和恢复计划**

8. **经验教训文档模板**

请提供具体可操作的内容。
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一位资深的安全事件响应专家。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.6,
                max_tokens=2500
            )

            return response.choices[0].message.content

        except Exception as e:
            return f"生成失败: {e}"

    def save_solutions(self, solutions):
        """保存解决方案到文件"""
        # 创建输出目录
        output_dir = Path("cve_solutions")
        output_dir.mkdir(exist_ok=True)

        # 保存完整报告
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = output_dir / f"high_risk_cve_solutions_{timestamp}.md"

        with open(report_file, "w", encoding="utf-8") as f:
            f.write("# 高危 CVE 详细解决方案报告\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("## 目录\n\n")

            # 分类写入
            critical_solutions = [s for s in solutions if s.get('severity') == 'CRITICAL']
            high_solutions = [s for s in solutions if s.get('severity') == 'HIGH']

            if critical_solutions:
                f.write("### 🔴 CRITICAL 级别漏洞\n\n")
                for sol in critical_solutions:
                    f.write(f"- [{sol['cve_id']}](#{sol['cve_id'].lower()})\n")

            if high_solutions:
                f.write("\n### 🟠 HIGH 级别漏洞\n\n")
                for sol in high_solutions:
                    f.write(f"- [{sol['cve_id']}](#{sol['cve_id'].lower()})\n")

            f.write("\n---\n\n")

            # 写入详细解决方案
            for solution in solutions:
                if "error" not in solution:
                    f.write(f"## {solution['cve_id']}\n\n")
                    f.write(f"**严重级别**: {solution['severity']}\n")
                    f.write(f"**生成时间**: {solution['generated_at']}\n\n")
                    f.write(solution['solution'])
                    f.write("\n\n---\n\n")

        print(f"\n📁 解决方案已保存到: {report_file}")

        # 保存 JSON 格式供程序使用
        json_file = output_dir / f"high_risk_cve_solutions_{timestamp}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(solutions, f, ensure_ascii=False, indent=2)

        print(f"📁 JSON 数据已保存到: {json_file}")

        return report_file

    def generate_executive_summary(self, solutions):
        """生成管理层摘要报告"""
        prompt = f"""
基于以下高危 CVE 分析结果，生成一份面向管理层的执行摘要：

分析的 CVE 数量：
- CRITICAL 级别: {len([s for s in solutions if s.get('severity') == 'CRITICAL'])} 个
- HIGH 级别: {len([s for s in solutions if s.get('severity') == 'HIGH'])} 个

请生成包含以下内容的执行摘要：

1. **风险概况**（1段，突出最关键风险）
2. **业务影响评估**（量化潜在损失）
3. **资源需求**（人力、时间、预算）
4. **建议行动计划**（分阶段）
5. **关键决策点**（需要管理层批准的事项）
6. **成功指标**（如何衡量修复效果）

要求：
- 使用商业语言，避免过多技术术语
- 突出成本效益分析
- 提供明确的时间线
- 强调合规性影响
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一位资深的信息安全顾问，擅长向管理层汇报。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.6,
                max_tokens=1500
            )

            return response.choices[0].message.content

        except Exception as e:
            return f"生成失败: {e}"


def main():
    """主函数"""
    print("\n🛡️ CVE 高危风险解决方案生成器\n")

    generator = CVEHighRiskSolutionGenerator()

    # 更新 TODO 状态
    print("📝 更新任务状态...")

    # 生成解决方案
    solutions = generator.generate_batch_solutions()

    # 生成应急响应计划
    print("\n📋 生成应急响应计划...")
    emergency_plan = generator.generate_emergency_response_plan()

    # 生成管理层报告
    print("\n📊 生成管理层摘要...")
    executive_summary = generator.generate_executive_summary(solutions)

    # 保存所有结果
    report_file = generator.save_solutions(solutions)

    # 保存应急响应计划
    emergency_file = Path("cve_solutions") / "emergency_response_plan.md"
    with open(emergency_file, "w", encoding="utf-8") as f:
        f.write("# CVE 应急响应计划\n\n")
        f.write(emergency_plan)
    print(f"📁 应急响应计划已保存到: {emergency_file}")

    # 保存管理层报告
    executive_file = Path("cve_solutions") / "executive_summary.md"
    with open(executive_file, "w", encoding="utf-8") as f:
        f.write("# 高危 CVE 风险管理层报告\n\n")
        f.write(executive_summary)
    print(f"📁 管理层报告已保存到: {executive_file}")

    print("\n" + "=" * 80)
    print("✅ 所有解决方案已生成完成！")
    print(f"   • 详细解决方案: {len(solutions)} 个")
    print(f"   • 应急响应计划: 已生成")
    print(f"   • 管理层报告: 已生成")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被中断")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()