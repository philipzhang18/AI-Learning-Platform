#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用 Qwen 分析 CVE 项目改进方案
"""

import sys
from openai import OpenAI
from llm_config import QWEN_API_KEY, QWEN_BASE_URL

# 设置输出编码
if sys.platform == 'win32':
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')

def analyze_cve_improvements():
    """使用 Qwen 分析 CVE 项目改进方案"""

    import httpx
    http_client = httpx.Client(
        base_url=QWEN_BASE_URL,
        follow_redirects=True,
        timeout=30.0
    )
    
    client = OpenAI(
        api_key=QWEN_API_KEY,
        http_client=http_client
    )

    prompt = """基于 CVE 安全漏洞监控项目的 bug 分析报告，请提供详细的改进方案。

## 已发现的问题总结：

### 代码质量问题（7个）
1. collect_cves.py:32 - API密钥可能硬编码
2. collect_cves.py:337 - API密钥可能硬编码
3. cve_gui.py:488 - 裸露的 except 语句
4. cve_gui.py:680 - 裸露的 except 语句
5. cve_gui_v2.py:722 - 裸露的 except 语句
6. cve_gui_v2.py:979 - 裸露的 except 语句
7. local_database.py:331 - 裸露的 except 语句

### 安全性问题
- API 密钥管理不当，存在硬编码风险
- 缺少请求频率限制机制
- 数据库连接未正确关闭，存在资源泄露
- 错误信息可能泄露敏感信息
- 缺少输入验证

### 架构问题
- 项目结构不够模块化，所有文件平铺在根目录
- 存在代码重复（cve_gui.py vs cve_gui_v2.py，main.py vs run.py）
- 模块间耦合度高，UI层直接依赖底层模块
- 缺少统一的错误处理机制
- 缺少配置管理系统

## 请提供以下改进方案：

### 1. 立即修复（优先级最高，1天内完成）
- 修复所有裸露的 except 语句
- 移除硬编码的 API 密钥
- 添加基本的输入验证

### 2. 短期改进（1周内完成）
- 实现请求频率限制
- 改进数据库连接管理
- 统一错误处理机制

### 3. 中期重构（2-4周完成）
- 重组项目结构
- 消除代码重复
- 实现配置管理系统

### 4. 长期优化（1-2个月）
- 完整的安全审计
- 性能优化
- 添加单元测试

请为每个阶段提供具体的实施步骤和代码示例。
"""

    try:
        response = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {"role": "system", "content": "你是一个资深的软件架构师和安全专家，擅长 Python 项目的重构和优化。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )

        result = response.choices[0].message.content

        # 打印结果
        print("=" * 80)
        print("CVE 项目改进方案 - Powered by Qwen".center(80))
        print("=" * 80)
        print("\n" + result)

        # 保存到文件
        with open("cve_improvement_plan.md", "w", encoding="utf-8") as f:
            f.write(f"# CVE 项目改进方案\n\n{result}")

        print("\n" + "=" * 80)
        print("✅ 改进方案已保存到: cve_improvement_plan.md")

        return result

    except Exception as e:
        print(f"❌ 错误: {e}")
        return None

if __name__ == "__main__":
    print("\n🤖 使用 Qwen 模型分析 CVE 项目改进方案...\n")
    analyze_cve_improvements()