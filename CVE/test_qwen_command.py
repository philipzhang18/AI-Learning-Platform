#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 Qwen Code Helper 功能
"""

import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL


def test_qwen_helper():
    """测试 Qwen 辅助脚本"""
    print("🧪 测试 Qwen Code Helper")
    print("=" * 60)

    # 测试 1: 检查配置
    print("\n1️⃣ 检查配置...")
    print(f"   API Key: {'✓ 已配置' if QWEN_API_KEY else '✗ 未配置'}")
    print(f"   Base URL: {QWEN_BASE_URL}")
    print(f"   Model: {QWEN_MODEL}")

    if not QWEN_API_KEY or QWEN_API_KEY == "your-qwen-api-key":
        print("\n❌ 错误：请在 llm_config.py 中配置正确的 QWEN_API_KEY")
        return False

    # 测试 2: 调用 API
    print("\n2️⃣ 测试 API 调用...")
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=QWEN_API_KEY,
            base_url=QWEN_BASE_URL
        )

        response = client.chat.completions.create(
            model=QWEN_MODEL,
            messages=[
                {"role": "system", "content": "你是一个代码助手"},
                {"role": "user", "content": "请写一个 Python 函数计算斐波那契数列"}
            ],
            temperature=0.7,
            max_tokens=500
        )

        result = response.choices[0].message.content
        print("   ✓ API 调用成功")
        print(f"\n   响应预览：\n   {result[:200]}...")

        # 测试 3: 测试辅助脚本
        print("\n3️⃣ 测试辅助脚本...")
        import subprocess

        result = subprocess.run(
            ["python", ".claude/qwen_code_helper.py", "什么是快速排序？"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30
        )

        if result.returncode == 0:
            print("   ✓ 辅助脚本执行成功")
            print(f"\n   响应预览：\n   {result.stdout[:200]}...")
        else:
            print(f"   ✗ 辅助脚本执行失败：{result.stderr}")
            return False

        print("\n✅ 所有测试通过！")
        return True

    except Exception as e:
        print(f"   ✗ 测试失败：{e}")
        import traceback
        traceback.print_exc()
        return False


def show_usage():
    """显示使用说明"""
    print("\n" + "=" * 60)
    print("📖 使用说明")
    print("=" * 60)
    print("""
在 Claude Code 中使用 /qwen-code 命令：

1. 基本用法：
   /qwen-code 你的问题

2. 示例：
   /qwen-code 如何在 Python 中实现单例模式？
   /qwen-code 帮我优化这段代码的性能
   /qwen-code 解释一下什么是装饰器

3. 适用场景：
   - 代码编写和生成
   - 代码审查和优化
   - 算法问题求解
   - 架构设计建议
   - 调试和问题诊断

4. 注意事项：
   - 问题要清晰、具体
   - 可以进行多轮对话
   - Qwen Coder Plus 专注于代码相关任务
""")


if __name__ == "__main__":
    # 设置输出编码
    if sys.platform == 'win32':
        if sys.stdout.encoding != 'UTF-8':
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')

    print("\n🚀 Qwen Code Helper 测试工具")

    # 运行测试
    success = test_qwen_helper()

    # 显示使用说明
    if success:
        show_usage()
    else:
        print("\n⚠️  请先解决配置问题，然后重新运行测试")

    sys.exit(0 if success else 1)
