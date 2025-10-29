#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Qwen Code Helper - 用于 Claude Code 自定义命令
通过命令行调用 Qwen 3 Coder Plus 模型
"""

import sys
import os
import json
from openai import OpenAI

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入配置
from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL


def call_qwen(prompt: str, system_prompt: str = None, temperature: float = 0.7) -> str:
    """
    调用 Qwen Coder Plus 模型

    Args:
        prompt: 用户提示
        system_prompt: 系统提示（可选）
        temperature: 温度参数

    Returns:
        str: 模型响应
    """
    try:
        # 初始化客户端
        client = OpenAI(
            api_key=QWEN_API_KEY,
            base_url=QWEN_BASE_URL
        )

        # 构建消息
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # 调用 API
        response = client.chat.completions.create(
            model=QWEN_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=4096
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"❌ 错误：{str(e)}"


def main():
    """主函数 - 从命令行参数或标准输入读取提示"""
    # 设置输出编码
    if sys.platform == 'win32':
        if sys.stdout.encoding != 'UTF-8':
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')

    # 读取参数
    if len(sys.argv) > 1:
        # 从命令行参数读取
        prompt = " ".join(sys.argv[1:])
    else:
        # 从标准输入读取
        print("请输入你的问题（输入 Ctrl+D 或 Ctrl+Z 结束）：", file=sys.stderr)
        prompt = sys.stdin.read().strip()

    if not prompt:
        print("错误：未提供提示内容", file=sys.stderr)
        sys.exit(1)

    # 系统提示 - 专注于代码相关任务
    system_prompt = """你是 Qwen 3 Coder Plus，一个专业的代码助手。
你擅长：
- 编写高质量代码
- 代码审查和优化
- 调试和问题解决
- 算法和数据结构
- 架构设计

请提供清晰、准确、可执行的代码和技术建议。
"""

    # 调用模型
    response = call_qwen(prompt, system_prompt)

    # 输出结果
    print(response)


if __name__ == "__main__":
    main()
