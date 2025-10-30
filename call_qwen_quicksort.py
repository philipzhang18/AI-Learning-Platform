#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调用 qwen-code 工具生成快速排序算法
"""

import json
import sys
import requests

# 设置编码
if sys.platform == 'win32':
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')

# 加载配置
with open('qwen_http_tools.json', 'r', encoding='utf-8') as f:
    config = json.load(f)

tool_config = config['tools']['qwen-code']

# 准备请求
prompt = """请编写一个 Python 快速排序算法实现。

要求：
1. 使用递归方式实现
2. 包含详细的中文注释
3. 添加类型注解
4. 提供使用示例
5. 分析时间和空间复杂度
"""

# 构建请求体
body = tool_config['body_template'].copy()
for msg in body['messages']:
    if msg['role'] == 'user':
        msg['content'] = prompt

print("=" * 70)
print("🚀 调用 Qwen3 Coder Plus 生成快速排序算法")
print("=" * 70)
print(f"\n📍 端点: {tool_config['endpoint']}")
print(f"🤖 模型: {body['model']}")
print(f"🌡️  温度: {body['temperature']}")
print("\n正在生成代码...\n")

# 发送请求
try:
    response = requests.post(
        tool_config['endpoint'],
        headers=tool_config['headers'],
        json=body,
        timeout=60
    )

    response.raise_for_status()
    result = response.json()

    # 提取内容
    content = result['choices'][0]['message']['content']

    print("=" * 70)
    print("✅ 生成成功！")
    print("=" * 70)
    print("\n" + content + "\n")

    # 显示使用统计
    if 'usage' in result:
        usage = result['usage']
        print("\n" + "=" * 70)
        print("📊 Token 使用统计:")
        print(f"  - 输入 Token: {usage.get('prompt_tokens', 'N/A')}")
        print(f"  - 输出 Token: {usage.get('completion_tokens', 'N/A')}")
        print(f"  - 总计: {usage.get('total_tokens', 'N/A')}")
        print("=" * 70)

except requests.exceptions.RequestException as e:
    print(f"❌ 请求失败: {e}")
except Exception as e:
    print(f"❌ 错误: {e}")
