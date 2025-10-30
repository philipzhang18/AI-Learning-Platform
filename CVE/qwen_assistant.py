#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用 Qwen 模型作为 AI 助手
"""

import sys
import os
from typing import List, Dict
from openai import OpenAI

# 设置输出编码
if sys.platform == 'win32':
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')

# 导入配置
from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL


class QwenAssistant:
    """Qwen AI 助手"""

    def __init__(self):
        """初始化 Qwen 助手"""
        self.client = OpenAI(
            api_key=QWEN_API_KEY,
            base_url=QWEN_BASE_URL
        )
        self.model = QWEN_MODEL  # 使用配置中的模型（如 qwen3-coder-plus）
        self.conversation_history = []
        print("🤖 Qwen 助手已就绪！")
        print("-" * 60)

    def chat(self, user_input: str, system_prompt: str = None) -> str:
        """与 Qwen 对话"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # 添加历史对话
        messages.extend(self.conversation_history)

        # 添加用户输入
        messages.append({"role": "user", "content": user_input})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=2000
            )

            assistant_reply = response.choices[0].message.content

            # 更新对话历史
            self.conversation_history.append({"role": "user", "content": user_input})
            self.conversation_history.append({"role": "assistant", "content": assistant_reply})

            # 限制历史长度
            if len(self.conversation_history) > 10:
                self.conversation_history = self.conversation_history[-10:]

            return assistant_reply

        except Exception as e:
            return f"❌ 错误: {str(e)}"

    def analyze_cve_improvements(self):
        """分析 CVE 项目的改进建议"""
        prompt = """基于之前的 bug 分析报告，请提供 CVE 项目的具体改进方案：

已发现的主要问题：
1. 7个裸露的 except 语句
2. API 密钥可能硬编码
3. 缺少请求频率限制
4. 资源泄露风险
5. 项目结构不够模块化
6. 存在代码重复（多个 GUI 版本和入口文件）

请提供：
1. 立即可执行的快速修复方案（1天内完成）
2. 中期重构计划（1周内完成）
3. 长期架构优化建议（1个月内完成）

重点关注安全性和代码质量。
"""

        print("\n🔍 分析 CVE 项目改进方案...")
        print("=" * 60)

        response = self.chat(prompt, system_prompt="你是一个专业的软件架构师和安全专家")
        print(response)

        return response

    def generate_fix_code(self, issue_type: str):
        """生成修复代码"""
        fixes = {
            "exception": """修复裸露的 except 语句的示例代码：

```python
# ❌ 错误的写法
try:
    result = dangerous_operation()
except:
    pass

# ✅ 正确的写法
try:
    result = dangerous_operation()
except (ValueError, TypeError) as e:
    logger.error(f"操作失败: {e}")
    # 处理特定异常
except Exception as e:
    logger.exception(f"未预期的错误: {e}")
    # 处理其他异常
    raise  # 重新抛出严重错误
```""",

            "api_key": """修复 API 密钥硬编码的方案：

```python
# ❌ 错误的写法（请勿在生产环境中使用）
api_key = "sk-abc123def456"  # 这是示例，不要使用真实的API密钥

# ✅ 正确的写法
import os
from pathlib import Path
from dotenv import load_dotenv

# 方法1：环境变量
api_key = os.getenv("NVD_API_KEY")
if not api_key:
    raise ValueError("请设置 NVD_API_KEY 环境变量")

# 方法2：配置文件
load_dotenv()  # 加载 .env 文件
api_key = os.getenv("NVD_API_KEY")

# 方法3：密钥管理服务
from keyvault import SecretClient
client = SecretClient(vault_url="https://your-vault.vault.azure.net/")
api_key = client.get_secret("nvd-api-key").value
```""",

            "rate_limit": """实现请求频率限制：

```python
import time
import asyncio
from functools import wraps

class RateLimiter:
    def __init__(self, calls: int, period: float):
        self.calls = calls
        self.period = period
        self.clock = time.monotonic
        self.last_reset = self.clock()
        self.num_calls = 0

    async def __aenter__(self):
        while self.num_calls >= self.calls:
            sleep_time = self.period - (self.clock() - self.last_reset)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
            self.last_reset = self.clock()
            self.num_calls = 0
        self.num_calls += 1

    async def __aexit__(self, *args):
        pass

# 使用示例
rate_limiter = RateLimiter(calls=5, period=60)  # 每分钟5次

async def fetch_cve_data():
    async with rate_limiter:
        # 执行 API 请求
        response = await session.get(url)
        return response
```"""
        }

        if issue_type in fixes:
            print(f"\n📝 {issue_type} 问题的修复代码：")
            print("-" * 60)
            print(fixes[issue_type])
        else:
            # 使用 Qwen 生成自定义修复代码
            prompt = f"请为 {issue_type} 问题生成 Python 修复代码示例"
            response = self.chat(prompt)
            print(f"\n📝 {issue_type} 问题的修复代码：")
            print("-" * 60)
            print(response)

    def interactive_mode(self):
        """交互式对话模式"""
        print("\n💬 进入 Qwen 交互模式")
        print("输入 'exit' 退出，'clear' 清空历史，'help' 查看帮助")
        print("-" * 60)

        while True:
            try:
                user_input = input("\n您: ").strip()

                if user_input.lower() == 'exit':
                    print("👋 再见！")
                    break
                elif user_input.lower() == 'clear':
                    self.conversation_history = []
                    print("✅ 对话历史已清空")
                    continue
                elif user_input.lower() == 'help':
                    print("""
可用命令：
- exit: 退出交互模式
- clear: 清空对话历史
- analyze: 分析 CVE 项目改进方案
- fix <type>: 生成修复代码 (exception/api_key/rate_limit)
                    """)
                    continue
                elif user_input.startswith('fix '):
                    issue_type = user_input[4:].strip()
                    self.generate_fix_code(issue_type)
                    continue
                elif user_input == 'analyze':
                    self.analyze_cve_improvements()
                    continue

                # 普通对话
                print("\nQwen: ", end="", flush=True)
                response = self.chat(user_input)
                print(response)

            except KeyboardInterrupt:
                print("\n\n👋 再见！")
                break
            except Exception as e:
                print(f"\n❌ 错误: {e}")


def main():
    """主函数"""
    print("\n🚀 Qwen 模型助手")
    print("=" * 60)

    assistant = QwenAssistant()

    # 显示菜单
    print("\n请选择操作：")
    print("1. 分析 CVE 项目改进方案")
    print("2. 生成异常处理修复代码")
    print("3. 生成 API 密钥管理代码")
    print("4. 生成频率限制代码")
    print("5. 进入交互对话模式")
    print("0. 退出")

    choice = input("\n请选择 (0-5): ").strip()

    if choice == "1":
        assistant.analyze_cve_improvements()
    elif choice == "2":
        assistant.generate_fix_code("exception")
    elif choice == "3":
        assistant.generate_fix_code("api_key")
    elif choice == "4":
        assistant.generate_fix_code("rate_limit")
    elif choice == "5":
        assistant.interactive_mode()
    elif choice == "0":
        print("👋 再见！")
    else:
        print("无效选择")
        # 默认进入交互模式
        assistant.interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被中断")
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()