#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Qwen HTTP 工具配置使用示例

本示例演示如何使用 qwen_http_tools.json 配置文件调用 Qwen Coder Plus 模型。
这是一种灵活的配置方式，可以轻松切换不同的 HTTP 端点和模型参数。
"""

import json
import sys
import requests
from pathlib import Path
from typing import Dict, Any, Optional


class QwenHTTPToolsClient:
    """
    基于 HTTP 工具配置文件的 Qwen 客户端

    从 qwen_http_tools.json 读取配置，支持动态调用各种 HTTP 端点
    """

    def __init__(self, config_path: str = "qwen_http_tools.json", tool_name: str = "qwen-code"):
        """
        初始化客户端

        Args:
            config_path: 配置文件路径
            tool_name: 要使用的工具名称（在配置文件的 tools 字段中）
        """
        self.config_path = Path(config_path)
        self.tool_name = tool_name
        self.config = self._load_config()

        # 验证配置
        if not self.config:
            raise ValueError(f"无法从 {config_path} 加载配置")

        print(f"✅ 已加载配置工具: {tool_name}")
        print(f"📍 端点: {self.config.get('endpoint', 'N/A')}")
        print(f"🤖 模型: {self.config.get('body_template', {}).get('model', 'N/A')}")
        print("-" * 70)

    def _load_config(self) -> Optional[Dict[str, Any]]:
        """加载并解析配置文件"""
        try:
            if not self.config_path.exists():
                print(f"❌ 配置文件不存在: {self.config_path}")
                return None

            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)

            # 获取指定工具的配置
            tools = config_data.get("tools", {})
            tool_config = tools.get(self.tool_name)

            if not tool_config:
                print(f"❌ 配置中未找到工具: {self.tool_name}")
                print(f"可用工具: {list(tools.keys())}")
                return None

            return tool_config

        except json.JSONDecodeError as e:
            print(f"❌ JSON 解析错误: {e}")
            return None
        except Exception as e:
            print(f"❌ 加载配置失败: {e}")
            return None

    def chat(self, user_input: str, temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """
        发送聊天请求

        Args:
            user_input: 用户输入的内容
            temperature: 温度参数（可选，覆盖配置）
            max_tokens: 最大 token 数（可选，覆盖配置）

        Returns:
            包含响应内容和元数据的字典
        """
        try:
            # 准备请求体
            body = self._prepare_request_body(user_input, temperature, max_tokens)

            # 发送请求
            response = requests.post(
                self.config["endpoint"],
                headers=self.config["headers"],
                json=body,
                timeout=60
            )

            response.raise_for_status()
            response_data = response.json()

            # 解析响应
            return self._parse_response(response_data)

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"请求失败: {e}",
                "content": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"未知错误: {e}",
                "content": None
            }

    def _prepare_request_body(self, user_input: str, temperature: Optional[float],
                              max_tokens: Optional[int]) -> Dict[str, Any]:
        """准备请求体"""
        # 深拷贝模板以避免修改原配置
        body = json.loads(json.dumps(self.config["body_template"]))

        # 替换用户输入
        for message in body["messages"]:
            if message["role"] == "user":
                message["content"] = user_input

        # 覆盖参数
        if temperature is not None:
            body["temperature"] = temperature
        if max_tokens is not None:
            body["max_tokens"] = max_tokens

        return body

    def _parse_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """解析响应数据"""
        try:
            # 使用配置中的映射规则提取内容
            mapping = self.config.get("response_mapping", {})
            output_path = mapping.get("output", "choices[0].message.content")

            # 简单的路径解析（支持 choices[0].message.content 格式）
            content = response_data
            for part in output_path.replace("[", ".").replace("]", "").split("."):
                if part.isdigit():
                    content = content[int(part)]
                else:
                    content = content.get(part)

            return {
                "success": True,
                "error": None,
                "content": content,
                "raw_response": response_data
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"解析响应失败: {e}",
                "content": None,
                "raw_response": response_data
            }


def example_code_generation():
    """示例1：代码生成"""
    print("\n" + "=" * 70)
    print("📝 示例 1: 代码生成")
    print("=" * 70)

    client = QwenHTTPToolsClient()

    prompt = """
请编写一个 Python 函数，实现二分查找算法。
要求：
1. 包含完整的文档字符串
2. 添加类型注解
3. 包含边界情况处理
4. 提供使用示例
"""

    print(f"\n💬 用户请求:\n{prompt}")
    print("\n🤖 Qwen Coder Plus 生成中...\n")

    response = client.chat(prompt, temperature=0.3)

    if response["success"]:
        print(response["content"])
    else:
        print(f"❌ 错误: {response['error']}")


def example_code_debugging():
    """示例2：代码调试"""
    print("\n" + "=" * 70)
    print("🐛 示例 2: 代码调试")
    print("=" * 70)

    client = QwenHTTPToolsClient()

    buggy_code = """
def calculate_average(numbers):
    total = 0
    for num in numbers:
        total += num
    return total / len(numbers)

# 测试
result = calculate_average([])
print(result)
"""

    prompt = f"""
以下代码存在 bug，请找出问题并提供修复方案：

```python
{buggy_code}
```

请说明：
1. 问题是什么
2. 为什么会出现这个问题
3. 如何修复（提供修复后的代码）
4. 如何避免类似问题
"""

    print(f"\n💬 待调试代码:\n{buggy_code}")
    print("\n🤖 Qwen Coder Plus 分析中...\n")

    response = client.chat(prompt, temperature=0.2)

    if response["success"]:
        print(response["content"])
    else:
        print(f"❌ 错误: {response['error']}")


def example_code_optimization():
    """示例3：代码优化"""
    print("\n" + "=" * 70)
    print("⚡ 示例 3: 代码优化")
    print("=" * 70)

    client = QwenHTTPToolsClient()

    slow_code = """
def find_duplicates(numbers):
    duplicates = []
    for i in range(len(numbers)):
        for j in range(i + 1, len(numbers)):
            if numbers[i] == numbers[j] and numbers[i] not in duplicates:
                duplicates.append(numbers[i])
    return duplicates

# 性能问题：大数据量时很慢
nums = list(range(10000)) * 2
result = find_duplicates(nums)
"""

    prompt = f"""
请优化以下代码的性能：

```python
{slow_code}
```

要求：
1. 分析当前代码的时间复杂度
2. 提供优化后的代码
3. 说明优化后的时间复杂度
4. 对比性能提升
"""

    print(f"\n💬 待优化代码:\n{slow_code}")
    print("\n🤖 Qwen Coder Plus 优化中...\n")

    response = client.chat(prompt, temperature=0.4)

    if response["success"]:
        print(response["content"])
    else:
        print(f"❌ 错误: {response['error']}")


def example_explain_code():
    """示例4：代码解释"""
    print("\n" + "=" * 70)
    print("📖 示例 4: 代码解释")
    print("=" * 70)

    client = QwenHTTPToolsClient()

    complex_code = """
from functools import lru_cache

@lru_cache(maxsize=None)
def fibonacci(n):
    if n < 2:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""

    prompt = f"""
请详细解释以下代码的工作原理：

```python
{complex_code}
```

请说明：
1. 代码的功能
2. 每行代码的作用
3. @lru_cache 装饰器的作用和原理
4. 时间和空间复杂度分析
"""

    print(f"\n💬 待解释代码:\n{complex_code}")
    print("\n🤖 Qwen Coder Plus 解释中...\n")

    response = client.chat(prompt, temperature=0.5)

    if response["success"]:
        print(response["content"])
    else:
        print(f"❌ 错误: {response['error']}")


def example_custom_tool():
    """示例5：使用自定义工具配置"""
    print("\n" + "=" * 70)
    print("🔧 示例 5: 自定义工具配置")
    print("=" * 70)

    print("""
本示例展示如何创建和使用自定义 HTTP 工具配置。

配置文件格式 (qwen_http_tools.json):
{
  "tools": {
    "qwen-code": {
      "type": "http",
      "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY",
        "Content-Type": "application/json"
      },
      "body_template": {
        "model": "qwen3-coder-plus",
        "messages": [
          {
            "role": "system",
            "content": "You are a code expert."
          },
          {
            "role": "user",
            "content": "{{input}}"
          }
        ],
        "temperature": 0.6,
        "max_tokens": 4096
      },
      "response_mapping": {
        "output": "choices[0].message.content"
      }
    }
  }
}

配置说明：
1. endpoint: API 端点 URL
2. headers: 请求头（包含认证信息）
3. body_template: 请求体模板（{{input}} 会被替换为用户输入）
4. response_mapping: 响应数据映射规则

使用方法：
1. 编辑 qwen_http_tools.json，替换 YOUR_API_KEY
2. 运行本脚本即可使用配置的工具
3. 可以添加多个工具配置，通过 tool_name 参数选择使用
""")


def interactive_mode():
    """交互式模式"""
    print("\n" + "=" * 70)
    print("💬 交互式模式")
    print("=" * 70)
    print("输入 'exit' 退出，'help' 查看帮助\n")

    try:
        client = QwenHTTPToolsClient()
    except ValueError as e:
        print(f"❌ 初始化失败: {e}")
        return

    while True:
        try:
            user_input = input("\n您: ").strip()

            if user_input.lower() == 'exit':
                print("👋 再见！")
                break
            elif user_input.lower() == 'help':
                print("""
可用命令:
- exit: 退出交互模式
- help: 显示帮助信息
- 其他: 直接输入问题，与 Qwen Coder Plus 对话

示例问题:
- 如何在 Python 中读取 JSON 文件？
- 解释什么是装饰器
- 写一个快速排序的实现
- 优化这段代码：[粘贴代码]
""")
                continue

            if not user_input:
                continue

            print("\n🤖 Qwen Coder Plus: ", end="", flush=True)
            response = client.chat(user_input)

            if response["success"]:
                print(response["content"])
            else:
                print(f"\n❌ 错误: {response['error']}")

        except KeyboardInterrupt:
            print("\n\n👋 再见！")
            break
        except Exception as e:
            print(f"\n❌ 错误: {e}")


def main():
    """主函数"""
    # 设置控制台编码
    if sys.platform == 'win32':
        if sys.stdout.encoding != 'UTF-8':
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')

    print("\n" + "=" * 70)
    print("🚀 Qwen HTTP 工具配置使用示例")
    print("=" * 70)
    print("""
本程序演示如何使用 qwen_http_tools.json 配置文件调用 Qwen Coder Plus 模型。

配置文件位置: D:\\AI\\Claude\\qwen_http_tools.json

⚠️  使用前请确保：
1. 已安装依赖: pip install requests
2. 已配置 API 密钥（编辑 qwen_http_tools.json）
3. 网络连接正常
""")

    print("\n请选择示例：")
    print("  1. 代码生成 - 生成二分查找算法")
    print("  2. 代码调试 - 找出并修复 bug")
    print("  3. 代码优化 - 性能优化建议")
    print("  4. 代码解释 - 详细解释代码原理")
    print("  5. 自定义配置说明")
    print("  6. 交互式对话")
    print("  0. 退出")

    choice = input("\n请选择 (0-6): ").strip()

    examples = {
        "1": example_code_generation,
        "2": example_code_debugging,
        "3": example_code_optimization,
        "4": example_explain_code,
        "5": example_custom_tool,
        "6": interactive_mode,
    }

    if choice == "0":
        print("👋 再见！")
    elif choice in examples:
        try:
            examples[choice]()
        except Exception as e:
            print(f"\n❌ 执行示例时出错: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("❌ 无效的选择")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n❌ 程序错误: {e}")
        import traceback
        traceback.print_exc()
