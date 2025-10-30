"""
LLM API 集成使用示例
展示如何使用 Claude 和 Qwen API 集成模块
"""

import os
import sys
from llm_api_client import (
    LLMClient, Message, create_client,
    chat_with_llm, ModelProvider
)


def example_basic_chat():
    """基础聊天示例"""
    print("=" * 60)
    print("基础聊天示例")
    print("=" * 60)

    # 方式1：使用便捷函数
    response = chat_with_llm(
        prompt="请解释什么是Python装饰器",
        system_prompt="你是一个Python编程专家"
    )
    print(f"回复: {response[:200]}...\n")


def example_with_fallback():
    """自动故障切换示例"""
    print("=" * 60)
    print("自动故障切换示例")
    print("=" * 60)

    # 创建支持自动切换的客户端
    client = create_client(primary="claude", auto_fallback=True)

    messages = [
        Message(role="system", content="你是一个代码审查专家"),
        Message(role="user", content="""
请审查以下代码并给出改进建议：

def calculate_sum(numbers):
    total = 0
    for num in numbers:
        total = total + num
    return total
""")
    ]

    response = client.chat(messages)

    if response.error:
        print(f"错误: {response.error}")
    else:
        print(f"使用的模型: {response.provider.value} - {response.model}")
        print(f"回复: {response.content[:300]}...")
        if response.usage:
            print(f"Token 使用情况: {response.usage}")


def example_specific_provider():
    """指定模型提供商示例"""
    print("\n" + "=" * 60)
    print("指定模型提供商示例")
    print("=" * 60)

    client = LLMClient(auto_fallback=False)  # 禁用自动切换

    # 明确使用 Qwen 模型
    messages = [
        Message(role="user", content="写一个快速排序的Python实现")
    ]

    print("尝试使用 Qwen 模型...")
    response = client.chat(messages, provider="qwen")

    if response.error:
        print(f"Qwen 调用失败: {response.error}")

        # 手动切换到 Claude
        print("\n手动切换到 Claude 模型...")
        response = client.chat(messages, provider="claude")

    if not response.error:
        print(f"成功使用: {response.provider.value}")
        print(f"代码:\n{response.content[:500]}...")


def example_streaming():
    """流式输出示例"""
    print("\n" + "=" * 60)
    print("流式输出示例")
    print("=" * 60)

    client = create_client()

    messages = [
        Message(role="user", content="简单介绍一下机器学习")
    ]

    print("流式输出: ", end="", flush=True)
    for chunk in client.stream_chat(messages):
        print(chunk, end="", flush=True)
    print("\n")


def example_code_assistance():
    """代码辅助示例"""
    print("=" * 60)
    print("代码辅助示例")
    print("=" * 60)

    client = create_client(primary="qwen", auto_fallback=True)

    # 代码补全请求
    code_prompt = """
完成以下Python类的实现：

class TodoList:
    def __init__(self):
        self.todos = []

    def add_todo(self, task, priority=1):
        # TODO: 实现添加任务的方法
        pass

    def remove_todo(self, task_id):
        # TODO: 实现删除任务的方法
        pass

    def get_todos_by_priority(self, priority):
        # TODO: 返回指定优先级的任务
        pass
"""

    messages = [
        Message(role="system", content="你是一个Python编程助手，请完成代码实现"),
        Message(role="user", content=code_prompt)
    ]

    response = client.chat(messages, temperature=0.3)  # 降低温度以获得更一致的代码

    if not response.error:
        print(f"使用模型: {response.provider.value}")
        print("完成的代码：")
        print(response.content)


def example_multi_turn_conversation():
    """多轮对话示例"""
    print("\n" + "=" * 60)
    print("多轮对话示例")
    print("=" * 60)

    client = create_client()

    conversation = [
        Message(role="system", content="你是一个有帮助的编程助手")
    ]

    # 第一轮对话
    conversation.append(Message(role="user", content="什么是REST API？"))
    response = client.chat(conversation)

    if not response.error:
        print(f"助手: {response.content[:200]}...")
        conversation.append(Message(role="assistant", content=response.content))

        # 第二轮对话
        conversation.append(Message(role="user", content="能给一个Python Flask的例子吗？"))
        response = client.chat(conversation)

        if not response.error:
            print(f"\n助手: {response.content[:300]}...")


def test_all_providers():
    """测试所有可用的模型提供商"""
    print("=" * 60)
    print("测试所有模型提供商")
    print("=" * 60)

    client = LLMClient(auto_fallback=False)
    test_message = [Message(role="user", content="回复OK即可")]

    providers = client.get_available_providers()
    print(f"可用的提供商: {providers}\n")

    for provider in providers:
        print(f"测试 {provider}...")
        response = client.chat(test_message, provider=provider, max_tokens=10)

        if response.error:
            print(f"  ✗ 失败: {response.error}")
        else:
            print(f"  ✓ 成功: {response.content}")


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("LLM API 集成示例程序")
    print("=" * 60 + "\n")

    # 检查配置
    if not os.path.exists("llm_config.py"):
        print("警告: 未找到 llm_config.py 配置文件")
        print("请先配置 API 密钥\n")

    examples = {
        "1": ("基础聊天", example_basic_chat),
        "2": ("自动故障切换", example_with_fallback),
        "3": ("指定模型提供商", example_specific_provider),
        "4": ("流式输出", example_streaming),
        "5": ("代码辅助", example_code_assistance),
        "6": ("多轮对话", example_multi_turn_conversation),
        "7": ("测试所有提供商", test_all_providers),
    }

    while True:
        print("\n请选择示例：")
        for key, (name, _) in examples.items():
            print(f"  {key}. {name}")
        print("  0. 退出")

        choice = input("\n请输入选择 (0-7): ").strip()

        if choice == "0":
            print("退出程序")
            break
        elif choice in examples:
            print()
            try:
                examples[choice][1]()
            except Exception as e:
                print(f"\n执行示例时出错: {e}")
        else:
            print("无效的选择，请重试")


if __name__ == "__main__":
    # 可以设置环境变量来覆盖配置文件
    # os.environ["CLAUDE_API_KEY"] = "your-key"
    # os.environ["QWEN_API_KEY"] = "your-key"

    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n程序错误: {e}")