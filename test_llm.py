#!/usr/bin/env python3
"""
快速测试 LLM API 集成
"""

import sys
import os


def test_imports():
    """测试模块导入"""
    print("测试模块导入...")
    try:
        import anthropic
        print("  ✓ anthropic 已安装")
    except ImportError:
        print("  ✗ anthropic 未安装 - 运行: pip install anthropic")
        return False

    try:
        import openai
        print("  ✓ openai 已安装")
    except ImportError:
        print("  ✗ openai 未安装 - 运行: pip install openai")
        return False

    try:
        from llm_api_client import LLMClient, chat_with_llm
        print("  ✓ llm_api_client 模块正常")
    except ImportError as e:
        print(f"  ✗ 无法导入 llm_api_client: {e}")
        return False

    return True


def test_config():
    """测试配置"""
    print("\n测试配置文件...")

    if os.path.exists("llm_config.py"):
        print("  ✓ llm_config.py 存在")
        try:
            import llm_config
            if hasattr(llm_config, 'CLAUDE_API_KEY'):
                if llm_config.CLAUDE_API_KEY != "your-claude-api-key":
                    print("  ✓ Claude API Key 已配置")
                else:
                    print("  ⚠ Claude API Key 未配置（使用默认值）")

            if hasattr(llm_config, 'QWEN_API_KEY'):
                if llm_config.QWEN_API_KEY != "sk-your-qwen-api-key":
                    print("  ✓ Qwen API Key 已配置")
                else:
                    print("  ⚠ Qwen API Key 未配置（使用默认值）")
        except ImportError:
            print("  ✗ 无法导入配置文件")
            return False
    else:
        print("  ⚠ llm_config.py 不存在，将使用环境变量")

    return True


def test_quick_chat():
    """测试快速聊天"""
    print("\n测试快速聊天功能...")

    try:
        from llm_api_client import chat_with_llm

        # 简单测试
        response = chat_with_llm(
            "回复 'OK' 即可",
            temperature=0.1,
            max_tokens=10
        )

        if response and not response.startswith("错误"):
            print(f"  ✓ 聊天测试成功: {response[:50]}")
            return True
        else:
            print(f"  ✗ 聊天测试失败: {response}")
            return False

    except Exception as e:
        print(f"  ✗ 测试失败: {e}")
        return False


def test_providers():
    """测试可用的提供商"""
    print("\n测试模型提供商...")

    try:
        from llm_api_client import LLMClient

        client = LLMClient(auto_fallback=True)
        providers = client.get_available_providers()

        if providers:
            print(f"  ✓ 可用的提供商: {', '.join(providers)}")

            for provider in providers:
                print(f"\n  测试 {provider}:")
                if client.test_connection(provider):
                    print(f"    ✓ {provider} 连接正常")
                else:
                    print(f"    ✗ {provider} 连接失败")
            return True
        else:
            print("  ✗ 没有可用的提供商")
            return False

    except Exception as e:
        print(f"  ✗ 测试失败: {e}")
        return False


def main():
    """主函数"""
    print("=" * 60)
    print("LLM API 集成快速测试".center(60))
    print("=" * 60)

    tests = [
        ("模块导入", test_imports),
        ("配置文件", test_config),
        ("模型提供商", test_providers),
        ("快速聊天", test_quick_chat),
    ]

    results = []
    for name, test_func in tests:
        print(f"\n[{len(results)+1}/{len(tests)}] {name}")
        print("-" * 40)
        success = test_func()
        results.append((name, success))

    # 总结
    print("\n" + "=" * 60)
    print("测试结果总结".center(60))
    print("=" * 60)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for name, success in results:
        status = "✓ 通过" if success else "✗ 失败"
        print(f"  {name:15} {status}")

    print(f"\n总计: {passed}/{total} 测试通过")

    if passed == total:
        print("\n🎉 所有测试通过！LLM API 集成工作正常。")
        print("\n下一步：")
        print("  python llm_examples.py  # 运行更多示例")
    else:
        print("\n⚠️  部分测试失败，请检查：")
        print("  1. API 密钥是否正确配置")
        print("  2. 网络连接是否正常")
        print("  3. 依赖包是否全部安装")
        print("\n运行 python setup_llm.py 重新配置")

    return passed == total


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n测试出错: {e}")
        sys.exit(1)