#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
专门测试 Qwen API 连通性
"""

import json
import sys
import os

# 设置输出编码为 UTF-8
if sys.platform == 'win32':
    import locale
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')


def test_qwen_connection():
    """测试 Qwen API 连接"""
    print("=" * 60)
    print("测试 Qwen API 连通性")
    print("=" * 60)

    try:
        # 导入必要的模块
        from llm_api_client import QwenAPI, Message

        print("\n1. 初始化 Qwen 客户端...")

        # 从配置文件读取
        try:
            from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL
            configured = bool(QWEN_API_KEY)
            print(f"   - API Key: {'✓ 已配置' if configured else '✗ 未配置'}")
            print(f"   - Base URL: {QWEN_BASE_URL}")
            print(f"   - Model: {QWEN_MODEL}")
        except ImportError:
            print("   ✗ 无法导入配置文件")
            return False

        # 创建 Qwen 客户端（使用配置/环境变量）
        from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL
        qwen_client = QwenAPI(api_key=QWEN_API_KEY, base_url=QWEN_BASE_URL)
        print("   ✓ Qwen 客户端创建成功")

        # 测试简单请求
        print("\n2. 发送测试请求...")
        test_messages = [
            Message(role="user", content="请回复'测试成功'这四个字")
        ]

        response = qwen_client.chat(test_messages, temperature=0.1, max_tokens=20)

        if response.error:
            print(f"   ✗ 请求失败: {response.error}")
            return False
        else:
            print(f"   ✓ 请求成功")
            print(f"   - 模型: {response.model}")
            print(f"   - 回复: {response.content}")
            if response.usage:
                print(f"   - Token 使用: {json.dumps(response.usage, indent=4)}")

        # 测试代码生成能力
        print("\n3. 测试代码生成...")
        code_messages = [
            Message(role="user", content="用Python写一个计算斐波那契数列的函数，只需要函数定义，不要解释")
        ]

        response = qwen_client.chat(code_messages, temperature=0.3, max_tokens=200)

        if not response.error:
            print("   ✓ 代码生成成功")
            print("   生成的代码:")
            print("-" * 40)
            print(response.content[:500])
            if len(response.content) > 500:
                print("... (已截断)")
            print("-" * 40)
        else:
            print(f"   ✗ 代码生成失败: {response.error}")

        return True

    except Exception as e:
        print(f"\n✗ 测试过程出错: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_fallback():
    """测试自动故障切换到 Qwen"""
    print("\n" + "=" * 60)
    print("测试自动故障切换功能")
    print("=" * 60)

    try:
        from llm_api_client import LLMClient, Message

        print("\n1. 创建支持故障切换的客户端...")
        # 故意使用错误的 Claude key，测试是否会切换到 Qwen
        client = LLMClient(
            primary_provider="claude",
            auto_fallback=True,
            claude_api_key="invalid-key-for-testing"
        )

        print(f"   - 主模型: Claude (使用无效密钥)")
        print(f"   - 备用模型: Qwen")
        print(f"   - 自动切换: 已启用")

        print("\n2. 发送请求（预期将切换到 Qwen）...")
        messages = [
            Message(role="user", content="说'Hello from Qwen'")
        ]

        response = client.chat(messages, max_tokens=50)

        if not response.error:
            print(f"   ✓ 请求成功")
            print(f"   - 使用的模型: {response.provider.value}")
            print(f"   - 模型名称: {response.model}")
            print(f"   - 回复: {response.content}")

            if response.provider.value == "qwen":
                print("\n   ✓ 成功切换到 Qwen 备用模型！")
                return True
            else:
                print("\n   ⚠ 未切换到备用模型")
                return False
        else:
            print(f"   ✗ 请求失败: {response.error}")
            return False

    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        return False


def test_qwen_models():
    """测试不同的 Qwen 模型"""
    print("\n" + "=" * 60)
    print("测试不同的 Qwen 模型")
    print("=" * 60)

    try:
        from llm_api_client import QwenAPI, Message
        from llm_config import QWEN_API_KEY

        # 测试不同的模型
        models = [
            os.getenv("QWEN_MODEL", "qwen3-coder-plus"),
            "qwen-coder-plus",
            "qwen-plus",
            "qwen-turbo",
        ]

        test_message = [
            Message(role="user", content="1+1=?")
        ]

        for model in models:
            print(f"\n测试模型: {model}")
            print("-" * 30)

            try:
                # 创建客户端
                client = QwenAPI(api_key=QWEN_API_KEY)
                client.model = model

                # 发送请求
                response = client.chat(test_message, max_tokens=10)

                if not response.error:
                    print(f"  ✓ 成功")
                    print(f"    回复: {response.content}")
                    if response.usage:
                        print(f"    Tokens: {response.usage.get('total_tokens', 'N/A')}")
                else:
                    print(f"  ✗ 失败: {response.error}")

            except Exception as e:
                print(f"  ✗ 错误: {e}")

        return True

    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        return False


def main():
    """主函数"""
    print("\n" + "🔧 Qwen API 连通性测试工具\n")

    # 检查配置文件
    if not os.path.exists("llm_config.py"):
        print("❌ 错误: 未找到 llm_config.py 配置文件")
        print("请先运行: python setup_llm.py")
        return False

    # 运行测试
    tests = [
        ("Qwen API 基础连接", test_qwen_connection),
        ("自动故障切换", test_fallback),
        ("多模型测试", test_qwen_models),
    ]

    results = []
    for i, (name, test_func) in enumerate(tests, 1):
        print(f"\n[测试 {i}/{len(tests)}] {name}")
        print("=" * 60)

        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"✗ 测试异常: {e}")
            results.append((name, False))

    # 总结
    print("\n" + "=" * 60)
    print("测试结果总结")
    print("=" * 60)

    for name, success in results:
        status = "✅ 通过" if success else "❌ 失败"
        print(f"  {status} - {name}")

    passed = sum(1 for _, s in results if s)
    total = len(results)

    print(f"\n总计: {passed}/{total} 测试通过")

    if passed == total:
        print("\n✅ Qwen API 连通性测试全部通过！")
        print("您可以使用 Qwen 作为备用模型。")
    else:
        print("\n⚠️ 部分测试失败")
        print("请检查：")
        print("1. API Key 是否正确")
        print("2. 网络连接是否正常")
        print("3. 阿里云账户是否有足够额度")

    return passed == total


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n测试被中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)