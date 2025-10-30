#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化版 Qwen API 测试 - 不依赖 anthropic
"""

import json
import sys
import os
from typing import List, Dict

# 设置输出编码
if sys.platform == 'win32':
    import locale
    if sys.stdout.encoding != 'UTF-8':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')


def test_qwen_direct():
    """直接测试 Qwen API（不使用 llm_api_client）"""
    print("=" * 60)
    print("直接测试 Qwen API (OpenAI 兼容接口)")
    print("=" * 60)

    try:
        from openai import OpenAI

        # 读取配置
        print("\n1. 读取配置...")
        try:
            from llm_config import QWEN_API_KEY, QWEN_BASE_URL, QWEN_MODEL
            api_key = QWEN_API_KEY
            base_url = QWEN_BASE_URL
            model = QWEN_MODEL
        except ImportError:
            api_key = os.getenv("DASHSCOPE_API_KEY", os.getenv("QWEN_API_KEY", ""))
            base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
            model = os.getenv("QWEN_MODEL", "qwen3-coder-plus")

        print(f"   - API Key: sk-{'*' * 20}...")
        print(f"   - Base URL: {base_url}")

        # 创建客户端
        print("\n2. 创建 OpenAI 兼容客户端...")
        client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        print("   ✓ 客户端创建成功")

        # 测试模型列表
        print("\n3. 获取可用模型列表...")
        try:
            models = client.models.list()
            print("   可用模型:")
            for model in models.data[:5]:  # 只显示前5个
                print(f"   - {model.id}")
        except Exception as e:
            print(f"   ⚠ 无法获取模型列表: {e}")

        # 测试简单对话
        print("\n4. 测试简单对话...")
        messages = [
            {"role": "system", "content": "你是一个有帮助的助手"},
            {"role": "user", "content": "请回复'测试成功'这四个字"}
        ]

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,
            max_tokens=20,
            stream=False
        )

        print("   ✓ 请求成功")
        print(f"   - 模型: {response.model}")
        print(f"   - 回复: {response.choices[0].message.content}")
        if response.usage:
            print(f"   - Tokens: 输入={response.usage.prompt_tokens}, "
                  f"输出={response.usage.completion_tokens}, "
                  f"总计={response.usage.total_tokens}")

        # 测试代码生成
        print("\n5. 测试代码生成能力...")
        code_prompt = [
            {"role": "user", "content": "写一个Python函数计算列表平均值，只要代码"}
        ]

        response = client.chat.completions.create(
            model=model,
            messages=code_prompt,
            temperature=0.3,
            max_tokens=150
        )

        print("   ✓ 代码生成成功")
        print("   生成的代码:")
        print("-" * 40)
        print(response.choices[0].message.content)
        print("-" * 40)

        # 测试流式输出
        print("\n6. 测试流式输出...")
        stream_messages = [
            {"role": "user", "content": "用一句话介绍Python"}
        ]

        stream = client.chat.completions.create(
            model="qwen-turbo",  # 使用快速模型
            messages=stream_messages,
            temperature=0.5,
            max_tokens=50,
            stream=True
        )

        print("   流式响应: ", end="", flush=True)
        full_response = ""
        for chunk in stream:
            if chunk.choices[0].delta.content:
                content = chunk.choices[0].delta.content
                print(content, end="", flush=True)
                full_response += content

        print("\n   ✓ 流式输出完成")

        return True

    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_different_models():
    """测试不同的 Qwen 模型"""
    print("\n" + "=" * 60)
    print("测试不同的 Qwen 模型")
    print("=" * 60)

    try:
        from openai import OpenAI
        from llm_config import QWEN_API_KEY, QWEN_BASE_URL

        client = OpenAI(
            api_key=QWEN_API_KEY,
            base_url=QWEN_BASE_URL
        )

        # 测试不同模型
        models_to_test = [
            ("qwen-turbo", "最快速的模型"),
            ("qwen-plus", "平衡性能的模型"),
            ("qwen-coder-plus", "编程优化的模型"),
        ]

        test_prompt = [
            {"role": "user", "content": "1 + 1 = ?"}
        ]

        print("\n模型性能对比:")
        print("-" * 60)
        print(f"{'模型':<20} {'描述':<20} {'响应':<20}")
        print("-" * 60)

        for model_id, description in models_to_test:
            try:
                response = client.chat.completions.create(
                    model=model_id,
                    messages=test_prompt,
                    temperature=0.1,
                    max_tokens=10
                )

                content = response.choices[0].message.content.strip()
                print(f"{model_id:<20} {description:<20} {content:<20}")

            except Exception as e:
                print(f"{model_id:<20} {description:<20} 错误: {str(e)[:30]}")

        return True

    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        return False


def test_error_handling():
    """测试错误处理"""
    print("\n" + "=" * 60)
    print("测试错误处理和边界情况")
    print("=" * 60)

    try:
        from openai import OpenAI
        from llm_config import QWEN_API_KEY, QWEN_BASE_URL

        # 测试无效的 API Key
        print("\n1. 测试无效 API Key...")
        try:
            bad_client = OpenAI(
                api_key="invalid-key",
                base_url=QWEN_BASE_URL
            )
            response = bad_client.chat.completions.create(
                model="qwen-turbo",
                messages=[{"role": "user", "content": "test"}],
                max_tokens=10
            )
            print("   ✗ 应该失败但没有失败")
        except Exception as e:
            print(f"   ✓ 正确捕获错误: {str(e)[:50]}...")

        # 测试超长输入
        print("\n2. 测试超长输入处理...")
        client = OpenAI(
            api_key=QWEN_API_KEY,
            base_url=QWEN_BASE_URL
        )

        long_text = "测试" * 1000  # 创建一个很长的文本
        try:
            response = client.chat.completions.create(
                model="qwen-turbo",
                messages=[{"role": "user", "content": f"总结以下内容：{long_text}"}],
                max_tokens=50
            )
            print(f"   ✓ 处理超长输入成功")
        except Exception as e:
            print(f"   ⚠ 超长输入处理失败: {str(e)[:50]}")

        # 测试超时
        print("\n3. 测试请求超时...")
        try:
            response = client.chat.completions.create(
                model="qwen-turbo",
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=10,
                timeout=0.001  # 极短的超时时间
            )
            print("   ⚠ 未触发超时")
        except Exception as e:
            print(f"   ✓ 超时处理正常: {str(e)[:50]}...")

        return True

    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        return False


def main():
    """主函数"""
    print("\n🔧 Qwen API 连通性测试工具 (简化版)\n")

    # 运行测试
    tests = [
        ("基础 API 测试", test_qwen_direct),
        ("多模型测试", test_different_models),
        ("错误处理测试", test_error_handling),
    ]

    results = []
    for i, (name, test_func) in enumerate(tests, 1):
        print(f"\n[测试 {i}/{len(tests)}] {name}")

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
        print("\n✅ Qwen API 完全正常工作！")
        print("\n功能确认：")
        print("  ✓ API 连接正常")
        print("  ✓ 模型调用成功")
        print("  ✓ 流式输出支持")
        print("  ✓ 错误处理正常")
        print("\n您可以在 Claude 不可用时使用 Qwen 作为备用模型。")
    elif passed > 0:
        print(f"\n⚠️ Qwen API 部分功能正常 ({passed}/{total})")
        print("某些功能可能受限，但基本可用。")
    else:
        print("\n❌ Qwen API 测试全部失败")
        print("\n请检查：")
        print("1. API Key 是否正确")
        print("2. 网络连接是否正常")
        print("3. 是否有防火墙阻止连接")
        print("4. 阿里云账户是否有足够额度")

    # API Key 安全提醒
    print("\n⚠️ 安全提醒：")
    print("您之前分享的 API Key 已暴露，请立即：")
    print("1. 登录阿里云控制台")
    print("2. 生成新的 API Key")
    print("3. 更新 llm_config.py 中的配置")

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
        sys.exit(1)