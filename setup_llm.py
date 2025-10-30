#!/usr/bin/env python3
"""
LLM API 集成安装和配置脚本
帮助用户快速设置 Claude 和 Qwen API 集成
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def print_header(text):
    """打印标题"""
    print("\n" + "=" * 60)
    print(text.center(60))
    print("=" * 60)


def check_python_version():
    """检查 Python 版本"""
    print("\n检查 Python 版本...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"✗ Python 版本过低: {sys.version}")
        print("  需要 Python 3.7 或更高版本")
        return False
    print(f"✓ Python 版本: {sys.version}")
    return True


def install_dependencies():
    """安装依赖包"""
    print("\n安装依赖包...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements_llm.txt"
        ])
        print("✓ 依赖包安装成功")
        return True
    except subprocess.CalledProcessError:
        print("✗ 依赖包安装失败")
        print("  请手动运行: pip install -r requirements_llm.txt")
        return False


def setup_config():
    """设置配置文件"""
    print("\n设置配置文件...")

    # 检查是否已存在配置
    if os.path.exists("llm_config.py"):
        response = input("配置文件已存在，是否覆盖？(y/n): ").strip().lower()
        if response != 'y':
            print("跳过配置文件设置")
            return True

    print("\n请输入 API 密钥（直接回车跳过）：")

    # 获取 Claude API Key
    claude_key = input("Claude API Key: ").strip()
    if not claude_key:
        claude_key = "your-claude-api-key"
        print("  使用占位符，请稍后在 llm_config.py 中配置")

    # 获取 Qwen API Key
    qwen_key = input("Qwen API Key (sk-xxx): ").strip()
    if not qwen_key:
        qwen_key = "sk-your-qwen-api-key"
        print("  使用占位符，请稍后在 llm_config.py 中配置")

    # 选择默认模型
    print("\n选择默认模型提供商：")
    print("  1. Claude (Anthropic)")
    print("  2. Qwen (阿里云)")
    choice = input("请选择 (1/2) [默认: 1]: ").strip()

    if choice == "2":
        default_provider = "qwen"
    else:
        default_provider = "claude"

    # 生成配置文件
    config_content = f"""# LLM API 集成配置
# 警告：请勿将真实 API Key 提交到版本控制系统

# Claude API 配置
CLAUDE_API_KEY = "{claude_key}"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL = "claude-3-opus-20240229"

# Qwen API 配置（阿里云百炼）
QWEN_API_KEY = "{qwen_key}"
QWEN_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
QWEN_MODEL = "qwen-coder-plus"

# 系统配置
DEFAULT_MODEL_PROVIDER = "{default_provider}"
AUTO_FALLBACK = True  # 当主模型失败时自动切换到备用模型
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_DELAY = 2

# 日志配置
LOG_LEVEL = "INFO"
LOG_FILE = "llm_api.log"
"""

    try:
        with open("llm_config.py", "w", encoding="utf-8") as f:
            f.write(config_content)
        print("✓ 配置文件创建成功: llm_config.py")
        return True
    except Exception as e:
        print(f"✗ 配置文件创建失败: {e}")
        return False


def test_connection():
    """测试 API 连接"""
    print("\n测试 API 连接...")

    try:
        from llm_api_client import create_client

        client = create_client()
        providers = client.get_available_providers()

        if not providers:
            print("✗ 没有可用的模型提供商")
            print("  请检查 API 密钥配置")
            return False

        print(f"✓ 可用的模型提供商: {', '.join(providers)}")

        # 测试每个提供商
        for provider in providers:
            print(f"\n测试 {provider}...")
            if client.test_connection(provider):
                print(f"  ✓ {provider} 连接成功")
            else:
                print(f"  ✗ {provider} 连接失败")

        return True

    except ImportError:
        print("✗ 无法导入 llm_api_client 模块")
        return False
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        return False


def run_example():
    """运行示例程序"""
    print("\n是否运行示例程序？")
    response = input("运行示例 (y/n) [默认: n]: ").strip().lower()

    if response == 'y':
        try:
            subprocess.call([sys.executable, "llm_examples.py"])
        except Exception as e:
            print(f"运行示例失败: {e}")


def main():
    """主函数"""
    print_header("LLM API 集成安装程序")

    steps = [
        ("检查 Python 版本", check_python_version),
        ("安装依赖包", install_dependencies),
        ("设置配置文件", setup_config),
        ("测试 API 连接", test_connection),
    ]

    success = True
    for step_name, step_func in steps:
        print(f"\n步骤: {step_name}")
        print("-" * 40)
        if not step_func():
            success = False
            print(f"\n⚠️  {step_name} 失败")
            response = input("是否继续？(y/n): ").strip().lower()
            if response != 'y':
                break

    if success:
        print_header("安装完成")
        print("\n✅ 所有步骤都已成功完成！")
        print("\n下一步：")
        print("1. 编辑 llm_config.py 配置您的 API 密钥")
        print("2. 运行 python llm_examples.py 查看示例")
        print("3. 在您的代码中导入并使用:")
        print("   from llm_api_client import chat_with_llm")
        print("   response = chat_with_llm('你的问题')")

        run_example()
    else:
        print_header("安装未完成")
        print("\n⚠️  部分步骤失败，请手动完成配置")
        print("\n故障排除：")
        print("1. 确保 Python >= 3.7")
        print("2. 手动安装依赖: pip install -r requirements_llm.txt")
        print("3. 复制 .env.llm.example 为 .env 并填入 API 密钥")
        print("4. 查看 README_LLM.md 获取详细说明")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n安装被用户取消")
    except Exception as e:
        print(f"\n安装出错: {e}")
        sys.exit(1)