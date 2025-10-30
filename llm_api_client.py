"""
LLM API 集成模块 - 支持 Claude 和 Qwen 模型
实现了自动故障切换和重试机制
"""

import os
import json
import time
import logging
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from enum import Enum
import requests
from openai import OpenAI

# 导入配置
try:
    from llm_config import *
except ImportError:
    print("警告：未找到 llm_config.py，使用默认配置")
    CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
    QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")
    QWEN_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    DEFAULT_MODEL_PROVIDER = "claude"
    AUTO_FALLBACK = True
    TIMEOUT_SECONDS = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    LOG_LEVEL = "INFO"
    LOG_FILE = "llm_api.log"

# 配置日志
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ModelProvider(Enum):
    """模型提供商枚举"""
    CLAUDE = "claude"
    QWEN = "qwen"


@dataclass
class Message:
    """消息数据类"""
    role: str  # "user", "assistant", "system"
    content: str


@dataclass
class ModelResponse:
    """模型响应数据类"""
    content: str
    provider: ModelProvider
    model: str
    usage: Optional[Dict[str, int]] = None
    error: Optional[str] = None


class ClaudeAPI:
    """Claude API 客户端"""

    def __init__(self, api_key: str = None):
        """初始化 Claude API 客户端"""
        self.api_key = api_key or CLAUDE_API_KEY
        if not self.api_key:
            raise ValueError("Claude API key 未配置")

        # 延迟导入，避免未安装 anthropic 时阻塞仅使用 Qwen 的场景
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            raise ImportError("未安装 anthropic 库，Claude 客户端不可用。若仅使用 Qwen 可忽略，或 pip install anthropic") from e

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = CLAUDE_MODEL if 'CLAUDE_MODEL' in globals() else "claude-3-opus-20240229"
        logger.info("Claude API 客户端初始化成功")

    def chat(self, messages: List[Message], **kwargs) -> ModelResponse:
        """发送聊天请求到 Claude"""
        try:
            # 转换消息格式
            formatted_messages = []
            system_message = None

            for msg in messages:
                if msg.role == "system":
                    system_message = msg.content
                else:
                    formatted_messages.append({
                        "role": msg.role,
                        "content": msg.content
                    })

            # 调用 Claude API
            response = self.client.messages.create(
                model=self.model,
                messages=formatted_messages,
                system=system_message,
                max_tokens=kwargs.get("max_tokens", 4096),
                temperature=kwargs.get("temperature", 0.7),
                timeout=TIMEOUT_SECONDS
            )

            # 构建响应
            return ModelResponse(
                content=response.content[0].text if response.content else "",
                provider=ModelProvider.CLAUDE,
                model=self.model,
                usage={
                    "input_tokens": response.usage.input_tokens if hasattr(response, 'usage') else 0,
                    "output_tokens": response.usage.output_tokens if hasattr(response, 'usage') else 0
                }
            )

        except Exception as e:
            logger.error(f"Claude API 调用失败: {str(e)}")
            return ModelResponse(
                content="",
                provider=ModelProvider.CLAUDE,
                model=self.model,
                error=str(e)
            )


class QwenAPI:
    """Qwen API 客户端（通过 OpenAI 兼容接口）"""

    def __init__(self, api_key: str = None, base_url: str = None):
        """初始化 Qwen API 客户端"""
        self.api_key = api_key or QWEN_API_KEY
        self.base_url = base_url or QWEN_BASE_URL

        if not self.api_key:
            raise ValueError("Qwen API key 未配置")

        # 使用 OpenAI 客户端连接到 Qwen
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )
        self.model = QWEN_MODEL if 'QWEN_MODEL' in globals() else "qwen-coder-plus"
        logger.info("Qwen API 客户端初始化成功")

    def chat(self, messages: List[Message], **kwargs) -> ModelResponse:
        """发送聊天请求到 Qwen"""
        try:
            # 转换消息格式
            formatted_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            # 调用 Qwen API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=formatted_messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 4096),
                stream=False,
                timeout=TIMEOUT_SECONDS
            )

            # 构建响应
            return ModelResponse(
                content=response.choices[0].message.content,
                provider=ModelProvider.QWEN,
                model=self.model,
                usage={
                    "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "output_tokens": response.usage.completion_tokens if response.usage else 0,
                    "total_tokens": response.usage.total_tokens if response.usage else 0
                }
            )

        except Exception as e:
            logger.error(f"Qwen API 调用失败: {str(e)}")
            return ModelResponse(
                content="",
                provider=ModelProvider.QWEN,
                model=self.model,
                error=str(e)
            )


class LLMClient:
    """统一的 LLM 客户端，支持自动故障切换"""

    def __init__(
        self,
        primary_provider: str = None,
        auto_fallback: bool = None,
        claude_api_key: str = None,
        qwen_api_key: str = None
    ):
        """
        初始化 LLM 客户端

        Args:
            primary_provider: 主要模型提供商 ("claude" 或 "qwen")
            auto_fallback: 是否自动切换到备用模型
            claude_api_key: Claude API 密钥
            qwen_api_key: Qwen API 密钥
        """
        self.primary_provider = ModelProvider(primary_provider or DEFAULT_MODEL_PROVIDER)
        self.auto_fallback = auto_fallback if auto_fallback is not None else AUTO_FALLBACK

        # 初始化 API 客户端
        self.claude_client = None
        self.qwen_client = None

        # 尝试初始化 Claude 客户端
        try:
            self.claude_client = ClaudeAPI(claude_api_key)
            logger.info("Claude 客户端已就绪")
        except Exception as e:
            logger.warning(f"Claude 客户端初始化失败: {e}")

        # 尝试初始化 Qwen 客户端
        try:
            self.qwen_client = QwenAPI(qwen_api_key)
            logger.info("Qwen 客户端已就绪")
        except Exception as e:
            logger.warning(f"Qwen 客户端初始化失败: {e}")

        # 检查至少有一个客户端可用
        if not self.claude_client and not self.qwen_client:
            raise RuntimeError("没有可用的 LLM 客户端")

    def _get_client(self, provider: ModelProvider):
        """获取指定提供商的客户端"""
        if provider == ModelProvider.CLAUDE:
            return self.claude_client
        elif provider == ModelProvider.QWEN:
            return self.qwen_client
        return None

    def _retry_with_backoff(self, func, *args, **kwargs):
        """带有退避的重试机制"""
        for attempt in range(MAX_RETRIES):
            try:
                result = func(*args, **kwargs)
                if result and not result.error:
                    return result

                # 如果有错误，记录并重试
                if result and result.error:
                    logger.warning(f"尝试 {attempt + 1}/{MAX_RETRIES} 失败: {result.error}")

            except Exception as e:
                logger.warning(f"尝试 {attempt + 1}/{MAX_RETRIES} 发生异常: {e}")

            # 退避延迟
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))

        return None

    def chat(
        self,
        messages: Union[List[Message], List[Dict[str, str]]],
        provider: Optional[str] = None,
        **kwargs
    ) -> ModelResponse:
        """
        发送聊天请求

        Args:
            messages: 消息列表
            provider: 指定使用的模型提供商（可选）
            **kwargs: 其他参数（temperature, max_tokens 等）

        Returns:
            ModelResponse: 模型响应
        """
        # 转换消息格式
        if messages and isinstance(messages[0], dict):
            messages = [Message(role=m["role"], content=m["content"]) for m in messages]

        # 确定使用的提供商
        use_provider = ModelProvider(provider) if provider else self.primary_provider

        # 尝试使用主要提供商
        primary_client = self._get_client(use_provider)
        if primary_client:
            logger.info(f"使用 {use_provider.value} 模型")
            response = self._retry_with_backoff(primary_client.chat, messages, **kwargs)

            if response and not response.error:
                return response

            logger.warning(f"{use_provider.value} 模型调用失败")

        # 如果启用了自动故障切换，尝试备用提供商
        if self.auto_fallback:
            fallback_provider = (
                ModelProvider.QWEN if use_provider == ModelProvider.CLAUDE
                else ModelProvider.CLAUDE
            )

            fallback_client = self._get_client(fallback_provider)
            if fallback_client:
                logger.info(f"切换到备用模型: {fallback_provider.value}")
                response = self._retry_with_backoff(fallback_client.chat, messages, **kwargs)

                if response and not response.error:
                    logger.info(f"备用模型 {fallback_provider.value} 调用成功")
                    return response

        # 所有尝试都失败
        error_msg = "所有模型提供商都不可用"
        logger.error(error_msg)
        return ModelResponse(
            content="",
            provider=use_provider,
            model="",
            error=error_msg
        )

    def stream_chat(
        self,
        messages: Union[List[Message], List[Dict[str, str]]],
        provider: Optional[str] = None,
        **kwargs
    ):
        """
        流式聊天（生成器）

        注意：当前实现为简化版本，后续可以添加真正的流式支持
        """
        response = self.chat(messages, provider, **kwargs)

        if response.error:
            yield f"错误: {response.error}"
        else:
            # 模拟流式输出
            words = response.content.split()
            for i in range(0, len(words), 5):
                chunk = " ".join(words[i:i+5])
                yield chunk + " "
                time.sleep(0.05)  # 模拟延迟

    def get_available_providers(self) -> List[str]:
        """获取可用的模型提供商列表"""
        available = []
        if self.claude_client:
            available.append("claude")
        if self.qwen_client:
            available.append("qwen")
        return available

    def test_connection(self, provider: Optional[str] = None) -> bool:
        """
        测试与模型提供商的连接

        Args:
            provider: 要测试的提供商，None 表示测试所有

        Returns:
            bool: 连接是否成功
        """
        test_message = [Message(role="user", content="Hello, please respond with 'OK'")]

        if provider:
            response = self.chat(test_message, provider=provider, max_tokens=10)
            return not response.error
        else:
            # 测试所有提供商
            results = {}
            for p in [ModelProvider.CLAUDE, ModelProvider.QWEN]:
                client = self._get_client(p)
                if client:
                    response = client.chat(test_message, max_tokens=10)
                    results[p.value] = not response.error

            logger.info(f"连接测试结果: {results}")
            return any(results.values())


# 便捷函数
def create_client(
    primary: str = "claude",
    auto_fallback: bool = True
) -> LLMClient:
    """
    创建 LLM 客户端的便捷函数

    Args:
        primary: 主要使用的模型 ("claude" 或 "qwen")
        auto_fallback: 是否启用自动故障切换

    Returns:
        LLMClient: 配置好的 LLM 客户端
    """
    return LLMClient(
        primary_provider=primary,
        auto_fallback=auto_fallback
    )


def chat_with_llm(
    prompt: str,
    system_prompt: str = None,
    provider: str = None,
    **kwargs
) -> str:
    """
    快速聊天函数

    Args:
        prompt: 用户输入
        system_prompt: 系统提示（可选）
        provider: 指定模型提供商（可选）
        **kwargs: 其他参数

    Returns:
        str: 模型回复
    """
    client = create_client()

    messages = []
    if system_prompt:
        messages.append(Message(role="system", content=system_prompt))
    messages.append(Message(role="user", content=prompt))

    response = client.chat(messages, provider=provider, **kwargs)

    if response.error:
        return f"错误: {response.error}"

    return response.content


if __name__ == "__main__":
    # 测试代码
    print("正在测试 LLM API 集成...")

    # 创建客户端
    try:
        client = create_client(primary="claude", auto_fallback=True)
        print(f"可用的模型提供商: {client.get_available_providers()}")

        # 测试连接
        print("\n测试连接...")
        if client.test_connection():
            print("✓ 连接测试成功")
        else:
            print("✗ 连接测试失败")

        # 测试聊天
        print("\n测试聊天功能...")
        response = client.chat([
            Message(role="system", content="你是一个有帮助的助手"),
            Message(role="user", content="请用一句话介绍自己")
        ])

        if response.error:
            print(f"✗ 聊天失败: {response.error}")
        else:
            print(f"✓ 聊天成功")
            print(f"  提供商: {response.provider.value}")
            print(f"  模型: {response.model}")
            print(f"  回复: {response.content[:100]}...")
            if response.usage:
                print(f"  Token 使用: {response.usage}")

    except Exception as e:
        print(f"✗ 测试失败: {e}")