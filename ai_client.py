"""
AI 客户端统一初始化模块
避免在主程序中重复 OpenAI() 初始化代码

使用示例：
    from ai_client import get_ai_client, call_ai

    # 方式1：获取客户端自行调用
    client = get_ai_client()
    response = client.chat.completions.create(...)

    # 方式2：使用封装好的调用函数
    result = call_ai(messages, temperature=0.7, max_tokens=2000)
"""
import os
from typing import List, Dict, Optional
from openai import OpenAI
from config import AI_CONFIG, get_api_key


def get_ai_client(provider: str = "qwen", timeout: int = 60) -> OpenAI:
    """获取 AI 客户端实例

    Args:
        provider: AI 提供商，目前支持 'qwen'
        timeout: 请求超时时间（秒）

    Returns:
        OpenAI 客户端实例

    Raises:
        ValueError: 如果未配置 API Key
    """
    api_key = get_api_key(provider)
    if not api_key:
        raise ValueError(
            f"未设置 {provider.upper()}_API_KEY，无法调用 AI。"
            f"请在 .env 文件中配置相应的 API Key。"
        )

    if provider == "qwen":
        return OpenAI(
            api_key=api_key,
            base_url=AI_CONFIG["qwen_base_url"],
            timeout=timeout
        )
    else:
        raise ValueError(f"不支持的 AI 提供商: {provider}")


def call_ai(
    messages: List[Dict[str, str]],
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    model: Optional[str] = None,
    provider: str = "qwen",
    timeout: int = 60
) -> str:
    """统一的 AI 调用接口

    Args:
        messages: 对话消息列表 [{"role": "user", "content": "..."}]
        temperature: 温度参数，None 则使用默认值
        max_tokens: 最大 token 数，None 则使用默认值
        model: 模型名称，None 则使用配置的默认模型
        provider: AI 提供商
        timeout: 请求超时时间（秒）

    Returns:
        AI 回复的文本内容

    Raises:
        ValueError: 如果未配置 API Key
        Exception: AI 调用失败时抛出原始异常
    """
    client = get_ai_client(provider, timeout)

    # 使用配置的默认值
    if temperature is None:
        temperature = AI_CONFIG["default_temperature"]
    if max_tokens is None:
        max_tokens = AI_CONFIG["default_max_tokens"]
    if model is None:
        model = AI_CONFIG["qwen_model"]

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    return response.choices[0].message.content.strip()


def call_ai_for_summary(content: str, source_type: str = "文档") -> Dict[str, any]:
    """专用于生成资料摘要的 AI 调用

    Args:
        content: 资料内容
        source_type: 资料类型（文档、新闻、技术文章等）

    Returns:
        {
            "summary": "摘要文本",
            "key_topics": ["主题1", "主题2", ...],
            "suggested_questions": ["问题1", "问题2", ...]
        }
    """
    import json

    # 限制内容长度
    content_preview = content[:AI_CONFIG["summary_max_tokens"]] if len(content) > AI_CONFIG["summary_max_tokens"] else content

    prompt = f"""请分析以下{source_type}内容，生成结构化的学习辅助信息。

内容：
{content_preview}

请严格按以下 JSON 格式返回，不要添加任何其他文字或 markdown 标记：
{{
  "summary": "用 2-3 句话概括核心内容",
  "key_topics": ["提取 3-5 个核心主题或关键概念"],
  "suggested_questions": ["生成 5 个适合学习的问题，从浅到深"]
}}

要求：
1. 摘要要简洁准确，突出核心价值
2. 主题要具体明确，便于后续学习
3. 问题要有层次感，覆盖理解、应用、分析等不同层次
4. 仅返回 JSON，不要有任何其他内容"""

    messages = [
        {"role": "system", "content": "你是一位专业的学习内容分析专家。仅返回纯 JSON，不要使用 markdown 代码块。"},
        {"role": "user", "content": prompt}
    ]

    reply = call_ai(
        messages,
        temperature=AI_CONFIG["summary_temperature"],
        max_tokens=AI_CONFIG["summary_max_tokens"]
    )

    # 清理 markdown 代码块标记
    if reply.startswith("```"):
        lines = reply.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        reply = "\n".join(lines)

    try:
        return json.loads(reply)
    except json.JSONDecodeError as e:
        return {
            "summary": f"自动摘要生成失败: {e}",
            "key_topics": [],
            "suggested_questions": []
        }
