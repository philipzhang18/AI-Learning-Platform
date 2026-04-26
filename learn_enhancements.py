"""
智能学习增强功能模块
实现 NotebookLM 风格的学习辅助功能
"""
import json
import re
from typing import Dict, List, Tuple, Optional
from openai import OpenAI


class LearnEnhancer:
    """学习增强功能类"""

    def __init__(self, api_key: str, model: str = "qwen3.6-plus",
                 base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model

    def generate_auto_summary(self, content: str, source_type: str = "文档") -> Dict[str, any]:
        """
        生成资料的自动摘要、主题提炼和关键问题建议

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
        # 限制内容长度
        content_preview = content[:3000] if len(content) > 3000 else content

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

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一位专业的学习内容分析专家。仅返回纯 JSON，不要使用 markdown 代码块。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500,
            )
            reply = response.choices[0].message.content.strip()

            # 清理 markdown 代码块标记
            if reply.startswith("```"):
                lines = reply.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                reply = "\n".join(lines)

            result = json.loads(reply)
            return result
        except Exception as e:
            return {
                "summary": f"自动摘要生成失败: {e}",
                "key_topics": [],
                "suggested_questions": []
            }

    def add_source_citations(self, ai_response: str, source_content: str) -> str:
        """
        为 AI 回答添加来源引用标记

        Args:
            ai_response: AI 的原始回答
            source_content: 源资料内容

        Returns:
            带引用标记的回答文本
        """
        # 这是一个简化实现，实际应该使用更复杂的匹配算法
        # 在实际应用中，可以在 AI 生成时就要求其标注引用
        return ai_response + "\n\n📚 本回答基于您提供的学习资料生成"

    def generate_learning_artifacts(self, conversation: List[Dict],
                                   topic: str, artifact_type: str) -> Dict[str, str]:
        """
        生成学习产物（时间线、脑图、学习指南、FAQ）

        Args:
            conversation: 对话历史
            topic: 学习主题
            artifact_type: 产物类型 (timeline/mindmap/guide/faq)

        Returns:
            {"title": "标题", "content": "内容", "format": "格式"}
        """
        # 提取对话内容
        conv_text = ""
        for msg in conversation:
            if msg.get("role") in ("user", "assistant"):
                role_label = "学习者" if msg["role"] == "user" else "导师"
                conv_text += f"{role_label}: {msg['content']}\n\n"

        conv_text = conv_text[:4000]  # 限制长度

        prompts = {
            "timeline": f"""基于以下关于「{topic}」的学习对话，生成学习时间线。

对话内容：
{conv_text}

请生成一个 Markdown 格式的学习时间线，包含：
1. 学习的主要阶段（按时间顺序）
2. 每个阶段的关键理解和突破
3. 遇到的困难和解决方法
4. 知识点之间的递进关系

格式示例：
## 学习时间线：{topic}

### 阶段 1：初步理解（第 1-2 轮对话）
- 🎯 目标：理解基本概念
- 💡 关键突破：...
- 🤔 困惑点：...

### 阶段 2：深入探索（第 3-4 轮对话）
...

仅返回 Markdown 内容，不要有其他说明。""",

            "mindmap": f"""基于以下关于「{topic}」的学习对话，生成思维导图。

对话内容：
{conv_text}

请生成一个 Mermaid 格式的思维导图，展示：
1. 核心概念及其层次结构
2. 概念之间的关系
3. 关键知识点

格式示例：
```mermaid
mindmap
  root(({topic}))
    核心概念1
      子概念1.1
      子概念1.2
    核心概念2
      子概念2.1
      子概念2.2
```

仅返回 Mermaid 代码，不要有其他说明。""",

            "guide": f"""基于以下关于「{topic}」的学习对话，生成学习指南。

对话内容：
{conv_text}

请生成一个结构化的学习指南，包含：
1. 学习目标
2. 前置知识
3. 核心概念清单
4. 学习路径（分步骤）
5. 实践建议
6. 进阶方向

使用 Markdown 格式，清晰易读。仅返回内容，不要有其他说明。""",

            "faq": f"""基于以下关于「{topic}」的学习对话，生成常见问题解答（FAQ）。

对话内容：
{conv_text}

请生成 5-8 个常见问题及其解答，包含：
1. 基础概念问题
2. 常见误解
3. 实际应用问题
4. 进阶问题

格式示例：
## 常见问题解答：{topic}

### Q1: [问题]
**A:** [简洁的回答]

### Q2: [问题]
**A:** [简洁的回答]

仅返回 Markdown 内容，不要有其他说明。"""
        }

        prompt = prompts.get(artifact_type, prompts["guide"])

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一位专业的学习内容组织专家，擅长将学习对话转化为结构化的学习资料。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=3000,
            )
            content = response.choices[0].message.content.strip()

            titles = {
                "timeline": f"学习时间线：{topic}",
                "mindmap": f"思维导图：{topic}",
                "guide": f"学习指南：{topic}",
                "faq": f"常见问题：{topic}"
            }

            return {
                "title": titles.get(artifact_type, f"学习产物：{topic}"),
                "content": content,
                "format": "mermaid" if artifact_type == "mindmap" else "markdown"
            }
        except Exception as e:
            return {
                "title": f"生成失败：{artifact_type}",
                "content": f"生成学习产物时出错：{e}",
                "format": "text"
            }

    def generate_podcast_with_citations(self, content: str, topic: str) -> Tuple[str, List[Dict]]:
        """
        生成带来源追踪的对话式播客脚本

        Args:
            content: 资料内容
            topic: 主题

        Returns:
            (脚本文本, 引用列表)
        """
        content_preview = content[:3000] if len(content) > 3000 else content

        prompt = f"""基于以下关于「{topic}」的资料，生成一段双人对话式播客脚本。

资料内容：
{content_preview}

要求：
1. 对话要自然流畅，像真实的播客节目
2. 主持人 A（提问者）和主持人 B（讲解者）
3. 时长约 3-5 分钟（约 800-1200 字）
4. 用通俗易懂的语言解释技术概念
5. 在关键信息后标注 [来源] 标记

格式示例：
主持人 A：大家好，欢迎来到今天的节目。今天我们要聊聊{topic}。

主持人 B：是的，这是一个很重要的话题。[来源] 根据资料显示...

仅返回对话脚本，不要有其他说明。"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一位专业的播客脚本作者，擅长将技术内容转化为轻松易懂的对话。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000,
            )
            script = response.choices[0].message.content.strip()

            # 提取引用标记
            citations = []
            citation_pattern = r'\[来源\]'
            matches = list(re.finditer(citation_pattern, script))
            for i, match in enumerate(matches):
                citations.append({
                    "index": i + 1,
                    "position": match.start(),
                    "source": "学习资料"
                })

            return script, citations
        except Exception as e:
            return f"生成播客脚本失败：{e}", []

    def enhance_system_prompt_with_citations(self, base_prompt: str, source_content: str) -> str:
        """
        增强系统提示词，要求 AI 标注来源引用

        Args:
            base_prompt: 原始系统提示词
            source_content: 源资料内容（用于上下文）

        Returns:
            增强后的系统提示词
        """
        citation_instruction = """

【重要约束】
1. 你的回答必须严格基于用户提供的学习资料，不要引入资料之外的信息
2. 当引用资料中的具体信息时，在句子末尾添加 [📚] 标记
3. 如果用户的问题无法从资料中找到答案，明确告知"资料中未提及此内容"
4. 保持回答的准确性和可追溯性，这是费曼学习法的核心要求"""

        return base_prompt + citation_instruction
