"""
Ollama LLM 服务集成
使用本地 GPU 加速的 LLM 进行 CVE 分析
"""
import os
import requests
import json
from typing import List, Dict, Any, Optional
import psycopg2
from psycopg2.extras import execute_values
import numpy as np


class OllamaLLMService:
    """Ollama LLM 服务管理类"""

    def __init__(self, base_url: str = "http://localhost:11434"):
        """初始化 Ollama 服务

        Args:
            base_url: Ollama API 基础 URL
        """
        self.base_url = base_url
        self.embeddings_model = "nomic-embed-text"  # 轻量级嵌入模型
        self.chat_model = "qwen2.5:3b"  # 轻量级聊天模型（适合 940MX）

    def check_connection(self) -> bool:
        """检查 Ollama 服务连接"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def list_models(self) -> List[str]:
        """列出已安装的模型"""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            data = response.json()
            return [model['name'] for model in data.get('models', [])]
        except:
            return []

    def pull_model(self, model_name: str) -> bool:
        """拉取模型

        Args:
            model_name: 模型名称

        Returns:
            是否成功
        """
        try:
            print(f"正在拉取模型: {model_name}...")
            response = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": model_name},
                stream=True
            )

            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    status = data.get('status', '')
                    if 'total' in data and 'completed' in data:
                        progress = (data['completed'] / data['total']) * 100
                        print(f"\r进度: {progress:.1f}%", end='')

            print(f"\n模型 {model_name} 拉取完成")
            return True
        except Exception as e:
            print(f"拉取模型失败: {e}")
            return False

    def generate_embedding(self, text: str) -> Optional[List[float]]:
        """生成文本向量嵌入（GPU 加速）

        Args:
            text: 输入文本

        Returns:
            向量嵌入列表
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/embeddings",
                json={
                    "model": self.embeddings_model,
                    "prompt": text
                }
            )

            if response.status_code == 200:
                data = response.json()
                return data.get('embedding')
            else:
                print(f"生成嵌入失败: {response.text}")
                return None
        except Exception as e:
            print(f"生成嵌入错误: {e}")
            return None

    def batch_generate_embeddings(self, texts: List[str], batch_size: int = 10) -> List[Optional[List[float]]]:
        """批量生成向量嵌入

        Args:
            texts: 文本列表
            batch_size: 批处理大小

        Returns:
            向量嵌入列表
        """
        embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            print(f"处理批次 {i//batch_size + 1}/{(len(texts)-1)//batch_size + 1}")

            for text in batch:
                embedding = self.generate_embedding(text)
                embeddings.append(embedding)

        return embeddings

    def chat(self, prompt: str, system_prompt: Optional[str] = None, stream: bool = False) -> str:
        """与 LLM 对话（GPU 加速推理）

        Args:
            prompt: 用户提示
            system_prompt: 系统提示
            stream: 是否流式输出

        Returns:
            LLM 响应
        """
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.chat_model,
                    "messages": messages,
                    "stream": stream
                }
            )

            if stream:
                full_response = ""
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        content = data.get('message', {}).get('content', '')
                        full_response += content
                        print(content, end='', flush=True)
                print()  # 换行
                return full_response
            else:
                data = response.json()
                return data.get('message', {}).get('content', '')

        except Exception as e:
            print(f"对话错误: {e}")
            return ""

    def analyze_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析 CVE 漏洞（使用 LLM）

        Args:
            cve_data: CVE 数据字典

        Returns:
            分析结果
        """
        cve_id = cve_data.get('cve_id', 'Unknown')
        description = cve_data.get('description', '')
        cvss_score = cve_data.get('cvss_score', 0)

        system_prompt = """你是一个网络安全专家，专注于分析 CVE 漏洞。
请用中文简洁地回答，提供实用的安全建议。"""

        prompt = f"""
请分析以下 CVE 漏洞：

CVE ID: {cve_id}
描述: {description}
CVSS 评分: {cvss_score}

请提供：
1. 漏洞影响范围
2. 潜在风险
3. 建议的缓解措施

请简洁回答（300字以内）。
"""

        analysis = self.chat(prompt, system_prompt)

        return {
            'cve_id': cve_id,
            'analysis': analysis,
            'cvss_score': cvss_score
        }


class VectorDatabaseManager:
    """PostgreSQL + pgvector 向量数据库管理"""

    def __init__(self, db_url: str):
        """初始化数据库连接

        Args:
            db_url: PostgreSQL 连接 URL
        """
        self.db_url = db_url
        self.conn = None

    def connect(self):
        """连接数据库"""
        try:
            self.conn = psycopg2.connect(self.db_url)
            print("[OK] PostgreSQL 连接成功")
            return True
        except Exception as e:
            print(f"[ERROR] PostgreSQL 连接失败: {e}")
            return False

    def close(self):
        """关闭连接"""
        if self.conn:
            self.conn.close()

    def insert_cve_embedding(self, cve_id: str, title: str, description: str,
                            embedding: List[float], severity: str, cvss_score: float,
                            published_date: str):
        """插入 CVE 向量嵌入

        Args:
            cve_id: CVE ID
            title: 标题
            description: 描述
            embedding: 向量嵌入
            severity: 严重程度
            cvss_score: CVSS 评分
            published_date: 发布日期
        """
        try:
            cursor = self.conn.cursor()

            # 转换向量为字符串格式
            embedding_str = '[' + ','.join(map(str, embedding)) + ']'

            cursor.execute("""
                INSERT INTO cve_embeddings
                (cve_id, title, description, embedding, severity, cvss_score, published_date)
                VALUES (%s, %s, %s, %s::vector, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    embedding = EXCLUDED.embedding,
                    severity = EXCLUDED.severity,
                    cvss_score = EXCLUDED.cvss_score,
                    published_date = EXCLUDED.published_date
            """, (cve_id, title, description, embedding_str, severity, cvss_score, published_date))

            self.conn.commit()
        except Exception as e:
            print(f"插入嵌入失败: {e}")
            self.conn.rollback()

    def search_similar_cves(self, query_embedding: List[float], limit: int = 10,
                           threshold: float = 0.7) -> List[Dict[str, Any]]:
        """搜索相似的 CVE

        Args:
            query_embedding: 查询向量
            limit: 返回数量
            threshold: 相似度阈值

        Returns:
            相似 CVE 列表
        """
        try:
            cursor = self.conn.cursor()

            embedding_str = '[' + ','.join(map(str, query_embedding)) + ']'

            cursor.execute("""
                SELECT * FROM search_similar_cves(%s::vector, %s, %s)
            """, (embedding_str, threshold, limit))

            results = []
            for row in cursor.fetchall():
                results.append({
                    'cve_id': row[0],
                    'title': row[1],
                    'description': row[2],
                    'similarity': row[3],
                    'severity': row[4],
                    'cvss_score': row[5],
                    'published_date': str(row[6])
                })

            return results
        except Exception as e:
            print(f"搜索失败: {e}")
            return []


# 测试代码
if __name__ == "__main__":
    # 初始化 Ollama 服务
    ollama = OllamaLLMService(base_url="http://localhost:11434")

    # 检查连接
    if ollama.check_connection():
        print("[OK] Ollama 服务连接成功")

        # 列出模型
        models = ollama.list_models()
        print(f"\n已安装的模型: {models}")

        # 如果没有嵌入模型，拉取
        if ollama.embeddings_model not in models:
            print(f"\n拉取嵌入模型: {ollama.embeddings_model}")
            ollama.pull_model(ollama.embeddings_model)

        # 如果没有聊天模型，拉取
        if ollama.chat_model not in models:
            print(f"\n拉取聊天模型: {ollama.chat_model}")
            ollama.pull_model(ollama.chat_model)

        # 测试嵌入生成
        print("\n测试向量嵌入生成...")
        test_text = "SQL injection vulnerability in web application"
        embedding = ollama.generate_embedding(test_text)

        if embedding:
            print(f"嵌入维度: {len(embedding)}")
            print(f"嵌入前5个值: {embedding[:5]}")

        # 测试 CVE 分析
        print("\n测试 CVE 分析...")
        test_cve = {
            'cve_id': 'CVE-2024-0001',
            'description': 'A SQL injection vulnerability exists in the login form of the application',
            'cvss_score': 8.5
        }

        analysis = ollama.analyze_cve(test_cve)
        print(f"\nCVE 分析结果:")
        print(f"CVE ID: {analysis['cve_id']}")
        print(f"分析: {analysis['analysis']}")

    else:
        print("[ERROR] Ollama 服务未运行")
        print("请先启动 Ollama 服务:")
        print("  docker-compose -f docker-compose-gpu.yml up -d ollama")
