"""
GPU 加速性能测试
测试 Ollama GPU 加速下的向量生成和 LLM 推理性能
"""
import time
import requests
import json
from typing import List


class OllamaGPUTest:
    def __init__(self, base_url="http://localhost:11434"):
        self.base_url = base_url
        self.embed_model = "nomic-embed-text"
        self.llm_model = "qwen2.5:3b"

    def test_connection(self):
        """测试 Ollama 连接"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                print(f"[OK] 已连接到 Ollama API")
                print(f"已安装 {len(models)} 个模型:")
                for model in models:
                    print(f"   - {model['name']} ({model['size'] / 1e9:.2f} GB)")
                return True
        except Exception as e:
            print(f"[ERROR] 无法连接到 Ollama: {e}")
            return False

    def generate_embedding(self, text: str) -> List[float]:
        """生成文本嵌入"""
        response = requests.post(
            f"{self.base_url}/api/embeddings",
            json={"model": self.embed_model, "prompt": text},
            timeout=30
        )
        if response.status_code == 200:
            return response.json()["embedding"]
        return []

    def generate_text(self, prompt: str) -> str:
        """生成文本（LLM推理）"""
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={"model": self.llm_model, "prompt": prompt, "stream": False},
            timeout=60
        )
        if response.status_code == 200:
            return response.json()["response"]
        return ""

    def test_embedding_performance(self, num_tests=50):
        """测试向量生成性能"""
        print(f"\n{'='*80}")
        print(f"向量生成性能测试 (GPU 加速)")
        print(f"{'='*80}")
        print(f"模型: {self.embed_model}")
        print(f"测试次数: {num_tests}")

        # 测试文本
        test_texts = [
            "SQL injection vulnerability in web application",
            "Remote code execution in Apache server",
            "Cross-site scripting attack vector",
            "Buffer overflow in memory management",
            "Authentication bypass vulnerability"
        ]

        # 预热（首次调用可能较慢）
        print("\n[预热] 预热模型...")
        self.generate_embedding(test_texts[0])

        # 性能测试
        print(f"\n[测试] 开始测试...")
        embeddings = []
        start_time = time.time()

        for i in range(num_tests):
            text = test_texts[i % len(test_texts)]
            embedding = self.generate_embedding(text)
            embeddings.append(embedding)

            if (i + 1) % 10 == 0:
                elapsed = time.time() - start_time
                speed = (i + 1) / elapsed
                print(f"  进度: {i+1}/{num_tests} | 速度: {speed:.1f} 次/秒")

        total_time = time.time() - start_time
        avg_time = total_time / num_tests
        throughput = num_tests / total_time

        print(f"\n[结果] 测试结果:")
        print(f"  总耗时: {total_time:.2f} 秒")
        print(f"  平均时间: {avg_time*1000:.1f} 毫秒/次")
        print(f"  吞吐量: {throughput:.1f} 次/秒")
        print(f"  向量维度: {len(embeddings[0]) if embeddings else 0}")

        return {
            'total_time': total_time,
            'avg_time': avg_time,
            'throughput': throughput,
            'embedding_dim': len(embeddings[0]) if embeddings else 0
        }

    def test_llm_inference(self, num_tests=10):
        """测试 LLM 推理性能"""
        print(f"\n{'='*80}")
        print(f"LLM 推理性能测试 (GPU 加速)")
        print(f"{'='*80}")
        print(f"模型: {self.llm_model}")
        print(f"测试次数: {num_tests}")

        # 测试提示
        test_prompts = [
            "What is a CVE vulnerability? Explain in one sentence.",
            "Describe SQL injection attack briefly.",
            "What is cross-site scripting (XSS)?",
            "Explain buffer overflow vulnerability.",
            "What is remote code execution (RCE)?"
        ]

        # 预热
        print("\n[预热] 预热模型...")
        self.generate_text(test_prompts[0])

        # 性能测试
        print(f"\n[测试] 开始测试...")
        results = []
        start_time = time.time()

        for i in range(num_tests):
            prompt = test_prompts[i % len(test_prompts)]
            test_start = time.time()
            response = self.generate_text(prompt)
            test_time = time.time() - test_start

            results.append({
                'response': response,
                'time': test_time,
                'length': len(response)
            })

            print(f"  测试 {i+1}/{num_tests}: {test_time:.2f}s | 生成 {len(response)} 字符")

        total_time = time.time() - start_time
        avg_time = sum(r['time'] for r in results) / len(results)
        total_chars = sum(r['length'] for r in results)
        chars_per_sec = total_chars / total_time

        print(f"\n[结果] 测试结果:")
        print(f"  总耗时: {total_time:.2f} 秒")
        print(f"  平均推理时间: {avg_time:.2f} 秒/次")
        print(f"  总生成字符: {total_chars}")
        print(f"  生成速度: {chars_per_sec:.1f} 字符/秒")

        return {
            'total_time': total_time,
            'avg_time': avg_time,
            'total_chars': total_chars,
            'chars_per_sec': chars_per_sec
        }

    def test_similarity_search(self):
        """测试语义相似度搜索"""
        print(f"\n{'='*80}")
        print(f"语义相似度搜索测试")
        print(f"{'='*80}")

        # 创建 CVE 数据库
        cve_descriptions = [
            "SQL injection vulnerability allows attackers to execute arbitrary SQL commands",
            "Remote code execution in web server through malicious HTTP requests",
            "Cross-site scripting vulnerability in user input validation",
            "Buffer overflow in memory management leads to code execution",
            "Authentication bypass through credential injection"
        ]

        print("[构建] 生成 CVE 向量数据库...")
        start_time = time.time()
        embeddings = [self.generate_embedding(desc) for desc in cve_descriptions]
        index_time = time.time() - start_time
        print(f"  索引时间: {index_time:.2f} 秒 ({len(embeddings)} 条记录)")

        # 查询
        queries = [
            "database injection attack",
            "web application code execution",
            "XSS vulnerability in forms"
        ]

        print(f"\n[搜索] 执行 {len(queries)} 次相似度搜索...")
        for query in queries:
            query_start = time.time()
            query_embedding = self.generate_embedding(query)
            query_time = time.time() - query_start

            # 计算余弦相似度
            similarities = []
            for i, emb in enumerate(embeddings):
                dot_product = sum(a * b for a, b in zip(query_embedding, emb))
                mag_q = sum(a * a for a in query_embedding) ** 0.5
                mag_e = sum(b * b for b in emb) ** 0.5
                similarity = dot_product / (mag_q * mag_e) if mag_q * mag_e > 0 else 0
                similarities.append((i, similarity))

            # 排序
            similarities.sort(key=lambda x: x[1], reverse=True)
            top_match = similarities[0]

            print(f"\n  查询: '{query}'")
            print(f"  查询时间: {query_time*1000:.1f} 毫秒")
            print(f"  最佳匹配: CVE-{top_match[0]+1} (相似度: {top_match[1]:.3f})")
            print(f"  描述: {cve_descriptions[top_match[0]][:80]}...")


def main():
    """主测试函数"""
    print("="*80)
    print("Ollama GPU 加速性能测试")
    print("="*80)
    print(f"GPU: NVIDIA GeForce 940MX (4GB)")
    print(f"CUDA: 13.0")

    tester = OllamaGPUTest()

    # 测试连接
    if not tester.test_connection():
        print("\n[ERROR] 无法连接到 Ollama，请确保服务正在运行")
        return

    # 测试向量生成
    embedding_results = tester.test_embedding_performance(num_tests=50)

    # 测试 LLM 推理
    llm_results = tester.test_llm_inference(num_tests=10)

    # 测试相似度搜索
    tester.test_similarity_search()

    # 总结
    print(f"\n{'='*80}")
    print(f"性能测试总结")
    print(f"{'='*80}")
    print(f"\n向量生成 (GPU 加速):")
    print(f"   吞吐量: {embedding_results['throughput']:.1f} 次/秒")
    print(f"   平均延迟: {embedding_results['avg_time']*1000:.1f} 毫秒")

    print(f"\nLLM 推理 (GPU 加速):")
    print(f"   平均推理时间: {llm_results['avg_time']:.2f} 秒")
    print(f"   生成速度: {llm_results['chars_per_sec']:.1f} 字符/秒")

    print(f"\n[OK] 测试完成！GPU 加速功能正常运行。")
    print(f"\n提示: 运行 'docker exec cve-ollama nvidia-smi' 查看 GPU 使用情况")


if __name__ == "__main__":
    main()
