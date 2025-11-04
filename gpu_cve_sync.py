"""
GPU 加速 CVE 数据同步脚本
从 SQLite/Redis 读取 CVE 数据，使用 Ollama GPU 加速生成向量，保存到 PostgreSQL
"""
import sys
import time
from pathlib import Path
from typing import List, Dict
from ollama_llm_service import OllamaLLMService, VectorDatabaseManager
from hybrid_data_manager import HybridDataManager

# 设置输出编码
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def print_progress_bar(current, total, prefix='', suffix='', length=50):
    """打印进度条"""
    percent = ("{0:.1f}").format(100 * (current / float(total)))
    filled_length = int(length * current // total)
    bar = '=' * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if current == total:
        print()


class GPUCVESync:
    """GPU 加速 CVE 数据同步器"""

    def __init__(
        self,
        sqlite_db_path: str = "cve_data/cve_database.db",
        redis_password: str = "defaultpassword",
        postgres_url: str = "postgresql://admin:defaultpassword@localhost:5432/cve_vectors",
        ollama_url: str = "http://localhost:11434"
    ):
        """初始化同步器"""
        self.sqlite_db_path = sqlite_db_path
        self.redis_password = redis_password

        # 初始化服务
        print("[初始化] 连接到各个服务...")
        self.ollama = OllamaLLMService(base_url=ollama_url)
        self.vector_db = VectorDatabaseManager(postgres_url)
        self.hybrid_manager = HybridDataManager(sqlite_db_path, redis_password=redis_password)

        # 检查连接
        if not self.ollama.check_connection():
            raise Exception("无法连接到 Ollama 服务，请确保容器正在运行")

        if not self.vector_db.connect():
            raise Exception("无法连接到 PostgreSQL 向量数据库")

        print("[OK] 所有服务连接成功")

    def get_cves_to_sync(self, limit: int = None, days: int = 30) -> List[Dict]:
        """获取需要同步的 CVE 数据"""
        print(f"\n[读取] 从数据库读取最近 {days} 天的 CVE...")

        # 从混合数据管理器获取 CVE
        cves = self.hybrid_manager.get_recent_cves(days=days)

        if limit:
            cves = cves[:limit]

        print(f"[OK] 找到 {len(cves)} 条 CVE 记录")
        return cves

    def sync_cves_with_gpu(self, cves: List[Dict], batch_size: int = 10):
        """使用 GPU 加速同步 CVE 向量"""
        total = len(cves)
        print(f"\n[GPU 同步] 开始处理 {total} 条 CVE (批次大小: {batch_size})")
        print("=" * 80)

        success_count = 0
        failed_count = 0
        start_time = time.time()

        for i in range(0, total, batch_size):
            batch = cves[i:i + batch_size]
            batch_start = time.time()

            for cve in batch:
                try:
                    cve_id = cve.get('cve_id', '')
                    description = cve.get('description', '')
                    title = cve.get('title', cve_id)

                    if not description:
                        print(f"[跳过] {cve_id}: 无描述信息")
                        continue

                    # GPU 加速生成向量
                    embedding = self.ollama.generate_embedding(description)

                    if not embedding:
                        print(f"[失败] {cve_id}: 向量生成失败")
                        failed_count += 1
                        continue

                    # 保存到向量数据库
                    self.vector_db.insert_cve_embedding(
                        cve_id=cve_id,
                        title=title,
                        description=description,
                        embedding=embedding,
                        severity=cve.get('severity', 'UNKNOWN'),
                        cvss_score=cve.get('cvss_score', 0.0),
                        published_date=cve.get('published_date', '2025-01-01')
                    )

                    success_count += 1

                except Exception as e:
                    print(f"[错误] {cve.get('cve_id', 'UNKNOWN')}: {e}")
                    failed_count += 1

            # 显示进度
            batch_time = time.time() - batch_start
            speed = len(batch) / batch_time if batch_time > 0 else 0
            elapsed = time.time() - start_time

            print_progress_bar(
                min(i + batch_size, total),
                total,
                prefix='进度',
                suffix=f'完成 | 成功: {success_count} | 失败: {failed_count} | 速度: {speed:.1f} 条/秒'
            )

        # 总结
        total_time = time.time() - start_time
        print(f"\n{'=' * 80}")
        print(f"[完成] GPU 同步任务完成")
        print(f"  总计: {total} 条")
        print(f"  成功: {success_count} 条")
        print(f"  失败: {failed_count} 条")
        print(f"  耗时: {total_time:.2f} 秒")
        print(f"  平均速度: {total / total_time:.2f} 条/秒")
        print(f"{'=' * 80}")

    def test_similarity_search(self, query: str = "SQL injection vulnerability"):
        """测试语义相似度搜索"""
        print(f"\n[测试] 语义搜索: '{query}'")
        print("-" * 80)

        # 生成查询向量
        start_time = time.time()
        query_embedding = self.ollama.generate_embedding(query)
        embedding_time = time.time() - start_time

        if not query_embedding:
            print("[错误] 无法生成查询向量")
            return

        print(f"[OK] 向量生成耗时: {embedding_time*1000:.1f} 毫秒")

        # 搜索相似 CVE
        search_start = time.time()
        results = self.vector_db.search_similar_cves(query_embedding, limit=5)
        search_time = time.time() - search_start

        print(f"[OK] 搜索耗时: {search_time*1000:.1f} 毫秒")
        print(f"\n找到 {len(results)} 个相似结果:")
        print("-" * 80)

        for i, result in enumerate(results, 1):
            print(f"\n{i}. {result['cve_id']} (相似度: {result['similarity']:.3f})")
            print(f"   标题: {result['title']}")
            print(f"   严重程度: {result['severity']} | CVSS: {result['cvss_score']}")
            print(f"   描述: {result['description'][:100]}...")

    def get_stats(self):
        """获取统计信息"""
        print("\n[统计] 数据库统计信息")
        print("=" * 80)

        stats = self.vector_db.get_stats()

        print(f"CVE 向量总数: {stats['total_cves']}")
        print(f"按严重程度分类:")
        for severity, count in stats['by_severity'].items():
            print(f"  {severity}: {count}")
        print(f"最早日期: {stats['date_range']['earliest']}")
        print(f"最晚日期: {stats['date_range']['latest']}")
        print("=" * 80)

    def close(self):
        """关闭所有连接"""
        self.vector_db.close()
        self.hybrid_manager.close()


def main():
    """主函数"""
    print("=" * 80)
    print("GPU 加速 CVE 数据同步")
    print("=" * 80)
    print(f"GPU: NVIDIA GeForce 940MX (4GB)")
    print(f"向量模型: nomic-embed-text (768 维)")
    print(f"数据源: SQLite + Redis")
    print(f"目标: PostgreSQL + pgvector")
    print("=" * 80)

    try:
        # 初始化同步器
        syncer = GPUCVESync()

        # 获取要同步的 CVE（限制数量以便测试）
        cves = syncer.get_cves_to_sync(limit=100, days=30)  # 测试：同步 100 条

        if not cves:
            print("\n[警告] 没有找到 CVE 数据")
            print("请先运行 CVE 采集程序获取数据")
            return

        # GPU 加速同步
        syncer.sync_cves_with_gpu(cves, batch_size=10)

        # 显示统计信息
        syncer.get_stats()

        # 测试语义搜索
        syncer.test_similarity_search("SQL injection vulnerability")
        syncer.test_similarity_search("remote code execution")
        syncer.test_similarity_search("cross-site scripting XSS")

        print("\n[OK] 所有任务完成!")

    except Exception as e:
        print(f"\n[错误] {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            syncer.close()
        except:
            pass


if __name__ == "__main__":
    main()
