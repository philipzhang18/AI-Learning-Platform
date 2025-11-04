# Docker Desktop GPU 配置完整指南

## 当前状态 ✅

你的 Docker Desktop GPU 支持已经正确配置!

**验证结果**:
- GPU: NVIDIA GeForce 940MX (4GB 显存)
- CUDA: 13.0 (驱动 581.57)
- Docker: 28.4.0
- GPU 访问测试: ✅ 通过

## 启动服务

### 1. 启动 GPU 优化的服务栈

```bash
# 启动所有服务(后台运行)
docker-compose -f docker-compose-gpu.yml up -d

# 查看服务状态
docker-compose -f docker-compose-gpu.yml ps

# 查看启动日志
docker-compose -f docker-compose-gpu.yml logs -f
```

### 2. 检查服务健康状态

等待所有服务启动(通常需要 2-3 分钟),然后检查:

```bash
# 查看运行中的容器
docker ps

# 检查 GPU 在 Ollama 容器中是否可用
docker exec cve-ollama nvidia-smi

# 查看 MongoDB 状态
docker exec cve-mongodb mongosh --eval "db.adminCommand('ping')"

# 查看 PostgreSQL 状态
docker exec cve-postgres-vector psql -U admin -d cve_vectors -c "SELECT version();"

# 查看 Redis 状态
docker exec cve-redis redis-cli -a defaultpassword PING
```

## 下载 LLM 模型

### 必需模型

```bash
# 1. 下载嵌入模型 (约 137MB,用于生成向量)
docker exec -it cve-ollama ollama pull nomic-embed-text

# 2. 下载分析模型 (约 2GB,用于 CVE 智能分析)
docker exec -it cve-ollama ollama pull qwen2.5:3b

# 查看已安装的模型
docker exec -it cve-ollama ollama list
```

### 可选模型(根据需求选择)

```bash
# 更小的模型(适合显存受限)
docker exec -it cve-ollama ollama pull qwen2.5:1.8b

# 量化模型(减少 75% 显存使用)
docker exec -it cve-ollama ollama pull qwen2.5:3b-q4_0

# 替代分析模型
docker exec -it cve-ollama ollama pull llama3.2:3b
docker exec -it cve-ollama ollama pull phi3:mini
```

## 访问 Web 界面

服务启动后,可以访问以下界面:

| 服务名称 | 访问地址 | 默认账号 | 用途 |
|---------|---------|---------|------|
| **Open WebUI** | http://localhost:8080 | 首次访问时注册 | LLM 对话和管理界面 |
| **Redis Commander** | http://localhost:8081 | - | Redis 缓存管理 |
| **pgAdmin** | http://localhost:5050 | admin@admin.com / admin | PostgreSQL 管理 |
| **Ollama API** | http://localhost:11434 | - | LLM API 端点 |

## 使用示例

### 1. 测试 LLM 服务 (命令行)

```bash
# 测试 API 可用性
curl http://localhost:11434/api/tags

# 生成文本嵌入
curl http://localhost:11434/api/embeddings -d '{
  "model": "nomic-embed-text",
  "prompt": "SQL injection vulnerability in web application"
}'

# 进行对话
curl http://localhost:11434/api/generate -d '{
  "model": "qwen2.5:3b",
  "prompt": "Explain what is a CVE vulnerability",
  "stream": false
}'
```

### 2. Python 代码示例

首先激活虚拟环境:

```bash
# Git Bash
source /D/AI/cursor/starone/.venv/Scripts/activate
cd /D/AI/Claude/CVE
```

然后运行 Python 代码:

```python
from ollama_llm_service import OllamaLLMService, VectorDatabaseManager

# 初始化服务
ollama = OllamaLLMService(base_url="http://localhost:11434")
db = VectorDatabaseManager(
    "postgresql://admin:defaultpassword@localhost:5432/cve_vectors"
)
db.connect()

# 测试 1: 生成嵌入
text = "SQL injection vulnerability in login form"
embedding = ollama.generate_embedding(text)
print(f"嵌入维度: {len(embedding)}")

# 测试 2: 保存到向量数据库
db.insert_cve_embedding(
    cve_id="CVE-TEST-001",
    title="SQL Injection Test",
    description=text,
    embedding=embedding,
    severity="HIGH",
    cvss_score=8.5,
    published_date="2025-01-01"
)

# 测试 3: 语义搜索
query = "database security issue"
query_embedding = ollama.generate_embedding(query)
results = db.search_similar_cves(query_embedding, limit=5)

for result in results:
    print(f"{result['cve_id']}: {result['title']}")
    print(f"  相似度: {result['similarity']:.2f}")

# 测试 4: LLM 分析 CVE
cve_data = {
    'cve_id': 'CVE-2024-0001',
    'description': 'A SQL injection vulnerability allows attackers...',
    'cvss_score': 9.8
}
analysis = ollama.analyze_cve(cve_data)
print(f"\nLLM 分析:\n{analysis['analysis']}")
```

## GPU 监控

### 实时监控 GPU 使用

```bash
# 方法 1: 主机上实时监控
nvidia-smi -l 1  # 每秒刷新一次

# 方法 2: 容器内查看
docker exec cve-ollama nvidia-smi

# 方法 3: 持续监控(推荐)
watch -n 1 'docker exec cve-ollama nvidia-smi'
```

### 关键性能指标

- **GPU 利用率**: 推理时应达到 60-90%
- **显存使用**:
  - nomic-embed-text: ~500MB
  - qwen2.5:3b: ~2GB
  - 总计: ~2.5GB / 4GB
- **温度**: 保持在 85°C 以下
- **功耗**: 940MX 约 30-40W

## 批量处理 CVE 示例

```python
from redis_manager import RedisDataManager
from hybrid_data_manager import HybridDataManager

# 初始化
redis_manager = RedisDataManager(password='defaultpassword')
hybrid = HybridDataManager(
    "cve_data/cve_database.db",
    redis_password='defaultpassword'
)
ollama = OllamaLLMService()
db = VectorDatabaseManager(
    "postgresql://admin:defaultpassword@localhost:5432/cve_vectors"
)
db.connect()

# 获取最近 30 天的 CVE
recent_cves = hybrid.get_recent_cves(days=30)
print(f"发现 {len(recent_cves)} 条最近的 CVE")

# 批量生成嵌入(GPU 加速)
for i, cve in enumerate(recent_cves):
    print(f"处理 {i+1}/{len(recent_cves)}: {cve.get('cve_id')}")

    # 生成嵌入
    embedding = ollama.generate_embedding(cve.get('description', ''))

    if embedding:
        # 保存到向量数据库
        db.insert_cve_embedding(
            cve_id=cve.get('cve_id'),
            title=cve.get('title', ''),
            description=cve.get('description', ''),
            embedding=embedding,
            severity=cve.get('severity', 'UNKNOWN'),
            cvss_score=cve.get('cvss_score', 0),
            published_date=cve.get('published_date', '2025-01-01')
        )

print("批量处理完成!")
```

## 性能基准测试

### 运行性能测试

```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate
cd /D/AI/Claude/CVE

# 运行全面的性能测试
python comprehensive_performance_test.py

# 或运行快速测试
python performance_test.py
```

### 预期性能 (940MX)

- **向量生成速度**: 20-30 文本/秒
- **GPU vs CPU 加速比**: 5-10x
- **推理延迟**: 1-3 秒 (3B 模型)
- **向量搜索**: 毫秒级 (10 万条数据)

## 故障排查

### 问题 1: Ollama 无法访问 GPU

**症状**: `docker exec cve-ollama nvidia-smi` 报错

**解决方案**:
```bash
# 1. 检查 Docker GPU 支持
docker run --rm --gpus all nvidia/cuda:13.0.1-runtime-ubuntu22.04 nvidia-smi

# 2. 重启 Ollama 服务
docker-compose -f docker-compose-gpu.yml restart ollama

# 3. 查看日志
docker logs cve-ollama --tail 100
```

### 问题 2: 显存不足

**症状**: `CUDA out of memory` 错误

**解决方案**:
```bash
# 方案 1: 重启释放显存
docker restart cve-ollama

# 方案 2: 使用更小的模型
docker exec -it cve-ollama ollama rm qwen2.5:3b
docker exec -it cve-ollama ollama pull qwen2.5:1.8b

# 方案 3: 使用量化模型
docker exec -it cve-ollama ollama pull qwen2.5:3b-q4_0
```

### 问题 3: 服务启动失败

**症状**: 某个容器状态为 `Exited`

**解决方案**:
```bash
# 1. 查看具体容器的日志
docker logs cve-[服务名] --tail 50

# 2. 检查端口占用
netstat -an | grep -E "27017|6379|5432|11434|8080"

# 3. 重新启动失败的服务
docker-compose -f docker-compose-gpu.yml restart [服务名]

# 4. 完全重建服务
docker-compose -f docker-compose-gpu.yml down
docker-compose -f docker-compose-gpu.yml up -d
```

### 问题 4: 向量搜索慢

**症状**: 搜索响应时间 >100ms

**解决方案**:
```sql
-- 连接到 PostgreSQL
docker exec -it cve-postgres-vector psql -U admin -d cve_vectors

-- 检查索引
\d cve_embeddings

-- 重建 HNSW 索引
DROP INDEX IF EXISTS cve_embeddings_vector_idx;
CREATE INDEX cve_embeddings_vector_idx
ON cve_embeddings
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- 分析表
ANALYZE cve_embeddings;
```

## 停止和清理

### 停止服务

```bash
# 停止所有服务
docker-compose -f docker-compose-gpu.yml stop

# 停止特定服务
docker-compose -f docker-compose-gpu.yml stop ollama

# 停止并删除容器
docker-compose -f docker-compose-gpu.yml down
```

### 清理数据(慎用!)

```bash
# 删除所有容器和数据卷
docker-compose -f docker-compose-gpu.yml down -v

# 删除未使用的镜像
docker image prune -a

# 清理系统
docker system prune --volumes
```

## 数据备份

### 备份 PostgreSQL 向量数据库

```bash
# 备份数据库
docker exec cve-postgres-vector pg_dump -U admin cve_vectors > backup_vectors_$(date +%Y%m%d).sql

# 恢复数据库
cat backup_vectors_20250103.sql | docker exec -i cve-postgres-vector psql -U admin -d cve_vectors
```

### 备份 MongoDB

```bash
# 备份
docker exec cve-mongodb mongodump \
  --uri="mongodb://admin:defaultpassword@localhost:27017/cve_monitor?authSource=admin" \
  --out=/tmp/backup

# 复制到主机
docker cp cve-mongodb:/tmp/backup ./mongodb_backup_$(date +%Y%m%d)

# 恢复
docker exec cve-mongodb mongorestore \
  --uri="mongodb://admin:defaultpassword@localhost:27017/cve_monitor?authSource=admin" \
  /tmp/backup/cve_monitor
```

### 备份 Ollama 模型

```bash
# 备份模型数据
docker cp cve-ollama:/root/.ollama ./ollama_backup_$(date +%Y%m%d)

# 恢复模型
docker cp ollama_backup_20250103 cve-ollama:/root/.ollama
docker restart cve-ollama
```

## 进阶配置

### 调整 GPU 显存分配

编辑 `docker-compose-gpu.yml` 中的 Ollama 服务:

```yaml
ollama:
  environment:
    - CUDA_VISIBLE_DEVICES=0  # 使用第一个 GPU
    - OLLAMA_NUM_GPU=1         # GPU 数量
    - OLLAMA_KEEP_ALIVE=5m     # 模型保持时间(自动卸载)
```

### 调整 PostgreSQL 向量索引

编辑 `init-vector-db.sql`:

```sql
-- 调整 HNSW 参数
-- m: 连接数(12-48,越大越准确但占用更多内存)
-- ef_construction: 构建质量(64-200,越大越准确但构建越慢)
CREATE INDEX cve_embeddings_vector_idx
ON cve_embeddings
USING hnsw (embedding vector_cosine_ops)
WITH (m = 24, ef_construction = 128);
```

## 参考文档

- **快速启动**: `GPU_QUICKSTART.md`
- **架构设计**: `GPU_ARCHITECTURE.md`
- **性能优化**: `GPU_OPTIMIZATION_SUMMARY.md`
- **Redis 指南**: `docs/REDIS_GUIDE.md`
- **API 文档**: `DOCUMENTATION_INDEX.md`

## 获取帮助

如果遇到问题:

1. 查看日志: `docker-compose -f docker-compose-gpu.yml logs -f`
2. 检查服务状态: `docker ps -a`
3. 查看 GPU 状态: `nvidia-smi`
4. 阅读文档: 查看上述参考文档

---

**版本**: v1.0.0
**最后更新**: 2025-11-03
**GPU**: NVIDIA GeForce 940MX (4GB)
**状态**: ✅ 配置完成,可以开始使用
