# GPU 加速版 CVE 监控系统 - 快速启动指南

## 🚀 5 分钟快速启动

### 前置检查

```bash
# 1. 检查 GPU
nvidia-smi

# 2. 检查 Docker
docker --version

# 3. 测试 Docker GPU 支持
docker run --rm --gpus all nvidia/cuda:12.0.0-base-ubuntu22.04 nvidia-smi
```

### 快速启动步骤

#### 步骤 1: 启动所有服务

```bash
# 启动 GPU 优化的完整服务栈
docker-compose -f docker-compose-gpu.yml up -d

# 查看服务状态
docker-compose -f docker-compose-gpu.yml ps
```

#### 步骤 2: 下载 LLM 模型（后台运行）

```bash
# 下载嵌入模型（~137MB，用于向量生成）
docker exec -it cve-ollama ollama pull nomic-embed-text

# 下载分析模型（~2GB，用于 CVE 智能分析）
docker exec -it cve-ollama ollama pull qwen2.5:3b

# 查看已安装模型
docker exec -it cve-ollama ollama list
```

#### 步骤 3: 验证服务

```bash
# 测试 Ollama LLM
curl http://localhost:11434/api/tags

# 测试 PostgreSQL 向量数据库
docker exec cve-postgres-vector psql -U admin -d cve_vectors -c "SELECT version();"

# 测试 Redis
docker exec cve-redis redis-cli -a defaultpassword PING
```

#### 步骤 4: 访问 Web 界面

打开浏览器访问：

| 服务 | URL | 默认账号 |
|------|-----|---------|
| **LLM 对话界面** | http://localhost:8080 | 首次访问时注册 |
| **Redis 管理** | http://localhost:8081 | - |
| **PostgreSQL 管理** | http://localhost:5050 | admin@admin.com / admin |

## 📊 功能演示

### 1. 使用 LLM 分析 CVE

打开 Python 环境：

```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate

# 安装 GPU 相关依赖
pip install psycopg2-binary requests numpy

# 运行测试
cd /D/AI/Claude/CVE
python ollama_llm_service.py
```

### 2. 生成向量嵌入并搜索

```python
from ollama_llm_service import OllamaLLMService, VectorDatabaseManager

# 初始化
ollama = OllamaLLMService("http://localhost:11434")
db = VectorDatabaseManager("postgresql://admin:defaultpassword@localhost:5432/cve_vectors")
db.connect()

# 生成嵌入
text = "SQL injection vulnerability in web application"
embedding = ollama.generate_embedding(text)
print(f"嵌入维度: {len(embedding)}")

# 保存
db.insert_cve_embedding(
    cve_id="CVE-TEST-001",
    title="SQL Injection Test",
    description=text,
    embedding=embedding,
    severity="HIGH",
    cvss_score=8.5,
    published_date="2025-01-01"
)

# 搜索相似 CVE
query = "database security issue"
query_embedding = ollama.generate_embedding(query)
results = db.search_similar_cves(query_embedding, limit=5)

for result in results:
    print(f"{result['cve_id']}: {result['similarity']:.2f}")
```

### 3. 智能 CVE 分析

```python
# CVE 数据
cve = {
    'cve_id': 'CVE-2024-0001',
    'description': 'A SQL injection vulnerability allows attackers to execute arbitrary SQL commands',
    'cvss_score': 9.8
}

# LLM 分析
analysis = ollama.analyze_cve(cve)
print(f"\n分析结果:\n{analysis['analysis']}")
```

## 🔍 监控 GPU 使用

### 实时监控

```bash
# 方法 1: 直接查看
nvidia-smi -l 1  # 每秒刷新

# 方法 2: 容器内查看
watch -n 1 'docker exec cve-ollama nvidia-smi'

# 方法 3: 查看详细统计
nvidia-smi dmon -i 0
```

### 性能指标

关注以下指标：
- **GPU 利用率**: 推理时应达到 60-90%
- **显存使用**: 3B 模型约 2-2.5GB
- **温度**: 保持在 85°C 以下
- **功耗**: 940MX 约 30-40W

## 📈 性能对比

### GPU vs CPU 性能

```python
import time

# CPU 模式（禁用 GPU）
start = time.time()
for _ in range(10):
    embedding_cpu = ollama.generate_embedding(text)
cpu_time = time.time() - start

# GPU 模式
start = time.time()
for _ in range(10):
    embedding_gpu = ollama.generate_embedding(text)
gpu_time = time.time() - start

print(f"CPU: {cpu_time:.2f}s")
print(f"GPU: {gpu_time:.2f}s")
print(f"加速比: {cpu_time/gpu_time:.2f}x")
```

**预期结果** (940MX):
- CPU: ~5-8 秒（10次）
- GPU: ~0.5-1 秒（10次）
- **加速比: 5-10倍**

## 🛑 停止服务

```bash
# 停止所有服务
docker-compose -f docker-compose-gpu.yml down

# 停止并删除数据卷（慎用！）
docker-compose -f docker-compose-gpu.yml down -v

# 仅停止特定服务
docker-compose -f docker-compose-gpu.yml stop ollama
```

## 🔧 常见任务

### 切换 LLM 模型

```bash
# 查看可用模型
curl http://localhost:11434/api/tags | jq '.models[].name'

# 下载新模型
docker exec -it cve-ollama ollama pull llama3.2:3b

# 删除旧模型（释放空间）
docker exec -it cve-ollama ollama rm qwen2.5:3b
```

### 查看日志

```bash
# 查看所有服务日志
docker-compose -f docker-compose-gpu.yml logs -f

# 查看特定服务
docker-compose -f docker-compose-gpu.yml logs -f ollama

# 查看最近 100 行
docker-compose -f docker-compose-gpu.yml logs --tail=100 ollama
```

### 备份数据

```bash
# 备份 PostgreSQL 向量数据库
docker exec cve-postgres-vector pg_dump -U admin cve_vectors > backup_vectors.sql

# 备份 MongoDB
docker exec cve-mongodb mongodump --uri="mongodb://admin:defaultpassword@localhost:27017/cve_monitor?authSource=admin"

# 备份 Ollama 模型
docker cp cve-ollama:/root/.ollama ./ollama_backup
```

## 📚 进阶功能

### 批量处理 CVE

```python
from redis_manager import RedisDataManager
import json

# 获取所有 CVE
redis_manager = RedisDataManager(password='defaultpassword')
all_cves = redis_manager.get_all_cves(limit=100)

# 批量生成嵌入
descriptions = [cve.get('description', '') for cve in all_cves]
embeddings = ollama.batch_generate_embeddings(descriptions, batch_size=10)

# 批量保存到向量数据库
for cve, embedding in zip(all_cves, embeddings):
    if embedding:
        db.insert_cve_embedding(
            cve_id=cve.get('cve_id'),
            title=cve.get('title', ''),
            description=cve.get('description', ''),
            embedding=embedding,
            severity=cve.get('severity', 'UNKNOWN'),
            cvss_score=cve.get('cvss_score', 0),
            published_date=cve.get('published_date', '2025-01-01')
        )

print(f"处理完成: {len(all_cves)} 条 CVE")
```

### 定时任务（每日更新向量）

创建 `update_vectors_daily.py`:

```python
#!/usr/bin/env python3
"""每日更新 CVE 向量嵌入"""

from datetime import datetime, timedelta
from ollama_llm_service import OllamaLLMService, VectorDatabaseManager
from redis_manager import RedisDataManager

def update_recent_cves():
    """更新最近的 CVE 向量"""
    # 初始化
    ollama = OllamaLLMService()
    db = VectorDatabaseManager("postgresql://admin:defaultpassword@localhost:5432/cve_vectors")
    db.connect()
    redis_manager = RedisDataManager(password='defaultpassword')

    # 获取最近 7 天的 CVE
    from hybrid_data_manager import HybridDataManager
    hybrid = HybridDataManager("cve_data/cve_database.db", redis_password='defaultpassword')
    recent_cves = hybrid.get_recent_cves(days=7)

    print(f"发现 {len(recent_cves)} 条最近的 CVE")

    # 生成嵌入并保存
    for i, cve in enumerate(recent_cves):
        print(f"处理 {i+1}/{len(recent_cves)}: {cve.get('cve_id')}")

        embedding = ollama.generate_embedding(cve.get('description', ''))
        if embedding:
            db.insert_cve_embedding(
                cve_id=cve.get('cve_id'),
                title=cve.get('title', ''),
                description=cve.get('description', ''),
                embedding=embedding,
                severity=cve.get('severity', 'UNKNOWN'),
                cvss_score=cve.get('cvss_score', 0),
                published_date=cve.get('published_date', '2025-01-01')
            )

    print("更新完成")

if __name__ == "__main__":
    update_recent_cves()
```

### 设置定时任务（Linux/Mac）

```bash
# 编辑 crontab
crontab -e

# 添加每日 2:00 AM 执行
0 2 * * * cd /path/to/CVE && /path/to/python update_vectors_daily.py >> /var/log/cve_update.log 2>&1
```

## 🎯 性能调优

### 针对 940MX (4GB) 的优化建议

1. **使用量化模型**
   ```bash
   # 4-bit 量化（显存减少 75%）
   docker exec -it cve-ollama ollama pull qwen2.5:3b-q4_0
   ```

2. **限制批量大小**
   ```python
   # 避免 OOM
   embeddings = ollama.batch_generate_embeddings(texts, batch_size=5)  # 降低批量
   ```

3. **启用模型卸载**
   ```bash
   # 不使用时自动卸载模型（释放显存）
   docker exec cve-ollama bash -c "export OLLAMA_KEEP_ALIVE=5m"
   ```

## 🆘 故障排查

### 问题 1: Ollama 无法使用 GPU

**检查**:
```bash
docker exec cve-ollama nvidia-smi
```

**解决**:
```bash
# 重启服务
docker-compose -f docker-compose-gpu.yml restart ollama

# 检查日志
docker logs cve-ollama
```

### 问题 2: 向量搜索返回空结果

**检查**:
```sql
-- 连接数据库
docker exec -it cve-postgres-vector psql -U admin -d cve_vectors

-- 查看数据量
SELECT COUNT(*) FROM cve_embeddings;

-- 检查索引
\d cve_embeddings
```

### 问题 3: 显存不足

**症状**: `CUDA out of memory`

**解决**:
```bash
# 1. 重启 Ollama 释放显存
docker restart cve-ollama

# 2. 切换到更小的模型
docker exec -it cve-ollama ollama pull phi3:mini

# 3. 使用量化模型
docker exec -it cve-ollama ollama pull qwen2.5:3b-q4_0
```

## 📞 获取帮助

- **文档**: `GPU_ARCHITECTURE.md`
- **示例代码**: `ollama_llm_service.py`
- **配置文件**: `docker-compose-gpu.yml`

---

**版本**: v1.0.0
**最后更新**: 2025-11-03
**GPU**: NVIDIA GeForce 940MX (4GB)
