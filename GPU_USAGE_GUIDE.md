# CVE 系统 GPU 加速 - 快速使用指南

## 📋 前置要求

- ✅ NVIDIA GPU（支持CUDA）
- ✅ Docker + Docker Compose
- ✅ NVIDIA Container Toolkit（可选，用于GPU加速）

## 🚀 快速启动（3步）

### 步骤 1: 启动 GPU 服务

```bash
# Linux/Mac/Git Bash
bash start_gpu_services.sh

# Windows PowerShell
docker-compose -f docker-compose-gpu.yml up -d
```

### 步骤 2: 安装 LLM 模型

```bash
# 向量生成模型（~137MB，必需）
docker exec -it cve-ollama ollama pull nomic-embed-text

# CVE 分析模型（~2GB，可选）
docker exec -it cve-ollama ollama pull qwen2.5:3b
```

### 步骤 3: 测试 GPU 功能

```bash
# 运行测试脚本
bash test_gpu_services.sh

# 或手动测试
source /D/AI/cursor/starone/.venv/Scripts/activate
python gpu_performance_test.py
```

## 🎯 主要功能

### 1. CVE 向量同步（语义搜索）

```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate

# 同步 CVE 数据到向量数据库（GPU 加速）
python gpu_cve_sync.py
```

**功能说明：**
- 从 SQLite/Redis 读取 CVE 数据
- 使用 GPU 加速生成 768 维向量嵌入
- 保存到 PostgreSQL + pgvector 数据库
- 支持语义相似度搜索

### 2. 性能测试

```bash
python gpu_performance_test.py
```

**测试内容：**
- GPU vs CPU 性能对比
- 向量生成速度
- 批量处理性能
- 内存使用情况

### 3. 智能 CVE 分析

```python
from ollama_llm_service import OllamaLLMService

# 初始化服务
ollama = OllamaLLMService("http://localhost:11434")

# 分析 CVE
cve_data = {
    'cve_id': 'CVE-2024-0001',
    'description': 'SQL injection vulnerability...',
    'cvss_score': 9.8
}

analysis = ollama.analyze_cve(cve_data)
print(analysis['analysis'])
```

### 4. 语义搜索

```python
from ollama_llm_service import VectorDatabaseManager

# 连接向量数据库
db = VectorDatabaseManager(
    "postgresql://admin:defaultpassword@localhost:5432/cve_vectors"
)
db.connect()

# 搜索相似 CVE
query = "SQL injection in web applications"
query_embedding = ollama.generate_embedding(query)
results = db.search_similar_cves(query_embedding, limit=10)

for r in results:
    print(f"{r['cve_id']} - 相似度: {r['similarity']:.3f}")
```

## 📊 服务访问

| 服务 | 地址 | 说明 |
|------|------|------|
| Ollama API | http://localhost:11434 | LLM 推理服务 |
| Ollama Web UI | http://localhost:8080 | 对话界面 |
| Redis | localhost:6379 | 密码: defaultpassword |
| PostgreSQL | localhost:5432 | 用户: admin, 密码: defaultpassword |
| MongoDB | localhost:27017 | 用户: admin, 密码: defaultpassword |

## 🛠️ 常用命令

```bash
# 查看服务状态
docker-compose -f docker-compose-gpu.yml ps

# 查看日志
docker-compose -f docker-compose-gpu.yml logs -f ollama

# 重启服务
docker-compose -f docker-compose-gpu.yml restart

# 停止服务
docker-compose -f docker-compose-gpu.yml down

# 监控 GPU 使用
watch -n 1 'docker exec cve-ollama nvidia-smi'

# 查看已安装模型
docker exec cve-ollama ollama list
```

## ⚡ 性能优化建议

### 针对中低端 GPU（如 940MX 4GB）

1. **使用量化模型**
   ```bash
   docker exec -it cve-ollama ollama pull qwen2.5:3b-q4_0
   ```

2. **降低批量大小**
   ```python
   # 在 gpu_cve_sync.py 中调整
   syncer.sync_cves_with_gpu(cves, batch_size=5)  # 默认 10
   ```

3. **限制并发数**
   - 一次只运行一个 GPU 任务
   - 避免同时运行向量生成和 LLM 分析

## 🔧 故障排查

### 问题 1: GPU 不可用

```bash
# 检查 GPU
nvidia-smi

# 检查容器内 GPU
docker exec cve-ollama nvidia-smi

# 如果失败，重启 Docker 服务
```

### 问题 2: 模型下载失败

```bash
# 手动下载到本地，然后导入
ollama pull nomic-embed-text
docker cp ~/.ollama cve-ollama:/root/
```

### 问题 3: 内存不足

```bash
# 查看模型占用
docker exec cve-ollama ollama list

# 删除不需要的模型
docker exec cve-ollama ollama rm <model_name>
```

## 📚 更多文档

- `GPU_QUICKSTART.md` - 详细的快速入门指南
- `GPU_ARCHITECTURE.md` - 系统架构说明
- `ollama_llm_service.py` - Python API 示例代码
- `gpu_cve_sync.py` - 数据同步脚本源码

## ⚠️ 注意事项

1. **首次启动较慢** - Docker 需要下载镜像（约 5-10GB）
2. **模型下载耗时** - qwen2.5:3b 约 2GB，需要几分钟
3. **GPU 显存** - 建议至少 4GB 显存
4. **磁盘空间** - 预留至少 20GB 空间

## 💡 使用建议

1. **日常使用** - 仅启动 SQLite 模式（更快，更轻量）
   ```bash
   bash start_cve_sqlite.sh
   ```

2. **需要语义搜索时** - 启动 GPU 服务
   ```bash
   bash start_gpu_services.sh
   ```

3. **定期同步** - 每周同步一次向量数据
   ```bash
   python gpu_cve_sync.py
   ```

---

**版本**: v1.0
**创建日期**: 2025-11-04
**适用GPU**: NVIDIA 系列（CUDA 兼容）
