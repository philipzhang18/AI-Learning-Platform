# CVE 系统轻量级架构迁移指南

## 📋 迁移概述

**当前架构**: Docker MongoDB + Docker Redis
**目标架构**: SQLite + Redis on WSL
**迁移目标**: 降低 CPU 和内存占用 70-80%

---

## 🎯 架构对比

### 当前架构（Docker）

```
┌─────────────────────────────────────────────────────┐
│ Windows 系统                                         │
│  ┌──────────────────────────────────────────────┐  │
│  │ Docker Desktop                                │  │
│  │  ┌──────────────┐      ┌──────────────┐      │  │
│  │  │ MongoDB 7.0  │      │  Redis 7     │      │  │
│  │  │ 271 MB 内存  │      │  3.3 MB 内存 │      │  │
│  │  │ 1 核 CPU     │      │  0.5 核 CPU  │      │  │
│  │  └──────────────┘      └──────────────┘      │  │
│  │                                               │  │
│  │  WSL 2 Backend (Vmmem)                       │  │
│  │  - 高内存占用 (8-15 GB)                      │  │
│  │  - 高 CPU 占用 (>50%)                        │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │ GUI 程序 (Python/Tkinter)                     │  │
│  │ - 使用 SQLite 作为主存储                      │  │
│  │ - Redis 作为缓存（可选）                      │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘

资源占用：
- CPU: 高占用 (Docker Backend)
- 内存: 8-15 GB (Docker + WSL 2)
- 磁盘 I/O: 中等
```

### 目标架构（轻量级）

```
┌─────────────────────────────────────────────────────┐
│ Windows 系统                                         │
│                                                      │
│  ┌──────────────────────────────────────────────┐  │
│  │ SQLite 数据库 (文件)                          │  │
│  │ - 无服务进程                                  │  │
│  │ - 零内存占用                                  │  │
│  │ - 文件: cve_database.db (143 MB)             │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │ WSL 2 (Ubuntu)                                │  │
│  │  ┌──────────────┐                             │  │
│  │  │ Redis 原生   │                             │  │
│  │  │ ~5 MB 内存   │                             │  │
│  │  │ 低 CPU 占用  │                             │  │
│  │  └──────────────┘                             │  │
│  │  (无 Docker Backend 开销)                    │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │ GUI 程序 (Python/Tkinter)                     │  │
│  │ - SQLite 主存储                               │  │
│  │ - Redis on WSL 缓存                          │  │
│  │ - (可选) GPU 加速计算                         │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘

资源占用：
- CPU: 低占用 (无 Docker)
- 内存: 2-4 GB (仅 Redis + Python)
- 磁盘 I/O: 低
```

---

## 📊 资源占用对比

| 项目 | Docker 架构 | 轻量级架构 | 改善 |
|-----|------------|-----------|------|
| **内存占用** | 8-15 GB | 2-4 GB | **降低 70%** ⚡⚡⚡ |
| **CPU 占用** | 高 (>50%) | 低 (<10%) | **降低 80%** ⚡⚡⚡ |
| **磁盘 I/O** | 中等 | 低 | **降低 40%** ⚡ |
| **启动时间** | 30-60 秒 | 5-10 秒 | **快 5 倍** ⚡⚡ |
| **查询性能** | 0.3-0.7 秒 | 0.5-1.5 秒 | 略慢但可接受 ✓ |

---

## 🚀 迁移步骤

### 阶段 1：准备工作（5 分钟）

#### 1.1 备份数据

```bash
# 备份 SQLite 数据库
cd /D/AI/Claude/CVE
cp cve_data/cve_database.db backups/cve_database_pre_migration_$(date +%Y%m%d_%H%M%S).db

# 验证备份
ls -lh backups/ | tail -3
```

#### 1.2 导出 Redis 数据（可选）

```bash
# 如果 Redis 中有重要数据
docker exec cve-redis redis-cli -a defaultpassword BGSAVE
docker cp cve-redis:/data/dump.rdb backups/redis_dump_$(date +%Y%m%d).rdb
```

#### 1.3 验证 SQLite 数据完整性

```bash
cd /D/AI/Claude/CVE
python -c "
import sqlite3
conn = sqlite3.connect('cve_data/cve_database.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM cves')
print(f'CVE count: {cursor.fetchone()[0]}')
cursor.execute('SELECT COUNT(*) FROM dell_advisories')
print(f'Dell count: {cursor.fetchone()[0]}')
conn.close()
"
```

**预期输出**:
```
CVE count: 51127
Dell count: 431
```

---

### 阶段 2：停止并移除 Docker 服务（3 分钟）

#### 2.1 停止所有 Docker 容器

```bash
cd /D/AI/Claude/CVE
docker-compose -f docker-compose-mongodb-optimized.yml down
```

#### 2.2 验证容器已停止

```bash
docker ps | grep cve-
# 应该没有输出
```

#### 2.3 清理 Docker 资源（可选）

```bash
# 清理未使用的镜像和卷
docker system prune -a --volumes -f
```

**注意**: 这会删除所有未使用的 Docker 数据，包括 MongoDB 中的数据。请确保已备份！

---

### 阶段 3：安装 WSL Redis（10 分钟）

#### 3.1 更新 WSL 包管理器

```bash
# 在 WSL 终端中执行
sudo apt update
sudo apt upgrade -y
```

#### 3.2 安装 Redis

```bash
# 安装 Redis 服务器
sudo apt install redis-server -y

# 验证安装
redis-server --version
```

**预期输出**: `Redis server v=6.0.16` (或更高版本)

#### 3.3 配置 Redis

编辑 Redis 配置文件：

```bash
sudo nano /etc/redis/redis.conf
```

修改以下配置：

```ini
# 监听所有网络接口（允许 Windows 访问）
bind 0.0.0.0

# 设置密码
requirepass defaultpassword

# 内存限制
maxmemory 1gb
maxmemory-policy allkeys-lru

# 持久化
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec

# 日志
loglevel notice
logfile /var/log/redis/redis-server.log
```

保存并退出 (`Ctrl+X`, `Y`, `Enter`)

#### 3.4 启动 Redis 服务

```bash
# 启动 Redis
sudo service redis-server start

# 验证运行状态
sudo service redis-server status

# 测试连接
redis-cli -a defaultpassword ping
# 应该返回: PONG
```

#### 3.5 配置开机自启动

```bash
# 添加到 WSL 启动脚本
echo 'sudo service redis-server start' >> ~/.bashrc

# 或者创建 Windows 启动任务（推荐）
# 在 PowerShell 中执行：
# wsl -u root service redis-server start
```

---

### 阶段 4：更新 GUI 配置（5 分钟）

#### 4.1 获取 WSL Redis 地址

```bash
# 在 WSL 中获取 IP 地址
ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
```

**示例输出**: `172.x.x.x`

#### 4.2 更新环境变量

创建或编辑 `.env` 文件：

```bash
cd /D/AI/Claude/CVE
cat > .env << 'EOF'
# Redis 配置（WSL 原生）
REDIS_HOST=172.x.x.x  # 替换为实际 WSL IP
REDIS_PORT=6379
REDIS_PASSWORD=defaultpassword

# SQLite 配置
SQLITE_DB_PATH=cve_data/cve_database.db

# GPU 配置（可选）
ENABLE_GPU=false
GPU_DEVICE=0
EOF
```

**注意**: 将 `172.x.x.x` 替换为实际的 WSL IP 地址。

#### 4.3 修改 `redis_manager.py`（如果需要）

如果 Redis IP 地址不是 localhost，需要修改连接配置：

```python
# redis_manager.py 中的连接配置
def __init__(self, host='172.x.x.x', port=6379, password='defaultpassword'):
    self.redis_client = redis.Redis(
        host=host,
        port=port,
        password=password,
        decode_responses=True
    )
```

---

### 阶段 5：验证新架构（5 分钟）

#### 5.1 测试 Redis 连接

```bash
cd /D/AI/Claude/CVE
python -c "
import redis
client = redis.Redis(host='172.x.x.x', port=6379, password='defaultpassword', decode_responses=True)
print('Redis connection:', client.ping())
client.set('test_key', 'test_value')
print('Set test:', client.get('test_key'))
client.delete('test_key')
"
```

**预期输出**:
```
Redis connection: True
Set test: test_value
```

#### 5.2 测试 SQLite 查询性能

```bash
python -c "
import sqlite3
import time
conn = sqlite3.connect('cve_data/cve_database.db')
cursor = conn.cursor()

start = time.time()
cursor.execute('SELECT * FROM cves LIMIT 100')
rows = cursor.fetchall()
elapsed = time.time() - start

print(f'Query time: {elapsed:.3f} seconds')
print(f'Rows fetched: {len(rows)}')
conn.close()
"
```

**预期输出**:
```
Query time: 0.5-1.5 seconds
Rows fetched: 100
```

#### 5.3 运行 GUI 程序

```bash
cd /D/AI/Claude/CVE
python cve_integrated_gui.py
```

**验证项**:
- ✓ GUI 窗口正常打开
- ✓ 数据能够加载（点击"加载本地数据"）
- ✓ Redis 连接成功（查看日志）
- ✓ SQLite 查询正常

---

## ⚡ GPU 加速方案（可选）

### GPU 加速适用场景

**您的 GPU**: NVIDIA GeForce 940MX (Maxwell 架构)

**适合的场景**:
- ✓ CVE 文本相似度计算
- ✓ CVSS 评分批量计算
- ✓ 关键词提取和 NLP 处理
- ✓ 数据聚类和分类

**不适合的场景**:
- ✗ SQL 查询（SQLite 不支持 GPU）
- ✗ Redis 缓存操作
- ✗ 文件 I/O 操作

### 安装 CUDA 和 CuPy（如需 GPU 加速）

#### 1. 安装 CUDA Toolkit

```bash
# 检查 CUDA 版本
nvidia-smi

# 下载并安装 CUDA Toolkit 11.x
# https://developer.nvidia.com/cuda-downloads
```

#### 2. 安装 CuPy（GPU 加速 NumPy）

```bash
# 激活虚拟环境
source /D/AI/cursor/starone/.venv/Scripts/activate

# 安装 CuPy（根据 CUDA 版本）
pip install cupy-cuda11x  # 替换 11x 为实际 CUDA 版本

# 验证安装
python -c "import cupy as cp; print('CuPy version:', cp.__version__); print('GPU available:', cp.cuda.is_available())"
```

#### 3. GPU 加速示例

创建 GPU 加速的 CVE 文本相似度计算：

```python
# gpu_utils.py
import cupy as cp
import numpy as np

class GPUAccelerator:
    """GPU 加速工具类"""

    @staticmethod
    def is_available():
        """检查 GPU 是否可用"""
        try:
            import cupy as cp
            return cp.cuda.is_available()
        except:
            return False

    @staticmethod
    def cosine_similarity_batch(vectors1, vectors2):
        """
        批量计算余弦相似度（GPU 加速）

        Args:
            vectors1: numpy array, shape (n, d)
            vectors2: numpy array, shape (m, d)

        Returns:
            similarity matrix, shape (n, m)
        """
        if GPUAccelerator.is_available():
            # 使用 GPU
            import cupy as cp
            v1_gpu = cp.asarray(vectors1)
            v2_gpu = cp.asarray(vectors2)

            # 归一化
            v1_norm = v1_gpu / cp.linalg.norm(v1_gpu, axis=1, keepdims=True)
            v2_norm = v2_gpu / cp.linalg.norm(v2_gpu, axis=1, keepdims=True)

            # 计算相似度
            similarity = cp.dot(v1_norm, v2_norm.T)

            # 返回到 CPU
            return cp.asnumpy(similarity)
        else:
            # 回退到 CPU
            v1_norm = vectors1 / np.linalg.norm(vectors1, axis=1, keepdims=True)
            v2_norm = vectors2 / np.linalg.norm(vectors2, axis=1, keepdims=True)
            return np.dot(v1_norm, v2_norm.T)

    @staticmethod
    def batch_cvss_score(cvss_vectors):
        """
        批量计算 CVSS 评分（GPU 加速）

        Args:
            cvss_vectors: list of CVSS vector strings

        Returns:
            scores: numpy array of scores
        """
        # 实现 GPU 加速的 CVSS 计算
        pass
```

使用示例：

```python
from gpu_utils import GPUAccelerator

# 检查 GPU
if GPUAccelerator.is_available():
    print("✓ GPU 加速可用")
else:
    print("⚠ GPU 不可用，使用 CPU")

# CVE 文本相似度匹配
import numpy as np
vectors1 = np.random.rand(1000, 512)  # 1000 个 CVE 描述向量
vectors2 = np.random.rand(431, 512)   # 431 个 Dell 公告向量

# GPU 加速计算
similarity = GPUAccelerator.cosine_similarity_batch(vectors1, vectors2)
print(f"Similarity matrix shape: {similarity.shape}")
```

---

## 📈 性能优化建议

### SQLite 优化

#### 1. 启用 WAL 模式

```python
# 在 cve_integrated_gui.py 中
conn = sqlite3.connect('cve_data/cve_database.db')
conn.execute('PRAGMA journal_mode=WAL')  # 已启用
conn.execute('PRAGMA synchronous=NORMAL')
conn.execute('PRAGMA cache_size=-64000')  # 64MB 缓存
conn.execute('PRAGMA temp_store=MEMORY')
```

#### 2. 添加索引（如果还没有）

```sql
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_dell_published ON dell_advisories(published_date DESC);
```

#### 3. 分页查询

```python
# 避免一次加载所有数据
def load_cve_data_paginated(page=1, limit=100):
    cursor.execute("SELECT * FROM cves ORDER BY published_date DESC LIMIT ? OFFSET ?",
                   (limit, (page-1)*limit))
    return cursor.fetchall()
```

### Redis 优化

#### 1. 使用连接池

```python
# redis_manager.py
from redis import ConnectionPool

pool = ConnectionPool(host='172.x.x.x', port=6379, password='defaultpassword', max_connections=10)
redis_client = redis.Redis(connection_pool=pool)
```

#### 2. 批量操作

```python
# 使用 pipeline
pipe = redis_client.pipeline()
for i in range(100):
    pipe.set(f'key_{i}', f'value_{i}')
pipe.execute()
```

---

## 🔧 故障排查

### 问题 1: WSL Redis 无法从 Windows 访问

**症状**: GUI 提示"Redis 连接失败"

**解决方法**:

1. 检查 Redis 是否在监听 0.0.0.0：
   ```bash
   sudo netstat -tlnp | grep redis
   ```

2. 检查 WSL 防火墙：
   ```bash
   sudo ufw allow 6379/tcp
   ```

3. 检查 Windows 防火墙（允许入站连接）

4. 重新获取 WSL IP：
   ```bash
   ip addr show eth0 | grep inet
   ```

### 问题 2: SQLite 查询太慢

**症状**: GUI 加载数据超过 5 秒

**解决方法**:

1. 重建索引：
   ```bash
   python -c "
   import sqlite3
   conn = sqlite3.connect('cve_data/cve_database.db')
   conn.execute('REINDEX')
   conn.execute('VACUUM')
   conn.close()
   "
   ```

2. 启用分页加载（修改 GUI 代码）

3. 增加 SQLite 缓存：
   ```python
   conn.execute('PRAGMA cache_size=-128000')  # 128MB
   ```

### 问题 3: GPU 加速不工作

**症状**: `cp.cuda.is_available()` 返回 False

**解决方法**:

1. 检查 CUDA 安装：
   ```bash
   nvidia-smi
   nvcc --version
   ```

2. 重新安装 CuPy：
   ```bash
   pip uninstall cupy
   pip install cupy-cuda11x  # 匹配 CUDA 版本
   ```

3. 检查 GPU 驱动：
   ```bash
   # 更新 NVIDIA 驱动到最新版本
   ```

---

## 📁 新的项目结构

```
D:\AI\Claude\CVE\
├── cve_data/
│   └── cve_database.db           # SQLite 数据库（143 MB）
├── backups/
│   └── cve_database_backup_*.db  # 备份文件
├── cve_integrated_gui.py         # GUI 主程序
├── redis_manager.py              # Redis 管理器（更新配置）
├── gpu_utils.py                  # GPU 加速工具（新增）
├── lightweight_startup.sh        # 新的启动脚本
├── .env                          # 环境配置
└── LIGHTWEIGHT_MIGRATION_GUIDE.md # 本文档
```

---

## 🚀 新的启动流程

### Linux/Git Bash

```bash
cd /D/AI/Claude/CVE
bash lightweight_startup.sh
```

### Windows PowerShell

```powershell
cd D:\AI\Claude\CVE
.\lightweight_startup.bat
```

---

## 📊 迁移后验证清单

- [ ] Docker 服务已完全停止
- [ ] WSL Redis 正常运行
- [ ] SQLite 数据完整（51,127 CVE + 431 Dell）
- [ ] GUI 可以正常启动
- [ ] 数据可以正常加载
- [ ] Redis 缓存功能正常
- [ ] CPU 占用显著降低
- [ ] 内存占用显著降低
- [ ] 系统响应速度改善

---

## 🎯 预期效果

完成迁移后，您应该看到：

| 指标 | 迁移前 | 迁移后 | 改善 |
|-----|--------|--------|------|
| **CPU 占用** | 50-70% | 5-10% | **降低 80%** ⚡⚡⚡ |
| **内存占用** | 8-15 GB | 2-4 GB | **降低 70%** ⚡⚡⚡ |
| **启动时间** | 30-60 秒 | 5-10 秒 | **快 5 倍** ⚡⚡ |
| **系统响应** | 偶尔卡顿 | 流畅 | **显著改善** ⚡⚡ |
| **数据完整性** | 100% | 100% | **无损迁移** ✓ |

---

## 📞 支持

如遇到问题，请检查：
1. WSL Redis 日志: `/var/log/redis/redis-server.log`
2. GUI 操作日志标签
3. SQLite 数据库完整性

---

**迁移完成时间**: 约 30 分钟
**技术难度**: 中等
**风险等级**: 低（已备份数据）

🎉 **祝迁移顺利！**
