# CVE 漏洞监控系统 - WSL 架构文档

## 架构概览

**版本**: v4.0  
**架构**: SQLite + WSL Redis + GPU 加速（可选）  
**更新日期**: 2025-11-05

### 核心特性

- **SQLite 数据库**: 主数据存储，性能优化（WAL 模式）
- **WSL Redis**: 高性能缓存层，无需 Docker
- **GPU 加速**: 可选的向量搜索功能（Ollama + pgvector）
- **混合模式**: Redis 失败自动降级到纯 SQLite 模式

---

## 系统架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    CVE 监控系统 GUI                          │
│              (cve_integrated_gui.py)                        │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
   ┌────▼────┐              ┌────▼────┐
   │ SQLite  │              │ WSL     │
   │ 数据库  │◄─────备份────┤ Redis   │
   │(主存储) │              │(缓存层) │
   └─────────┘              └─────────┘
                                 │
                            失败自动降级
                                 │
                                 ▼
                          [纯 SQLite 模式]

可选 GPU 加速：
┌──────────────────────────────────────────────────┐
│  Ollama (LLM)  +  PostgreSQL/pgvector (向量DB)  │
│  └─ 用于智能分析和相似度搜索                     │
└──────────────────────────────────────────────────┘
```

---

## 快速开始

### 前提条件

1. **WSL 2** (Ubuntu)
2. **Redis** 在 WSL 中运行
3. **Python 3.8+** 和虚拟环境
4. **可选**: Docker Desktop（仅 GPU 功能需要）

### 一键启动

#### Windows 用户

```bat
双击运行: 启动CVE系统-WSL.bat
```

#### Linux/WSL 用户

```bash
# 检查环境
bash check_wsl_environment.sh

# 启动应用
source /D/AI/cursor/starone/.venv/Scripts/activate
python cve_integrated_gui.py
```

---

## 详细配置

### 1. WSL Redis 配置

#### 启动 Redis

```bash
# 在 WSL 中启动
wsl
sudo service redis-server start

# 验证
redis-cli ping  # 应返回 PONG
```

#### 配置 Redis（可选）

```bash
# 编辑配置文件
sudo nano /etc/redis/redis.conf

# 推荐配置
bind 0.0.0.0              # 允许外部访问
protected-mode no         # 禁用保护模式（内网环境）
requirepass your_password # 设置密码（推荐）
maxmemory 2gb            # 最大内存
maxmemory-policy allkeys-lru  # 淘汰策略
```

#### 环境变量配置

编辑 `.env` 文件：

```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=          # 如有密码填写
REDIS_DB=0
```

### 2. SQLite 优化配置

系统已自动应用以下 SQLite 优化：

| 配置项 | 值 | 说明 |
|-------|-----|------|
| journal_mode | WAL | 写前日志，提升并发 |
| cache_size | 10000 | ~40MB 缓存 |
| synchronous | NORMAL | 平衡性能和安全 |
| temp_store | MEMORY | 临时数据在内存 |
| mmap_size | 30GB | 内存映射 I/O |
| page_size | 4KB | 页大小 |

**数据库文件位置**: `cve_data/cve_database.db`

### 3. GPU 加速配置（可选）

#### 启动 GPU 服务

```bash
# 确保 Docker Desktop 正在运行
# 在 Git Bash 或 WSL 中执行
bash start_gpu_wsl.sh
```

#### GPU 服务包含

- **Ollama**: LLM 服务（端口 11434）
- **PostgreSQL/pgvector**: 向量数据库（端口 5432）
- **Open WebUI**: LLM 管理界面（端口 8080）
- **pgAdmin**: 数据库管理（端口 5050）

#### 安装 LLM 模型

```bash
# 向量生成模型（~137MB）
docker exec -it cve-ollama ollama pull nomic-embed-text

# CVE 分析模型（~2GB）
docker exec -it cve-ollama ollama pull qwen2.5:3b
```

---

## 运行模式

### 模式 1: SQLite + WSL Redis（推荐）

- **优点**: 高性能，自动缓存，故障自动降级
- **适用**: 日常使用，生产环境
- **启动**: `启动CVE系统-WSL.bat`

### 模式 2: 纯 SQLite

- **优点**: 无依赖，简单可靠
- **适用**: Redis 不可用时
- **启动**: 系统自动检测并降级

### 模式 3: SQLite + WSL Redis + GPU

- **优点**: 完整功能，智能分析，向量搜索
- **适用**: 高级分析需求
- **启动**: 
  1. `bash start_gpu_wsl.sh`（启动 GPU 服务）
  2. `启动CVE系统-WSL.bat`（启动主程序）

---

## 性能优化

### SQLite 优化

✅ **已应用优化**:
- WAL 模式（并发读写）
- 40MB 缓存
- 内存映射 I/O
- 增量自动清理

### Redis 优化

推荐配置 (WSL `/etc/redis/redis.conf`):

```conf
# 内存管理
maxmemory 2gb
maxmemory-policy allkeys-lru

# 性能优化
tcp-backlog 511
timeout 0
tcp-keepalive 300

# 禁用持久化（缓存模式）
save ""
appendonly no
```

### GPU 优化

- **模型选择**: 使用轻量级模型（如 qwen2.5:3b）
- **批处理**: 批量处理 CVE 向量化
- **缓存**: 向量结果缓存到 PostgreSQL

---

## 故障排查

### Redis 连接失败

```bash
# 检查 Redis 状态
wsl redis-cli ping

# 启动 Redis
wsl sudo service redis-server start

# 查看 Redis 日志
wsl sudo tail -f /var/log/redis/redis-server.log
```

### SQLite 数据库锁定

```bash
# 检查 WAL 文件
ls -lh cve_data/cve_database.db*

# 清理 WAL 文件（谨慎！）
sqlite3 cve_data/cve_database.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

### GPU 服务启动失败

```bash
# 检查 Docker
docker ps

# 查看服务日志
docker-compose -f docker-compose-gpu-lite.yml logs -f

# 检查 GPU
nvidia-smi
```

---

## 文件结构

```
CVE/
├── cve_integrated_gui.py          # 主程序
├── redis_manager.py               # Redis 管理器
├── collect_cves.py                # CVE 收集器
├── dell_security_scraper.py       # Dell 公告爬虫
│
├── .env.example                   # 环境配置模板
├── requirements.txt               # Python 依赖
│
├── 启动CVE系统-WSL.bat            # Windows 启动脚本
├── check_wsl_environment.sh       # WSL 环境检查
├── start_gpu_wsl.sh              # GPU 服务启动
│
├── docker-compose-gpu-lite.yml    # GPU 服务配置
├── init-vector-db.sql            # 向量数据库初始化
│
├── cve_data/                      # 数据目录
│   ├── cve_database.db           # SQLite 数据库
│   ├── cve_database.db-wal       # WAL 日志
│   └── *.csv                     # CSV 备份
│
└── archive/                       # 归档目录
    └── mongodb_backup_*/         # MongoDB 旧文件
```

---

## 依赖版本

```
Python >= 3.8
redis[hiredis] >= 5.0.1
aiohttp >= 3.9.0
requests >= 2.31.0
feedparser >= 6.0.10
beautifulsoup4 >= 4.12.0
pandas >= 2.0.0
numpy >= 1.24.0
```

**GPU 可选依赖**:
```
psycopg2-binary >= 2.9.9  # PostgreSQL 驱动
```

---

## 常用命令

### WSL Redis

```bash
# 启动
wsl sudo service redis-server start

# 停止
wsl sudo service redis-server stop

# 重启
wsl sudo service redis-server restart

# 查看状态
wsl redis-cli info server

# 清空缓存
wsl redis-cli FLUSHALL
```

### GPU 服务

```bash
# 启动
bash start_gpu_wsl.sh

# 停止
docker-compose -f docker-compose-gpu-lite.yml down

# 查看日志
docker-compose -f docker-compose-gpu-lite.yml logs -f

# 重启
docker-compose -f docker-compose-gpu-lite.yml restart
```

### 数据库维护

```bash
# SQLite 优化
sqlite3 cve_data/cve_database.db "VACUUM;"

# 查看数据库大小
du -h cve_data/cve_database.db*

# 导出 CSV
python cve_integrated_gui.py --export-csv
```

---

## 性能基准

### SQLite + Redis 模式

| 操作 | 性能 | 说明 |
|-----|------|------|
| 首次加载 | ~2-3s | 从 SQLite 加载 |
| 缓存命中 | ~50-100ms | 从 Redis 读取 |
| 写入 | ~1000/s | 批量插入 |
| 搜索 | ~10ms | 索引查询 |

### GPU 加速模式

| 操作 | 性能 | 说明 |
|-----|------|------|
| 向量生成 | ~100/s | Ollama GPU |
| 相似度搜索 | ~5ms | pgvector 索引 |

---

## 更新日志

### v4.0 (2025-11-05)

- ✨ 迁移到 SQLite + WSL Redis 架构
- ⚡ SQLite 性能优化（WAL 模式）
- 🔧 Redis 连接自动降级
- 🎯 GPU 加速可选化
- 🧹 清理 MongoDB 相关代码
- 📝 新增完整文档

### v3.7 (之前版本)

- MongoDB + Redis 架构
- Docker 容器化部署

---

## 支持与反馈

- **文档**: `README_WSL_ARCHITECTURE.md`
- **环境检查**: `bash check_wsl_environment.sh`
- **问题反馈**: GitHub Issues

---

**最后更新**: 2025-11-05  
**架构版本**: v4.0 - SQLite + WSL Redis  
**维护者**: CVE 监控系统团队
