# 智能知识管理平台 - 配置指南

**版本**: v5.2
**更新日期**: 2026-04-08

---

## 配置概述

本文档提供系统的详细配置说明，包括环境变量、数据库配置、性能调优等。

## 基础配置

### 1. Python 环境

**推荐版本**: Python 3.12+

```bash
# 查看 Python 版本
python --version

# 使用项目虚拟环境
source /E/AI/cursor/starone/.venv/Scripts/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. Redis 配置（可选，WSL 部署）

Redis 作为可选缓存层，通过 WSL 部署。系统在 Redis 不可用时自动降级到纯 SQLite 模式。

#### 安装与启动

```bash
# 在 WSL 中安装
wsl
sudo apt-get update
sudo apt-get install redis-server

# 启动 Redis
wsl sudo service redis-server start

# 验证连接
wsl redis-cli ping
# 输出: PONG
```

#### 配置密码（可选）

```bash
# 编辑 redis.conf
sudo nano /etc/redis/redis.conf

# 添加/修改
requirepass your_password_here
bind 0.0.0.0

# 重启服务
sudo service redis-server restart
```

### 3. 环境变量配置

复制 `.env.example` 为 `.env`，填入实际密钥：

```bash
# NVD API 配置
NVD_API_KEY=your_nvd_api_key_here

# AI API 配置
DASHSCOPE_API_KEY=your_qwen_api_key
CLAUDE_API_KEY=your_claude_api_key
EXA_API_KEY=your_exa_api_key

# Redis 配置（可选）
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# 数据目录
DATA_DIR=cve_data
```

---

## 高级配置

### NVD API Key 配置

**获取 API Key**:
1. 访问 https://nvd.nist.gov/developers/request-an-api-key
2. 填写申请表单（免费）
3. 在邮箱中接收 API Key

**性能对比**:
- 无 API Key: 6 秒/请求（限速 5 req/30s）
- 有 API Key: 0.6 秒/请求（限速 50 req/30s）
- **提升**: 10 倍

### Redis 性能优化

编辑 WSL 中的 `/etc/redis/redis.conf`：

```conf
# 内存管理
maxmemory 2gb
maxmemory-policy allkeys-lru

# 性能优化
tcp-backlog 511
timeout 0
tcp-keepalive 300

# 缓存模式（禁用持久化）
save ""
appendonly no
```

### SQLite 优化

系统已自动应用以下优化：

| 配置项 | 值 | 说明 |
|-------|-----|------|
| journal_mode | WAL | 写前日志，提升并发 |
| cache_size | 10000 | ~40MB 缓存 |
| synchronous | NORMAL | 平衡性能和安全 |
| temp_store | MEMORY | 临时数据在内存 |
| mmap_size | 30GB | 内存映射 I/O |

**数据库文件位置**: `cve_data/cve_database.db`

### 数据库备份

```bash
# 每日备份脚本
DATE=$(date +%Y%m%d)
cp cve_data/cve_database.db cve_data/backups/cve_database_$DATE.db

# 保留最近 30 天的备份
find cve_data/backups/ -name "*.db" -mtime +30 -delete
```

---

## 性能调优

### 系统资源配置

| 数据量 | CPU | 内存 | 磁盘 |
|--------|-----|------|------|
| < 10,000 条 | 2 核 | 2GB | 5GB |
| 10,000 - 50,000 | 4 核 | 4GB | 10GB |
| > 50,000 | 8 核 | 8GB | 20GB |

### 数据采集优化

```python
# collect_cves.py - 调整并发数
CONCURRENT_REQUESTS = 5  # 默认 5，可调整到 10-20（需要 API Key）
TIMEOUT = 30  # 秒

# cve_integrated_gui.py - 时间范围分块
chunk_size = timedelta(days=120)  # 默认 120 天
```

### GUI 性能优化

```python
# 关联数据显示限制
max_display = 1000  # 默认 1000

# 统计图表缩放（默认 110%）
stats_chart_scale = 1.1  # 范围 0.7 - 1.6

# 智能学习搜索结果上限
learn_search_limit = 500  # 有关键字时
learn_default_limit = 200  # 无关键字时
```

---

## 安全配置

### Redis 安全

```conf
# /etc/redis/redis.conf
requirepass your_strong_password_here
bind 127.0.0.1
```

### 防火墙配置

```bash
# 仅允许本地访问 Redis
sudo ufw deny 6379
sudo ufw allow from 127.0.0.1 to any port 6379
```

---

## 故障排查

### Redis 连接失败

```bash
# 检查 Redis 状态
wsl redis-cli ping

# 启动 Redis
wsl sudo service redis-server start

# 查看日志
wsl sudo tail -f /var/log/redis/redis-server.log
```

系统会自动降级到纯 SQLite 模式，无需手动干预。

### SQLite 数据库锁定

```bash
# 检查 WAL 文件
ls -lh cve_data/cve_database.db*

# 清理 WAL 文件（谨慎）
sqlite3 cve_data/cve_database.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

### 启用调试模式

```python
# cve_integrated_gui.py
DEBUG = True
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='cve_monitor_debug.log'
)
```

---

## 配置检查清单

- [ ] Python 3.12+ 已安装
- [ ] 虚拟环境已激活
- [ ] 依赖包已安装 (`pip install -r requirements.txt`)
- [ ] `.env` 文件已配置（API Key）
- [ ] 数据目录 `cve_data/` 已创建
- [ ] WSL Redis 已启动（可选）
- [ ] NVD API Key 已设置（推荐）

---

## 相关文档

- [README.md](README.md) - 项目概述和快速开始
- [README_WSL_ARCHITECTURE.md](README_WSL_ARCHITECTURE.md) - WSL 架构详细文档
- [CHANGELOG.md](CHANGELOG.md) - 版本变更记录

---

**维护者**: Claude AI + Philip Zhang
**最后更新**: 2026-04-08
**配置版本**: v5.2
